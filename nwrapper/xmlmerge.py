"""Build a derived combined report from authoritative per-job Nmap XML."""

from __future__ import annotations

import copy
import ipaddress
import os
import xml.etree.ElementTree as ET
from pathlib import Path

from nwrapper.models import ScanPlan
from nwrapper.nmap_xml import NmapXmlError, host_address, load_completed_xml


class XmlMergeError(ValueError):
    """Raised when completed job XML cannot form one combined report."""


def _required_attribute(
    element: ET.Element, attribute: str, source: Path
) -> str:
    value = element.get(attribute)
    if not value:
        raise XmlMergeError(
            f"Nmap XML is missing {element.tag!r} attribute "
            f"{attribute!r}: {source}"
        )
    return value


def _timestamp(value: str, source: Path, attribute: str) -> float:
    try:
        return float(value)
    except ValueError as exc:
        raise XmlMergeError(
            f"Nmap XML has an invalid {attribute} timestamp: {source}"
        ) from exc


def _common_value(values: list[str]) -> str:
    return values[0] if len(set(values)) == 1 else "mixed"


def merge_completed_xml(
    plan: ScanPlan, jobs_dir: Path, destination: Path
) -> None:
    """Atomically publish a combined XML report for every job in ``plan``."""
    if not plan.jobs:
        raise XmlMergeError("cannot merge an empty scan plan")

    starts: list[tuple[float, str, str | None]] = []
    finishes: list[tuple[float, str, str | None]] = []
    versions: list[str] = []
    xml_versions: list[str] = []
    combined_hosts: list[ET.Element] = []
    seen_addresses: set[str] = set()
    up = 0
    down = 0

    for job in plan.jobs:
        source = jobs_dir / f"{job.identifier}.xml"
        try:
            root = load_completed_xml(source, job.targets)
        except NmapXmlError as exc:
            raise XmlMergeError(str(exc)) from exc

        start_value = _required_attribute(root, "start", source)
        starts.append(
            (
                _timestamp(start_value, source, "start"),
                start_value,
                root.get("startstr"),
            )
        )
        versions.append(_required_attribute(root, "version", source))
        xml_versions.append(
            _required_attribute(root, "xmloutputversion", source)
        )

        finished = root.find("./runstats/finished")
        if finished is None:  # load_completed_xml already enforces this boundary.
            raise XmlMergeError(f"Nmap XML is incomplete: {source}")
        finish_value = _required_attribute(finished, "time", source)
        finishes.append(
            (
                _timestamp(finish_value, source, "finished time"),
                finish_value,
                finished.get("timestr"),
            )
        )

        hosts = {host_address(host): host for host in root.findall("host")}
        for target in job.targets:
            address = str(ipaddress.ip_address(target))
            if address in seen_addresses:
                raise XmlMergeError(
                    f"target appears in more than one planned job: {address}"
                )
            seen_addresses.add(address)
            host = hosts[address]
            status = host.find("status")
            if status is None:
                raise XmlMergeError(
                    f"Nmap host is missing status for {address}: {source}"
                )
            state = status.get("state")
            if state == "up":
                up += 1
            elif state == "down":
                down += 1
            combined_hosts.append(copy.deepcopy(host))

    earliest = min(starts, key=lambda item: item[0])
    latest = max(finishes, key=lambda item: item[0])
    root_attributes = {
        "scanner": "nmap",
        "args": "nwrapper combined report",
        "start": earliest[1],
        "version": _common_value(versions),
        "xmloutputversion": _common_value(xml_versions),
    }
    if earliest[2]:
        root_attributes["startstr"] = earliest[2]

    combined = ET.Element("nmaprun", root_attributes)
    ET.SubElement(combined, "verbose", level="0")
    ET.SubElement(combined, "debugging", level="0")
    combined.extend(combined_hosts)

    runstats = ET.SubElement(combined, "runstats")
    elapsed = max(0.0, latest[0] - earliest[0])
    finished_attributes = {
        "time": latest[1],
        "elapsed": f"{elapsed:.2f}",
        "summary": (
            f"Nmap done; {len(combined_hosts)} IP addresses scanned "
            f"by nwrapper across {len(plan.jobs)} jobs"
        ),
        "exit": "success",
    }
    if latest[2]:
        finished_attributes["timestr"] = latest[2]
    ET.SubElement(runstats, "finished", finished_attributes)
    ET.SubElement(
        runstats,
        "hosts",
        up=str(up),
        down=str(down),
        total=str(len(combined_hosts)),
    )

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f"{destination.name}.partial")
    temporary.unlink(missing_ok=True)
    try:
        ET.ElementTree(combined).write(
            temporary, encoding="utf-8", xml_declaration=True
        )
        parsed = ET.parse(temporary).getroot()
        if parsed.tag != "nmaprun":
            raise XmlMergeError("combined XML has an unexpected root element")
        os.replace(temporary, destination)
    except (OSError, ET.ParseError) as exc:
        temporary.unlink(missing_ok=True)
        raise XmlMergeError(f"cannot publish combined Nmap XML: {exc}") from exc
