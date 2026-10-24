"""Validation helpers for authoritative per-job Nmap XML."""

from __future__ import annotations

import ipaddress
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from pathlib import Path


class NmapXmlError(ValueError):
    """Raised when a per-job Nmap XML file is not a completed result."""


def host_address(host: ET.Element) -> str:
    """Return the normalized IP address represented by an Nmap host."""
    for address in host.findall("address"):
        if address.get("addrtype") not in {"ipv4", "ipv6"}:
            continue
        value = address.get("addr")
        if value is None:
            break
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise NmapXmlError(f"invalid host address in Nmap XML: {value!r}") from exc
    raise NmapXmlError("Nmap host is missing an IPv4 or IPv6 address")


def load_completed_xml(path: Path, expected_targets: Iterable[str]) -> ET.Element:
    """Load a completed Nmap XML document for exactly ``expected_targets``."""
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise NmapXmlError(f"cannot parse completed Nmap XML {path}: {exc}") from exc

    if root.tag != "nmaprun":
        raise NmapXmlError(f"unexpected Nmap XML root in {path}: {root.tag!r}")
    finished = root.find("./runstats/finished")
    if finished is None:
        raise NmapXmlError(f"Nmap XML is incomplete: {path}")
    if finished.get("exit") != "success":
        raise NmapXmlError(f"Nmap XML did not finish successfully: {path}")

    hosts = root.findall("host")
    timed_out = [
        host_address(host) for host in hosts if host.get("timedout") == "true"
    ]
    if timed_out:
        raise NmapXmlError(
            f"Nmap XML contains timed-out hosts: {path} "
            f"(targets={','.join(timed_out)})"
        )

    actual = [host_address(host) for host in hosts]
    if len(actual) != len(set(actual)):
        raise NmapXmlError(f"Nmap XML contains duplicate hosts: {path}")

    expected = {str(ipaddress.ip_address(target)) for target in expected_targets}
    actual_set = set(actual)
    if actual_set != expected:
        missing = ",".join(sorted(expected - actual_set)) or "none"
        unexpected = ",".join(sorted(actual_set - expected)) or "none"
        raise NmapXmlError(
            f"Nmap XML targets do not match the planned job: {path} "
            f"(missing={missing}; unexpected={unexpected})"
        )
    return root
