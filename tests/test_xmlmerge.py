from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from nwrapper.models import ScanJob, ScanPlan
from nwrapper.xmlmerge import XmlMergeError, merge_completed_xml


def _plan(*jobs: ScanJob) -> ScanPlan:
    return ScanPlan(
        source="scan.oG",
        jobs=jobs,
        target_count=sum(len(job.targets) for job in jobs),
        host_port_count=sum(job.host_port_count for job in jobs),
    )


def _write_job_xml(
    path: Path,
    hosts: tuple[tuple[str, str], ...],
    *,
    start: str = "100",
    finish: str = "150",
    version: str = "7.95",
    xml_version: str = "1.05",
) -> None:
    root = ET.Element(
        "nmaprun",
        scanner="nmap",
        args="nmap per-job command",
        start=start,
        startstr=f"start-{start}",
        version=version,
        xmloutputversion=xml_version,
    )
    ET.SubElement(root, "verbose", level="0")
    ET.SubElement(root, "debugging", level="0")
    for address, state in hosts:
        host = ET.SubElement(root, "host")
        ET.SubElement(
            host, "status", state=state, reason="user-set", reason_ttl="0"
        )
        ET.SubElement(host, "address", addr=address, addrtype="ipv4")
    runstats = ET.SubElement(root, "runstats")
    ET.SubElement(
        runstats,
        "finished",
        time=finish,
        timestr=f"finish-{finish}",
        elapsed=str(float(finish) - float(start)),
        summary="per-job summary",
        exit="success",
    )
    up = sum(state == "up" for _, state in hosts)
    down = sum(state == "down" for _, state in hosts)
    ET.SubElement(
        runstats,
        "hosts",
        up=str(up),
        down=str(down),
        total=str(len(hosts)),
    )
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


def test_merge_builds_deterministic_current_plan_report(tmp_path: Path) -> None:
    first = ScanJob("first", (22, 80), ("192.0.2.2", "192.0.2.1"))
    second = ScanJob("second", (443,), ("192.0.2.3",))
    plan = _plan(first, second)
    jobs_dir = tmp_path / "jobs"
    jobs_dir.mkdir()
    first_xml = jobs_dir / "first.xml"
    second_xml = jobs_dir / "second.xml"
    _write_job_xml(
        first_xml,
        (("192.0.2.1", "down"), ("192.0.2.2", "up")),
        start="100",
        finish="175",
        version="7.94",
    )
    _write_job_xml(
        second_xml,
        (("192.0.2.3", "up"),),
        start="150",
        finish="250",
        version="7.95",
    )
    before = {first_xml: first_xml.read_bytes(), second_xml: second_xml.read_bytes()}
    (jobs_dir / "orphan.xml").write_text("<not-xml", encoding="utf-8")

    destination = tmp_path / "combined.xml"
    merge_completed_xml(plan, jobs_dir, destination)

    combined = ET.parse(destination).getroot()
    assert combined.attrib == {
        "scanner": "nmap",
        "args": "nwrapper combined report",
        "start": "100",
        "version": "mixed",
        "xmloutputversion": "1.05",
        "startstr": "start-100",
    }
    assert [child.tag for child in combined] == [
        "verbose",
        "debugging",
        "host",
        "host",
        "host",
        "runstats",
    ]
    addresses = [host.find("address") for host in combined.findall("host")]
    assert all(address is not None for address in addresses)
    assert [address.get("addr") for address in addresses if address is not None] == [
        "192.0.2.2",
        "192.0.2.1",
        "192.0.2.3",
    ]
    assert combined.findall("scaninfo") == []
    finished = combined.find("./runstats/finished")
    assert finished is not None
    assert finished.get("time") == "250"
    assert finished.get("timestr") == "finish-250"
    assert finished.get("elapsed") == "150.00"
    hosts = combined.find("./runstats/hosts")
    assert hosts is not None
    assert hosts.attrib == {"up": "2", "down": "1", "total": "3"}
    assert not (tmp_path / "combined.xml.partial").exists()
    assert {path: path.read_bytes() for path in before} == before

    first_report = destination.read_bytes()
    destination.unlink()
    merge_completed_xml(plan, jobs_dir, destination)
    assert destination.read_bytes() == first_report


@pytest.mark.parametrize(
    "contents",
    [
        "<not-xml",
        (
            "<nmaprun scanner='nmap' start='1' version='7.95' "
            "xmloutputversion='1.05'><runstats><finished time='2'/>"
            "</runstats></nmaprun>"
        ),
    ],
)
def test_merge_rejects_malformed_or_missing_hosts_without_replacing_destination(
    tmp_path: Path, contents: str
) -> None:
    job = ScanJob("job", (80,), ("192.0.2.1",))
    jobs_dir = tmp_path / "jobs"
    jobs_dir.mkdir()
    (jobs_dir / "job.xml").write_text(contents, encoding="utf-8")
    destination = tmp_path / "combined.xml"
    destination.write_text("previous report", encoding="utf-8")

    with pytest.raises(XmlMergeError):
        merge_completed_xml(_plan(job), jobs_dir, destination)

    assert destination.read_text(encoding="utf-8") == "previous report"
    assert not (tmp_path / "combined.xml.partial").exists()


def test_merge_rejects_target_repeated_across_jobs(tmp_path: Path) -> None:
    first = ScanJob("first", (80,), ("192.0.2.1",))
    second = ScanJob("second", (443,), ("192.0.2.1",))
    jobs_dir = tmp_path / "jobs"
    jobs_dir.mkdir()
    _write_job_xml(jobs_dir / "first.xml", (("192.0.2.1", "up"),))
    _write_job_xml(jobs_dir / "second.xml", (("192.0.2.1", "up"),))

    with pytest.raises(XmlMergeError, match="more than one planned job"):
        merge_completed_xml(_plan(first, second), jobs_dir, tmp_path / "combined.xml")


def test_merge_requires_every_current_plan_job(tmp_path: Path) -> None:
    job = ScanJob("missing", (80,), ("192.0.2.1",))

    with pytest.raises(XmlMergeError, match="cannot parse completed Nmap XML"):
        merge_completed_xml(
            _plan(job), tmp_path / "jobs", tmp_path / "combined.xml"
        )
