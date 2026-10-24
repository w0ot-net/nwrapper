import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from nwrapper.nmap_xml import NmapXmlError, load_completed_xml


def _write_xml(path: Path, targets: tuple[str, ...], finished: bool = True) -> None:
    root = ET.Element(
        "nmaprun",
        scanner="nmap",
        version="7.95",
        xmloutputversion="1.05",
    )
    for target in targets:
        host = ET.SubElement(root, "host")
        ET.SubElement(host, "status", state="up", reason="user-set", reason_ttl="0")
        ET.SubElement(host, "address", addr=target, addrtype="ipv4")
    if finished:
        runstats = ET.SubElement(root, "runstats")
        ET.SubElement(runstats, "finished", time="1", elapsed="0.1")
        ET.SubElement(runstats, "hosts", up=str(len(targets)), total=str(len(targets)))
    ET.ElementTree(root).write(path, encoding="unicode", xml_declaration=True)


def test_load_completed_xml_accepts_exact_targets(tmp_path: Path) -> None:
    path = tmp_path / "result.xml"
    _write_xml(path, ("192.0.2.1", "192.0.2.2"))

    root = load_completed_xml(path, ("192.0.2.2", "192.0.2.1"))

    assert root.tag == "nmaprun"


@pytest.mark.parametrize("contents", ["<nmaprun>", "<wrong />"])
def test_load_completed_xml_rejects_malformed_or_wrong_root(
    tmp_path: Path, contents: str
) -> None:
    path = tmp_path / "result.xml"
    path.write_text(contents, encoding="utf-8")

    with pytest.raises(NmapXmlError):
        load_completed_xml(path, ("192.0.2.1",))


def test_load_completed_xml_rejects_incomplete_results(tmp_path: Path) -> None:
    path = tmp_path / "result.xml"
    _write_xml(path, ("192.0.2.1",), finished=False)

    with pytest.raises(NmapXmlError, match="incomplete"):
        load_completed_xml(path, ("192.0.2.1",))


def test_load_completed_xml_rejects_wrong_targets(tmp_path: Path) -> None:
    path = tmp_path / "result.xml"
    _write_xml(path, ("192.0.2.2",))

    with pytest.raises(NmapXmlError, match="missing=192.0.2.1; unexpected=192.0.2.2"):
        load_completed_xml(path, ("192.0.2.1",))
