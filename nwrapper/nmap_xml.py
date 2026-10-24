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
    if root.find("./runstats/finished") is None:
        raise NmapXmlError(f"Nmap XML is incomplete: {path}")

    actual = [host_address(host) for host in root.findall("host")]
    if len(actual) != len(set(actual)):
        raise NmapXmlError(f"Nmap XML contains duplicate hosts: {path}")

    expected = {str(ipaddress.ip_address(target)) for target in expected_targets}
    if set(actual) != expected:
        raise NmapXmlError(
            f"Nmap XML targets do not match the planned job: {path}"
        )
    return root
