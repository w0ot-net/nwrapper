"""Parse Masscan grepable output."""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from pathlib import Path


class MasscanParseError(ValueError):
    """Raised when a Masscan result line cannot be interpreted safely."""


def _parse_address(host_field: str, line_number: int) -> str:
    value = host_field.removeprefix("Host:").strip().split(maxsplit=1)[0]
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise MasscanParseError(
            f"line {line_number}: invalid host address {value!r}"
        ) from exc


def parse_grepable(path: Path) -> dict[str, tuple[int, ...]]:
    """Return open TCP ports by address from a Masscan ``-oG`` report.

    Non-TCP entries are intentionally ignored. Duplicate discoveries are
    collapsed, which also handles reports assembled from multiple Masscan
    runs.
    """
    discovered: dict[str, set[int]] = defaultdict(set)

    with path.open(encoding="utf-8", errors="replace") as report:
        for line_number, raw_line in enumerate(report, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            fields = line.split("\t")
            host_field = next(
                (field for field in fields if field.startswith("Host:")), None
            )
            ports_field = next(
                (field for field in fields if field.startswith("Ports:")), None
            )
            if host_field is None or ports_field is None:
                continue

            address = _parse_address(host_field, line_number)
            entries = ports_field.removeprefix("Ports:").strip()
            for entry in entries.split(","):
                parts = entry.strip().split("/")
                if len(parts) < 3:
                    raise MasscanParseError(
                        f"line {line_number}: malformed port entry {entry!r}"
                    )

                port_text, state, protocol = parts[:3]
                if state != "open" or protocol.lower() != "tcp":
                    continue

                try:
                    port = int(port_text)
                except ValueError as exc:
                    raise MasscanParseError(
                        f"line {line_number}: invalid TCP port {port_text!r}"
                    ) from exc

                if not 0 <= port <= 65535:
                    raise MasscanParseError(
                        f"line {line_number}: TCP port out of range: {port}"
                    )
                discovered[address].add(port)

    return {
        address: tuple(sorted(ports))
        for address, ports in discovered.items()
        if ports
    }
