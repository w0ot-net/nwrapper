"""Create exact, deterministic Nmap jobs."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections import defaultdict
from pathlib import Path

from nwrapper.models import ScanJob, ScanPlan


def _address_key(address: str) -> tuple[int, int]:
    parsed = ipaddress.ip_address(address)
    return parsed.version, int(parsed)


def _job_identifier(ports: tuple[int, ...], targets: tuple[str, ...]) -> str:
    payload = json.dumps(
        {"ports": ports, "targets": targets},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()[:16]


def build_plan(
    source: Path,
    targets: dict[str, tuple[int, ...]],
    batch_size: int,
) -> ScanPlan:
    """Group identical port sets and split them into bounded target chunks."""
    if batch_size < 1:
        raise ValueError("batch_size must be at least 1")

    grouped: dict[tuple[int, ...], list[str]] = defaultdict(list)
    for address, ports in targets.items():
        if ports:
            grouped[tuple(sorted(set(ports)))].append(address)

    jobs: list[ScanJob] = []
    for ports in sorted(grouped):
        addresses = sorted(grouped[ports], key=_address_key)
        for offset in range(0, len(addresses), batch_size):
            chunk = tuple(addresses[offset : offset + batch_size])
            jobs.append(
                ScanJob(
                    identifier=_job_identifier(ports, chunk),
                    ports=ports,
                    targets=chunk,
                )
            )

    return ScanPlan(
        source=str(source),
        jobs=tuple(jobs),
        target_count=len(targets),
        host_port_count=sum(len(ports) for ports in targets.values()),
    )
