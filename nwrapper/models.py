"""Core immutable planning models."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanJob:
    """One exact Nmap target chunk sharing a TCP port set."""

    identifier: str
    ports: tuple[int, ...]
    targets: tuple[str, ...]

    @property
    def host_port_count(self) -> int:
        """Return the number of host/port pairs covered by the job."""
        return len(self.targets) * len(self.ports)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible representation."""
        return {
            "id": self.identifier,
            "ports": list(self.ports),
            "targets": list(self.targets),
        }


@dataclass(frozen=True)
class ScanPlan:
    """A deterministic collection of jobs for one Masscan input."""

    source: str
    jobs: tuple[ScanJob, ...]
    target_count: int
    host_port_count: int

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible representation."""
        return {
            "format_version": 1,
            "source": self.source,
            "target_count": self.target_count,
            "host_port_count": self.host_port_count,
            "jobs": [job.to_dict() for job in self.jobs],
        }
