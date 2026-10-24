"""Nmap command construction and future process orchestration boundary."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from nwrapper.models import ScanJob


def build_nmap_command(
    job: ScanJob,
    targets_file: Path,
    partial_xml: Path,
    host_timeout: str = "15m",
    nmap_binary: str = "nmap",
    extra_arguments: Sequence[str] = (),
) -> list[str]:
    """Build, but do not execute, one exact TCP service scan command."""
    if not job.ports:
        raise ValueError("an Nmap job must contain at least one TCP port")
    if not job.targets:
        raise ValueError("an Nmap job must contain at least one target")

    return [
        nmap_binary,
        "-Pn",
        "-n",
        "-sV",
        "--host-timeout",
        host_timeout,
        "-p",
        ",".join(str(port) for port in job.ports),
        *extra_arguments,
        "-iL",
        str(targets_file),
        "-oX",
        str(partial_xml),
    ]
