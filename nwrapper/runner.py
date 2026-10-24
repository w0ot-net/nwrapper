"""Nmap command construction and bounded process orchestration."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from nwrapper.models import ScanJob, ScanPlan
from nwrapper.nmap_xml import NmapXmlError, load_completed_xml


class RunnerError(RuntimeError):
    """Raised when the scan runner cannot start safely."""


@dataclass(frozen=True)
class RunResult:
    """Outcome of running all jobs in one plan."""

    completed: int
    skipped: int
    failed_ids: tuple[str, ...]
    interrupted: bool = False


@dataclass(frozen=True)
class _ActiveJob:
    job: ScanJob
    process: subprocess.Popen[bytes]
    partial_xml: Path
    final_xml: Path


def build_nmap_command(
    job: ScanJob,
    targets_file: Path,
    partial_xml: Path,
    host_timeout: str = "15m",
    nmap_binary: str = "nmap",
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
        "-iL",
        str(targets_file),
        "-oX",
        str(partial_xml),
    ]


def _paths(jobs_dir: Path, job: ScanJob) -> tuple[Path, Path, Path, Path]:
    base = jobs_dir / job.identifier
    return (
        base.with_suffix(".targets"),
        base.with_suffix(".log"),
        base.with_suffix(".xml.partial"),
        base.with_suffix(".xml"),
    )


def _is_complete(path: Path, job: ScanJob) -> bool:
    try:
        load_completed_xml(path, job.targets)
    except NmapXmlError:
        return False
    return True


def _start_job(
    job: ScanJob,
    jobs_dir: Path,
    host_timeout: str,
    nmap_binary: str,
) -> _ActiveJob:
    targets_file, log_file, partial_xml, final_xml = _paths(jobs_dir, job)
    targets_file.write_text("\n".join(job.targets) + "\n", encoding="utf-8")
    partial_xml.unlink(missing_ok=True)
    command = build_nmap_command(
        job,
        targets_file,
        partial_xml,
        host_timeout=host_timeout,
        nmap_binary=nmap_binary,
    )

    log: BinaryIO
    with log_file.open("wb") as log:
        process = subprocess.Popen(
            command,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    return _ActiveJob(job, process, partial_xml, final_xml)


def _stop_active(active: list[_ActiveJob]) -> None:
    for item in active:
        if item.process.poll() is None:
            item.process.terminate()
    for item in active:
        try:
            item.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            item.process.kill()
            item.process.wait()


def run_jobs(
    plan: ScanPlan,
    output_dir: Path,
    max_processes: int,
    host_timeout: str,
    nmap_binary: str = "nmap",
    poll_interval: float = 0.05,
) -> RunResult:
    """Run all incomplete jobs with bounded concurrency."""
    if max_processes < 1:
        raise ValueError("jobs must be at least 1")
    if not host_timeout:
        raise ValueError("host timeout must not be empty")

    resolved_nmap = shutil.which(nmap_binary)
    if resolved_nmap is None:
        raise RunnerError(f"Nmap executable not found: {nmap_binary}")

    jobs_dir = output_dir / "jobs"
    jobs_dir.mkdir(parents=True, exist_ok=True)
    pending: deque[ScanJob] = deque()
    skipped = 0
    for job in plan.jobs:
        final_xml = _paths(jobs_dir, job)[3]
        if _is_complete(final_xml, job):
            skipped += 1
        else:
            pending.append(job)

    active: list[_ActiveJob] = []
    completed = 0
    failed_ids: list[str] = []

    try:
        while pending or active:
            while pending and len(active) < max_processes:
                job = pending.popleft()
                try:
                    active.append(
                        _start_job(job, jobs_dir, host_timeout, resolved_nmap)
                    )
                except OSError:
                    failed_ids.append(job.identifier)

            made_progress = False
            for item in active.copy():
                return_code = item.process.poll()
                if return_code is None:
                    continue
                active.remove(item)
                made_progress = True
                if return_code != 0:
                    failed_ids.append(item.job.identifier)
                    continue
                try:
                    load_completed_xml(item.partial_xml, item.job.targets)
                    os.replace(item.partial_xml, item.final_xml)
                except (NmapXmlError, OSError):
                    failed_ids.append(item.job.identifier)
                    continue
                completed += 1

            if active and not made_progress:
                time.sleep(poll_interval)
    except KeyboardInterrupt:
        _stop_active(active)
        return RunResult(
            completed=completed,
            skipped=skipped,
            failed_ids=tuple(failed_ids),
            interrupted=True,
        )

    return RunResult(
        completed=completed,
        skipped=skipped,
        failed_ids=tuple(failed_ids),
    )
