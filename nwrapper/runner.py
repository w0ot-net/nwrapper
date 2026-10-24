"""Nmap command construction and bounded process orchestration."""

from __future__ import annotations

import logging
import os
import shlex
import shutil
import subprocess
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from nwrapper.models import ScanJob, ScanPlan
from nwrapper.nmap_xml import NmapXmlError, load_completed_xml

logger = logging.getLogger(__name__)

DEFAULT_HOST_TIMEOUT = "15m"
PROGRESS_INTERVAL_SECONDS = 30.0


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
    started_at: float


def _progress(message: str) -> None:
    print(message, flush=True)


def build_nmap_command(
    job: ScanJob,
    targets_file: Path,
    partial_xml: Path,
    host_timeout: str = DEFAULT_HOST_TIMEOUT,
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
    except NmapXmlError as exc:
        logger.debug(
            "job result is not reusable id=%s path=%s reason=%s",
            job.identifier,
            path,
            exc,
        )
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
    if partial_xml.exists():
        logger.debug(
            "removing stale partial XML id=%s path=%s",
            job.identifier,
            partial_xml,
        )
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
    started_at = time.monotonic()
    logger.debug("job command id=%s command=%s", job.identifier, shlex.join(command))
    logger.info(
        "job started id=%s pid=%d targets=%d ports=%s nmap_log=%s",
        job.identifier,
        process.pid,
        len(job.targets),
        ",".join(str(port) for port in job.ports),
        log_file,
    )
    return _ActiveJob(job, process, partial_xml, final_xml, started_at)


def _stop_active(active: list[_ActiveJob]) -> None:
    for item in active:
        if item.process.poll() is None:
            logger.warning(
                "terminating active job id=%s pid=%d",
                item.job.identifier,
                item.process.pid,
            )
            item.process.terminate()
    for item in active:
        try:
            item.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            logger.warning(
                "killing unresponsive job id=%s pid=%d",
                item.job.identifier,
                item.process.pid,
            )
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
    started = time.monotonic()
    if max_processes < 1:
        raise ValueError("jobs must be at least 1")
    if not host_timeout:
        raise ValueError("host timeout must not be empty")

    logger.info(
        "runner started jobs=%d max_processes=%d host_timeout=%s",
        len(plan.jobs),
        max_processes,
        host_timeout,
    )

    jobs_dir = output_dir / "jobs"
    jobs_dir.mkdir(parents=True, exist_ok=True)
    pending: deque[ScanJob] = deque()
    skipped = 0
    for job in plan.jobs:
        final_xml = _paths(jobs_dir, job)[3]
        if _is_complete(final_xml, job):
            skipped += 1
            logger.info(
                "job skipped as complete id=%s path=%s",
                job.identifier,
                final_xml,
            )
        else:
            pending.append(job)

    active: list[_ActiveJob] = []
    completed = 0
    failed_ids: list[str] = []
    total_jobs = len(plan.jobs)
    worker_count = min(max_processes, len(pending))
    _progress(
        f"[*] {total_jobs} jobs: {skipped} already complete, "
        f"{len(pending)} pending, {worker_count} workers"
    )

    if not pending:
        logger.info(
            "runner finished interrupted=false completed=0 skipped=%d failed=0 "
            "duration_seconds=%.3f",
            skipped,
            time.monotonic() - started,
        )
        return RunResult(completed=0, skipped=skipped, failed_ids=())

    resolved_nmap = shutil.which(nmap_binary)
    if resolved_nmap is None:
        raise RunnerError(f"Nmap executable not found: {nmap_binary}")
    logger.debug("Nmap executable resolved path=%s", resolved_nmap)
    next_heartbeat = time.monotonic() + PROGRESS_INTERVAL_SECONDS

    try:
        while pending or active:
            while pending and len(active) < max_processes:
                job = pending.popleft()
                try:
                    item = _start_job(job, jobs_dir, host_timeout, resolved_nmap)
                    active.append(item)
                    _progress(
                        f"[>] Started {job.identifier}: {len(job.targets)} hosts, "
                        f"{len(job.ports)} ports"
                    )
                except OSError as exc:
                    failed_ids.append(job.identifier)
                    logger.exception(
                        "job failed to start id=%s reason=%s",
                        job.identifier,
                        exc,
                    )
                    finished = skipped + completed + len(failed_ids)
                    _progress(
                        f"[!] Failed to start {job.identifier} "
                        f"({finished}/{total_jobs} finished); see nwrapper.log"
                    )

            made_progress = False
            for item in active.copy():
                return_code = item.process.poll()
                if return_code is None:
                    continue
                active.remove(item)
                made_progress = True
                logger.info(
                    "job process exited id=%s pid=%d return_code=%d",
                    item.job.identifier,
                    item.process.pid,
                    return_code,
                )
                if return_code != 0:
                    failed_ids.append(item.job.identifier)
                    logger.error(
                        "job failed id=%s return_code=%d",
                        item.job.identifier,
                        return_code,
                    )
                    elapsed = time.monotonic() - item.started_at
                    finished = skipped + completed + len(failed_ids)
                    _progress(
                        f"[!] Failed {item.job.identifier} after {elapsed:.1f}s "
                        f"({finished}/{total_jobs} finished): Nmap exited with "
                        f"code {return_code}; see nwrapper.log"
                    )
                    continue
                try:
                    load_completed_xml(item.partial_xml, item.job.targets)
                except NmapXmlError as exc:
                    failed_ids.append(item.job.identifier)
                    logger.error(
                        "job XML validation failed id=%s path=%s reason=%s",
                        item.job.identifier,
                        item.partial_xml,
                        exc,
                    )
                    elapsed = time.monotonic() - item.started_at
                    finished = skipped + completed + len(failed_ids)
                    _progress(
                        f"[!] Failed {item.job.identifier} after {elapsed:.1f}s "
                        f"({finished}/{total_jobs} finished): XML validation "
                        "failed; see nwrapper.log"
                    )
                    continue
                try:
                    os.replace(item.partial_xml, item.final_xml)
                except OSError as exc:
                    failed_ids.append(item.job.identifier)
                    logger.exception(
                        "job XML promotion failed id=%s source=%s "
                        "destination=%s reason=%s",
                        item.job.identifier,
                        item.partial_xml,
                        item.final_xml,
                        exc,
                    )
                    elapsed = time.monotonic() - item.started_at
                    finished = skipped + completed + len(failed_ids)
                    _progress(
                        f"[!] Failed {item.job.identifier} after {elapsed:.1f}s "
                        f"({finished}/{total_jobs} finished): XML promotion "
                        "failed; see nwrapper.log"
                    )
                    continue
                completed += 1
                logger.info(
                    "job completed id=%s path=%s",
                    item.job.identifier,
                    item.final_xml,
                )
                elapsed = time.monotonic() - item.started_at
                finished = skipped + completed + len(failed_ids)
                _progress(
                    f"[+] Completed {item.job.identifier} in {elapsed:.1f}s "
                    f"({finished}/{total_jobs} finished)"
                )

            now = time.monotonic()
            if active and now >= next_heartbeat:
                finished = skipped + completed + len(failed_ids)
                _progress(
                    f"[*] Progress: {finished}/{total_jobs} finished, "
                    f"{len(active)} running, {len(pending)} pending, "
                    f"{len(failed_ids)} failed"
                )
                next_heartbeat = now + PROGRESS_INTERVAL_SECONDS

            if active and not made_progress:
                time.sleep(poll_interval)
    except KeyboardInterrupt:
        logger.warning("runner interrupted active_jobs=%d", len(active))
        _stop_active(active)
        logger.warning(
            "runner finished interrupted=true completed=%d skipped=%d failed=%d "
            "duration_seconds=%.3f",
            completed,
            skipped,
            len(failed_ids),
            time.monotonic() - started,
        )
        return RunResult(
            completed=completed,
            skipped=skipped,
            failed_ids=tuple(failed_ids),
            interrupted=True,
        )

    logger.info(
        "runner finished interrupted=false completed=%d skipped=%d failed=%d "
        "duration_seconds=%.3f",
        completed,
        skipped,
        len(failed_ids),
        time.monotonic() - started,
    )
    return RunResult(
        completed=completed,
        skipped=skipped,
        failed_ids=tuple(failed_ids),
    )
