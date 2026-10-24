from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from nwrapper.models import ScanJob, ScanPlan
from nwrapper.runlog import configure_debug_log
from nwrapper.runner import build_nmap_command, run_jobs


class FakeProcess:
    """Controllable Nmap process used to exercise the polling scheduler."""

    active = 0
    maximum_active = 0
    polls_per_process = 1
    failing_target: str | None = None
    interrupted: list[FakeProcess] = []
    next_pid = 1000

    def __init__(self, command: list[str], **_: object) -> None:
        self.command = command
        self.pid = FakeProcess.next_pid
        FakeProcess.next_pid += 1
        self.return_code = 0
        self.polls_remaining = FakeProcess.polls_per_process
        self.stopped = False
        FakeProcess.active += 1
        FakeProcess.maximum_active = max(
            FakeProcess.maximum_active, FakeProcess.active
        )

        targets_file = Path(command[command.index("-iL") + 1])
        targets = tuple(targets_file.read_text(encoding="utf-8").splitlines())
        if FakeProcess.failing_target in targets:
            self.return_code = 1
        else:
            self._write_xml(Path(command[command.index("-oX") + 1]), targets)

    @staticmethod
    def _write_xml(path: Path, targets: tuple[str, ...]) -> None:
        root = ET.Element(
            "nmaprun",
            scanner="nmap",
            start="1",
            version="7.95",
            xmloutputversion="1.05",
        )
        for target in targets:
            host = ET.SubElement(root, "host")
            ET.SubElement(
                host, "status", state="up", reason="user-set", reason_ttl="0"
            )
            ET.SubElement(host, "address", addr=target, addrtype="ipv4")
        runstats = ET.SubElement(root, "runstats")
        ET.SubElement(
            runstats, "finished", time="2", elapsed="1.0", exit="success"
        )
        ET.SubElement(runstats, "hosts", up=str(len(targets)), total=str(len(targets)))
        ET.ElementTree(root).write(path, encoding="unicode", xml_declaration=True)

    def poll(self) -> int | None:
        if self.stopped:
            return self.return_code
        if self.polls_remaining:
            self.polls_remaining -= 1
            return None
        self.stopped = True
        FakeProcess.active -= 1
        return self.return_code

    def terminate(self) -> None:
        if not self.stopped:
            self.stopped = True
            FakeProcess.active -= 1
        FakeProcess.interrupted.append(self)

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        return self.return_code

    def kill(self) -> None:
        self.terminate()


@pytest.fixture(autouse=True)
def reset_fake_process() -> None:
    FakeProcess.active = 0
    FakeProcess.maximum_active = 0
    FakeProcess.polls_per_process = 1
    FakeProcess.failing_target = None
    FakeProcess.interrupted = []
    FakeProcess.next_pid = 1000


def _plan(*jobs: ScanJob) -> ScanPlan:
    return ScanPlan(
        source="scan.oG",
        jobs=jobs,
        target_count=sum(len(job.targets) for job in jobs),
        host_port_count=sum(job.host_port_count for job in jobs),
    )


def test_build_nmap_command_is_tcp_only_and_uses_service_detection() -> None:
    job = ScanJob(
        identifier="example",
        ports=(22, 80, 443),
        targets=("192.0.2.1", "192.0.2.2"),
    )

    command = build_nmap_command(
        job,
        Path("example.targets"),
        Path("example.xml.partial"),
    )

    assert command == [
        "nmap",
        "-Pn",
        "-n",
        "-sV",
        "--host-timeout",
        "15m",
        "-p",
        "22,80,443",
        "-iL",
        "example.targets",
        "-oX",
        "example.xml.partial",
    ]
    assert "-sU" not in command


def test_run_jobs_bounds_concurrency_and_promotes_xml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    jobs = tuple(
        ScanJob(f"job-{number}", (80,), (f"192.0.2.{number}",))
        for number in range(1, 5)
    )
    monkeypatch.setattr("nwrapper.runner.shutil.which", lambda _: "/usr/bin/nmap")
    monkeypatch.setattr("nwrapper.runner.subprocess.Popen", FakeProcess)
    debug_log = configure_debug_log(tmp_path)

    result = run_jobs(
        _plan(*jobs), tmp_path, max_processes=2, host_timeout="15m", poll_interval=0
    )

    assert result.completed == 4
    assert result.failed_ids == ()
    assert FakeProcess.maximum_active == 2
    assert all((tmp_path / "jobs" / f"{job.identifier}.xml").exists() for job in jobs)
    assert not list((tmp_path / "jobs").glob("*.xml.partial"))
    log_text = debug_log.read_text(encoding="utf-8")
    assert "runner started jobs=4 max_processes=2" in log_text
    assert "job command id=job-1" in log_text
    assert "job completed id=job-4" in log_text


def test_run_jobs_skips_valid_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    job = ScanJob("existing", (443,), ("192.0.2.1",))
    jobs_dir = tmp_path / "jobs"
    jobs_dir.mkdir()
    FakeProcess._write_xml(jobs_dir / "existing.xml", job.targets)

    def unexpected_lookup(_: str) -> str:
        raise AssertionError("Nmap lookup is unnecessary for completed jobs")

    monkeypatch.setattr("nwrapper.runner.shutil.which", unexpected_lookup)

    def unexpected_process(*_: object, **__: object) -> subprocess.Popen[bytes]:
        raise AssertionError("completed job was launched again")

    monkeypatch.setattr("nwrapper.runner.subprocess.Popen", unexpected_process)

    result = run_jobs(
        _plan(job), tmp_path, max_processes=1, host_timeout="15m", poll_interval=0
    )

    assert result.completed == 0
    assert result.skipped == 1
    assert result.failed_ids == ()


def test_run_jobs_reruns_nmap_host_timeouts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    job = ScanJob("timed-out", (443,), ("192.0.2.1",))
    jobs_dir = tmp_path / "jobs"
    jobs_dir.mkdir()
    result_xml = jobs_dir / "timed-out.xml"
    FakeProcess._write_xml(result_xml, job.targets)
    tree = ET.parse(result_xml)
    host = tree.getroot().find("host")
    assert host is not None
    host.set("timedout", "true")
    tree.write(result_xml, encoding="unicode", xml_declaration=True)
    monkeypatch.setattr("nwrapper.runner.shutil.which", lambda _: "/usr/bin/nmap")
    monkeypatch.setattr("nwrapper.runner.subprocess.Popen", FakeProcess)
    debug_log = configure_debug_log(tmp_path)

    result = run_jobs(
        _plan(job), tmp_path, max_processes=1, host_timeout="15m", poll_interval=0
    )

    assert result.completed == 1
    assert result.skipped == 0
    assert "Nmap XML contains timed-out hosts" in debug_log.read_text(
        encoding="utf-8"
    )
    final_host = ET.parse(result_xml).getroot().find("host")
    assert final_host is not None
    assert final_host.get("timedout") is None


def test_run_jobs_reruns_invalid_and_partial_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    job = ScanJob("retry", (443,), ("192.0.2.1",))
    jobs_dir = tmp_path / "jobs"
    jobs_dir.mkdir()
    (jobs_dir / "retry.xml").write_text("<invalid />", encoding="utf-8")
    (jobs_dir / "retry.xml.partial").write_text("stale", encoding="utf-8")
    monkeypatch.setattr("nwrapper.runner.shutil.which", lambda _: "/usr/bin/nmap")
    monkeypatch.setattr("nwrapper.runner.subprocess.Popen", FakeProcess)
    debug_log = configure_debug_log(tmp_path)

    result = run_jobs(
        _plan(job), tmp_path, max_processes=1, host_timeout="15m", poll_interval=0
    )

    assert result.completed == 1
    assert result.skipped == 0
    assert not (jobs_dir / "retry.xml.partial").exists()
    assert ET.parse(jobs_dir / "retry.xml").getroot().tag == "nmaprun"
    assert "job result is not reusable id=retry" in debug_log.read_text(
        encoding="utf-8"
    )


def test_run_jobs_continues_after_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    failed = ScanJob("failed", (80,), ("192.0.2.1",))
    successful = ScanJob("successful", (443,), ("192.0.2.2",))
    FakeProcess.failing_target = "192.0.2.1"
    monkeypatch.setattr("nwrapper.runner.shutil.which", lambda _: "/usr/bin/nmap")
    monkeypatch.setattr("nwrapper.runner.subprocess.Popen", FakeProcess)

    result = run_jobs(
        _plan(failed, successful),
        tmp_path,
        max_processes=1,
        host_timeout="15m",
        poll_interval=0,
    )

    assert result.completed == 1
    assert result.failed_ids == ("failed",)
    assert not (tmp_path / "jobs" / "failed.xml").exists()
    assert (tmp_path / "jobs" / "successful.xml").exists()


def test_run_jobs_stops_active_processes_on_interrupt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    job = ScanJob("interrupted", (80,), ("192.0.2.1",))
    monkeypatch.setattr("nwrapper.runner.shutil.which", lambda _: "/usr/bin/nmap")
    monkeypatch.setattr("nwrapper.runner.subprocess.Popen", FakeProcess)
    FakeProcess.polls_per_process = 10

    def interrupt(_: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("nwrapper.runner.time.sleep", interrupt)

    result = run_jobs(
        _plan(job), tmp_path, max_processes=1, host_timeout="15m", poll_interval=0
    )

    assert result.interrupted is True
    assert len(FakeProcess.interrupted) == 1
    assert not (tmp_path / "jobs" / "interrupted.xml").exists()

    FakeProcess.polls_per_process = 1
    monkeypatch.setattr("nwrapper.runner.time.sleep", lambda _: None)
    resumed = run_jobs(
        _plan(job), tmp_path, max_processes=1, host_timeout="15m", poll_interval=0
    )

    assert resumed.completed == 1
    assert (tmp_path / "jobs" / "interrupted.xml").exists()
