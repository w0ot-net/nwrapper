from __future__ import annotations

import json
from pathlib import Path

import pytest

from nwrapper.cli import main
from nwrapper.runner import RunResult


def test_plan_command_writes_manifest(tmp_path: Path) -> None:
    report = tmp_path / "scan.oG"
    output = tmp_path / "plan.json"
    report.write_text(
        "Host: 192.0.2.1 ()\tPorts: 80/open/tcp//http///\n"
        "Host: 192.0.2.2 ()\tPorts: 80/open/tcp//http///\n",
        encoding="utf-8",
    )

    assert main(["plan", str(report), "--output", str(output)]) == 0

    manifest = json.loads(output.read_text(encoding="utf-8"))
    assert manifest["format_version"] == 1
    assert manifest["target_count"] == 2
    assert manifest["host_port_count"] == 2
    assert manifest["jobs"][0]["targets"] == ["192.0.2.1", "192.0.2.2"]


def test_scan_command_writes_manifest_and_reports_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report = tmp_path / "scan.oG"
    output_dir = tmp_path / "results"
    report.write_text(
        "Host: 192.0.2.1 ()\tPorts: 80/open/tcp//http///\n",
        encoding="utf-8",
    )
    output_dir.mkdir()
    stale_combined = output_dir / "combined.xml"
    stale_combined.write_text("stale", encoding="utf-8")

    def fake_run_jobs(*args: object, **kwargs: object) -> RunResult:
        del args, kwargs
        return RunResult(completed=0, skipped=0, failed_ids=("failed-job",))

    monkeypatch.setattr("nwrapper.cli.run_jobs", fake_run_jobs)
    monkeypatch.setattr(
        "nwrapper.cli.merge_completed_xml",
        lambda *args, **kwargs: pytest.fail("failed scans must not be merged"),
    )

    assert main(["scan", str(report), "--output-dir", str(output_dir)]) == 1
    assert (output_dir / "manifest.json").exists()
    assert not stale_combined.exists()
    assert "failed 1 Nmap jobs" in capsys.readouterr().out
    debug_log = (output_dir / "nwrapper.log").read_text(encoding="utf-8")
    assert "scan started" in debug_log
    assert "runner finished completed=0 skipped=0 failed=1" in debug_log
    assert "scan finished exit_code=1 failed_jobs=failed-job" in debug_log


def test_scan_command_rebuilds_combined_xml_when_all_jobs_are_skipped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report = tmp_path / "scan.oG"
    output_dir = tmp_path / "results"
    report.write_text(
        "Host: 192.0.2.1 ()\tPorts: 443/open/tcp//https///\n",
        encoding="utf-8",
    )
    output_dir.mkdir()
    combined = output_dir / "combined.xml"
    combined.write_text("stale", encoding="utf-8")

    def fake_run_jobs(*args: object, **kwargs: object) -> RunResult:
        del args, kwargs
        assert not combined.exists()
        return RunResult(completed=0, skipped=1, failed_ids=())

    def fake_merge(*args: object, **kwargs: object) -> None:
        del args, kwargs
        combined.write_text("rebuilt", encoding="utf-8")

    monkeypatch.setattr("nwrapper.cli.run_jobs", fake_run_jobs)
    monkeypatch.setattr("nwrapper.cli.merge_completed_xml", fake_merge)

    assert main(["scan", str(report), "--output-dir", str(output_dir)]) == 0
    assert combined.read_text(encoding="utf-8") == "rebuilt"
    assert "Wrote" in capsys.readouterr().out


def test_scan_command_does_not_merge_after_interrupt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = tmp_path / "scan.oG"
    output_dir = tmp_path / "results"
    report.write_text(
        "Host: 192.0.2.1 ()\tPorts: 80/open/tcp//http///\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "nwrapper.cli.run_jobs",
        lambda *args, **kwargs: RunResult(
            completed=0, skipped=0, failed_ids=(), interrupted=True
        ),
    )
    monkeypatch.setattr(
        "nwrapper.cli.merge_completed_xml",
        lambda *args, **kwargs: pytest.fail("interrupted scans must not be merged"),
    )

    assert main(["scan", str(report), "--output-dir", str(output_dir)]) == 130
    assert not (output_dir / "combined.xml").exists()
