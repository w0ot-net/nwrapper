import json
from pathlib import Path

from nwrapper.cli import main


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
