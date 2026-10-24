from pathlib import Path

import pytest

from nwrapper.masscan import MasscanParseError, parse_grepable


def test_parse_grepable_keeps_only_open_tcp_and_deduplicates(
    tmp_path: Path,
) -> None:
    report = tmp_path / "scan.oG"
    report.write_text(
        "# Masscan 1.3 scan initiated\n"
        "Host: 10.0.0.2 ()\tPorts: 443/open/tcp//https///, "
        "53/open/udp//domain///\n"
        "Host: 10.0.0.1 ()\tPorts: 80/open/tcp//http///, "
        "22/closed/tcp//ssh///\n"
        "Host: 10.0.0.2 ()\tPorts: 443/open/tcp//https///, "
        "22/open/tcp//ssh///\n",
        encoding="utf-8",
    )

    assert parse_grepable(report) == {
        "10.0.0.1": (80,),
        "10.0.0.2": (22, 443),
    }


def test_parse_grepable_rejects_invalid_addresses(tmp_path: Path) -> None:
    report = tmp_path / "scan.oG"
    report.write_text(
        "Host: not-an-address ()\tPorts: 80/open/tcp//http///\n",
        encoding="utf-8",
    )

    with pytest.raises(MasscanParseError, match="invalid host address"):
        parse_grepable(report)
