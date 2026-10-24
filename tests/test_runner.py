from pathlib import Path

from nwrapper.models import ScanJob
from nwrapper.runner import build_nmap_command


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
