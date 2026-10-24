from pathlib import Path

import pytest

from nwrapper.planner import build_plan


def test_build_plan_groups_identical_ports_and_chunks_targets() -> None:
    targets = {
        "10.0.0.3": (445,),
        "10.0.0.2": (22, 80, 443),
        "10.0.0.1": (22, 80, 443),
        "10.0.0.4": (22, 80, 443),
    }

    plan = build_plan(Path("masscan.oG"), targets, batch_size=2)

    assert [(job.ports, job.targets) for job in plan.jobs] == [
        ((22, 80, 443), ("10.0.0.1", "10.0.0.2")),
        ((22, 80, 443), ("10.0.0.4",)),
        ((445,), ("10.0.0.3",)),
    ]
    assert plan.target_count == 4
    assert plan.host_port_count == 10


def test_plan_covers_exact_input_host_port_pairs() -> None:
    targets = {
        "192.0.2.1": (22, 443),
        "192.0.2.2": (22, 443),
        "192.0.2.3": (80,),
    }

    plan = build_plan(Path("masscan.oG"), targets, batch_size=128)
    planned = {
        (target, port)
        for job in plan.jobs
        for target in job.targets
        for port in job.ports
    }
    expected = {
        (target, port) for target, ports in targets.items() for port in ports
    }

    assert planned == expected


def test_build_plan_rejects_ipv6_targets() -> None:
    with pytest.raises(ValueError, match="IPv6 targets are not supported"):
        build_plan(Path("masscan.oG"), {"2001:db8::1": (443,)}, batch_size=128)
