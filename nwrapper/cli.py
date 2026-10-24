"""Command-line interface."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from nwrapper.manifest import write_plan
from nwrapper.masscan import MasscanParseError, parse_grepable
from nwrapper.planner import build_plan


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="nwrapper",
        description="Plan exact TCP Nmap service scans from Masscan .oG output.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan_parser = subparsers.add_parser(
        "plan", help="parse Masscan output and write a grouped job manifest"
    )
    plan_parser.add_argument("input", type=Path, help="Masscan -oG report")
    plan_parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("nwrapper-plan.json"),
        help="plan destination (default: nwrapper-plan.json)",
    )
    plan_parser.add_argument(
        "--batch-size",
        type=int,
        default=128,
        help="maximum targets per job (default: 128)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line interface."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "plan":
        try:
            targets = parse_grepable(args.input)
            if not targets:
                parser.error("the input contains no open TCP ports")
            plan = build_plan(args.input, targets, args.batch_size)
            write_plan(plan, args.output)
        except (OSError, MasscanParseError, ValueError) as exc:
            parser.error(str(exc))

        print(
            f"Planned {plan.host_port_count} TCP host/port pairs "
            f"across {plan.target_count} targets in {len(plan.jobs)} jobs."
        )
        print(f"Wrote {args.output}")
        return 0

    parser.error(f"unsupported command: {args.command}")
    return 2
