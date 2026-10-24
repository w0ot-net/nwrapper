"""Command-line interface."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from nwrapper.manifest import write_plan
from nwrapper.masscan import MasscanParseError, parse_grepable
from nwrapper.models import ScanPlan
from nwrapper.planner import build_plan
from nwrapper.runlog import configure_debug_log
from nwrapper.runner import RunnerError, run_jobs
from nwrapper.xmlmerge import XmlMergeError, merge_completed_xml

logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="nwrapper",
        description="Plan and run exact TCP Nmap scans from Masscan .oG output.",
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

    scan_parser = subparsers.add_parser(
        "scan", help="run or resume grouped Nmap service scans"
    )
    scan_parser.add_argument("input", type=Path, help="Masscan -oG report")
    scan_parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("nwrapper-output"),
        help="result directory (default: nwrapper-output)",
    )
    scan_parser.add_argument(
        "--jobs",
        type=int,
        default=4,
        help="maximum concurrent Nmap processes (default: 4)",
    )
    scan_parser.add_argument(
        "--batch-size",
        type=int,
        default=128,
        help="maximum targets per Nmap process (default: 128)",
    )
    scan_parser.add_argument(
        "--host-timeout",
        default="15m",
        help="Nmap timeout for each host (default: 15m)",
    )
    return parser


def _load_plan(input_path: Path, batch_size: int) -> ScanPlan:
    targets = parse_grepable(input_path)
    if not targets:
        raise ValueError("the input contains no open TCP ports")
    return build_plan(input_path, targets, batch_size)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line interface."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "plan":
        try:
            plan = _load_plan(args.input, args.batch_size)
            write_plan(plan, args.output)
        except (OSError, MasscanParseError, ValueError) as exc:
            parser.error(str(exc))

        print(
            f"Planned {plan.host_port_count} TCP host/port pairs "
            f"across {plan.target_count} targets in {len(plan.jobs)} jobs."
        )
        print(f"Wrote {args.output}")
        return 0

    if args.command == "scan":
        try:
            debug_log = configure_debug_log(args.output_dir)
            logger.info(
                "scan started input=%s output_dir=%s jobs=%d batch_size=%d "
                "host_timeout=%s",
                args.input,
                args.output_dir,
                args.jobs,
                args.batch_size,
                args.host_timeout,
            )
            plan = _load_plan(args.input, args.batch_size)
            if args.jobs < 1:
                raise ValueError("jobs must be at least 1")
            logger.info(
                "plan built targets=%d host_port_pairs=%d jobs=%d",
                plan.target_count,
                plan.host_port_count,
                len(plan.jobs),
            )
            combined_xml = args.output_dir / "combined.xml"
            if combined_xml.exists():
                logger.debug("removing stale combined report path=%s", combined_xml)
            combined_xml.unlink(missing_ok=True)
            manifest = args.output_dir / "manifest.json"
            write_plan(plan, manifest)
            logger.debug("manifest written path=%s", manifest)
            result = run_jobs(
                plan,
                args.output_dir,
                max_processes=args.jobs,
                host_timeout=args.host_timeout,
            )
        except (OSError, MasscanParseError, RunnerError, ValueError) as exc:
            logger.exception("scan setup or execution failed: %s", exc)
            parser.error(str(exc))

        logger.info(
            "runner finished completed=%d skipped=%d failed=%d interrupted=%s",
            result.completed,
            result.skipped,
            len(result.failed_ids),
            result.interrupted,
        )
        print(
            f"Completed {result.completed}, skipped {result.skipped}, "
            f"failed {len(result.failed_ids)} Nmap jobs."
        )
        print(f"Debug log: {debug_log}")
        if result.failed_ids:
            print(f"Failed job IDs: {', '.join(result.failed_ids)}")
        if result.interrupted:
            logger.warning("scan finished exit_code=130 status=interrupted")
            return 130
        if result.failed_ids:
            logger.error(
                "scan finished exit_code=1 failed_jobs=%s",
                ",".join(result.failed_ids),
            )
            return 1

        try:
            merge_completed_xml(plan, args.output_dir / "jobs", combined_xml)
        except (OSError, XmlMergeError) as exc:
            logger.exception("combined report failed: %s", exc)
            print(f"Could not create combined XML: {exc}", file=sys.stderr)
            return 1
        logger.info("scan finished exit_code=0 combined_xml=%s", combined_xml)
        print(f"Wrote {combined_xml}")
        return 0

    parser.error(f"unsupported command: {args.command}")
    return 2
