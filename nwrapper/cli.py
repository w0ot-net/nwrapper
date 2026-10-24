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
from nwrapper.runner import DEFAULT_HOST_TIMEOUT, RunnerError, run_jobs
from nwrapper.workspace import WorkspaceBusyError, scan_output_lock
from nwrapper.xmlmerge import XmlMergeError, merge_completed_xml

logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="nwrapper",
        description="Run exact TCP Nmap scans from Masscan .oG output.",
    )
    parser.add_argument(
        "-i",
        "--input",
        type=Path,
        required=True,
        help="Masscan -oG report",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("nwrapper-output"),
        help="result directory (default: nwrapper-output)",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=4,
        help="maximum concurrent Nmap processes (default: 4)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=128,
        help="maximum targets per Nmap process (default: 128)",
    )
    parser.add_argument(
        "--host-timeout",
        default=DEFAULT_HOST_TIMEOUT,
        help="Nmap timeout for each host (default: %(default)s)",
    )
    return parser


def _load_plan(input_path: Path, batch_size: int) -> ScanPlan:
    targets = parse_grepable(input_path)
    if not targets:
        raise ValueError("the input contains no open TCP ports")
    return build_plan(input_path, targets, batch_size)


def _run_scan(args: argparse.Namespace) -> int:
    debug_log: Path | None = None
    try:
        with scan_output_lock(args.output_dir):
            debug_log = configure_debug_log(args.output_dir)
            print(f"Debug log: {debug_log}", flush=True)
            logger.info(
                "scan started input=%s output_dir=%s jobs=%d batch_size=%d "
                "host_timeout=%s",
                args.input,
                args.output_dir,
                args.jobs,
                args.batch_size,
                args.host_timeout,
            )
            if args.jobs < 1:
                raise ValueError("jobs must be at least 1")
            plan = _load_plan(args.input, args.batch_size)
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

            merge_completed_xml(plan, args.output_dir / "jobs", combined_xml)
            logger.info("scan finished exit_code=0 combined_xml=%s", combined_xml)
            print(f"Wrote {combined_xml}")
            return 0
    except (
        MasscanParseError,
        OSError,
        RunnerError,
        ValueError,
        WorkspaceBusyError,
        XmlMergeError,
    ) as exc:
        if debug_log is not None:
            logger.exception("scan failed: %s", exc)
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line interface."""
    return _run_scan(build_parser().parse_args(argv))
