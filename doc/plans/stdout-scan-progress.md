# Plan: Add Concise Scan Progress Output

## Summary

Print concise, line-based scan progress to stdout while the existing synchronous
runner schedules Nmap jobs. Report the initial resume state, individual job starts
and outcomes, and a heartbeat at most every 30 seconds while work is active. Keep
the detailed commands, paths, process IDs, and validation diagnostics in
`nwrapper.log`; do not add a progress framework or another execution model.

## Problem

`nwrapper` currently prints the debug-log path before calling the runner and a final
summary after it returns. During a long scan, the runner may produce no terminal
output for many minutes even though Nmap processes are healthy, which makes the
command appear stuck. The runner already owns all lifecycle state needed for truthful
progress, but exposes it only through the debug log.

## Scope

In scope:

- Print one startup summary after existing XML results have been validated, including
  total jobs, already-complete jobs, pending jobs, and the effective worker count.
- Print a flushed line when each Nmap job starts, identifying the job and summarizing
  its host and port counts without dumping long target or port lists.
- Print a flushed completion or failure line when a started job settles, including
  its elapsed time in seconds and the current finished-versus-total count; report a
  launch failure without inventing a duration.
- Cover process launch failures, nonzero Nmap exits, XML validation failures, and XML
  promotion failures with concise stdout failure progress while retaining the exact
  diagnostic in `nwrapper.log`.
- While jobs remain active, print a flushed aggregate heartbeat no more than once
  every 30 seconds showing finished, running, pending, and failed counts.
- Preserve the CLI's existing final summary, exit codes, debug log, resume behavior,
  concurrency bound, and result-file semantics.
- Document the terminal progress behavior and add deterministic scheduler tests that
  do not wait in real time or run real Nmap processes.

Out of scope:

- Animated or in-place progress bars, ANSI color, terminal-width detection, and
  third-party progress dependencies.
- New `--quiet`, verbosity, heartbeat-interval, machine-readable progress, or output
  destination options.
- Streaming raw Nmap output, per-host or per-port progress, parsing Nmap percentages,
  or estimating completion time.
- Changes to job planning, retries, timeouts, concurrency, XML validation, report
  merging, or the append-only debug log format.

## Design

Keep progress ownership in `nwrapper/runner.py`, where pending, active, skipped,
completed, and failed jobs are already authoritative. Add a small internal emitter
that writes one complete line to stdout with `flush=True`. Direct runner output is
preferable to a callback interface because the project has one CLI consumer; routing
the existing logger to stdout would expose verbose diagnostic records rather than the
requested concise status.

Extend the private active-job record with its monotonic start time. Derive elapsed
times from `time.monotonic()` and derive the finished count from existing state:

```text
finished = skipped + completed + failed
```

Do not introduce a second mutable progress counter. Use the same job transition
points that currently update `failed_ids` or `completed` to emit outcome lines, so
printed counts cannot drift from `RunResult`. Start lines should include the
16-character job identifier plus host and port counts; exact commands and full details
remain in the per-job and debug logs.

Maintain one next-heartbeat monotonic deadline in the polling loop, initialized 30
seconds after scheduling begins. When active jobs exist and the deadline has passed,
emit one aggregate status line and set the next deadline from the current monotonic
time. This must not alter the existing poll interval or sleep behavior. The
all-complete resume path prints its startup summary and returns without requiring
Nmap, just as it does today.

Use stable, line-oriented markers that remain readable in captured logs, for example:

```text
[*] 18 jobs: 5 already complete, 13 pending, 4 workers
[>] Started a1b2c3d4e5f60718: 24 hosts, 2 ports
[+] Completed a1b2c3d4e5f60718 in 31.4s (6/18 finished)
[!] Failed d4e5f60718293a4b after 900.0s (7/18 finished); see nwrapper.log
[*] Progress: 12/18 finished, 4 running, 2 pending, 1 failed
```

Durations should use a direct one-decimal seconds format rather than a separate
humanization abstraction. Failure progress may name the failure category or return
code, but detailed exception text remains in the debug log. Progress lines, including
failures, go to stdout as one coherent event stream; setup/runtime errors that prevent
a scan remain on stderr through the existing CLI behavior.

## Affected Components

- `nwrapper/runner.py`: emit startup, lifecycle, and heartbeat progress from the
  existing scheduler state and retain per-job monotonic start times.
- `tests/test_runner.py`: cover resume-aware startup counts, job start/completion and
  failure output, flushed line-oriented status, and a deterministic 30-second
  heartbeat using fake processes and a controlled monotonic clock.
- `README.md`: describe the concise stdout progress stream and its separation from
  detailed `nwrapper.log` diagnostics.

## Implementation Sequence

1. Add the internal progress emitter and private active-job start time without
   changing scheduler decisions.
2. Emit the resume-aware startup summary and job start/outcome lines from the
   runner's existing state transitions.
3. Add the fixed 30-second heartbeat deadline to the current polling loop.
4. Add focused fake-runner tests for normal, resumed, failed, and long-running jobs,
   then document the user-visible behavior.

## Validation

- `.venv/bin/python -m pytest`
- `.venv/bin/ruff check .`
- `.venv/bin/mypy`
- Run the fake scheduler with multiple concurrent jobs and capture stdout to verify
  every progress record is a complete flushed line with truthful aggregate counts.
- Advance a controlled monotonic clock across the 30-second deadline and verify a
  heartbeat appears without real sleeping; verify shorter runs emit no heartbeat.
- Resume from valid existing job XML and verify the startup and final summaries agree
  while no completed job is launched again.

## Success Criteria

- A normal scan immediately reports how much work is already complete, pending, and
  runnable, then reports every job start and outcome on stdout.
- A scan with no job outcome for 30 seconds emits aggregate progress and continues to
  emit no more than one heartbeat per 30-second interval while jobs remain active.
- All printed finished, running, pending, and failed counts are derived from the
  runner's real collections and agree with the returned result and final CLI summary.
- Progress output does not change scheduling, resume detection, failure handling,
  interruption cleanup, XML publication, combined-report generation, or exit codes.
- The implementation adds no dependency, callback framework, dynamic terminal UI,
  or new command-line option.
