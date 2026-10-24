# Architecture

`nwrapper` converts a Masscan `.oG` report into bounded Nmap service-detection
jobs while preserving exact host-to-TCP-port relationships.

## Invariants

1. The project is TCP-only.
2. Every open TCP `(address, port)` pair from the input appears in exactly one
   planned job.
3. A planned job does not introduce a port that Masscan did not report for
   every target in that job.
4. Job identifiers are deterministic for the port set and target chunk.
5. A job becomes complete only after Nmap exits successfully and its XML
   output parses as a completed document.
6. Individual job XML files remain authoritative. The combined XML is derived
   and can always be rebuilt.

## Components

- `masscan.py`: stream and normalize Masscan grepable output.
- `planner.py`: group identical port sets, chunk targets, and assign stable
  job identifiers.
- `manifest.py`: serialize plans atomically.
- `runlog.py`: configure the append-only per-output-directory diagnostic log.
- `runner.py`: construct Nmap argument vectors and own bounded subprocess
  concurrency, cancellation, and atomic XML promotion.
- `nmap_xml.py`: validate that per-job XML is complete for exactly its planned
  targets.
- `xmlmerge.py`: validate current-plan job XML files, collect their `<host>`
  elements in plan order, and atomically publish truthful aggregate run
  statistics without copying one job's scan metadata as though it described
  every job.

## Intended job lifecycle

```text
planned -> running -> validating -> complete
                  \-> failed -> planned (retry)
```

Nmap writes to `<job-id>.xml.partial`. After a successful exit and XML
validation, the runner atomically renames that file to `<job-id>.xml`. The
final XML itself is the completion record; the manifest remains an immutable
description of the current plan. Interrupted, failed, or malformed jobs are
rerun, while valid final XML is skipped.

Large groups are split into bounded chunks so job-level reruns remain cheap
and the scheduler has enough work to use its configured concurrency.

Each scan invocation appends orchestration events to `<output-dir>/nwrapper.log`
at DEBUG level. Run boundaries, effective settings, process launches and exit
codes, resume decisions, XML validation failures, detected Nmap host timeouts,
interrupt cleanup, and report publication are logged there. Per-job `.log`
files remain the non-duplicated source for raw Nmap stdout and stderr.

## Combined report lifecycle

The scan command removes any prior `combined.xml` before starting or resuming
a plan. Once every current-plan job is complete, the merger reads only those
job IDs, creates a fresh Nmap-shaped root, copies each expected host exactly
once in plan order, and derives timing, version, and host statistics across
all jobs. Orphan XML files are ignored.

The merger writes `combined.xml.partial`, parses it as a final sanity check,
and atomically promotes it to `combined.xml`. A failed or interrupted scan
therefore has no report that looks current. The authoritative per-job XML is
never modified, so a fully completed rerun can validate and skip every Nmap
job while rebuilding the derived report.
