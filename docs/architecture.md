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
- `runner.py`: construct Nmap argument vectors and own bounded subprocess
  concurrency, cancellation, and atomic XML promotion.
- `nmap_xml.py`: validate that per-job XML is complete for exactly its planned
  targets.
- Future `xmlmerge.py`: validate completed job XML files, collect their
  `<host>` elements, and create truthful aggregate run statistics without
  copying one job's scan metadata as though it described every job.

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
