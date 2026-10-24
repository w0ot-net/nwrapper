# Plan: Merge Completed Nmap XML

## Summary

After every current-plan job has a valid authoritative XML result, build one
derived `combined.xml` containing their Nmap `<host>` elements and truthful
aggregate run statistics. Read only job IDs in the current in-memory plan,
preserve every individual XML file, and publish the combined document
atomically. Integrate this directly into the `scan` command rather than adding
a second state system or a separate report-management interface.

## Problem

The resumable runner from the first plan intentionally produces independent
XML documents because they are safe completion boundaries. Consumers still
need a single Nmap-shaped XML report, but concatenating those documents is
invalid and copying one job's root metadata would falsely describe a scan made
from different target and port groups.

## Scope

In scope:

- Merge only the validated final XML files corresponding to jobs in the
  current `ScanPlan`; ignore unrelated or orphaned files in the output
  directory.
- Require all current-plan jobs to be complete before producing the normal
  combined report.
- Create a fresh Nmap-compatible `nmaprun` root, omit per-job `scaninfo`, copy
  each expected `host` exactly once in deterministic plan order, and generate
  aggregate `runstats`.
- Represent root metadata honestly: identify the document as a combined
  report in `args`, use the earliest job start and latest finish, retain a
  common Nmap/XML version when all jobs agree, and use `mixed` when they do not.
- Atomically replace `<output-dir>/combined.xml` only after the assembled XML
  parses successfully.
- Remove a stale prior `combined.xml` before executing a new current plan so
  an interrupted or failed run cannot leave an old report looking current.
- Automatically generate the report at the end of a successful `scan`,
  including a rerun where every individual job was skipped as already
  complete.
- Update the README and architecture document with the combined report's
  derived, rebuildable status.

Out of scope:

- Partial merges when jobs are missing or failed.
- A separate `merge` subcommand; rerunning `scan` already validates/skips job
  XML and rebuilds the report without network work.
- Combining results from different manifests, recursive directory discovery,
  deduplicating conflicting host results, or deleting orphaned job files.
- HTML, XSLT, normal/grepable output, databases, and import/export formats.

## Design

Add a focused `xmlmerge.py` function that accepts the current `ScanPlan`, the
jobs directory, and the combined destination. For each job, use the completed
job loader introduced by the first plan. Index the direct `host` elements by
their IPv4/IPv6 address, require exactly the job's expected targets, and append
them following the deterministic order already present in the plan. Duplicate
or missing expected addresses are errors rather than cases for conflict
resolution.

Construct a new root that follows Nmap's required element order:

```text
nmaprun
  verbose
  debugging
  host...
  runstats
    finished
    hosts
```

The Nmap DTD requires `scanner="nmap"`, so retain that value, but set `args` to
an explicit `nwrapper combined report` description. Do not copy any job's
`scaninfo`, because no one port list or scan record describes every host. Set
`version` and `xmloutputversion` to their shared input value or `mixed`, derive
the root start from the earliest job, derive the finish and elapsed interval
from all jobs, and count `up`, `down`, and total hosts from the copied host
status elements.

Write to `combined.xml.partial`, parse the completed temporary document as a
final sanity check, then promote it with `os.replace`. Individual job XML
files are never modified. The CLI removes any prior combined report before it
starts the current execution and calls the merger only when the runner reports
no incomplete jobs.

## Affected Components

- `nwrapper/xmlmerge.py`: implement current-plan-only XML collection,
  aggregate metadata/statistics, deterministic assembly, and atomic publish.
- `nwrapper/nmap_xml.py`: expose the already-validated root/host data needed by
  the merger without duplicating completion checks.
- `nwrapper/cli.py`: invalidate stale derived output at scan start and invoke
  the merger only after all jobs complete.
- `tests/test_xmlmerge.py`: cover multi-job assembly, deterministic host order,
  aggregate statistics, mixed metadata, missing/duplicate hosts, ignored
  orphan files, preservation of source XML, and atomic destination behavior.
- `tests/test_cli.py`: verify successful scans create/rebuild `combined.xml`
  and failed/interrupted scans do not leave a report presented as current.
- `README.md` and `docs/architecture.md`: document the report path, automatic
  rebuild behavior, and authoritative-versus-derived distinction.

## Implementation Sequence

1. Implement and test XML collection and fresh-root assembly using small Nmap
   XML fixtures from more than one job.
2. Add atomic combined-output publication and failure tests while verifying
   the individual job XML remains unchanged.
3. Integrate stale-output invalidation and successful-run merging into the
   `scan` command.
4. Update the user and architecture documentation.

## Validation

- `pytest`
- `ruff check .`
- `mypy`
- Parse `combined.xml` with Python's XML parser and, when the system Nmap DTD
  is available, validate its required root child ordering and run statistics.
- Run the fixture scan twice and confirm the second run launches no Nmap jobs
  but deterministically rebuilds the same host/report content.

## Success Criteria

- A successful complete scan produces one parseable `combined.xml` containing
  exactly one host result for every target in the current plan.
- The combined root does not claim one job's port list or command describes
  all results, and its timing/version/statistical metadata reflects all input
  jobs.
- Missing, malformed, duplicate, failed, or incomplete job output prevents
  publication of a current combined report.
- Individual job XML remains unchanged and sufficient to rebuild the combined
  report without rerunning Nmap.
- No partial-report mode, separate state store, or unrelated reporting format
  is added.

## Execution Notes

- Added current-plan-only XML merging with deterministic host order, aggregate
  timing/version/statistics metadata, Nmap DTD-compatible element ordering,
  and atomic `combined.xml` publication.
- Integrated stale-report invalidation and automatic rebuilding into
  `nwrapper scan`, including runs where every authoritative job result is
  already complete and skipped.
- Preserved per-job XML unchanged and ignored orphan result files. No partial
  merge mode, separate merge command, state store, UDP support, or additional
  output formats were added.
- Validation passed with 24 tests, `ruff check .`, `mypy`, CLI help inspection,
  deterministic report regeneration, and `xmllint` validation against the
  installed Nmap DTD.
- Implementation commit: `04fccb7`.
