# Plan: Run Resumable TCP Scan Jobs

## Summary

Add a `scan` command that turns the existing deterministic plan into bounded
concurrent Nmap processes and publishes one validated XML result per job. Use
the completed XML files themselves as durable resume state: rerunning the same
command skips valid results and reruns missing, partial, failed, or malformed
jobs. Keep the scheduler deliberately small and synchronous rather than adding
an async framework, worker service, or mutable status database.

## Problem

The repository can parse Masscan `.oG`, plan exact TCP host/port jobs, write a
JSON plan, and construct an Nmap command, but it never executes that command.
Consequently there is no bounded concurrency, interruption recovery, or safe
transition from Nmap's in-progress XML to an authoritative completed result.

## Scope

In scope:

- Add `nwrapper scan INPUT --output-dir DIR` with `--jobs`, `--batch-size`, and
  `--host-timeout` controls.
- Reuse the existing parser and planner so execution preserves every exact TCP
  host/port relationship.
- Create `manifest.json` plus deterministic per-job target, log, partial XML,
  and completed XML paths under the output directory.
- Run at most `--jobs` Nmap child processes at once with a simple polling
  scheduler.
- Treat a job as complete only when Nmap exits successfully and its XML is a
  completed `nmaprun` containing the job's expected target addresses.
- Atomically promote `<job-id>.xml.partial` to `<job-id>.xml` only after that
  validation succeeds.
- Resume automatically by validating and skipping existing completed XML;
  continue other jobs after an individual failure and return nonzero if any
  current-plan job remains incomplete.
- On interruption, stop active children and leave completed XML untouched so
  the next invocation can resume.
- Update the current README and architecture document to describe the actual
  command, output layout, and resume behavior.

Out of scope:

- Combined XML generation; that is the dependent second plan.
- UDP, NSE scripts, arbitrary Nmap argument passthrough, and script timeouts.
- Native Nmap `--resume`; bounded incomplete jobs are rerun as whole jobs.
- Automatic retry loops, a mutable status database, a background daemon, a
  progress UI, and cleanup of files belonging to older plans.
- A wrapper-level wall-clock watchdog; Nmap's existing `--host-timeout` is the
  initial runtime bound.

## Design

Keep `ScanPlan` and `ScanJob` immutable. The `scan` command builds the plan in
memory exactly as `plan` does and writes it atomically to
`<output-dir>/manifest.json`. Job files live in `<output-dir>/jobs/` and use
the existing deterministic job identifier:

```text
jobs/<job-id>.targets
jobs/<job-id>.log
jobs/<job-id>.xml.partial
jobs/<job-id>.xml
```

Do not add mutable status fields to the manifest. Before scheduling a job,
parse its final XML directly. A reusable Nmap XML loader should require a
`nmaprun` root, `runstats/finished`, and exactly the expected IPv4/IPv6
addresses among the document's direct `host` children. Valid final XML is
skipped; anything else is incomplete. This makes the filesystem result the
single source of truth and avoids state/XML disagreement after a crash.

Extend `runner.py` with one in-process scheduler around `subprocess.Popen` and
`poll()`. It should preflight the Nmap executable once, write each target file
before launch, redirect that job's stdout and stderr to its log, and never use
a shell. Remove the unused arbitrary `extra_arguments` hook from the command
builder so callers cannot override the exact ports, targets, or XML path. A
successful child is validated at the partial path and promoted with
`os.replace`; a failed or invalid result remains partial for diagnosis and is
overwritten on the next attempt.

The scheduler owns its active child set. On `KeyboardInterrupt`, it terminates
those children, waits briefly, kills only any that remain, and returns the
conventional interrupted exit status. No worker abstraction, callback system,
or separate lifecycle model is needed.

## Affected Components

- `nwrapper/cli.py`: add the `scan` command, shared plan construction, option
  validation, summary output, and exit-code handling.
- `nwrapper/runner.py`: remove unrestricted extra arguments and add workspace
  paths, bounded process scheduling, logging, interruption cleanup, and atomic
  result promotion.
- `nwrapper/nmap_xml.py`: add the small shared loader that proves whether a job
  XML file is complete for its expected targets.
- `tests/test_runner.py`: cover the concurrency bound, successful promotion,
  failure continuation, resume skipping, and interruption cleanup without
  making real network requests.
- `tests/test_nmap_xml.py`: cover completed, partial, malformed, and
  wrong-target XML documents.
- `tests/test_cli.py`: cover scan option validation, output layout, summaries,
  and nonzero results using a fake Nmap process boundary.
- `README.md` and `docs/architecture.md`: replace skeleton/future wording with
  the implemented scan and resume contract while retaining TCP-only scope.

## Implementation Sequence

1. Add the completed-job XML loader and focused fixtures/tests.
2. Tighten Nmap command construction and implement the filesystem layout,
   scheduler, validation, promotion, failure continuation, and interruption
   cleanup in `runner.py`.
3. Add the `scan` CLI path using the existing parser/planner and atomic
   manifest writer.
4. Update the nearest user and architecture documentation to match the shipped
   behavior.

## Validation

- `pytest`
- `ruff check .`
- `mypy`
- Run `nwrapper scan` against a fixture/fake Nmap executable and inspect that
  no more than the configured number of jobs overlap, completed files are
  promoted, and an immediate rerun launches no completed job.
- Interrupt a fixture run, rerun it, and verify that completed XML remains and
  only incomplete jobs launch again.

## Success Criteria

- `nwrapper scan` executes every current-plan TCP job with no more than the
  configured number of Nmap children.
- A final job XML exists only after successful exit and structural/target
  validation; partial or failed output is never mistaken for completion.
- Rerunning after normal completion or interruption skips every valid final
  result and reruns only incomplete jobs.
- One job failure does not prevent remaining jobs from running, and the command
  returns nonzero while any current-plan job is incomplete.
- No UDP, NSE, database, service, or general-purpose task framework is added.

## Execution Notes

- Implemented `nwrapper scan` with bounded `Popen` scheduling, deterministic
  job workspaces, per-job logs, completion validation, atomic XML promotion,
  automatic skip/resume, failure continuation, and interrupt cleanup.
- Added `nwrapper/nmap_xml.py` as the shared owner of completed-job validation;
  updated the CLI, runner, focused tests, README, and architecture document.
- No material design deviations were required. The architecture wording for
  job identifiers was corrected to match their existing port/target inputs.
- Validation passed with 17 tests, `ruff check .`, `mypy`, and CLI help
  inspection.
- Implementation commit: `0a9cad6`.
- Combined XML remains deliberately excluded here and is owned by the ordered
  second plan. All other listed non-goals remain excluded.
