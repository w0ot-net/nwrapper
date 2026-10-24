# nwrapper

`nwrapper` turns Masscan grepable (`.oG`) TCP discoveries into exact,
resumable Nmap service-detection jobs.

The project is intentionally IPv4 TCP-only. It will not accept IPv6 targets
or schedule UDP scans.

## Why

Passing every discovered port to Nmap for every discovered host creates a
large and wasteful host-by-port cross-product. `nwrapper` instead groups hosts
that have identical TCP port sets, so each Nmap invocation scans only the
ports Masscan reported for those hosts.

For example:

```text
10.0.0.1 -> 22,80,443
10.0.0.2 -> 22,80,443
10.0.0.3 -> 445
```

becomes two jobs: one for `10.0.0.1` and `10.0.0.2` on ports `22,80,443`, and
one for `10.0.0.3` on port `445`.

## Features

- Masscan `.oG` parsing for open TCP ports
- duplicate removal and deterministic address/port ordering
- grouping by identical TCP port sets
- configurable target chunking
- deterministic job identifiers
- JSON plan generation
- bounded concurrent `nmap -Pn -n -sV` execution
- validated, atomic XML results for each job
- automatic job-level resume after interruption or failure
- automatic, atomic `combined.xml` generation after every complete scan
- append-only debug logging for scan orchestration and validation decisions

## Requirements and usage

- Linux or another POSIX system
- Python 3.9 or newer
- Nmap available on `PATH`
- Masscan to create the input `.oG` report

Clone the repository and run it directly:

```bash
git clone https://github.com/w0ot-net/nwrapper.git
cd nwrapper
python3 main.py --help
```

Installing with `python -m pip install .` remains optional and provides the
shorter `nwrapper` command.

## Development

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
pytest
ruff check .
mypy
```

Generate a plan from a Masscan grepable report:

```bash
python3 main.py plan masscan-results.oG \
  --output nwrapper-plan.json \
  --batch-size 128
```

The plan records every input host/TCP-port relationship and the grouped jobs
that will execute it.

Run or resume the Nmap jobs:

```bash
python3 main.py scan masscan-results.oG \
  --output-dir nwrapper-output \
  --jobs 4 \
  --batch-size 128 \
  --host-timeout 15m
```

The output directory contains:

```text
nwrapper-output/
├── .nwrapper.lock
├── manifest.json
├── combined.xml
├── nwrapper.log
└── jobs/
    ├── <job-id>.targets
    ├── <job-id>.log
    └── <job-id>.xml
```

While Nmap is running, it writes `<job-id>.xml.partial`. `nwrapper` promotes
that file to `<job-id>.xml` only after Nmap exits successfully and the XML is
complete for the planned targets. A host marked as timed out makes the job
incomplete rather than publishing partial service results. Rerunning the same
command validates and skips completed job XML, then reruns only missing,
failed, timed-out, partial, or malformed jobs. If any job fails, the remaining
jobs continue and the command exits nonzero.

Every scan or resume appends timestamped DEBUG-and-higher events to
`nwrapper.log`. It records the effective options, plan summary, job commands
and process IDs, skip/retry decisions, exact XML validation errors, Nmap host
timeouts, interruption cleanup, and combined-report publication. Raw Nmap
output remains in each job's own `.log` file.

Only one scan may use an output directory at a time. The hidden lock file
prevents concurrent invocations from overwriting each other's manifest, logs,
or XML results.

The individual files under `jobs/` are the authoritative scan results.
`combined.xml` is a derived convenience report containing every current-plan
host in deterministic order. `nwrapper` removes an old combined report when a
scan starts and rebuilds it only after all jobs are complete. This also means
rerunning a completed scan launches no Nmap processes but still regenerates
`combined.xml` from the validated job XML files.

Only scan systems you own or are explicitly authorized to assess.
