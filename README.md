# nwrapper

`nwrapper` turns Masscan grepable (`.oG`) TCP discoveries into exact,
resumable Nmap service-detection jobs.

The project is intentionally TCP-only. It will not schedule UDP scans.

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

## Current status

This initial skeleton implements:

- Masscan `.oG` parsing for open TCP ports
- duplicate removal and deterministic address/port ordering
- grouping by identical TCP port sets
- configurable target chunking
- deterministic job identifiers
- JSON plan generation
- construction of the intended `nmap -Pn -n -sV` command

The bounded-concurrency runner, durable resume state, atomic per-job XML
handling, and combined XML report are the next implementation stages. The
planned boundaries are documented in [docs/architecture.md](docs/architecture.md).

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
nwrapper plan masscan-results.oG \
  --output nwrapper-plan.json \
  --batch-size 128
```

The plan records every input host/TCP-port relationship and the grouped jobs
that will eventually execute it.

Only scan systems you own or are explicitly authorized to assess.
