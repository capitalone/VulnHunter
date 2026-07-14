# VulnHunter Harness

Developer tooling for running the VulnHunter scanner at workstation scale and
measuring its detection accuracy. This is **dev-only** infrastructure — it is
not part of the shipped product and is not required to run any of the skills.
The importable module is `local_harness` (package name `c1-vulnhunter-harness`).

## Install

```bash
cd harness
python -m pip install -e ".[dev]"
```

Requires Python 3.12+ and an authenticated [Claude Code CLI](https://docs.claude.com/en/docs/claude-code)
on PATH — the harness shells out to `claude -p /vulnhunt ...` under the hood. It
has no other runtime dependencies.

Set the scanning/judging model once in `local_harness/config.py` (the `MODEL`
constant) to switch models across every workflow.

## What's inside

| Path | Purpose |
|------|---------|
| [`local_harness/`](local_harness/README.md) | The package: shared scan engine plus the two workflows below. |
| `local_harness/benchmark/` | Measures detection accuracy against a known-vulnerable corpus (clone → scan → LLM-judge → tally). |
| `local_harness/batch/` | Ad-hoc batch scanning of arbitrary GitHub repos from a URL list. |
| `tests/` | Unit tests for the harness (run with `pytest`). |

## Batch scanning

Manage your target list in `local_harness/batch/REPO_LIST.txt` (one GitHub URL
per line; `#` lines are ignored):

```bash
python -m local_harness.batch.run scan                 # clone + scan every repo
python -m local_harness.batch.run scan --resume        # skip repos already completed
python -m local_harness.batch.run scan --max-workers 3 # override parallelism
python -m local_harness.batch.run status               # check progress
python -m local_harness.batch.run collect              # gather results into to_upload/
```

## Benchmarking

Ground truth lives in `local_harness/benchmark/ground_truth/*.json` — one file
per repo, each finding pinned to a public GitHub URL at a specific commit. The
repo ships only a synthetic `EXAMPLE.json` mapped to public targets (OWASP Juice
Shop / WebGoat / NodeGoat); **bring your own corpus** by adding
`ground_truth/<repo>.json`.

```bash
python -m local_harness.benchmark.run                  # full run: clone + scan + judge + tally
python -m local_harness.benchmark.run --repos "name"   # single repo (substring match)
python -m local_harness.benchmark.run --judge-only --force-rejudge   # re-judge without re-scanning
python -m local_harness.benchmark.run --tally-only     # regenerate the report from saved state

python -m local_harness.benchmark.analyze_misses               # diagnose all missed findings
python -m local_harness.benchmark.analyze_misses --finding ID  # a single finding
```

State is persisted after every operation (`local_harness/benchmark_results/state.json`),
so any run is fully resumable.

## Tests

```bash
python -m pytest tests/ --cov=local_harness --cov-report=term-missing
```

## License

Part of the VulnHunter project; licensed under the Apache License, Version 2.0.
See the repository-root [`LICENSE`](../LICENSE).
