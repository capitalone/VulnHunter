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

Set the scanning/judging model once in `local_harness/config.py` (the
`DEFAULT_MODEL` constant) to switch models across every workflow, or override it
for a single run without editing the file:

```bash
VULNHUNT_HARNESS_MODEL=<model-id> python -m local_harness.batch.run scan
```

The value is read once at import, so export it before the process starts; a
blank value is treated as unset. Two things to know before reaching for it:

- `/vulnhunt` is written for Opus-class models and stops with a warning on
  anything lower (`vulnhunt/SKILL.md`, Step 0). A downgraded run is for
  exercising the plumbing, not for producing detection numbers.
- Both resume paths skip targets that already have results, even if the model
  changes. The benchmark keeps the saved model label when no scan runs,
  including with `--judge-only` or `--tally-only`. Use `--force-rescan`
  (benchmark) or a fresh clone (batch) to actually rescan. The benchmark stores
  one model label for the latest scans, so rescan all targets when switching
  models to avoid mixing results. A benchmark trial also appends to
  `finding_history.json`, which is what `--skip-stable` reads.

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

### Read-only by default

Scanned repos are untrusted, so scans (batch and benchmark) run read-only
unless you pass `--execute`. The harness pre-creates the
`<clone>/<clone>_VULNHUNT_RESULTS_<timestamp>` dir and passes it, plus branch
and origin URL, to the skill. It then runs `claude -p` with:

- `--tools Read,Write,Edit,Grep,Glob,Agent`: no Bash, WebFetch or WebSearch.
- `--permission-mode default`, where only writes under the results dir are
  pre-approved. Reads stay inside the clone and the skill dirs. Anything else
  would need a prompt, which headless mode denies.
- `--setting-sources user`, so the clone's own `.claude/settings*.json` and its
  hooks are never loaded.
- `--strict-mcp-config`, so no MCP servers or claude.ai connectors are loaded.

`--execute` re-grants Bash under `acceptEdits` so the skill can install
dependencies and run exploit tests. Use it only on code you trust.

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
python -m local_harness.benchmark.run --execute        # let the scan run code (trusted corpora only)

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
