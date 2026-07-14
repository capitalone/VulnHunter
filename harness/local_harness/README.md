# VulnHunter Harness

Operational tools for evaluating and running the VulnHunter security scanner.

> **Dev-only.** `local_harness/` is not shipped in the product wheel (it is
> excluded from `[tool.setuptools.packages.find]` in `pyproject.toml`) and is
> excluded from the CI/Sonar `agent` coverage gate. It exists purely for local
> benchmarking and batch scanning.

## Subpackages

- **[`benchmark/`](benchmark/README.md)** — Measures detection accuracy against known-vulnerable repos with an LLM judge and generates scorecards.
- **[`batch/`](batch/README.md)** — Ad-hoc batch scanning of arbitrary GitHub repos from a URL list.

## Shared Modules

| Module | Purpose |
|--------|---------|
| `config.py` | Constants, paths, timeouts, retry config for both workflows |
| `clone.py` | Git cloning utilities (`clone_at_commit` for benchmark, `shallow_clone` for batch) |
| `scan.py` | Scan engine: runs `/vulnhunt`, handles 429 retry, parallel execution |

## Quick Reference

```bash
# Benchmark
python -m local_harness.benchmark.run [OPTIONS]
python -m local_harness.benchmark.analyze_misses [--finding ID]

# Batch scanning
python -m local_harness.batch.run scan [--re-clone] [--max-workers N]
python -m local_harness.batch.run status
python -m local_harness.batch.run collect
```

## Tests

Unit tests live in `harness/tests/`. Coverage is measured locally (this
package is outside the CI `agent` gate):

```bash
cd harness && python -m pytest tests/ --cov=local_harness --cov-report=term-missing
```
