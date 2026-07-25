# Codex-grade comparative benchmark

This developer harness materializes 25 deterministic application fixtures with
100 labeled reportable, deferred, and safe instances across authorization,
injection, file handling, supply chain, SSRF, parsers, mobile sharing, and
secret controls.

```bash
python benchmarks/codex_grade_corpus.py materialize ./benchmark-work/corpus
python benchmarks/codex_grade_corpus.py score ./benchmark-work/vulnhunter-run-1.jsonl
```

Run VulnHunter and Codex Security against the same materialized fixture
directories, immutable contents, model family where possible, token budget, and
execution permissions. Normalize each result to one JSONL row per label:

```json
{"fixture_id":"authz-01","instance_id":"authz-vulnerable","prediction":"REPORTABLE","discoverers":["model-a"],"review_survived":true,"coverage_closed":true,"tokens":12000,"cost_usd":0.12,"duration_seconds":42}
```

Record three independent prediction files for each stochastic engine. Compare
validated recall, precision, High/Critical false-clean count, deferred/suppressed
accuracy, coverage closure, tokens, cost, and duration.

This repository does **not** claim Codex parity merely because the harness
exists. The release gate requires all regression tests, zero labeled
High/Critical false-cleans, recall and precision each within five percentage
points of Codex Security, auditable dispositions for every difference, and
reproduction across at least three runs.
