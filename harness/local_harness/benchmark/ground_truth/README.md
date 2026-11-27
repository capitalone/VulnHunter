# Benchmark Ground Truth

This directory holds the benchmark corpus: one JSON file per target repository,
each containing an array of known findings the scanner is expected to detect.

This repo ships a real starter corpus covering OWASP Juice Shop, WebGoat, and
NodeGoat (`juice-shop.json`, `WebGoat.json`, `NodeGoat.json`), each pinned to a
specific commit hash with exact file and line references. These run out of the box.

`EXAMPLE.json.template` documents the schema but uses placeholder commit hashes;
it is excluded from the benchmark glob (only `*.json` files are loaded). Copy and
rename it if you want a starting point for new entries.

## Schema

Each file is a JSON array of finding objects:

```json
[
  {
    "finding_id": "VULN-001",
    "type": "SQLInjection",
    "source_code": "https://github.com/your-org/example-vulnerable-app/tree/<commit_hash>",
    "description": "Human-readable description of the vulnerability, ideally with file paths, function names, and line numbers so the LLM judge can match the scanner's output."
  }
]
```

| Field | Meaning |
|-------|---------|
| `finding_id` | Stable identifier, **globally unique across the entire corpus** (not just within one file). The benchmark keys judgments and history by this ID, so collisions across files silently corrupt results. Convention: prefix with the app name (e.g. `NODEGOAT-001`, `JUICE-002`) to guarantee uniqueness. |
| `type` | Vulnerability class (free-form label used in the per-type scorecard). |
| `source_code` | `https://github.com/{org}/{repo}/tree/{commit_hash}` — the benchmark clones the repo at exactly this commit (`git fetch --depth=1 origin <hash>`, full-clone fallback). |
| `description` | The detail the judge compares the scanner's findings against. Be specific. |

## Notes

- Multiple findings that share the same `{org}/{repo}/{commit_hash}` are scanned
  together (one scan per unique repo+commit).
- Runtime output (`benchmark_repos/`, `benchmark_results/`, `finding_history.json`)
  is gitignored and never committed.
