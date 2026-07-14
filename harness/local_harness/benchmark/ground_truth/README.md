# Benchmark Ground Truth

This directory holds the benchmark corpus: one JSON file per target repository,
each containing an array of known findings the scanner is expected to detect.

**You supply your own corpus.** This repo ships only `EXAMPLE.json` — a small,
**synthetic** sample that documents the schema and points at public,
deliberately-vulnerable applications (OWASP NodeGoat / Juice Shop / WebGoat).
The commit hashes in `EXAMPLE.json` are **illustrative placeholders**; set them to
the exact commit that contains the vulnerability in your own targets before
running the benchmark. Add your own `<repo-name>.json` files here.

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
| `finding_id` | Unique label for this finding. Any stable string works; the `VULN-NNN` scheme mirrors the IDs `/vulnhunt` emits in its report. |
| `type` | Vulnerability class (free-form label used in the per-type scorecard). |
| `source_code` | `https://github.com/{org}/{repo}/tree/{commit_hash}` — the benchmark clones the repo at exactly this commit (`git fetch --depth=1 origin <hash>`, full-clone fallback). |
| `description` | The detail the judge compares the scanner's findings against. Be specific. |

## Notes

- Multiple findings that share the same `{org}/{repo}/{commit_hash}` are scanned
  together (one scan per unique repo+commit).
- Runtime output (`benchmark_repos/`, `benchmark_results/`, `finding_history.json`)
  is gitignored and never committed.
