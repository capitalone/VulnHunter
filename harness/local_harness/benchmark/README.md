# VulnHunter Benchmark Harness

A benchmark framework for measuring VulnHunter's detection accuracy against known vulnerabilities. Run scans against repos with confirmed findings, then use an LLM judge to score whether each was detected.

## How It Works

The harness operates in four phases:

1. **Clone** — Clones each benchmark repo at the exact commit hash where the vulnerability exists (not HEAD). Uses `git fetch --depth=1 origin <hash>` for speed, with a full-clone fallback.

2. **Scan** — Runs `/vulnhunt` against each cloned repo in parallel (5 workers by default). Produces the standard `*_VULNHUNT_RESULTS_*` output directory per repo. Automatically retries on 429 rate-limit errors with exponential backoff (up to 3 retries). Tracks cost and token usage per scan.

3. **Judge** — Invokes Claude as an LLM judge. For each scan target, sends the scanner's README.md report and all benchmark findings for that repo in a single batched call. The judge determines whether each known vulnerability was detected by matching on vulnerability class, location, and root cause.

4. **Tally** — Generates a scorecard: per-finding pass/fail, detection rate by vulnerability type, cost summary, and a detailed Markdown report.

5. **History** — Records detection/miss results per finding to `finding_history.json`, enabling trend tracking across runs and the `--skip-stable` optimization.

## Ground Truth Data

The `ground_truth/` directory contains JSON files (one per repo) with known findings across unique (repo, commit) combinations. This repo ships a small **synthetic** example corpus (`ground_truth/EXAMPLE.json`) pointing at public, deliberately-vulnerable apps; supply your own corpus of real findings locally. See `ground_truth/README.md` for the schema. Each finding records:

```json
{
  "finding_id": "VULN-001",
  "type": "IDOR",
  "source_code": "https://github.com/your-org/example-vulnerable-app/tree/<commit_hash>",
  "description": "Detailed vulnerability description with file paths and line numbers..."
}
```

## Usage

Run from the repo root:

```bash
# Full end-to-end run (clone + scan + judge + tally)
python -m local_harness.benchmark.run

# Test against a single repo
python -m local_harness.benchmark.run --repos "example-app"

# Resume after interruption (skips completed work automatically)
python -m local_harness.benchmark.run

# Re-judge after tuning the judge prompt (no re-scanning)
python -m local_harness.benchmark.run --judge-only --force-rejudge

# Re-run specific findings by ID (implies --force-rescan --force-rejudge)
python -m local_harness.benchmark.run --findings VULN-001,VULN-002

# Regenerate the report from existing judgments
python -m local_harness.benchmark.run --tally-only

# Clone and scan only (skip judging step)
python -m local_harness.benchmark.run --scan-only

# Override parallel worker count
python -m local_harness.benchmark.run --max-workers 5

# Skip findings that have been reliably detected across recent runs
python -m local_harness.benchmark.run --skip-stable
```

## CLI Options

| Flag | Description |
|------|-------------|
| `--scan-only` | Clone and scan, skip judging |
| `--judge-only` | Judge already-scanned results only |
| `--tally-only` | Regenerate report from existing state |
| `--force-rescan` | Re-scan repos even if results exist |
| `--force-rejudge` | Re-judge findings even if judgments exist |
| `--repos FILTER` | Only process repos matching substring |
| `--findings IDS` | Re-run specific finding IDs (comma-separated); implies `--force-rescan --force-rejudge` |
| `--max-workers N` | Parallel scan workers (default: 5) |
| `--skip-stable` | Skip findings detected in every one of the last 3 runs |

## Output

Results are written to `local_harness/benchmark_results/` (gitignored):

- `state.json` — Full state tracking clone/scan/judge progress (enables resumability)
- `tally.json` — Machine-readable results
- `BENCHMARK_REPORT.md` — Human-readable scorecard with summary table, per-type breakdown, and false negative analysis

## Analyzing Misses

After a benchmark run, if any findings were missed, the harness suggests running the analysis script:

```bash
# Analyze all missed findings — identifies loss phase and suggests prompt tunings
python -m local_harness.benchmark.analyze_misses

# Analyze a specific finding
python -m local_harness.benchmark.analyze_misses --finding VULN-002

# Verbose mode — prints full artifact excerpts
python -m local_harness.benchmark.analyze_misses --verbose
```

## Resumability

The harness is fully resumable. State is persisted after each operation:

- Repos already cloned at the correct commit are reused
- Repos with existing `*_VULNHUNT_RESULTS_*` directories skip scanning
- Findings with existing judgments skip re-judging
- Use `--force-rescan` or `--force-rejudge` to override

## Rate Limit Recovery

Scans automatically detect 429 rate-limit failures by inspecting the final event in the scan log. On detection, the harness retries with exponential backoff:

- Up to 3 retries per scan target
- Initial backoff: 60s, multiplier: 2x, max: 300s
- Prior partial results are cleaned before each retry

## Cost Tracking

Each scan records cost and token usage (extracted from the Claude Code `result` event):

- Total USD cost, input/output tokens, cache read/creation tokens
- Data stored in `state.json` per scan target (prefixed `scan_*`)
- Tally phase backfills cost data from logs for any scans missing it

## Finding History

`finding_history.json` records a timestamp for each detection or miss per finding across all runs. This enables:

- **`--skip-stable`** — skip findings reliably detected in the last N runs (default threshold: 3)
- Trend tracking to identify flaky or regressed detections over time

## Prerequisites

- Claude Code CLI installed and authenticated
- VulnHunter skill installed (`./install.sh`)
- Access to the benchmark repos on GitHub
