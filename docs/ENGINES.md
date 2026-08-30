# Running VulnHunter with Claude Code or Hermes

VulnHunter's methodology can run through Claude Code or Hermes. Claude Code
remains the unchanged reference path; Hermes is the single experimental
adapter included in this contribution. The architecture stays extensible so
future harnesses can be proposed and validated independently.

| Engine | Skill install | Headless invocation | Status |
|---|---|---|---|
| claude-code | `./install.sh` → `~/.claude/skills` | `claude -p '/vulnhunt …' --output-format stream-json` | reference (unchanged) |
| hermes | `./install.sh --target hermes` → `~/.hermes/skills` | `hermes chat -Q -s vulnhunt -t file,terminal,delegation -q '/vulnhunt …'` | experimental (skill verified end-to-end; full-scan parity unbenchmarked) |

## How it fits together

Three layers, each independently extensible:

1. **Skill rendering** — the repo-root skill directories are the single
   source of truth. `adapters/<engine>/adapter.json` declares declarative
   transforms (string substitutions, terminology overlays, frontmatter
   additions); `python3 scripts/render_skills.py` renders
   `dist/<engine>/<skill>/`. The `claude-code` adapter is the identity
   transform, and `tests/test_render_skills.py` enforces byte-identity, so
   a source edit is a deliberate prompt change every adapter inherits.
   Missing find-strings fail the render loudly — upstream prompt edits that
   break an adapter surface immediately in tests.

2. **Headless runtime engines** (`vulnhunter-agent/agent/engines/`) — a
   `ScanEngine` protocol (`get_engine(config)`) with `claude-code` (the
   existing SDK path) and `hermes` (the CLI-backed implementation). The
   registry remains intentionally small while `ScanEngine` and the generic
   `SubprocessEngine` base preserve the extension point. All engines share
   the results-directory success
   contract — a `*_VULNHUNT_RESULTS_*` directory containing the scan's
   `README.md` report (the subprocess engines pre-create the directory, so
   its mere existence is not success; a run that writes no report is a
   failure). Downstream publish / issues / audit / verify stages are
   engine-agnostic and consume the same `*_VULNHUNT_RESULTS_*` +
   `scan_manifest.json` layout. Select with
   `[scan] engine = "…"` in the agent TOML; tune with
   `engine_command`, `engine_provider`, `engine_timeout_seconds`,
   `engine_extra_args`.

3. **Benchmark harness engines** (`harness/`) — batch scans and the LLM
   judge are engine-parametrized (`VULNHUNT_HARNESS_ENGINE`,
   `VULNHUNT_HARNESS_JUDGE_ENGINE`). Judging with a *different* engine than the
   scanner (e.g. scan with hermes, judge with claude-code) avoids
   self-preference bias. Run the ground-truth corpus per engine to compare
   detection rates before trusting a new engine.

## Fan-out semantics per engine

The skill's Phase 2 parallelism maps differently per harness:

- **claude-code**: native Agent-tool subagents.
- **hermes**: native `delegate_task` subagents (own context + terminal).

## Model policy

**No model enforcement anywhere.** Whichever model you select (per-harness
flag, Hermes provider routing, agent TOML) runs the scan — Opus-class is not
treated as the only capable cyber-vulnerability model. The Hermes adapter
prints a one-line calibration notice ("gates tuned on Claude
Opus-class; quality on the selected model may differ") and proceed; engine
runs never gate on model family. The claude-code render keeps the upstream
interactive STOP gate byte-identically, since that adapter is the identity
transform. Use the benchmark harness (`VULNHUNT_HARNESS_ENGINE` /
`VULNHUNT_HARNESS_JUDGE_ENGINE`) to measure how a given model actually
performs on the ground-truth corpus rather than assuming.

## Safety notes

- Unattended Hermes runs: prefer `command_allowlist` or a containerized
  terminal backend over blanket bypass flags.
- Scanning untrusted code: use a containerized/sandboxed execution backend
  before enabling exploit-test execution.
- The methodology stays analysis-first: PoCs demonstrate reachability, not
  weaponized exploitation.

See `docs/engine-matrix.md` for the verified per-harness capability
matrix, and `docs/ADAPTER_GUIDE.md` to add a new harness.
