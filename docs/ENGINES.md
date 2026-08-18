# Running VulnHunter on multiple agent harnesses

VulnHunter's methodology is no longer Claude Code-only. The same scanner
skill can be rendered for — and driven by — several agent harnesses
("engines"), with the Claude Code path unchanged as the reference.

| Engine | Skill install | Headless invocation | Status |
|---|---|---|---|
| claude-code | `./install.sh` → `~/.claude/skills` | `claude -p '/vulnhunt …' --output-format stream-json` | reference (unchanged) |
| hermes | `./install.sh --target hermes` → `~/.hermes/skills` | `hermes chat -Q -s vulnhunt -t file,terminal,delegation -q '/vulnhunt …'` | experimental (skill verified end-to-end; full-scan parity unbenchmarked) |
| copilot | `./install.sh --target copilot` → `~/.copilot/skills` | `copilot -p "Read ~/.copilot/skills/vulnhunt/SKILL.md and execute the /vulnhunt workflow …"` | experimental (CLI flag surface unverified) |
| codex | `./install.sh --target codex` → `~/.codex/skills` | `codex exec -C <repo> -s workspace-write -m <model> "Read ~/.codex/skills/vulnhunt/SKILL.md …"` | experimental (flags verified on codex-cli 0.147.0) |

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
   existing SDK path), `hermes`, `copilot`, and `codex` subprocess
   implementations. All engines share the results-directory success
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
   `VULNHUNT_JUDGE_ENGINE`). Judging with a *different* engine than the
   scanner (e.g. scan with hermes, judge with claude-code) avoids
   self-preference bias. Run the ground-truth corpus per engine to compare
   detection rates before trusting a new engine.

## Fan-out semantics per engine

The skill's Phase 2 parallelism maps differently per harness:

- **claude-code**: native Agent-tool subagents.
- **hermes**: native `delegate_task` subagents (own context + terminal).
- **copilot**: fleet/delegate subagents.
- **codex**: no subagent tool — the adapter rewrites Phase 2 into
  **sequential class-group passes** (the phase files are already
  class-partitioned: inj/nav/log). Same minimum pass count, no parallelism;
  higher latency, different context profile.

## Model policy

**No model enforcement anywhere.** Whichever model you select (per-harness
flag, Hermes provider routing, agent TOML) runs the scan — Opus-class is not
treated as the only capable cyber-vulnerability model. The non-Claude
adapters print a one-line calibration notice ("gates tuned on Claude
Opus-class; quality on the selected model may differ") and proceed; engine
runs never gate on model family. The claude-code render keeps the upstream
interactive STOP gate byte-identically, since that adapter is the identity
transform. Use the benchmark harness (`VULNHUNT_HARNESS_ENGINE` /
`VULNHUNT_HARNESS_JUDGE_ENGINE`) to measure how a given model actually
performs on the ground-truth corpus rather than assuming.

## Safety notes

- Unattended runs: prefer per-engine permission presets (hermes
  `command_allowlist` / docker terminal backend; codex `-s workspace-write`
  sandbox; copilot `--allow-tool` patterns) over blanket bypass flags.
- Scanning untrusted code: use a containerized/sandboxed execution backend
  before enabling exploit-test execution.
- The methodology stays analysis-first: PoCs demonstrate reachability, not
  weaponized exploitation.

See `docs/engine-matrix.md` for the verified per-harness capability
matrix, and `docs/ADAPTER_GUIDE.md` to add a new harness.
