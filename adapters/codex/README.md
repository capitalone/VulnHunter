# Codex CLI adapter

Runs the VulnHunter scanner skill under the OpenAI Codex CLI.

Codex supports the SKILL.md convention under `~/.codex/skills/` and a
headless `codex exec` mode, so the skill installs like the other adapters.
One structural difference drives most of this adapter's rewrites: **Codex
has no subagent-dispatch tool**, so the orchestrator instructions are
rewritten from "dispatch N parallel agents" to "execute the phases
yourself, sequentially, one class-group pass at a time" — the
class-partitioned phase files (`phase2_class_{inj,nav,log}.md`) make that
decomposition natural.

- Phase loading points at `~/.codex/skills/vulnhunt/phases/`
- Subagent dispatch → sequential self-execution (Phase 2 fan-out becomes
  sequential class-group passes; minimum pass count preserved)
- ORCHESTRATOR role → sequential executor with file-based context hygiene
- `/model opus` gating → one-line calibration notice, then proceed on the
  selected model (no blocking, no model enforcement)
- `/cost` reporting → one-line progress reports
- Overlay maps Grep/Glob/Read/Bash → `rg`/`find`/file reads/sandboxed shell

## Install

```bash
./install.sh --target codex     # renders dist/codex + copies to ~/.codex/skills/vulnhunt
```

## Headless use

```bash
cd <target-repo>
codex exec -C . -s workspace-write -m <your-model> \
  "Read ~/.codex/skills/vulnhunt/SKILL.md and execute the /vulnhunt workflow on this repository"
```

Sandbox modes: `-s workspace-write` (default recommendation — the skill
must write its results dir), `-s read-only` (analysis without artifacts),
`-s danger-full-access` (only for exploit-test runs on disposable clones).

## Interactive use

In a Codex session inside the target repo: mention the vulnhunt skill /
ask to "run the vulnhunt security audit on this repository".

## Status

Experimental — skill layout and `codex exec` flags verified against
codex-cli 0.147.0, but full-scan parity vs Claude Code has not been
benchmarked. Sequential Phase 2 changes the cost/latency profile (no
parallel fan-out) and may stress context discipline on large repos;
benchmark before production use.
