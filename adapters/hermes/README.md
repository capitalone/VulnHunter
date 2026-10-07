# Hermes adapter

Runs the VulnHunter scanner skill under the [Hermes Agent](https://github.com/weav/hermes-agent)
harness. Hermes natively understands Claude-Code-style `SKILL.md` skills, so
this adapter keeps the methodology byte-for-byte and rewrites only the
harness-specific surface:

- `${CLAUDE_SKILL_DIR}` → `${HERMES_SKILL_DIR}`
- Agent-tool `general-purpose` subagent dispatch → `delegate_task` (Hermes'
  subagent tool; children get their own context and terminal session)
- `/cost` reporting → one-line progress reports
- `/model opus` gating → one-line calibration notice, then proceed on the
  selected model (no blocking, no model enforcement)
- Frontmatter gains `metadata.hermes.requires_toolsets: [file, terminal, delegation]`
- A short terminology overlay is prepended to `SKILL.md` and every phase file
  (Grep/Glob/Read/Bash → search_files / read_file / terminal)

## Install

```bash
./install.sh --target hermes     # renders dist/hermes + copies to ~/.hermes/skills/vulnhunt
```

Verify: `hermes skills list | grep vulnhunt`.

## Interactive use

In a Hermes session inside the repo you want scanned: `/vulnhunt .`

## Headless use

```bash
cd <target-repo>
hermes chat -Q -s vulnhunt -t file,terminal,delegation \
  --provider anthropic -m claude-opus-4-8 \
  -q '/vulnhunt . --no-read-only'      # or omit --no-read-only for read-only mode
```

`-Q` is the programmatic contract: stdout carries the final message,
stderr carries `session_id: <id>`, exit code 0/1. Scan success should be
judged by the VulnHunter results contract (`<repo>_VULNHUNT_RESULTS_*`
directory + `scan_manifest.json`), not by stdout text.

## Model policy

No model enforcement. Run whatever model you select (`--provider`/`-m`, or
your Hermes config default) — the skill prints a one-line calibration note
and proceeds. Hermes' multi-provider routing makes it easy to benchmark the
same skill across models with the harness's ground-truth corpus.

## Unattended / CI runs

- Approvals: scans issue shell commands (`mkdir`, package-manager installs)
  that Hermes' `DANGEROUS_PATTERNS` may flag. For unattended runs add the
  specific commands to `command_allowlist` in `~/.hermes/config.yaml`, or set
  `approvals.mode: smart`. Avoid blanket `--yolo` against untrusted code.
- Untrusted targets: run with a `docker` terminal backend
  (`terminal.backend: docker`) so dependency installs and exploit tests are
  containerized.
- Web lookups: phases reference CVE/vendor-advisory checks; enable the `web`
  toolset for best coverage (`-t file,terminal,delegation,web`).

## Status

Experimental — smoke-tested for skill discovery, headless preload
(`hermes chat -Q -s vulnhunt`) and `${HERMES_SKILL_DIR}` resolution.
Full-scan parity vs Claude Code has not yet been benchmarked (use
`harness/` benchmark mode with ground truth to compare engines).
