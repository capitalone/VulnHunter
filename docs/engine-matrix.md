# Engine / Harness Matrix

VulnHunter's methodology (skills) and headless runtime are being made
harness-agnostic. This matrix records the verified capability surface of each
supported agent harness so adapter authors know what they are targeting.

Status legend: ✅ verified locally, 📖 documented (not verified locally),
❌ absent, ⬜ planned/unknown (verify before relying on it).

| Capability | Claude Code (reference) | Hermes | GitHub Copilot CLI | Codex CLI |
|---|---|---|---|---|
| Skill / prompt file format | `SKILL.md` (frontmatter: name, description) in `~/.claude/skills/` | `SKILL.md` (same frontmatter + `metadata.hermes.*`, `required_environment_variables`) in `~/.hermes/skills/`; natively imports Claude skills via `hermes import-agent claude-code` 📖 | Custom instructions (`.github/copilot-instructions.md`, user/path-level files) 📖 | `SKILL.md` convention in `~/.codex/skills/` ✅ (dir exists on codex-cli 0.147.0; no CLI subcommand) |
| Skill-dir template token | `${CLAUDE_SKILL_DIR}` | `${HERMES_SKILL_DIR}` 📖 | n/a (instructions are repo-relative) | n/a |
| Slash-command invocation | `/vulnhunt` | `/<skill-name>` (every installed skill) 📖 | prompt files via `/` menu ⬜ | `/<prompt-name>` in TUI 📖 |
| Headless one-shot | `claude -p --output-format stream-json` | `hermes chat -q "<prompt>" -Q` (stdout = final response, stderr = `session_id: <id>`, exit 0/1) ✅ | non-interactive prompt flag ⬜ (confirm `copilot -h` once installed) | `codex exec [-C <dir>] [-s read-only\|workspace-write\|danger-full-access] [-m <model>] [--json]` ✅ |
| Preload skill headlessly | `--add-dir` skills dir + slash command in prompt | `-s/--skills <name>` ✅ | n/a — rely on instruction files | AGENTS.md discovered from cwd 📖 |
| Parallel subagents | `Agent` tool (general-purpose subagents) | `delegate_task` tool (`delegation` toolset; batch `tasks[]`, `output_schema`) 📖 | `/fleet` parallel subagents, `/delegate` cloud agent 📖 | none — use process-level fan-out 📖 |
| File search tools | `Grep` / `Glob` / `Read` | `search_files` / `read_file` (file toolset) 📖 | built-in search + shell 📖 | shell (`rg`, `find`) 📖 |
| Shell execution | `Bash` tool | `terminal` toolset (local/docker/ssh/modal/…) 📖 | shell with approval patterns (`shell(git:*)`) 📖 | sandboxed shell (`--sandbox workspace-write` etc.) 📖 |
| Permission model | `--permission-mode` (`acceptEdits`, …), `--allowedTools` | approval modes `manual|smart|off`, `--yolo`, `command_allowlist`, `DANGEROUS_PATTERNS` 📖 | `--allow-tool` / `--deny-tool` patterns, per-session approvals 📖 | `--sandbox read-only|workspace-write|danger-full-access` 📖 |
| Extra working dirs | `--add-dir` (repeatable) | session cwd; worktrees via `-w` ⬜ | `/add-dir` 📖 | `--add-dir`-equivalent via cwd ⬜ |
| Model selection | `--model claude-opus-4-…` | `-m <model> --provider <p>`; providers: anthropic, openai-codex, copilot (GITHUB_TOKEN), gemini, openrouter, ollama/vllm (custom), … 📖 | `/model` (Auto, Claude Opus/Sonnet 4.5, GPT-5.2 Codex, org models) 📖 | `-m`, config model/providers 📖 |
| Auth | `ANTHROPIC_API_KEY`, Bedrock OAuth/SigV4 | `~/.hermes/.env` per-provider keys 📖 | GitHub auth (`gh` / device flow) 📖 | `OPENAI_API_KEY` / ChatGPT auth 📖 |
| Programmatic result contract | results dir + `scan_manifest.json` (ours, harness-neutral) | same contract — judge by artifact presence, not stdout ✅ | same | same |

## VulnHunter-side coupling inventory (audit date: 2026-08-16)

- `vulnhunt/SKILL.md`: `${CLAUDE_SKILL_DIR}`, `Grep`/`Glob` tool vocabulary,
  Agent-tool subagent dispatch (Phase 2 fan-out), `/cost`, `/model opus`
  gating, Opus 4.7+ requirement.
- `vulnhunt/phases/*.md`: `Grep`/`Glob`/`Read` used as capability verbs
  (portable wording), `phase4_report.md` embeds a `claude-opus-…` example
  model string and `opus46` dir-tag example (illustrative only).
- `vulnhunter-fix/SKILL.md`: Opus gate table, `/model claude-opus-…`
  instruction, "Claude Code's Bash tool / sandbox" phrasing.
- `vulnhunt-fix-verify/SKILL.md`: declares tool inventory
  ("Read, Write, Edit, Glob, Grep, and Agent"), `${CLAUDE_SKILL_DIR}`,
  Agent-tool in-flight semantics.
- `harness/local_harness/scan.py`: shells out to `claude` with
  `--allowedTools "Read Write Edit Bash Agent"`, `--permission-mode
  acceptEdits`, `--add-dir` (skills + phases dirs).
- `harness/local_harness/benchmark/judge.py`: `claude -p` with
  `--system-prompt` and `--output-format text`.
- `vulnhunter-agent/`: `claude_agent_sdk` session construction
  (`runner.py`), provider chokepoint `_llm.py:_send_prompt`,
  Anthropic/Bedrock auth in `build_settings.py`,
  `_MODEL_FAMILIES = ("opus","sonnet","haiku","gpt","o3","o1")` in
  `runner.py` (already multi-family).

## Local environment (this machine)

- Hermes Agent v0.20.1 — `/home/mark/.local/bin/hermes`; skills at
  `~/.hermes/skills`; source with docs at `/home/mark/hermes-agent`.
- codex-cli 0.147.0 — `/home/mark/.local/bin/codex`; `~/.codex` configured.
- `claude`, `copilot` — not installed (rendering/tests do not require them;
  smoke tests for those harnesses are documented commands to run where the
  CLIs exist).
