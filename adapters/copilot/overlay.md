> **Harness adaptation note (GitHub Copilot CLI).** This skill was authored
> for Claude Code; the methodology is unchanged. Tool vocabulary mapping:
> "Grep" → code/content search (built-in search or `rg` via the shell tool);
> "Glob" → file/pattern search; "Read" → file read; "Bash" → the shell tool;
> "the Agent tool" / "launch a subagent" → your parallel-subagent capability
> (fleet/delegate agents) — dispatch one per quoted block and wait for all
> results before proceeding. This skill directory (containing `SKILL.md` and
> `phases/`) must be added to the session (`/add-dir`) so the phase files are
> readable.
