"""Coding-tool walkthroughs for the universal CLI surface."""

from __future__ import annotations


SUPPORTED_TOOLS = ("opencode", "pi", "codex", "claude-code", "generic")


def render_instructions(tool: str) -> str:
    normalized = tool.lower()
    if normalized not in SUPPORTED_TOOLS:
        raise ValueError(
            f"unknown coding tool {tool!r}; choose {', '.join(SUPPORTED_TOOLS)}"
        )
    tool_name = {
        "opencode": "OpenCode",
        "pi": "Pi",
        "codex": "Codex",
        "claude-code": "Claude Code",
        "generic": "your coding tool",
    }[normalized]
    invocation = (
        "vulnhunter scan ."
        if normalized != "generic"
        else "vulnhunter scan /absolute/path/to/repository"
    )
    return f"""\
# VulnHunter with {tool_name}

1. If {tool_name} supports GitHub Agent Skill imports, import the VulnHunter
   repository and select its root `SKILL.md`. Otherwise install the universal CLI:

   python -m pip install "git+https://github.com/JJsilvera1/Multi-VulnHunter.git#subdirectory=vulnhunter-agent"

2. Export provider credentials or place them in
   `~/.vulnhunter/providers.env`, then configure providers once:

   vulnhunter init
   vulnhunter doctor

   `init` queries provider model catalogs and saves the selected defaults. Use
   `vulnhunter models` later to search or page through current model IDs.
   If Codex CLI is installed, `codex login` can provide an optional
   ChatGPT/Codex-plan provider without exposing its OAuth token to VulnHunter.
   Reasoning-capable models also offer an `auto` or explicit effort selector.

3. From the repository that {tool_name} is working on, run:

   {invocation}

The interactive flow asks only the scan level and number of core models. For
unattended use:

   vulnhunter scan . --level standard --models 3 --yes --json

Wait for the process to exit, then read the printed results directory. The stable
machine contract is `<results>/run_manifest.json`; the human report is
`<results>/README.md`.

Status handling:

- COMPLETE_CLEAN: completed coverage with no confirmed finding.
- COMPLETE_FINDINGS: completed coverage with confirmed findings.
- COMPLETE_CONDITIONAL: completed coverage with conditional or unresolved candidates;
  do not call it clean.
- INCOMPLETE_LIMIT / INCOMPLETE_COVERAGE: partial scan; never call it clean.
- FAILED: provider or engine failure.

Exit 0 means a complete scan, exit 2 means incomplete, exit 3 means downstream
delivery was partial, exit 4 means execution failed, and exit 64 means invalid
configuration. Do not reinterpret an incomplete run as a clean security result.
Interactive incomplete runs offer a checkpoint resume. In automation, add
`--retry-incomplete` for one bounded retry of failed or unfinished assignments.
"""
