# GitHub Copilot CLI adapter

Runs the VulnHunter scanner skill under GitHub Copilot CLI.

Copilot CLI has no global skills directory like Claude Code or Hermes;
customization is driven by custom instruction files and session-attached
directories. This adapter therefore renders a self-contained skill bundle
(`SKILL.md` + `phases/`) whose harness-specific mechanics are rewritten:

- Phase loading points at the bundle's `phases/` subdir (attach the bundle
  directory to the session with `/add-dir`)
- Agent-tool subagent dispatch → parallel subagents (Copilot fleet/delegate)
- `/model opus` gating → one-line calibration notice, then proceed on the
  selected model (no blocking, no model enforcement)
- `/cost` reporting → one-line progress reports
- A terminology overlay maps Grep/Glob/Read/Bash vocabulary to Copilot's
  search/shell tools

## Install

```bash
./install.sh --target copilot     # renders dist/copilot + copies to ~/.copilot/skills/vulnhunt
```

## Interactive use (Copilot CLI)

```bash
cd <target-repo>
copilot
# in session:
/add-dir ~/.copilot/skills/vulnhunt
# then:
Read the SKILL.md in the added vulnhunt directory and execute the /vulnhunt
workflow on this repository (read-only mode).
```

## Permission preset (shell + writes for results dirs)

```bash
copilot --allow-tool 'write' --allow-tool 'shell(mkdir:*)' \
        --allow-tool 'shell(git:*)'
```

Tighten further for read-only scans: only `write` (for the results directory)
plus the package manager you expect (`shell(npm install:*)`, etc.).

## Status

**Experimental.** The Copilot CLI binary was not available when this adapter
was authored, so the non-interactive invocation (headless `-p`-style prompt
flag) is unverified — run `copilot -h` / `copilot help permissions` on your
install and adjust. Full-scan parity vs Claude Code has not been benchmarked.
