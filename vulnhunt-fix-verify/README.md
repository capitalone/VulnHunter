# VulnHunter Fix-Verify (`/vulnhunt-fix-verify`)

A standalone, **read-only** verification skill for [Claude Code](https://docs.claude.com/en/docs/claude-code).
Given a prior `/vulnhunt` scan and a developer's claim that certain findings are
fixed, it inspects the supplied code checkout and emits an **independent
per-finding verdict**. The developer's word is not evidence; the code is. This
is a **prompt-only** skill — `SKILL.md`, `comment_rules.md`, and the phase files
under `phases/`; there is no Python package to install.

## Install

This skill ships as part of the [VulnHunter](https://github.com/capitalone/vulnhunter)
repository. From the repository root, run the shared installer to copy all skills
(including this one) into `~/.claude/skills/`:

```bash
./install.sh      # installs vulnhunt, vulnhunt-fix-verify, and vulnhunter-fix
./uninstall.sh    # removes them
```

`install.sh` copies files directly (rather than symlinking) — symlinks break
`find`/`glob` inside subagents. Re-run `./install.sh` after editing any skill
file to refresh the installed copy.

> **Run on Opus.** Independent verification requires the same reasoning class as
> the scan it checks. You supply your own model access.

## Tool envelope (why it's safe)

The verifier runs under a deliberately tight allow-list — **Read, Write, Edit,
Glob, Grep, Agent** — with **no Bash and no network**. Consequences:

- It cannot run shell commands, exploit tests, or `git`.
- It cannot create directories — every output path must already exist, so the
  **caller must pre-create the `out` directory**.
- It cannot clone or fetch. It reads only within the **trusted roots** (`repo`
  plus any `additional_repos`). Cross-repo references in the comments file are
  resolved by the caller's pre-flight (URL-or-alias only, no inference);
  anything still unresolved is recorded as unverifiable and the run proceeds to
  a normal verdict rather than halting.

## Usage

```bash
claude --model opus \
       --add-dir ~/.claude/skills/vulnhunt-fix-verify \
       --add-dir ~/.claude/skills/vulnhunt-fix-verify/phases

# then inside the Claude Code session:
/vulnhunt-fix-verify repo=<abs> report=<abs> fixed=VULN-001,VULN-003 out=<abs> \
                     [comments=<abs>] [additional_repos=<abs1>,<abs2>,...]
```

| Argument | Required | Meaning |
|----------|----------|---------|
| `repo` | yes | Absolute path to the fixed-code checkout. |
| `report` | yes | Absolute path to the prior `*_VULNHUNT_RESULTS_*` directory. |
| `fixed` | yes | Comma-separated `VULN-NNN` list. |
| `out` | yes | Absolute path to an **already-existing** output directory. |
| `comments` | no | Absolute path to a free-form markdown file (e.g. a GitHub issue body). |
| `additional_repos` | no | Comma-separated absolute paths to other trusted roots. |

## Phases

| Phase | File | Responsibility |
|-------|------|----------------|
| 0 · Preflight | `phases/phase0_preflight.md` | Validate arguments and trusted roots. |
| 1 · Extract | `phases/phase1_extract.md` | Pull the claimed-fixed findings out of the prior report. |
| 2 · Verify | `phases/phase2_verify.md` | Inspect the checkout and reach a per-finding verdict. |
| 4 · Emit | `phases/phase4_emit.md` | Write the verdict JSON to `out`. |

`comment_rules.md` governs how developer comments are read as claims, never as
instructions.

## Requirements

- The [Claude Code CLI](https://docs.claude.com/en/docs/claude-code),
  authenticated, running on an Opus model.
- No Python, no network — verification is purely static over the trusted roots.

## License

Part of the VulnHunter project; licensed under the Apache License, Version 2.0.
See the repository-root [`LICENSE`](../LICENSE).
