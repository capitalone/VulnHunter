# VulnHunter-Fix

Automated security remediation skill for [Claude Code](https://docs.claude.com/en/docs/claude-code).
This is the companion to VulnHunter: VulnHunter finds the vulnerabilities,
VulnHunter-Fix remediates them via test-driven development. For each finding it
writes an exploit demo, writes a failing security test (RED), implements the fix
(GREEN), verifies the exploit is blocked and nothing regressed, then delivers a PR.

## Install

This skill ships as part of the [VulnHunter](https://github.com/capitalone/vulnhunter)
repository. From the repository root, run the shared installer to copy all skills
(including this one) into `~/.claude/skills/`:

```bash
./install.sh      # installs vulnhunt, vulnhunt-fix-verify, and vulnhunter-fix
./uninstall.sh    # removes them
```

Restart Claude Code afterward, then invoke it with `/vulnhunter-fix`. Re-run
`./install.sh` from the repo root any time you change this skill's files to sync the
installed copy.

> **Run on Opus.** The reasoning load (clustering, fix synthesis, the collaboration
> loop) is calibrated for Opus; the skill stops and asks you to switch if it detects
> Sonnet or Haiku.

## Requirements

- The [Claude Code CLI](https://docs.claude.com/en/docs/claude-code), authenticated,
  running on an Opus model.
- `git` and the GitHub CLI (`gh`), authenticated for the repos you target.
- Python 3.11+ with the skill's helper package installed:
  `python -m pip install -e ".[dev]"` (from this directory) — pulls in `jsonschema`.

## Modes

| Mode | Entry point | Orchestration | Use case |
|------|-------------|---------------|----------|
| **In-place** *(default)* | `cd` into the target repo, run `/vulnhunter-fix` with no args | Harvests `vulnhunter`-labeled GitHub issues on `origin`; fixes on per-finding git worktrees under `<repo>/.vulnhunter-fix/`; opens PRs back to the same repo | Remediation against your own checkout |
| **Fork** *(cross-org)* | `/vulnhunter-fix <TARGET_REPO> <RESULTS_PATH>` | Forks the target into your configured `fork_org`, clones the fork into `./work/`, delivers PRs to the fork | Delivering fixes without touching the upstream target |

Mode is auto-detected by `scripts/detect_mode.sh` (in-place when you are inside a
GitHub checkout with no args; fork when you pass a target + results path).

### Quick start (in-place)

```bash
cd ~/code/my-project          # a repo where VulnHunter has posted findings as issues
claude --model opus --add-dir ~/.claude/skills/vulnhunter-fix
# then in Claude Code:
/vulnhunter-fix
```

### Quick start (fork)

```bash
claude --model opus --add-dir ~/.claude/skills/vulnhunter-fix
# then in Claude Code:
/vulnhunter-fix https://github.com/your-org/my-service /path/to/RepoName_VULNHUNT_RESULTS_*/
```

## Workflow

The skill runs unattended *within* a phase but pauses at every phase boundary for an
operator Approve/Pause decision.

1. **Parse** — extract findings (from `vulnhunter`-labeled issues, or a results
   directory in fork mode) and cluster them.
2. **Plan** — decide fix order and approach per cluster.
3. **Implement (TDD gate)** — for each finding: exploit demo → failing security test
   (RED) → fix (GREEN) → confirm the exploit is blocked → regression check → commit.
   No source file is edited until RED evidence exists on disk.
4. **Verify** — re-run the full RED→GREEN matrix per cluster.
5. **Deliver** — six mechanical gates (severity mask, body completeness, scope,
   idempotency, anti-merge, verification table) run before any `gh pr create`.

## Key principles

- **TDD-driven** — no fix is "done" until a test proves it works.
- **Evidence-based PRs** — every PR shows the exploit, the test, and the fix.
- **One PR per unit of delivery** — a cluster (in-place) or a single finding (fork).
- **Operator-gated** — phase-boundary checkpoints; no fast-path or skip options.
- **Never modifies untargeted code** — fixes are scoped to the finding.

## Configuration

Settings live in `config.json`. The org fields ship as neutral placeholders — set
them to your own org names before running fork mode:

```json
{
  "github": {
    "default_target_org": "your-org",
    "fork_org": "your-fork-org",
    "fork_prefix": "vulnhunter-fix",
    "pr_draft": true
  }
}
```

| Key | Default | Meaning |
|-----|---------|---------|
| `github.host` | `github.com` | Target GitHub host |
| `github.default_target_org` | `your-org` | Default org when resolving bare target repo names |
| `github.fork_org` | `your-fork-org` | Org where forks are created (fork mode) |
| `github.fork_prefix` | `vulnhunter-fix` | Prefix for created fork repo names |
| `github.pr_draft` | `true` | Open PRs as drafts |
| `behavior.fork_visibility` | `private` | Visibility for created forks |

Override the GitHub host at runtime via `VULNFIX_GH_HOST` / `GH_HOST`.

## Tests

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

## License

Part of the VulnHunter project; licensed under the Apache License, Version 2.0.
See the repository-root `LICENSE`.
