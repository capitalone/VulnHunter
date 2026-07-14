# VulnHunter (`/vulnhunt`)

The core VulnHunter scanner skill for [Claude Code](https://docs.claude.com/en/docs/claude-code).
It maps every user-controllable input in a codebase, traces each one *forward*
to dangerous sinks, runs an adversarial pipeline to disprove weak candidates,
and emits only findings it can back with an executable proof-of-concept and a
proposed fix. This is a **prompt-only** skill — `SKILL.md` plus the phase files
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

> **Run on Opus.** The falsification discipline that keeps false positives low
> depends on frontier Opus-class reasoning. You supply your own model access.

## Usage

```bash
claude --model opus \
       --add-dir ~/.claude/skills/vulnhunt \
       --add-dir ~/.claude/skills/vulnhunt/phases

# then inside the Claude Code session:
/vulnhunt
```

The scan writes its artifacts to a `*_VULNHUNT_RESULTS_*` directory (report
`README.md`, executable PoCs, and exploit tests). VulnHunter **never modifies
the target codebase** — fix strategies are documented, not applied.

For unattended or batch operation, the [`vulnhunter-agent/`](../vulnhunter-agent/README.md)
runtime wraps this skill headlessly and the [`harness/`](../harness/README.md)
drives it across many repositories.

## Design: dispatcher + phase subagents

`SKILL.md` is an **orchestrator** — it never performs security analysis itself.
It creates the results directory, dispatches a subagent per phase, verifies each
subagent's output files exist, and compiles the final report. Keeping findings
out of the orchestrator's context is deliberate: it forces the systematic
methodology instead of improvised analysis.

| Phase | File | Responsibility |
|-------|------|----------------|
| 1 · Recon | `phases/phase1_recon.md` | Build the input inventory, partition the codebase, annotate production reachability. |
| 2 · Hunt | `phases/phase2_hunt.md` + `phase2_class_{inj,nav,log}.md` | Parallel class agents (injection / navigation-&-access / logic-&-crypto) trace inputs to sinks per partition, plus one sink-driven audit agent. |
| 2b · Verify | `phases/phase2b_verify.md` | Adversarial pass that tries to *disprove* each candidate; ~half are eliminated. |
| 3 · Reproduce | `phases/phase3_reproduce_test.md` + `phase3c_fixes.md` | Write PoCs, executable exploit tests, and fix strategies. |
| 3d · Sweep | `phases/phase3d_sweep.md` | Grep every confirmed root-cause pattern across the whole codebase. |
| 4 · Report | `phases/phase4_report.md` | Orchestrator compiles the final report. |

`phase2_shared.md` holds the reference material every class agent reads first, so
it is cached across the parallel dispatch.

## Requirements

- The [Claude Code CLI](https://docs.claude.com/en/docs/claude-code),
  authenticated, running on an Opus model.
- No Python, no network — the skill is read-only over the target checkout by
  default. (The agent runtime can opt into `--no-read-only --enable-bash` to run
  exploit tests; interactive use stays static.)

## License

Part of the VulnHunter project; licensed under the Apache License, Version 2.0.
See the repository-root [`LICENSE`](../LICENSE).
