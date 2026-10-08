# VulnHunter for GitHub Copilot

A port of all three VulnHunter [Claude Code](https://docs.claude.com/en/docs/claude-code)
Skills to **VS Code Copilot [Agent Skills](https://code.visualstudio.com/docs/agent-customization/agent-skills)**,
for interactive use inside VS Code:

| Skill | Phase | Port location |
|---|---|---|
| `/vulnhunt` | Hunt — scan a codebase and emit proven, exploitable findings | `skills/vulnhunt/` (overlay onto `vulnhunt/`) |
| `/vulnhunter-fix` | Fix — TDD remediation from scan results, delivered as PRs | `skills/vulnhunter-fix/` (overlay onto `vulnhunter-fix/`) |
| `/vulnhunt-fix-verify` | Verify — independent, read-only check that a fix actually landed | `skills/vulnhunt-fix-verify/` (overlay onto `vulnhunt-fix-verify/`) |

The headless `vulnhunter-agent/`/`harness/` runtimes are **not** ported — this
covers interactive, in-VS-Code use of all three skills only.

> [!NOTE]
> **Revision history.** An earlier revision of this port shipped `/vulnhunt`
> as a Copilot Chat *prompt file* and ran every phase sequentially in one
> session. That broke in practice: a prompt file's generic search/read tools
> are scoped to whatever workspace is currently open, so it couldn't see a
> separately installed `phases/` folder when scanning a different repo. This
> revision ships all three skills as proper **Agent Skills** instead —
> `SKILL.md` plus supporting files, which Copilot resolves relative to the
> skill package itself, independent of the open workspace — and restores
> genuine **parallel** subagent dispatch using VS Code's
> [Subagents](https://code.visualstudio.com/docs/copilot/agents/subagents)
> feature.

## Why this directory doesn't look like three complete, standalone skills

It isn't — and that's deliberate. `vulnhunt-copilot/skills/<name>/` contains
**only the files that differ from the existing Claude Code skill** of the
same name. Everything else — the vulnerability methodology, the gates and
severity tiers, and (most importantly) `vulnhunter-fix`'s entire tested
Python package — is not Claude-specific, so it isn't duplicated. The
install scripts assemble the real, complete skill at install time by
copying the existing skill directory (**base**) first, then this directory
(**overlay**) on top:

```
install destination = base(vulnhunt/) + overlay(vulnhunt-copilot/skills/vulnhunt/)
```

This means a future fix to, say, `vulnhunter-fix/scripts/preflight.py`
automatically applies to both the Claude Code and Copilot installs, with one
edit and no drift risk — there is exactly one copy of that file in the repo
(one specific check in it *is* downgraded for Copilot via a text
substitution — see "Small wording differences" below — but the file itself
is never duplicated). It also means this directory's file count is not the
whole story: if you're looking for
`vulnhunt-copilot/skills/vulnhunt/phases/phase2_class_inj.md`
and don't find it, that's correct — it's identical to
`vulnhunt/phases/phase2_class_inj.md`, so the overlay doesn't need its own
copy; the installer pulls it from the base directory.

### What's actually overridden, per skill

**`vulnhunt`** — overlay has 7 of 12 base files; these 5 are identical and
come from the base directory unchanged: `phase2_class_inj.md`,
`phase2_class_nav.md`, `phase2_class_log.md`, `phase2b_verify.md`,
`phase3c_fixes.md`.

**`vulnhunt-fix-verify`** — overlay has `SKILL.md` and three phase files
(`phase0_preflight.md`, `phase2_verify.md`, `phase4_emit.md`);
`phase1_extract.md` and `comment_rules.md` are identical and come from the
base directory. `phase4_emit.md` needs an override rather than a
substitution because its one-line change is a link, not plain prose: base
says the verification schema lives "at the repo root," which doesn't
resolve once this skill is installed standalone — the overlay points it at
`../verify_disposition.schema.json` instead, matching the same fix already
applied in `SKILL.md`. `verify_disposition.schema.json` itself isn't in
either skill's own base tree — the install scripts copy it in directly from
`vulnhunter-agent/verify_disposition.schema.json`, its actual canonical
location, rather than storing a third copy here.

**`vulnhunter-fix`** — overlay has exactly two files: `SKILL.md` and
`prompts/parse_issues.md`. Everything else in `vulnhunter-fix/` — all 16
other prompt files, `scripts/`, `references/`, `templates/`, `tests/`, the
entire `vulnhunter_fix/` Python package, `config.json`, `collaborators.json`,
`pyproject.toml`, `evals/` — is byte-identical to base and is never
duplicated in this repo.

**If you're changing shared methodology** (anything in the base
directories) and the Copilot behavior needs to diverge as a result, add an
override file here at the matching relative path — the overlay always wins
on conflict during install. If your change doesn't need Copilot-specific
handling, you don't need to touch this directory at all; the install
scripts will pick up your base-directory change automatically.

### Small wording differences: install-time text substitution, not files

A handful of base files need a one-line or few-line change that's purely
about which platform is running — a `Co-Authored-By` attribution trailer,
a couple of comments mentioning a Claude Code-specific tool by name. An
earlier revision of this port kept full-file overlay copies for these too,
but a [reviewer on the upstream PR](https://github.com/capitalone/VulnHunter/pull/32)
pointed out that this was actually worse than it looked: those "delta"
files were ~93% verbatim duplicates of base, and duplicating a whole file
to change one line recreates the exact drift risk the overlay design exists
to avoid — a future fix to the base file wouldn't reach Copilot users
unless someone remembered the near-identical copy existed too.

Instead, `vulnhunt-copilot/scripts/apply_substitutions.py` applies a small,
explicit, byte-exact substitution list to the relevant base files, after
they're copied to the install destination. Every rule:
- Was generated from a real diff, not retyped by hand (see the script's
  git history for the generation approach), so there's no risk of a
  transcription mismatch.
- **Fails loudly** if its expected text isn't found in the target file (or
  is found an unexpected number of times) — if upstream changes that
  wording, the install stops with a clear error naming the file and rule,
  rather than silently leaving stale "Claude Code" wording in a Copilot
  install. Verified directly: the script was run against a deliberately
  modified copy of a target file during development and confirmed to fail
  with the expected error, not silently succeed.
- Was verified byte-for-byte against the full-file overlay copies it
  replaced before those copies were deleted, so this is a mechanical
  restructuring of the same content, not a re-authoring of it.

This covers the `Co-Authored-By` trailer (in `templates/pr_body.md`,
`templates/pr_body_cluster.md`, `templates/commit_msg.md`, and
`prompts/{worker_agent_common,implement}.md`), a few `AskUserQuestion` →
neutral-phrasing wording changes in `prompts/{implement,verify}.md` and
`scripts/cluster_score.py`, a `Sonnet` → generic model-tier wording change
in `prompts/verify.md`, `prompts/parse.md`, and
`scripts/validate_findings_draft.py`, "the Claude Code sandbox" →
"macOS agent sandboxes" comment generalizations in
`tests/test_graph_build_bugs.py` and `vulnhunter_fix/graph/{build,config}.py`,
and one *behavioral* substitution in `scripts/preflight.py`: base treats a
missing Claude CLI as a hard failure that blocks `/vulnhunter-fix` from
proceeding, which is correct for Claude Code users but would make Step 0
unpassable on a Copilot-only machine, since installing the Claude Code CLI
isn't part of this port. The substitution downgrades that one check to
`optional=True` (a `[WARN]`, not a `[FAIL]`) — it still runs and still
reports if the Claude CLI happens to be present, it just never blocks
progress when it isn't. Every other substitution above is comment/docstring
wording only; this is the one exception, called out explicitly because it
changes what the script actually does, not just what it says.

Two more checks run in CI alongside `apply_substitutions.py --check`, for
the overlay files this mechanism doesn't cover:
`check_overlay_freshness.py` pins each full-file overlay's (`SKILL.md`,
`phase2_hunt.md`, `parse_issues.md`, etc.) base counterpart's content hash
and fails if the live base file has changed since — the same "fail loud on
drift" principle, extended to the files that are too different from base to
express as a substitution list. `check_dep_pins_consistent.py` asserts
`vulnhunter-fix`'s bundled venv dependency pin is identical across
`_install_common.sh`, `install.cmd`, and `install-copilot.cmd` (see "One
installer, not two" below for why it's three places and not one) —
previously relied on a comment to keep in sync by hand.

### One installer, not two — on the bash side only

`install.sh` and `install-copilot.sh` both need to locate a Python 3.11+
interpreter and build vulnhunter-fix's bundled venv — identical logic,
independent of which platform's skill is being installed. Rather than
duplicate that logic in both scripts (as an earlier revision of this port
did), both source a shared `_install_common.sh` at the repo root. Each
script sets `INSTALL_INVOCATION` to its own name before sourcing it, so the
one error message that names "which script to re-run" still names the
right one.

**The `.cmd` side was not unified the same way, after an attempt broke it.**
A prior revision tried the equivalent via `call "%SCRIPT_DIR%\_install_common.cmd" :label`,
reasoning that cmd.exe's documented `CALL :label` cross-file form would jump
straight into a label in another `.cmd` file. That form doesn't exist:
`CALL otherfile.cmd :label` does not jump to `:label` in `otherfile.cmd` — it
runs `otherfile.cmd` from the top, with `:label` passed in as `%1`. Verified
against multiple independent sources (Microsoft's own `call /?` reference,
SS64's documentation, and the well-known "BatchLibrary" idiom, which exists
specifically because this jump isn't automatic — it requires an explicit
`call :%1` dispatcher line the attempted shared file never had). Concretely,
this broke both `.cmd` installers: `_install_common.cmd`'s
`:build_vulnfix_venv` would read the literal string `:build_vulnfix_venv` as
its own destination-path argument (since the real argument shifted to `%2`
and was never read), try to build a venv at
`:build_vulnfix_venv\.venv` — an illegal Windows path — and abort the
install with a nonsense error, on `install.cmd` (Capital One's existing,
pre-PR Claude Code installer) as much as on `install-copilot.cmd`.

Caught before merge, and reverted: `install.cmd` and `install-copilot.cmd`
are byte-identical to their state before that attempt, each keeping its own
copy of `find_python`/`build_vulnfix_venv` again, guarded by
`check_dep_pins_consistent.py` the same as before. `install.sh`'s bash-side
unification is unaffected by any of this and was independently
verified end-to-end (fresh install, full skill set, bundled venv built and
smoke-tested, output byte-identical to before the change) — this section
exists mainly as a record of why the `.cmd` side still has its own copy,
for the next person who's tempted to try unifying it the same way.

## Install

macOS/Linux:

```bash
# From the repository root:
./install-copilot.sh      # installs all three skills to ~/.copilot/skills/
./uninstall-copilot.sh    # removes them
```

Windows (from `cmd.exe` or PowerShell — both can run `.cmd` files directly):

```bat
install-copilot.cmd
uninstall-copilot.cmd
```

> [!IMPORTANT]
> **Windows: Copilot's agent terminal needs to run bash, not PowerShell.**
> `SKILL.md` and the phase/prompt files embed bash syntax (`${VAR}`
> expansion, `[ ]` tests, heredocs) in their code blocks. VS Code Copilot's
> agent terminal tool defaults to whatever your workspace's default terminal
> profile is — normally PowerShell or cmd.exe on Windows, neither of which
> understands that syntax. `install-copilot.cmd` handles this automatically:
> if it finds Git for Windows, it sets `chat.tools.terminal.terminalProfile.windows`
> in your VS Code `settings.json` to Git Bash — a setting specific to
> Copilot's agent tool, confirmed against VS Code's own source, that doesn't
> touch your regular integrated terminal's default. It backs up
> `settings.json` first and skips cleanly (with manual instructions printed)
> if Git Bash isn't found or the existing `settings.json` can't be parsed
> safely. **This part of the installer was written and reviewed on macOS,
> not run against a real Windows/VS Code install — verify it did what you
> expect before relying on it**, and see
> `vulnhunt-copilot/scripts/windows/configure-terminal-profile.ps1` if you
> want to run or adapt it yourself. `uninstall-copilot.cmd` calls the
> companion `remove-terminal-profile.ps1`, which removes just that one
> setting — not a whole-file restore from the backup, which would also
> discard any unrelated `settings.json` changes made since install — but
> only if the live value still looks unchanged since install; it leaves the
> setting alone (and tells you why) if you changed it yourself in the
> meantime. Same macOS-only caveat applies.

`install-copilot.sh`/`install-copilot.cmd` assemble each skill at
`~/.copilot/skills/<name>/` from the base + overlay directories described
above — files, not symlinks, same reasoning as the Claude Code installer:
symlinks can break workspace search tooling. No path substitution or VS
Code settings edit is needed beyond the Windows terminal-profile step
above: Copilot auto-discovers Agent Skills from `~/.copilot/skills/` and
resolves a skill's own supporting files relative to its `SKILL.md`,
regardless of which workspace you have open when you invoke it.

`vulnhunter-fix` also ships a real Python package (graph-based analysis,
delivery gates, ~30 helper scripts) — one copy, in `vulnhunter-fix/` at the
repo root, used by both the Claude Code and Copilot installs. Like the
Claude Code installer, `install-copilot.sh` builds it a bundled venv at
`~/.copilot/skills/vulnhunter-fix/.venv` with `jsonschema` and `graphifyy`
pinned to the versions `preflight.py` expects — this needs Python 3.11+
available on your machine. The other two skills are prompt-only; no venv.

Re-run `./install-copilot.sh` after pulling changes to refresh your installed
copy (it rebuilds the venv too).

## Usage

1. Open the repository you want to scan/fix in VS Code.
2. Open Copilot Chat, switch to **Agent** mode.
3. Select a frontier-class reasoning model in the model picker — see the model note below.
4. Run one of:
   ```
   /vulnhunt              # scan the current repo
   /vulnhunter-fix         # remediate findings from a prior /vulnhunt scan
   /vulnhunt-fix-verify    # independently verify specific findings were fixed
   ```

`/vulnhunt` walks itself through recon, hunting, verification,
reproduction/fix-strategy, sweep, and report phases, checkpointing each
phase's output to disk under a `*_VULNHUNT_RESULTS_*` directory inside the
scanned repo. It **never modifies the target codebase** — fix strategies are
documented, not applied.

`/vulnhunter-fix` is the one that does modify the target: it creates git
worktrees/branches, writes exploit demos and tests, applies fixes, and opens
real PRs (or forks + PRs in fork mode). It needs `git` and the GitHub CLI
(`gh`, authenticated) in addition to VS Code/Copilot.

`/vulnhunt-fix-verify` is read-only over the code it inspects — see its
**Tool boundary** section below for an important caveat on how that's
enforced (or not) under Copilot.

### Model selection: pick a frontier-class model, same as the Claude Code version

The Claude Code version doesn't leave model choice to chance: it inspects
its own model identity at start-up and stops if it isn't running on Opus.
This port keeps that same discipline rather than softening it. Each skill's
`SKILL.md` checks the model selected in the Copilot Chat model picker and
stops, with an explicit message, if it isn't a frontier-class reasoning
model — the falsification discipline (`/vulnhunt`), clustering and fix
synthesis (`/vulnhunter-fix`) all depend on multi-step, adversarial
reasoning that's unreliable on lighter/faster models.

Deliberately **not** recommended here: GitHub Copilot's "Auto" model
selection mode. Auto delegates the model choice to automatic,
task-complexity-based routing — which is a reasonable default for general
use, but it's a different philosophy than the one this product is built
around. The underlying skill requires a specific, named-tier model and
tells the user to switch if they aren't on one; this port mirrors that
requirement rather than replacing it with "whatever the platform judges
best for this request."

Subagents dispatched by any of the three skills inherit the parent
session's model by default (VS Code's subagent model-priority order falls
back to "parent conversation's model" when no explicit override is given).
`/vulnhunter-fix`'s `parse_issues.md` is the one exception worth knowing
about: it explicitly asks for a frontier-tier subagent for one specific
extraction step (README parsing) regardless of the parent session's model,
because lighter models have measurably dropped findings there — see that
file's porting notes.

## Differences from the Claude Code version

Shared across all three ports:

| Claude Code | This port |
|---|---|
| Skill (`SKILL.md` + supporting files), invoked via `/<name>`, discovered from `~/.claude/skills/`. | Agent Skill (same shape), invoked via `/<name>`, discovered from `~/.copilot/skills/`. |
| Orchestrator dispatches **parallel subagents** via the Task tool. | Dispatches parallel subagents via VS Code's `agent`/`runSubagent` tool — same procedures, same minimum counts where applicable. |
| Skill auto-triggers on natural language (Skill `trigger:` frontmatter), in addition to explicit `/command`. | Agent Skills support the same dual invocation (explicit command, or auto-triggered when the skill's `description` matches the request) — a real capability of Copilot Agent Skills, not something these ports had to build. |
| Reports progress via Claude Code's `/cost` command after each phase. | No equivalent exists in Copilot Chat; the skills just confirm each phase's output files exist. |
| Bash tool. | A terminal tool (`runCommands` or equivalent), gated the same way the upstream skill gates Bash access. |

`/vulnhunt`-specific:

| Claude Code (`vulnhunt/`) | This port (`skills/vulnhunt/` overlay) |
|---|---|
| `SKILL.md` programmatically checks the running model and can tell the user to run `/model opus` mid-session. | Asks the user to confirm a frontier-class model is selected in the Copilot model picker at start-up, and stops with the same message-and-wait discipline if not — can't self-inspect or switch it for them the way Claude Code can, but doesn't relax the requirement either. |
| "Agent-driven" invocation path, where `vulnhunter-agent/`'s headless runtime pre-resolves scan metadata. | Not ported — interactive, in-session metadata resolution only (Step 1 of `SKILL.md`). |

`/vulnhunter-fix`-specific — the most consequential differences, since this skill pushes real commits and opens real PRs:

| Claude Code (`vulnhunter-fix/`) | This port (`skills/vulnhunter-fix/` overlay) |
|---|---|
| `TaskCreate`/`TaskUpdate`/`TaskList` for mandatory task tracking. | VS Code's built-in todo-list tool (`todo_write`/`todo_read`) — confirmed to exist and serve the same purpose. |
| `AskUserQuestion` for structured multi-choice prompts (mode disambiguation, cluster/issue selection, collaboration-loop options). | No confirmed Copilot equivalent. Ported as: present options as a numbered list in chat, ask the user to reply with the number(s) (comma-separated for multi-select), and wait. Functionally the same pause-and-wait; loses the structured button/checkbox UI. |
| Opus/Sonnet/Haiku-specific model gating, incl. `/model claude-opus-4-8`. | Same stop-and-confirm discipline, adapted to Copilot's model picker instead of one named Claude model — still requires a specific frontier-class model, not "Auto." Where the upstream skill deliberately routes specific subagent *tasks* to a cheaper vs. stronger model tier (e.g. Haiku for mechanical extraction, Sonnet for shape-variable extraction), this port keeps that tiering — generically, as "lightweight/fast model" vs. "frontier reasoning model" — since the underlying reasoning (cost vs. reliability trade-off) isn't Claude-specific. |
| An entire section of operational discipline for Claude Code's Bash tool's TLS/sandbox failure modes (manual hand-off to the user's own terminal, one command at a time). | Rewritten, not just relabeled: VS Code's terminal tool has its *own*, different sandboxing — confirmed to block network access by default with a **built-in retry-with-confirmation** flow, which the Claude Code Bash tool doesn't have. This port tries that retry first; the manual hand-off is now a fallback, not the first move. See `SKILL.md`'s **`git` + `gh` failure policy** section. |
| `Co-Authored-By: Claude Code (VulnFix)` trailer on commits/PRs. | `Co-Authored-By: GitHub Copilot (VulnFix)` — applied via install-time text substitution (see "Small wording differences" above), not a file override — leaving the old attribution would have been factually wrong in real git history regardless of which platform produced the commit. |
| `${SKILL_DIR}` resolved automatically by the platform. | No Copilot equivalent exists. Bound explicitly in `SKILL.md` Step 0 (derived from the path the agent read `SKILL.md` from, with a documented fallback default). |
| Scripts, references, templates, tests, and the `vulnhunter_fix` Python package. | Not duplicated at all — see "Why this directory doesn't look like three complete, standalone skills" above. A handful of individual files get a small, install-time text substitution (the `Co-Authored-By` attribution, a few comments generalized from "the Claude Code sandbox" to "macOS agent sandboxes") rather than a file override — see "Small wording differences" above for why. |

`/vulnhunt-fix-verify`-specific:

| Claude Code (`vulnhunt-fix-verify/`) | This port (`skills/vulnhunt-fix-verify/` overlay) |
|---|---|
| Skill `allowed-tools` frontmatter gives a **platform-enforced** guarantee that this skill never gets Bash or network tools — its whole trust model (independent, read-only verification) rests on that. | Copilot Agent Skills (as currently documented) have no confirmed equivalent per-skill tool allow-list field. **This is a real limitation, not cosmetic** — see the skill's **Tool boundary** section. The read-only claim is now instructional (the skill tells the model not to use those tools), not platform-enforced. Disable your terminal/network tools in Copilot Chat's tool picker for the session if you want the same hard guarantee. |
| References `verify_disposition.schema.json` "at the repo root." | That path doesn't actually resolve reliably once a skill is installed standalone. This port's install scripts copy it in from its real location (`vulnhunter-agent/verify_disposition.schema.json`) at install time instead. |

### What was ported as-is

The actual security/remediation methodology in every skill — vulnerability
classes, hard gates, severity tiers, TDD discipline, delivery gates, cluster
scoring, the graph-based analysis package — is not Claude-specific and
carries over unchanged (via the base+overlay install-time merge) or with
only cosmetic terminology tweaks where it does need an overlay override
(e.g. "the Grep tool" → "your search tool"). Each skill's `SKILL.md` (and,
for `/vulnhunt`, `phases/phase2_hunt.md`; for `/vulnhunter-fix`,
`prompts/parse_issues.md`) needed real rewrites for orchestration mechanics;
see the porting notes at the top of those files for exactly what changed and
why.

## Layout

```
vulnhunt-copilot/
├── README.md
├── scripts/
│   ├── apply_substitutions.py         # install-time text substitutions (see above)
│   ├── check_overlay_freshness.py     # CI: base-hash drift check for full-file overlays
│   ├── check_dep_pins_consistent.py   # CI: dep-pin parity across _install_common.sh + both .cmd files
│   ├── overlay_base_hashes.json       # manifest check_overlay_freshness.py verifies against
│   └── windows/
│       ├── configure-terminal-profile.ps1  # install: point Copilot's terminal at Git Bash
│       └── remove-terminal-profile.ps1     # uninstall: revert it, best-effort
└── skills/
    ├── vulnhunt/                  # overlay onto ../../vulnhunt/ — installs as ~/.copilot/skills/vulnhunt/
    │   ├── SKILL.md
    │   └── phases/                 (6 of 11 files — the other 5 come from the base directory)
    ├── vulnhunt-fix-verify/       # overlay onto ../../vulnhunt-fix-verify/ — installs as ~/.copilot/skills/vulnhunt-fix-verify/
    │   ├── SKILL.md
    │   └── phases/                 (3 of 4 files — the other, plus comment_rules.md, come from the base directory)
    └── vulnhunter-fix/            # overlay onto ../../vulnhunter-fix/ — installs as ~/.copilot/skills/vulnhunter-fix/
        ├── SKILL.md
        └── prompts/parse_issues.md  # the only other overlay file — everything else
                                       # (16 other prompts, scripts/, references/,
                                       # templates/, tests/, the vulnhunter_fix/
                                       # package) comes from the base directory,
                                       # with a small install-time text substitution
                                       # applied to a handful of files — see
                                       # scripts/apply_substitutions.py
```

See "Why this directory doesn't look like three complete, standalone
skills" above for the full per-skill list of what's intentionally omitted
and where it comes from instead.

## Requirements

- VS Code with GitHub Copilot Chat, Agent mode, Agent Skills, and Subagents
  enabled. These are actively evolving Copilot/VS Code features — if
  dispatch or discovery doesn't behave as documented here, check your VS
  Code/Copilot Chat version against current docs first.
- A frontier-class reasoning model available through your Copilot
  subscription, selected explicitly in the model picker (not "Auto").
- `/vulnhunt` and `/vulnhunt-fix-verify`: no Python, no network required for
  the skill itself. Terminal-enabled/non-read-only modes need your terminal
  tool available in the chat session.
- `/vulnhunter-fix`: Python 3.11+ (for its bundled venv), `git`, and the
  GitHub CLI (`gh`) authenticated to your target repositories.

## License

Part of the VulnHunter project; licensed under the Apache License, Version 2.0.
See the repository-root [`LICENSE`](../LICENSE).
