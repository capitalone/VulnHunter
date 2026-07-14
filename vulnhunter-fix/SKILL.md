---
name: vulnhunter-fix
description: >
  Automate vulnerability remediation from VulnHunter scan results using TDD.
  Parses VulnHunter findings, writes exploit demos proving each vulnerability,
  writes security tests that define correct behavior (RED), implements fixes
  to pass those tests (GREEN), and delivers via PR or fallback GitHub issue.
  Each PR includes the exploit demo, failing-then-passing test, and fix.
  Use when the user says "/vulnhunter-fix", "fix the vulnerabilities", "remediate
  the findings", "apply the security fixes", "create PRs for the vuln fixes",
  or provides a GitHub repo URL alongside a VulnHunter results path.
trigger:
  - /vulnhunter-fix
  - user wants to fix vulnerabilities from a VulnHunter scan
  - user wants to create a PR with security fixes
  - user asks to remediate VulnHunter findings
  - user provides a repo URL and results path for remediation
---

# VulnFix — Automated Security Remediation via TDD

## Overview

VulnFix takes VulnHunter scan results and automates the full remediation lifecycle:
1. Parse findings from the report (or from `vulnhunter`-labeled issues in in-place mode)
2. Plan fix order and approach
3. For each vulnerability: write exploit demo → write failing test → implement fix → verify test passes
4. Deliver as PRs — to a private fork (fork mode) or to the same repo (in-place mode)

## Modes

The skill runs in one of two modes, dispatched automatically.

| Mode | Trigger | Workflow |
|------|---------|----------|
| **In-place** *(default when invoked from inside a target repo checkout)* | User runs `/vulnhunter-fix` with no args from inside a git working tree whose `origin` is on GitHub. Findings are harvested from `vulnhunter`-labeled GitHub issues on that repo. The full report is staged from the publish repo named by the `vulnhunt-results-dir` marker. Fixes happen on per-finding worktrees rooted at `<repo>/.vulnhunter-fix/`. Delivery pushes branches and opens PRs back to the same repo; the source issue is commented and closed. | See `prompts/parse_issues.md`, then `plan.md` → `implement.md` → `verify.md` → `deliver.md` (in-place section). |
| **Fork** *(legacy / cross-org)* | User passes `TARGET_REPO` + `RESULTS_PATH` explicitly. Skill clones into `./work/`, forks the target into a configured org, and delivers PRs to the fork. | See `prompts/parse.md`, then the same downstream phases (fork section in `deliver.md`). |

### Mode dispatch (mandatory)

Before any other action, decide the mode. Run the canonical dispatcher script and parse its stdout:

```bash
# Returns one of: mode=in_place / mode=fork / mode=ambiguous / mode=none
# Exit 0 for in_place/fork/none; exit 2 for ambiguous (caller must resolve).
DISPATCH="$(bash "${SKILL_DIR}/scripts/detect_mode.sh" \
    "${TARGET_REPO:-}" "${RESULTS_PATH:-}")"
echo "$DISPATCH"
```

The script is the source of truth for the dispatch rule — it has its own tests under `tests/test_detect_mode_sh.py`. Behavior summary:

| Outcome | When | What stdout looks like |
|---------|------|------------------------|
| `mode=in_place` | CWD is inside a git working tree with a GitHub `origin`, no `TARGET_REPO` supplied. If `RESULTS_PATH` is also supplied, an optional `results=<path>` field appears — see the `RESULTS_PATH` note below. | `mode=in_place owner_repo=<o/r> root=<path> origin=<url> [results=<path>]` |
| `mode=fork` | `TARGET_REPO` AND `RESULTS_PATH` supplied (env or positional), CWD is not a git working tree | `mode=fork target=<url> results=<path>` |
| `mode=ambiguous` | Both `TARGET_REPO` and `RESULTS_PATH` supplied AND CWD is a GitHub checkout — caller picks one | `mode=ambiguous owner_repo=<o/r> target=<url> results=<path>`, exit 2 |
| `mode=none` | Neither: not in a git repo, no args | `mode=none`, exit 0 — caller prompts user for inputs |

Parse the `mode=...` line and the `owner_repo=`/`root=`/`target=`/`results=` fields with shell expansion or `awk`. Export them for downstream phases — every later `gh` call needs `$OWNER_REPO`, and every reference to the project root uses `$ROOT` (fork mode falls back to `pwd` / CWD).

When MODE resolves to **in-place**, the rest of the workflow uses CWD as the target repo, treats `<CWD>/.vulnhunter-fix/` as the work directory, and skips Steps 2 (`TARGET_REPO`/`RESULTS_PATH` prompting) and 5 (clone into `./work/`) below.

#### `RESULTS_PATH` in in-place mode (local scan reports)

When the operator supplies `RESULTS_PATH` in in-place mode, `detect_mode.sh` emits `mode=in_place results=<path>` — a single mode, with the findings source riding as an optional field. `prompts/parse_issues.md` § Step 0 reads that field and skips the GitHub-issue harvest, sourcing findings from disk instead. It writes `no_source_issues: true` + `results_path` to `work.json`. Downstream renderers (`deliver.md`, `templates/pr_body_cluster.md`) branch on `no_source_issues` to switch PR-body language from `Closes #N` to `Addresses VULN-N per <results_path>`.

Findings-source is a property of the work, not a property of the mode.

#### Handling `mode=ambiguous`

The user is inside a GitHub checkout AND supplied fork-mode arguments — both signals are present and only one can be the intended target. **Use `AskUserQuestion` to disambiguate** with these two options (label / description):

- *"In-place — fix `<owner_repo>` (current checkout)"* — discard `$TARGET_REPO`/`$RESULTS_PATH`, re-run dispatch with empty args so the result is `mode=in_place`.
- *"Fork mode — fix `<target>` using `<results>`"* — `cd` out of the current checkout (or set `OWNER_REPO=""`) and re-run with the original args so the result is `mode=fork`.

Do not guess; the developer's intent is the only signal. Until they answer, do not advance to Step 1.

#### Handling `mode=none`

Neither signal was supplied — not in a git repo and no `TARGET_REPO`/`RESULTS_PATH` arguments. **Use `AskUserQuestion`** to collect both inputs:

- *"TARGET_REPO"* — full GitHub URL (e.g., `https://github.com/org/repo`)
- *"RESULTS_PATH"* — local directory path OR a GitHub URL to a results repo

Once both are collected, re-invoke `detect_mode.sh` with them as positional args (`bash detect_mode.sh "$TARGET_REPO" "$RESULTS_PATH"`) and proceed on the resulting `mode=fork`. If the user can't provide one or both, **stop** with: *"Cannot proceed without TARGET_REPO and RESULTS_PATH when run outside a GitHub checkout."*

## Required Inputs (fork mode only)

- **TARGET_REPO**: GitHub repo URL (e.g., `https://github.com/org/repo`)
- **RESULTS_PATH**: Path to VulnHunter results — either:
  - Local directory: `/path/to/RepoName_VULNHUNT_RESULTS_*/`
  - GitHub repo URL: `https://github.com/org/vuln-findings` (will be cloned)

In-place mode harvests findings from `vulnhunter`-labeled issues; no inputs are required beyond the user running the skill from the target repo's working tree.

## Mandatory First Actions

**Step 0: Confirm you're running on Opus.** *(in-place / interactive mode only — headless skips this)*

The reasoning load in this skill — clustering findings by topic, the CANNOT_AUTO_FIX collaboration loop, fix synthesis when the report leaves gaps — is calibrated for Opus. Sonnet and Haiku produce noticeably worse results: weaker clustering, hand-wavier fix proposals, more dead-end iterations in the loop.

Check your own model identity from your session system prompt (it says "You are powered by the model named …"):

| You are | Action |
|---------|--------|
| Opus 4.x (any variant) | Proceed to Step 1. |
| Sonnet 4.x | **Stop.** Tell the user, verbatim: `This skill is calibrated for Opus. Please run `/model claude-opus-4-8` and then re-invoke `/vulnhunter-fix`.` Do not run any other tool calls. |
| Haiku 4.x | **Stop.** Same message as above. |

This is interactive-mode only. Headless mode invokes the executor with a fixed Opus model under the hood and skips this gate.

The check applies even if the user has *just* switched models mid-session — you may have started this turn on Sonnet because that was the session default before they ran `/vulnhunter-fix`. The `/model` command takes effect on the *next* turn, so stopping here gives the user the clean handoff.

**Step 0b: Confirm the installed skill is at upstream `main`.** *(in-place / interactive mode only)*

The skill itself is versioned in `https://github.com/capitalone/vulnhunter` on `main`. Stale installs miss bug fixes (today the failure list includes: TLS-quirk handoffs, sandbox-friendly clone flags, the cluster-as-PR semantic, the `--repo` rule). Before doing anything else, confirm the user is running the latest skill:

```bash
# 1. Get the latest upstream HEAD SHA of main.
UPSTREAM_HEAD="$(gh api repos/capitalone/vulnhunter/branches/main --jq .commit.sha 2>/dev/null)"

# 2. Get the SHA the installed skill is at. The installer (install.sh) writes
#    this on every install. If the file is missing, the user installed by
#    a different mechanism and we can't compare.
INSTALLED_SHA_FILE="${SKILL_DIR}/.installed-from"
if [ -f "$INSTALLED_SHA_FILE" ]; then
    INSTALLED_SHA="$(cat "$INSTALLED_SHA_FILE")"
else
    INSTALLED_SHA=""
fi
```

| Outcome | Action |
|---------|--------|
| Both SHAs equal | Proceed silently. |
| `INSTALLED_SHA` empty | Print a single-line warning: `Could not determine installed skill version (no ${SKILL_DIR}/.installed-from). Re-run install.sh to enable version checks.` — then proceed. |
| SHAs differ | **Stop and tell the user**, using the failure-policy template (⚠️ + bold + fenced block). Suggest the exact re-install command for their checkout: `cd <path-to-cloned-vulnhunter-repo> && git pull origin main && ./install.sh` — and ask them to re-invoke `/vulnhunter-fix` after the install completes. |
| `gh api` call fails for any reason | Print a single-line warning and proceed — don't block on the version check itself. Network failures here are common in corporate environments and shouldn't gate the actual fix work. |

The check is a courtesy gate, not a hard one — except when SHAs are confirmed to differ, in which case the user is running a known-stale skill and continuing risks reproducing already-fixed bugs.

**Step 1: Run preflight check.**
```bash
python3 "${SKILL_DIR}/scripts/preflight.py"
```
If any check fails, stop and report the failure to the user. Preflight only validates LOCAL state (tool versions, disk, working-tree-cleanness, etc.) — it does not check network or `gh` auth because Python subprocesses can't reliably reach GitHub in some target environments.

**Step 1b: Verify `gh` auth via Bash.**
```bash
gh auth status >&2 || { echo "Not authenticated. Run: gh auth login" >&2; exit 1; }
gh api user --jq .login >/dev/null || { echo "gh token invalid or GitHub unreachable" >&2; exit 1; }
```
This runs through the Bash tool's working context (which has TLS the Python preflight doesn't). For in-place mode also verify the user can see `origin` (using the `OWNER_REPO` computed in mode dispatch so the call doesn't depend on `gh repo set-default`):
```bash
gh repo view "$OWNER_REPO" --json name,owner >/dev/null \
    || { echo "Cannot view $OWNER_REPO via gh" >&2; exit 1; }
```

## `git` + `gh` failure policy — STOP and ask the user

**This rule overrides any local instinct to retry, fall back to a different tool, or work around a `git` / `gh` failure. Read it before every phase that runs either command.**

Some target environments (notably macOS with corporate keychain interception or restrictive sandboxes) make `git` and `gh` calls fail intermittently from within Claude Code's Bash tool — even though the same command works perfectly in the user's own terminal. The failure modes vary:

- TLS errors: `tls: failed to verify certificate`, `x509: OSStatus -…`, `SSL certificate problem: unable to get local issuer certificate`, `Could not resolve host: api.github.com`.
- Sandbox / filesystem denials during `git clone`: `Operation not permitted` when copying hook templates into `.git/hooks/`, `fatal: cannot copy '…/commit-msg.sample' to '…/.git/hooks/…'`.
- Transient transport errors: `Post "https://api.github.com/graphql": …`, `dial tcp …: i/o timeout`.
- Any `git` or `gh` invocation exiting non-zero with output that doesn't match a documented, locally-handled case (e.g., `git symbolic-ref` returning non-zero is *expected* — your script has a fallback chain; that doesn't trigger this rule. A `git clone` exit of 128 with sandbox or TLS output *does*).

When you hit one of these, this is the **only** acceptable sequence:

1. **STOP.** Do not retry the same command. Do not retry with different flags. Do not invoke a different but equivalent tool — that is the worst trap. Examples of forbidden "fixes":
   - `git clone` fails → trying `gh repo clone` instead.
   - `gh issue list` fails → trying `git ls-remote` or `curl https://api.github.com/...`.
   - `git clone <url> <repo-relative-path>` fails on sandbox → trying `git clone <url> $TMPDIR/...`.
   - Falling through to a different `gh` subcommand hoping it uses a different transport.
   
   Every "fix" in this category makes the transcript noisier, wastes the user's time, and never addresses the environmental root cause. The TLS / keychain / sandbox quirks are local to this Bash-tool environment; no command variation will fix them.

2. **Tell the user, in plain text, exactly ONE command to run in their own terminal** (NOT a multi-command pipeline, NOT a `cd && cmd` chain — one literal command they can copy and paste). Use this exact format so the command stands out visually instead of getting buried in prose:

   ````
   ⚠️ `<original tool call>` failed inside Claude Code's sandbox.

   **▶ Run this in your own terminal, then paste the output back (or just "done"):**

   ```bash
   <single command, exactly as you would have run it>
   ```

   _Why this works: <brief reason — TLS / sandbox / etc.>_
   ````

   Mandatory formatting elements (don't omit any):
   - ⚠️ marker on the first line so the user's eye lands there immediately.
   - **Bold call-to-action** line right above the command — not buried at the end of a paragraph.
   - Triple-backtick fenced block with `bash` language hint — renders as a distinct monospace box, NOT as 4-space indent (which gets visually mistaken for regular indented text).
   - Blank lines above and below the fenced block for breathing room.
   - The "why" line goes AFTER the command (in italics, smaller-feeling), so the command itself is the visual centerpiece.

   Do not wrap the command across multiple lines with backslash continuations — the user has to copy/paste it as-is, and multi-line bash is error-prone in pasting. If the command is long, accept the long single line.

3. **Wait for the user to paste the output.** Do NOT continue with any further `git` or `gh` calls in the meantime.

4. **Use the pasted output verbatim.** If the next step in the workflow needed a JSON blob, treat the paste as that blob. If the user was asked to clone a repo, **always specify a path inside the project's own `.vulnhunter-fix/` work dir** (e.g., `<project_root>/.vulnhunter-fix/publish/repo`). Never instruct the user to clone to `$HOME`, `$TMPDIR`, or any other path outside the project — those need extra permission grants for every later access and leave leftover state that breaks re-runs.

5. **Repeat for the next call.** One command at a time. Never batch.

Exceptions — when you MAY retry or work around:
- The user explicitly says "try a different approach" or "go ahead and retry".
- The failure is a **real API error** with a structured body — e.g., `gh` returns an HTTP 4xx with a JSON `{"message": "Not Found"}`, or `git` returns a clear domain error like `fatal: branch '…' does not exist`. Those are *actionable in-flow*: re-prompt the user, change the branch, etc.

This rule applies in every phase — parse, plan, implement, verify, deliver. If you find yourself running a second `git` or `gh` command of the same conceptual kind (clone, fetch, list-issues, …) with no user input in between, you are violating this rule.

### Hand-off command templates per language / tool

When the failing command involves a language toolchain that fetches dependencies, the user-paste command MUST include the corporate-proxy env vars — otherwise the user's `go test` / `npm install` / `pip install` will hit the public registry and fail the same way the sandbox call did. The required prefixes:

| Toolchain | Env var prefix to add to the user-paste command |
|-----------|-------------------------------------------------|
| **Go modules** (`go mod download`, `go mod tidy`, `go test`, `go build`) | `GO111MODULE=on GOPROXY=https://<your-go-module-proxy> GOAUTH=netrc` |
| **npm / yarn / pnpm** | (TBD — add when first encountered; today: tell the user to run from a shell with their corporate `~/.npmrc` already configured) |
| **pip / pip-tools** | (TBD — same as above; corporate `~/.pip/pip.conf` is the usual mechanism) |
| **maven / gradle** | (TBD — corporate `~/.m2/settings.xml`) |

For Go specifically — this is the most common case in the current target environments — the full template for module-cache repopulation is:

````
⚠️ `go mod download` failed inside Claude Code's sandbox (network/proxy block).

**▶ Run this in your own terminal, then paste "done" back:**

```bash
cd <ABSOLUTE_WORKTREE_PATH> && GO111MODULE=on GOPROXY=https://<your-go-module-proxy> GOAUTH=netrc go mod download all
```

_Why this works: your terminal can reach your corporate Go module proxy via netrc auth; the sandbox can't. Once the modules land in the shared `~/go/pkg/mod` cache, my sandboxed `go test` calls read from there without needing the network._
````

**Always** include the env-var prefix on the same line as `go mod` — Go does not auto-pick these up from a shell rc file in a non-interactive run, and missing one fails silently or talks to `proxy.golang.org` which is sandbox-blocked. If you find yourself emitting a bare `go mod download` to the user, you've forgotten this rule.

**Two additional rules every `gh` call must follow** (so user-pasted commands work identically):

1. **Always pass `--repo "$OWNER_REPO"` (or `--repo "<owner>/<repo>"`).** Otherwise `gh` falls through to `gh repo set-default`, which most users haven't configured, and the command fails with `No default remote repository has been set` even when authenticated. Local commands like `gh auth status` and `gh api user` don't need a repo.
2. **Prefer `git` over `gh` for anything that's local-discoverable.** Examples:
   - Default branch → `git symbolic-ref refs/remotes/origin/HEAD | sed 's|^refs/remotes/origin/||'` (no network).
   - Origin URL → `git remote get-url origin` (no network).
   - Listing branches → `git branch --list` (no network).
   - Use `gh` only when the data genuinely lives on GitHub (issue bodies, PR status, label state, etc.).

**Step 2: Validate inputs.**

In **fork mode**, both `TARGET_REPO` and `RESULTS_PATH` must be provided. If missing, ask the user:
- "Which GitHub repo should I fix?" (for TARGET_REPO)
- "Where are the VulnHunter results?" (for RESULTS_PATH)

In **in-place mode**, skip this step — inputs come from `vulnhunter`-labeled issues on `origin`.

**Step 3: Load configuration.**

Read `config.json` from this skill's directory for settings (GitHub host, branch prefix, behavior flags).

**Step 4: Set up work directory.**

In **fork mode**: clone the fork into `./work/<fork-repo-name>/` (e.g., `./work/vulnhunter-fix-my-service-api/`). The clone is deleted after successful delivery.

In **in-place mode**: CWD is already the target repo. Create the work tree at `<repo_root>/.vulnhunter-fix/`, add it to `.git/info/exclude` (never to tracked `.gitignore`), and `git worktree prune` to clean up orphans from previous crashed runs. One git worktree per cluster gets created later by `scripts/setup_worktree.sh` during Phase 3.

## Task tracking (mandatory)

Multi-finding clusters and the interactive collaboration loop both have many steps that the agent will forget if it doesn't externalize them. **Use the `TaskCreate` / `TaskUpdate` / `TaskList` tools from the start of every in-place run and update them aggressively.** Same applies in fork mode for runs with more than ~3 findings.

The granularity:

- **Phase 1 (parse_issues.md)** — one task per finding the developer selected. Subject = `<VULN-NNN> — <short title>`. Status starts `pending`. Don't conflate findings into one task even when they're in the same cluster — each finding has its own RED→GREEN evidence to track.
- **Phase 2 (plan.md)** — for each finding, set its task `description` to the planned approach (test framework, fix strategy, in-cluster sequence position). No status change.
- **Phase 3 (implement.md)** — flip a finding's task to `in_progress` when you enter its IP-Step A (exploit demo) and to `completed` only when the commit lands (IP-Step H). If the collaboration loop engages, create **sub-tasks** for each developer-driven decision (e.g., "Get PoP lib API contract from developer", "Decide between approach A and B", "Add env var to staging config") so the loop's progress is auditable.
- **Phase 4 (verify.md)** — one task per cluster, subject = `Verify cluster <name>`. Flip to `completed` only after the full RED→GREEN matrix passes.
- **Phase 5 (deliver.md)** — one task per cluster delivery: `Deliver cluster <name>: push, PR, comment source issues`. Flip to `completed` after `gh pr create` returns a URL AND every source issue has been commented with the PR link. **Do not include "close N issues" in the subject** — the skill does not close source `vulnhunter` issues at delivery time; the PR's `Closes #N1, #N2, …` keywords auto-close them on merge (the only safe closure path, since `--mode=verify` keys on issue closure and would reject a fix that was closed before its PR merged).

Re-run `TaskList` before any handoff (between phases, between findings within a cluster, before entering the collaboration loop, before each commit) so the agent's working set is always reconciled with reality.

The reason: when a cluster has 8 findings and the collaboration loop fires on 2 of them, there are easily 30+ discrete actions in flight. Without tasks, the agent silently drops sub-steps ("Wait, did I run the regression suite for VULN-007?") and either re-runs work or skips it entirely. Tasks make the dropped steps visible.

## Non-negotiable rules (read before every phase)

**No override, exception, or fast-path clauses.** This skill has none. It intentionally has none. If mid-run you find yourself:

- Proposing to skip a step "because it's a small batch" / "we already understand the code"
- Offering the operator a "keep going as-is" or "option 2 — faster path" that bypasses a documented gate (TDD RED, graph substrate, plan artifact, mechanical gates)
- Citing a rule or override you can't point to a specific `SKILL.md` / `prompts/*.md` line for
- Treating a phase's `Summary:` line here as sufficient instructions instead of opening the phase's prompt file

**STOP.** Do not offer the skipped step as an option to the operator. Do not invent a permission slip. The failure mode the skill exists to prevent is producing plausible-looking fixes that skipped rigor; a "fast path" — even one the operator would approve — re-introduces exactly that failure mode.

If the operator says "just keep going" or "skip the checkpoints," refuse politely and explain that rigor steps are not configuration options.

## Phase-boundary checkpoints (mandatory)

At the end of every phase (Parse → Plan → Implement → Verify → Sweep → Deliver), BEFORE opening the next phase's prompt file or taking any action toward it, you SHALL:

1. **Verify the phase's artifacts exist** on disk at the paths that phase's prompt file specifies (findings.json / clusters.json / work.json for Parse; the plan artifact per selected cluster for Plan; per-VULN red_evidence + green_evidence for Implement; sweep_summary for Sweep; all seven gate outputs for the pre-deliver gate step).
2. **Present a concrete summary** to the operator: what was produced, what wasn't, and any anomalies (script exit codes, backend=grep fallbacks, LLM_REVIEW tier judgments, etc.).
3. **Invoke `AskUserQuestion`** with a single approve-or-pause prompt: *"Phase N complete. Proceed to Phase N+1?"* — options: `Approve` / `Pause — I want to inspect first`.
4. **Do not read the next phase's prompt file** until the operator answers Approve.

If a phase's expected artifacts are missing or malformed, do NOT present an approve/pause question. Instead, stop and report what's missing. Do not offer to "proceed anyway."

The checkpoints are not decoration. They exist because prior E2E runs showed the agent skipping the graph substrate, jumping past plan.md, and starting Edit on source files without RED evidence. The checkpoints turn silent skips into visible refusals.

## Workflow

### Phase 1: Parse Results
- **Fork mode**: read `prompts/parse.md` for detailed instructions.
- **In-place mode**: read `prompts/parse_issues.md` instead. It harvests `vulnhunter`-labeled issues, stages the full report from the publish repo, and produces the same downstream contract as fork mode. If `RESULTS_PATH` is supplied alongside (in-place with local report), `parse_issues.md` § Step 0 short-circuits the issue-harvest and sources findings from disk.

### Phase 2: Plan Remediation
Read `prompts/plan.md` (in-place flow) or `prompts/plan_fork.md` (fork / headless flow) per the mode dispatch.

### Phase 3: Implement Fixes (TDD Gate)
Read `prompts/implement.md` for detailed instructions. Fork-only content (`## Fork-mode implementation` setup + `## CANNOT_AUTO_FIX — Issue Fallback (headless / fork mode only)`) lives inside `implement.md` under those section headings; skip when running in-place.

For EACH finding, on its own branch:
1. **Exploit Demo (RED)** — Write code proving the vulnerability is exploitable
2. **Security Test (RED)** — Write a test defining correct secure behavior; confirm it FAILS *before* any fix is written. Persist the RED evidence to `.vulnhunter-fix/state/<vuln>/red_evidence.json` (pytest output + test file hash).
3. **Fix (GREEN)** — Apply the fix ONLY after RED evidence exists for that VULN. Do not edit any source file until Step 2's evidence is on disk.
4. **Verify exploit blocked** — Re-run exploit demo; confirm it no longer succeeds
5. **Regression check** — Run existing tests; confirm nothing broke
6. **Commit** — Stage exploit demo + test + fix; commit with structured message

### Phase 4: Verify & Repair
Read `prompts/verify.md` for detailed instructions.

### Phase 5: Deliver
Read `prompts/deliver.md` for detailed instructions.

The seven mechanical delivery gates (severity mask, body completeness, scope, idempotency, anti-merge, verification-table, committed-test-naming) run BEFORE any `gh pr create` call — no PR is created if any gate fails.

## Key Principles

- **TDD-driven**: No fix is "done" until a test proves it works
- **One PR per unit-of-delivery**: in **in-place mode** the unit is the *cluster* the developer picked in Phase 1 — one PR carrying N per-finding commits, each with its own RED→GREEN evidence, and `Closes #N1, #N2, …` for every source issue. In **fork / headless mode** the unit is the *individual finding* — one PR per finding, per the strict grouping rules in `plan.md`. Either way: easy to review, easy to revert at the delivery-unit granularity.
- **Evidence-based PRs**: Every PR shows the exploit, the test, and the fix
- **Triage before delivery**: Each finding is classified as Ready PR (fully non-breaking) / Draft PR (non-breaking but requires setup, with explicit setup steps in body) / Issue only (design unresolved or setup non-trivial — spec is updated with open questions and a plan). The `pr_draft` config flag is the default for the Draft PR bucket; Ready PRs override it. See `prompts/deliver.md` § Delivery Triage.
- **Operator-gated between phases**: this skill runs unattended WITHIN a phase but pauses at every phase boundary for an operator Approve/Pause decision. See "Phase-boundary checkpoints (mandatory)" above. The prior "Fully automated: no confirmation gates" language authorized the agent to skip rigor steps end-to-end and has been removed.
- **Controlled access**: Fork is private with collaborators managed via `collaborators.json`

## Helper Scripts

| Script | Purpose |
|--------|---------|
| `scripts/preflight.py` | Verify LOCAL system requirements (Python, git, gh, Claude CLI, disk). Auth + network are checked via Bash in SKILL.md Step 1b. |
| `scripts/check_repo_access.sh` | Verify push access to target repo (fork mode only) |
| `scripts/clone_repo.sh` | Clone or fork target repo (fork mode only) |
| `scripts/parse_results.py` | Regex-based VulnHunter README → JSON (fork-mode/headless fallback; in-place uses model extraction in `prompts/parse_issues.md` Step 5a) |
| `scripts/setup_worktree.sh` | Create per-cluster (in-place) git worktree |
| `scripts/issue_intake.py` | Pure-logic marker extraction + homogeneity check + vulnfix_key |
| `scripts/detect_mode.sh` | Canonical mode-dispatch logic (in-place vs fork) — referenced by SKILL.md Step 0 |
| `scripts/cluster_score.py` | Authoritative risk-reduction scoring rubric (Critical=8, High=4, …) — called from `parse_issues.md` Step 3(b) |
| `scripts/validate_findings_draft.py` | Shape-check `findings.draft.json` output of `parse_issues.md` Step 5a's Sonnet subagent |
| `scripts/validate_pr_body.py` | Pre-flight check: PR body's `Closes #N` count matches cluster member count |

## Templates

| Template | Used For |
|----------|----------|
| `templates/pr_body.md` | PR description body — **fork mode** (one finding per PR) |
| `templates/pr_body_cluster.md` | PR description body — **in-place mode** (N findings per PR, `Closes #N1, #N2, …`) |
| `templates/issue_body.md` | Issue body (fallback) |
| `templates/commit_msg.md` | Commit message format |

## Configuration

Settings in `config.json`. Key options:
- `github.host`: Target GitHub host (default: `github.com`)
- `github.default_target_org`: Default org for target repos (default: `your-org`)
- `github.fork_org`: Org to create forks in (default: `your-fork-org`)
- `github.fork_prefix`: Prefix for fork repo names (default: `vulnhunter-fix`, e.g., `vulnhunter-fix-RepoName`)
- `github.pr_draft`: Create PRs as draft (default: true)
- `verification.max_repair_attempts`: Max repair loop iterations in **fork / headless** mode before escalating to human review (default: 3). In-place mode's collaboration loop is uncapped (see `implement.md`).
- `behavior.fork_visibility`: Visibility for created forks (default: `private`) — fork mode only
- `behavior.deliver_to_fork_only`: Never create PRs/issues in target repo (default: true) — fork mode only
- `behavior.confirm_before_push`: Ask before pushing (default: true) — fork mode only
- `behavior.work_dir`: Local directory for cloning target repo (default: `./work`) — fork mode only
- `collaborators_file`: Path to collaborators whitelist (default: `collaborators.json`) — fork mode only
- `verification.max_retries`: Legacy synonym for `max_repair_attempts` referenced by `headless/` docs; not read by the in-place prompts.

Override via env vars: `VULNFIX_GH_HOST`, `VULNFIX_BASE_BRANCH`, `GH_HOST`.

## Collaborators

The `collaborators.json` file controls who gets access to the private fork:

```json
{
  "collaborators": [
    {"username": "USER_ID", "role": "admin"},
    {"username": "ANOTHER_USER", "role": "write"}
  ]
}
```

Valid roles: `admin`, `write` (maintain), `read` (triage).

Collaborators are added automatically when the fork is created during Phase 5 delivery.
