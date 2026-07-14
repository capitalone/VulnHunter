# Phase 4: Verify & Repair

## Purpose

Validate that all fixes are correct, relevant, and high-quality before delivery. This phase runs AFTER Phase 3. It detects stale fixes, runs a multi-step validation, and coordinates a repair loop between a verification agent and a fix agent when issues are found.

> **Branch-name examples in this file use the illustrative form `vulnfix/VULN-NNN-...` for readability.** In fork mode, production branches actually follow the masked pattern `fix/code-quality-<descriptor>-<hash8>` per REQ-SEC-002/003 — substitute that when running commands. In in-place mode, the branch is `vulnfix/<cluster-slug>` (one branch carrying all findings in the cluster).

This spec applies to both execution modes:
- **In-place mode**: fixes committed directly in the user's checkout (primary path)
- **Fork mode**: fixes made on a clone under `.work/<repo>/` — for repos that must be forked rather than edited in place

## Execution Modes

In **in-place mode**, "In-place mode" below applies — the unit of work is a **cluster's branch** (one branch carrying commits for every finding in the cluster the developer picked in Phase 1), not a per-finding branch. Loop through the cluster's findings in commit order.

In **fork mode**, "Fork mode" applies — the unit of work is a per-finding branch on a clone under `.work/<repo>/clone/`.

The committed security test is a **discoverable, repo-convention** test file (e.g. `test_<behavior>.py`, `<module>.security.test.ts`, per `references/repo-type-adapters.md`) — never a `verify_VULN_NNN_*` scaffold (that transient name is renamed at commit and is never delivered). Locate the committed test from the discrimination evidence `assertion_target` field (`.vulnhunter-fix/discrimination/<vuln>.json`, or `.work/<repo>/discrimination/<vuln>.json` in fork mode); `$SEC_TEST` below refers to that path.

### In-place mode

The orchestrating session runs steps directly, spawns subagents for verification and repair, and presents results to the user.

- Pre-check uses `git fetch` + test on the **default branch** (the one captured in `.vulnhunter-fix/intake.json` as `default_branch`, usually `main`).
- Verification agent = fresh Agent tool subagent (model="sonnet" for test-quality review, model="opus" for diagnosis when a test fails). Haiku is documented in `prompts/parse_issues.md` Step 5a as unreliable on shape-variable input — test-quality review (tautological assertions, missing RED phase, mock leakage) is exactly that shape, and a missed flag here lets a fake fix merge.
- Fix agent = fresh Agent tool subagent operating on the cluster's worktree under `.vulnhunter-fix/worktrees/<CLUSTER_KEY>/`.
- Issue escalation does NOT use `.work/delivery/...` — that's fork-mode state. In-place artifacts live under `.vulnhunter-fix/delivery/` and the FIX_NOT_NEEDED / human-review records get rolled into the cluster's PR body instead of a parallel issue.
- The repair loop is **uncapped** in this mode — the developer at the console decides when to stop (see implement.md "CANNOT_AUTO_FIX — Interactive collaboration loop"). Do NOT cap repair attempts at 3.
- Final output is a human-readable summary table per cluster.

### Fork mode

The orchestrating session operates on a clone under `.work/<repo>/`, spawns subagents for verification and repair, and records per-finding outcomes in result JSONs. Used for repos that must be forked rather than edited in place.

- Pre-check runs `git fetch` + the security test against the clone's checked-out default branch.
- Verification agent = fresh Agent tool subagent (receives test + source only).
- Fix agent = fresh Agent tool subagent (receives fix brief + worktree path).
- Issue escalation data is stored in `.work/<repo>/delivery/pending-human-reviews.json`.
- The unit of work is a per-finding branch; each finding gets its own `group-NNN_result.json`.
- Repair attempts are capped (see Step 3); after exhaustion, escalate per Step 4.

## Agents

| Agent | Role | Isolation |
|-------|------|-----------|
| **Verification Agent** | Judges test quality, diagnoses failures, writes fix briefs. Has no context from the original fix session — gives unbiased assessment. | Fresh subagent, reads only the security test file + source under test |
| **Fix Agent** | Receives the verification agent's brief and applies code changes. Can modify the fix OR the test (if the test itself is wrong). | Worktree on the repo's vulnfix branch |

## Step 1: Pre-Check — Is the Fix Still Relevant?

Before running tests, determine if the vulnerability still exists on the default branch.

**In-place mode**: do NOT switch the user's main working tree to `main`. The user is in their own checkout; mutating it would lose their context. Instead, check from a fresh clone or a worktree pinned to `origin/<default_branch>` (read `default_branch` from `.vulnhunter-fix/intake.json`):

```bash
DEFAULT_BRANCH="$(jq -r .default_branch .vulnhunter-fix/intake.json)"
# Use git's plumbing — no working-tree switch.
# Look at origin/<default_branch>'s content at the finding's location:
git -C "$WT_PATH" fetch --quiet origin "$DEFAULT_BRANCH"
git -C "$WT_PATH" show "origin/${DEFAULT_BRANCH}:${FINDING_LOCATION}" \
    | grep -n "<vulnerable_pattern>" || echo "Pattern already gone on $DEFAULT_BRANCH"
```

The security-test-run-on-main approach (`git checkout main && pytest`) is **fork-mode only** — only safe when the agent owns the working tree under `.work/clone/`. Never run it in in-place mode.

**Fork mode**:

```bash
git fetch origin main
git checkout main && git pull
```

### Detection logic

Run the security test against the default branch state (in-place: against the worktree pinned to `origin/<default_branch>`; fork: against `.work/clone` post-checkout):

```bash
python3 -m pytest "$SEC_TEST" -v 2>&1 || true   # $SEC_TEST = committed test path (see assertion_target)
```

| Outcome | Meaning | Action |
|---------|---------|--------|
| Security test **passes** on `main` | Upstream already fixed the vulnerability | Mark as `FIX_NOT_NEEDED` |
| Target file(s) **no longer exist** or were substantially rewritten | Code diverged, fix no longer applies | Mark as `FIX_NOT_NEEDED` (diverged) |
| Merge conflict when rebasing fix branch onto `main` | Upstream modified the same code | Attempt resolution (counts as repair attempt); if unresolvable → `FIX_NOT_NEEDED` (diverged) |
| Security test **fails** on `main` | Vulnerability still present | Proceed to Step 2 |

### FIX_NOT_NEEDED documentation

**Interactive (in-place) mode** — drop the finding from `.vulnhunter-fix/work.json` and post an informational comment on its source `vulnhunter` issue (NOT closing it — that's the merge's job). The fact that the fix isn't needed gets rolled into the cluster PR's body as a per-finding note. No standalone `FIX_NOT_NEEDED.md` file — that's a fork-mode artifact.

```bash
gh issue comment "$ISSUE_NUMBER" \
  --repo "$OWNER_REPO" \
  --body "ℹ️ **VULN-NNN**: Fix not needed — vulnerability already remediated upstream (commit <sha>). This finding will be omitted from the cluster PR; the source issue stays open until you close it manually or it ages out."
```

**Fork mode (legacy `.md` artifact)** — write `work/<repo>/FIX_NOT_NEEDED.md`:

```markdown
# Fix Not Needed: VULN-NNN — <title>

**Status:** <Already fixed upstream | Code diverged>
**Detected:** <date>

## Evidence
- Security test `<test_file>` result on main: <PASS / FILE_MISSING / CONFLICT>
- Upstream commit: <sha> by <author> on <date> — "<message>"
- Fix branch: `vulnfix/VULN-NNN-short-description` (can be deleted)

## Recommendation
Close without merging. No PR needed.
```

**Fork mode** — also update the result JSON for this finding:

```json
{
  "vuln_id": "VULN-NNN",
  "group_id": "group-NNN",
  "status": "ALREADY_FIXED",
  "branch": "vulnfix/VULN-NNN-description",
  "cwe": "CWE-XXX",
  "file_path": "src/file.py",
  "completeness_tier": "FULL",
  "residual_vectors": [],
  "tier_judgment": {"invoked": false, "phase": null, "final_tier": null, "rationale": null, "failure_reason": null},
  "callers_routed_through_fix": [],
  "callers_not_routed": [],
  "pre_check": {
    "outcome": "already_fixed|diverged",
    "evidence": "security test passes on main at commit <sha>",
    "upstream_commit": "<sha>"
  }
}
```

**Fork mode** — if a tracking issue already exists, add an informational comment (no `needs-human-review` label):

```bash
gh issue comment <issue_number> \
  --repo <fork_org>/<fork_repo> \
  --body "ℹ️ **VULN-NNN**: Fix not needed — vulnerability already remediated upstream (commit <sha>). Branch can be deleted."
```

If `gh` is blocked, store this in `.work/<repo>/delivery/issue-comments-pending.json` to post after PR creation.

In-place mode handled this above — the source `vulnhunter` issue on `origin` got the informational comment directly. Do not duplicate here.

Skip to the next finding.

## Step 2: Validate

For findings that are still relevant, run the full validation:

### 2a. Run security test(s)

```bash
git checkout vulnfix/VULN-NNN-short-description
python3 -m pytest "$SEC_TEST" -v   # $SEC_TEST = committed test path (see assertion_target)
```

Expected: **PASS**. The fix should make the security test green.

### 2b. Run full test suite (regression check)

Behavior depends on the worker's `test_policy_applied` and resulting `regression_status`. The verify phase **does not re-run the regression suite**; it inspects the worker's already-recorded outcome and decides whether to gate on it.

| `test_policy_applied` | `regression_status` | Verify-phase action |
|---|---|---|
| `best-effort` | `NO_REGRESSIONS` | Pass — proceed to 2c |
| `best-effort` | `REGRESSIONS_FOUND` | Treat as failure — enter Step 3 repair loop |
| `best-effort` | `ENV_ERROR` | **Pass** — record so the delivery script attaches a "Human-in-the-Loop Validation Required" banner. Do not gate on it. |
| `best-effort` | `SKIPPED` | Anomalous — should not happen under best-effort |
| `must-pass` | `NO_REGRESSIONS` | Pass — proceed to 2c |
| `must-pass` | `REGRESSIONS_FOUND` | Treat as failure — enter Step 3 repair loop |
| `must-pass` | `ENV_ERROR` | Treat as failure — repair loop is unlikely to fix env issues; if exhausted, escalate to manual review |
| `must-pass` | `SKIPPED` | Anomalous — should not happen under must-pass; treat as failure |
| `skip` | `SKIPPED` | **Pass** — record so the delivery script attaches an "Unverified — Manual Test Execution Required" banner |
| `skip` | any other | Anomalous — workers should not run regression suite under skip |

The verification agent (2c) **always runs regardless of policy** — it reviews the security test code, not regression behavior. Test policy does not change verdict semantics for the verification agent.

For reference, the worker's regression-classification rules:

```bash
# Python (pytest)
if [ -f "pytest.ini" ] || [ -f "setup.cfg" ] || [ -d "tests" ] || [ -f "Pipfile" ]; then
  python3 -m pytest tests/ --tb=short -q 2>&1 | tail -30
fi

# Python (behave)
if [ -d "tests/features" ]; then
  pipenv run behave tests/features --tags=test 2>&1 | tail -30
fi

# Go
if [ -f "go.mod" ]; then
  go test ./... 2>&1 | tail -30
fi

# Node
if [ -f "package.json" ]; then
  npm test 2>&1 | tail -30
fi
```

Expected: **No regressions** introduced by the fix (subject to policy table above).

### 2c. Verification agent — test quality review

Spawn a verification agent with ONLY:
- The security test file(s) for this finding
- The source file(s) the test targets
- The VulnHunter finding description (CWE, root cause)

The verification agent evaluates:

1. **Does the test prove the vulnerability is fixed?** Not just that code was changed, but that the attack vector is blocked.
2. **Is the test behavioral or superficial?** AST/grep checks are acceptable for some classes (e.g., "no verify=False") but not others (e.g., SQL injection needs actual query execution or parameterization proof).
3. **Are there obvious bypasses?** Could the vulnerability recur without this test catching it?
4. **Is the test testing the right thing?** Would it pass even if the vulnerability remained (false-pass)?
5. **Does the test import and call the actual production function?** A test that reimplements the logic in a standalone demo is NOT a valid security test — it tests the demo, not the fix. Verdict must be `WRONG` if the test does not import from the production codebase.

Verdicts:
- `GOOD` — test is meaningful and covers the vulnerability
- `WEAK` — test passes but could miss recurrence (fixable)
- `WRONG` — test is nonsensical, tests implementation detail, would pass without a real fix, or does not import the actual production code (standalone demo)

If verdict is `WEAK` or `WRONG`, the verification agent writes a **fix brief** explaining what's wrong and what "correct" looks like.

**Verification agent prompt:** the canonical reviewer prompt lives in `prompts/reviewer_test.md`. The orchestrating session invokes it as a fresh subagent with `rubric_excerpt` (test-quality-rubric.md §R1-R5), `poc_payload`, and `discrimination_evidence` as inputs; the agent returns the JSON contract documented there (`verdict` + `rules{R1..R5}` + optional `fix_brief`). Do NOT duplicate the reviewer prompt in this file — reviewer_test.md is authoritative.

## Step 3: Repair Loop

If any validation step fails (2a, 2b, or 2c), enter the repair loop.

**Maximum attempts** (mode-dependent):

- **In-place (interactive) mode**: no cap. The developer at the console decides when to stop — see implement.md's "CANNOT_AUTO_FIX — Interactive collaboration loop". If `max_repair_attempts` would otherwise fire, instead enter the collaboration loop in implement.md and let the developer pick the next move.
- **Fork mode**: 3 (configurable via `config.json` → `verification.max_repair_attempts`). After exhaustion, escalate per Step 4.

### Per attempt:

1. **Verification agent diagnoses** the failure:
   - Which step failed (security test / regression / quality)
   - Root cause analysis
   - Writes a fix brief:
     ```
     ## Fix Brief — Attempt N

     **Failed step:** <2a|2b|2c>
     **Symptom:** <test output or quality verdict>
     **Root cause:** <why it failed>
     **Instruction:** <what specifically to change — file, function, approach>
     **Constraints:** <what NOT to do — e.g., "do not weaken the test assertion">
     ```

2. **Fix agent receives** the brief + relevant source files and applies changes:
   - Can modify the **fix code** if the fix is wrong or causes regression
   - Can modify the **test** if verification agent determined the test is nonsensical
   - **Cannot weaken a test** just to make it pass — verification agent must agree the weakening is justified
   - Commits each attempt separately for auditability:
     ```bash
     git commit -m "$(cat <<'EOF'
     fix(security): VULN-NNN repair attempt N

     <what was changed and why, per the fix brief>

     VulnHunter-Finding: VULN-NNN
     Co-Authored-By: Claude Code (VulnFix)
     EOF
     )"
     ```

3. **Re-run validation** (Steps 2a, 2b, 2c) against the updated code.

4. **If all pass** → exit loop, mark as verified.

5. **If still failing** → next attempt (up to max).

### Fork mode repair loop mechanics

In fork mode, the orchestrating session drives the repair loop over the clone:

1. Read the worker agent's result JSON (`status: "FAILED"`)
2. Spawn a **verification agent** (fresh context) with:
   - The test file, source file, finding data, and error output from the failed result
3. Verification agent returns a diagnosis JSON (verdict + fix brief)
4. Spawn a **fix agent** (fresh context) with:
   - The fix brief, worktree path, branch name, and constraint list
5. Fix agent applies changes, re-runs validation steps 2a+2b, commits, writes updated result JSON
6. Read the new result JSON
7. If still failing and attempts remain → repeat from step 2
8. If passing → update result to `VERIFIED`
9. If exhausted → update result to `NEEDS_MANUAL_REVIEW` with attempt history

**Fix agent prompt:** `prompts/agent_fix.md` carries the template + inputs + result-format contract. The orchestrating session invokes it with the fix brief, worktree path, and branch name.

## Step 4: Give Up — Escalate to Human Review *(fork mode only)*

> **In-place mode does not reach Step 4.** The repair loop is uncapped in interactive mode (see Step 3 + `implement.md`'s "CANNOT_AUTO_FIX — Interactive collaboration loop"). When verification fails, control bounces back to the collaboration loop in `implement.md` — the developer at the console picks the next move (rework the fix, rework the test, accept a different shape) and Phase 4 re-runs with the new commit on the cluster's branch. There is no "give up and tracking-issue" outcome. If you find yourself in in-place mode considering this Step 4, you've taken a wrong turn — go re-read implement.md's collaboration loop.

If the repair loop is exhausted (3 attempts in fork mode) and validation still fails:

### 4a. Write local documentation

Write `work/<repo>/NEEDS_HUMAN_REVIEW.md`:

```markdown
# Human Review Required: VULN-NNN — <title>

**Finding:** CWE-<id> — <description>
**Severity:** <Critical/High/Medium/Low>
**Fix branch:** `vulnfix/VULN-NNN-short-description`

## What was attempted

### Attempt 1
- **Change:** <what was done>
- **Result:** <what failed — test output snippet>

### Attempt 2
- **Change:** <what was adjusted>
- **Result:** <outcome>

### Attempt 3
- **Change:** <final attempt>
- **Result:** <outcome>

## Current state
- Security test: PASS / FAIL
- Full test suite: PASS / FAIL (which tests broke)
- Test quality: <verification agent's assessment>

## Why automated repair failed
<Root cause analysis — e.g., "fix requires understanding business logic in the
orchestrator that isn't testable locally" or "upstream refactored the auth flow;
the test targets a code path that no longer exists">

## Suggested next steps for reviewer
- [ ] <specific action 1>
- [ ] <specific action 2>
- [ ] Decide: merge as-is / rework / close
```

### 4b. Escalate via tracking issue

**When a tracking issue already exists:**

```bash
# Add label
gh issue edit <issue_number> \
  --repo <fork_org>/<fork_repo> \
  --add-label "needs-human-review"

# Add detailed comment
gh issue comment <issue_number> \
  --repo <fork_org>/<fork_repo> \
  --body-file .work/delivery/human-review-VULN-NNN.md
```

The comment body (`.work/delivery/human-review-VULN-NNN.md`):

```markdown
## ⚠️ VULN-NNN requires human review

**PR:** #<pr_number>
**Finding:** CWE-<id> — <short title>
**Severity:** <Critical/High/Medium>

### What was attempted
1. **Attempt 1:** <what was tried, what failed>
2. **Attempt 2:** <adjustment made, outcome>
3. **Attempt 3:** <final attempt, outcome>

### Current state
- Security test: PASS / FAIL
- Full suite: PASS / FAIL
- Test quality: <verdict>

### Why automated repair failed
<Verification agent's root cause analysis>

### Suggested next steps for reviewer
- [ ] <specific action 1>
- [ ] <specific action 2>
- [ ] Decide: merge as-is / rework / close
```

**When no tracking issue exists yet (pre-delivery):**

Store the review data in `.work/<repo>/delivery/pending-human-reviews.json`:

```json
[
  {
    "vuln_id": "VULN-NNN",
    "cwe": "CWE-XXX",
    "severity": "High",
    "branch": "vulnfix/VULN-NNN-short-description",
    "attempts": [
      {
        "attempt": 1,
        "change": "...",
        "result": "...",
        "diagnosis": "..."
      },
      {
        "attempt": 2,
        "change": "...",
        "result": "...",
        "diagnosis": "..."
      },
      {
        "attempt": 3,
        "change": "...",
        "result": "...",
        "diagnosis": "..."
      }
    ],
    "current_state": {
      "security_test": "FAIL",
      "full_suite": "PASS",
      "quality_verdict": "WEAK"
    },
    "root_cause": "...",
    "suggested_actions": ["...", "..."]
  }
]
```

When Phase 5 (deliver) runs via `gh`, it will:
- Create the PR as **draft** with labels: `security`, `vulnhunter-fix`, `needs-human-review`
- Include the review details in the tracking issue body under a **"Needs Human Review"** section
- Add a per-finding comment on the tracking issue with the full attempt history

### 4c. Mark the PR

If the PR already exists:

```bash
gh pr edit <pr_number> \
  --repo <fork_org>/<fork_repo> \
  --add-label "needs-human-review"

# Ensure it stays draft
gh pr ready <pr_number> --undo \
  --repo <fork_org>/<fork_repo> 2>/dev/null || true
```

If the PR is created later at delivery, labeling is applied from `pending-human-reviews.json` at that point.

### 4d. Update result JSON (fork mode)

Update the finding's result JSON to reflect the escalation:

```json
{
  "vuln_id": "VULN-NNN",
  "group_id": "group-NNN",
  "status": "NEEDS_MANUAL_REVIEW",
  "branch": "vulnfix/VULN-NNN-description",
  "commit_sha": "<latest>",
  "cwe": "CWE-XXX",
  "file_path": "src/file.py",
  "completeness_tier": "MITIGATION",
  "residual_vectors": ["<open vector>: <location> — <reason unclosed>"],
  "tier_judgment": {"invoked": false, "phase": null, "final_tier": null, "rationale": null, "failure_reason": null},
  "callers_routed_through_fix": [],
  "callers_not_routed": [],
  "repair_attempts": 3,
  "repair_history": [
    {"attempt": 1, "change": "...", "outcome": "FAIL", "diagnosis": "..."},
    {"attempt": 2, "change": "...", "outcome": "FAIL", "diagnosis": "..."},
    {"attempt": 3, "change": "...", "outcome": "FAIL", "diagnosis": "..."}
  ],
  "quality_verdict": "WEAK",
  "root_cause_analysis": "...",
  "suggested_actions": ["...", "..."],
  "test_post_fix": "FAIL",
  "regression_status": "NO_REGRESSIONS"
}
```

## Step 5: Post-fix completeness re-classification (REQ-HON-003)

> **Steps 5-9 are mandatory in both in-place and fork mode.** They are the exit criteria of this phase, not optional add-ons — do not present the Step 10 summary or advance to Phase 5 until every one of Steps 5-9 has run and produced its artifact. Tier-mismatch semantics and gate outcomes for each step live in `references/remediation-rigor.md § Phase 4 (Verify) rigor`.
>
> **Path convention:** the commands below use the fork-mode `.work/<repo>/` layout. In in-place mode, substitute the `.vulnhunter-fix/` equivalents — results under `.vulnhunter-fix/state/`, graph at `.vulnhunter-fix/cache/graph.json`, sweep/gate outputs under `.vulnhunter-fix/`.

Re-run the classifier against the applied diff; compare to the plan-phase projection.

```bash
git diff main..HEAD -- <files-affected> > /tmp/applied.diff
python3 scripts/compute-completeness-tier.py \
    --diff /tmp/applied.diff \
    --plan .work/<repo>/fix_plans/<vuln>.json \
    --result .work/<repo>/.vulnfix-manifests/group-NNN_result.json \
    --phase verify
```

Same tier as projection → record and proceed. Different terminal tier → trigger repair loop with a fix brief citing tier mismatch. `LLM_REVIEW` → invoke `prompts/tier_judgment.md` (temp=0, max 2 attempts per REQ-HON-014/015); LLM_REVIEW is never terminal (REQ-HON-013). Crypto findings: any `false` in `crypto_trust_chain` forces `MITIGATION` (REQ-CWE-007) with a `trust-chain:` residual.

## Step 6: Root-cause Sweep (REQ-SWP-001..009)

Run against every VERIFIED finding:

```bash
python3 scripts/sweep-root-causes.py \
    --repo-root .work/<repo>/clone \
    --results-dir .work/<repo>/.vulnfix-manifests/ \
    --graph .work/<repo>/cache/graph.json \
    --patterns references/sweep-patterns.md \
    --triage-dir .work/<repo>/graph_context/ \
    --out .work/<repo>/sweep_summary.json
```

Sibling defects in files already in `result.files_modified` get amended into the PR (Path A). Others become `vulnfix-sweep-detected` follow-up issues (Path B). Sweep siblings on a previously-FULL fix downgrade to `VERIFIED_MITIGATION` with `sweep_revised: true` (REQ-SWP-006).

## Step 7: 9-column verification table (REQ-GRA-011)

Assembled via `vulnhunter_fix.delivery.render_verification_table` when available, or composed verbatim from `references/verification-table-rules.md § Table shape` (nine columns: `#`, `VULN-NNN`, `Stated vector closed?`, `Test exercises real attack?`, `Default fail-closed?`, `Residual risk documented?`, `All call sites covered?`, `Sweep complete?`, `Verdict` — header spelling is contractually fixed). Every `yes` cell must carry a `file:line` citation; `scripts/validate-verification.py` refuses uncited cells (REQ-GRA-012) and refuses tables whose headers don't match verbatim. Column 7 enumerates `graph.callers_of(sink_symbol)`; low-confidence cells carry `(grep_fallback)` annotation (REQ-GRA-020).

## Step 8: Mechanical delivery gates (REQ-GAT-001..013)

Before any `gh` call, run the gate orchestrator:

```bash
python3 scripts/run-gates.py \
    --pr-body .work/delivery/pr-body-VULN_NNN.md \
    --issue-body .work/delivery/issue-body-VULN_NNN.md \
    --result .work/<repo>/.vulnfix-manifests/group-NNN_result.json \
    --sidecar .work/<repo>/graph_context/VULN-NNN.json \
    --sidecars-dir .work/<repo>/graph_context \
    --branch <branch-name> \
    --default-branch <target-repo-default-branch> \
    --repo-root .work/<repo>/clone
```

`--default-branch` is the target repo's base branch (often `main`, but many
repos use `master`). It lets Gate 7 diff the whole branch (`base...HEAD`) so a
scaffold committed in any commit of a multi-finding cluster PR is caught — not
just one in HEAD. Omit it only if the base is genuinely unknown; the gate then
auto-detects and warns if it must fall back to a HEAD-only scan.

Any failing gate halts delivery. Before every repair-loop retry, `python3 scripts/worktree-reset.py` hard-resets the worktree (REQ-GAT-009).

## Step 9: Phase-exit validators (REQ-SCH-003)

On the way out of Verify, each `group-NNN_result.json` must pass `python3 scripts/validate-result.py <path>`. Verification-table validation (`validate-verification.py`) runs at delivery as **Gate 6** inside `run-gates.py` above — pass `--sidecars-dir` so its column-7 caller-coverage check fires; the gate fails closed on any `yes` coverage cell it cannot verify against a sidecar. Failures route to the schema-repair loop (REQ-SCH-004).

**Phase-exit criteria — do not proceed to Step 10 or Phase 5 until ALL of these hold:**
- [ ] Step 5 ran: post-fix tier recorded for every VERIFIED finding (matches or supersedes the plan projection).
- [ ] Step 6 ran: `sweep_summary.json` exists; siblings routed (Path A amended / Path B filed).
- [ ] Step 7 ran: the 9-column verification table is assembled with `file:line` citations.
- [ ] Step 8 ran: `run-gates.py` reported `pass: true` (all seven gates).
- [ ] Step 9 ran: every `group-NNN_result.json` passed `validate-result.py`.

## Step 10: Final Summary

After processing all findings, present to the user:

```
Repo: <repo_name>
Findings processed: N

| VULN ID | Security Test | Full Suite | Quality | Attempts | Status          |
|---------|---------------|------------|---------|----------|-----------------|
| VULN-001 | PASS         | PASS       | GOOD    | 1        | ✓ Ready         |
| VULN-002 | PASS         | FAIL       | WEAK    | 3        | ✗ Human review  |
| VULN-003 | —            | —          | —       | 0        | ⊘ Not needed    |

Branches ready for delivery: vulnfix/VULN-001-..., ...
Branches needing human review: vulnfix/VULN-002-...
Branches to delete (not needed): vulnfix/VULN-003-...
```

Then proceed to Phase 5 (deliver). Delivery goes through `gh` in both modes:
- Only `VERIFIED` branches become ready PRs.
- `NEEDS_MANUAL_REVIEW` findings become labeled draft PRs (`needs-human-review`).
- `ALREADY_FIXED`/`FIX_NOT_NEEDED` findings are recorded as info in the tracking issue body.

## Configuration

Relevant `config.json` fields:

```json
{
  "verification": {
    "max_repair_attempts": 3,
    "test_timeout_seconds": 120
  }
}
```

