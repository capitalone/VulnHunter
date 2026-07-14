# Phase 5: Deliver

## Mode-dependent delivery

Delivery differs between fork mode and in-place mode. Both share the dedup, triage, and PR-body conventions in this document; they differ in **where** artifacts land.

- **Fork mode**: PRs and issues are created in a private fork (a separate repo, possibly in a different org). The target team is never alerted. Follow the **Fork-mode delivery** section below.
- **In-place mode**: PRs land on `origin` (the user's own checkout). The source `vulnhunter`-labeled issues already exist on `origin` and become the per-finding tracking issues — no parallel tracking issues are created. Follow the **In-place delivery** section near the end of this document.

> **Read the "`git` + `gh` failure policy" section of `SKILL.md` before continuing.** Every `gh` and `git` call in this phase — both fork-mode and in-place — must follow the same rule: STOP on `tls: failed to verify certificate`, `OSStatus -…`, sandbox copy denials, or any unexpected non-zero exit. Do not retry, do not substitute `curl` / `git push` for `gh pr create` / vice versa. The in-place section near the end repeats this reminder closer to its call sites.

## Purpose (fork mode)

Push verified fixes to the **fork** and create issues + PRs there. Do NOT create PRs or issues against the upstream target repo — all delivery stays in the private fork until the user explicitly decides to submit upstream.

> **Branch-name examples in fork-mode prose below use the illustrative form `vulnfix/VULN-NNN-...` for readability.** Production fork-mode branches actually follow the masked pattern `fix/code-quality-<descriptor>-<hash8>` per REQ-SEC-002/003 (see `plan_fork.md` Step 3 + `implement.md` fork-mode setup). Substitute the masked name when actually invoking `gh pr create` / `gh pr view`. In-place mode uses `vulnfix/<cluster-slug>` and the examples in the In-place delivery section near the end of this file are literal.

## Fork Setup

Before delivering, ensure the fork is properly configured:

**Step 0: Configure fork privacy and access.**

1. Set the fork to private:
```bash
gh repo edit <fork_org>/<fork_repo> --visibility private --accept-visibility-change-consequences
```

2. Enable issues on the fork:
```bash
gh repo edit <fork_org>/<fork_repo> --enable-issues
```

3. Add collaborators from `collaborators.json`:
```bash
# For each entry in collaborators.json:
gh api repos/<fork_org>/<fork_repo>/collaborators/<username> -X PUT -f permission=<role>
```

The collaborators file is at `${SKILL_DIR}/collaborators.json` and has this format:
```json
{
  "collaborators": [
    {"username": "USER_ID", "role": "admin|write|read"}
  ]
}
```

## Deduplication — Check Before Creating Anything

Before creating any issue or PR, search for existing artifacts to avoid duplicates. Two-tier lookup:

1. **By idempotency key (cross-report stable):** Each finding has a hash `SHA-256(location | primary_cwe | root_cause)[:16]` embedded in the body of any issue/PR as `<!-- vulnfix-key: <hash> -->`. Search bodies for this marker first — it correctly matches the same vulnerability across different VulnHunter reports even if the VULN ID changed. The pipe separators and `primary_cwe` (first `CWE-NNN` from a possibly-multi-CWE string) normalization are how `scripts/parse_results.compute_vulnfix_key` and `scripts/issue_intake.compute_vulnfix_key` stay in sync — see those two modules for the canonical implementation.
2. **By VULN ID (in-report stable, fallback):** Search titles for `VULN-NNN` substring.

```bash
# Search open AND closed issues/PRs for this VULN ID (fallback search)
gh issue list --repo <fork_org>/<fork_repo> --state all --search "VULN-NNN" --json number,title,state,url
gh pr list --repo <fork_org>/<fork_repo> --state all --search "VULN-NNN" --json number,title,state,url
```

| Result | Action |
|--------|--------|
| No match found | Create new artifact, embed `<!-- vulnfix-key: <hash> -->` in body |
| Match found, state=open | Update the body (preserving the key marker); skip creation |
| Match found, state=closed | **Reopen** it and update the body |

To reopen a closed issue:
```bash
gh issue reopen <number> --repo <fork_org>/<fork_repo>
gh issue edit <number> --repo <fork_org>/<fork_repo> --body-file <updated-body-file>
```

To reopen a closed PR:
```bash
gh pr reopen <number> --repo <fork_org>/<fork_repo>
```

## Re-run vs New-Report Detection

When the user runs the skill on the same VulnHunter report twice (e.g., to apply skill changes), old PRs whose findings are no longer in the report should be closed. When the user runs on a NEW report, those old PRs should be preserved (unless a duplicate by hash exists).

Detect via `<!-- vulnfix-report-id: <results-dir-name> -->` embedded in the most recent tracking issue body:
- Same `report-id` as current run → re-run → close orphan PRs (any open `vulnfix/*` PR whose hash/VULN ID is not in the current findings)
- Different `report-id` (or no prior tracking issue) → new-report run → preserve existing PRs; only update exact-match duplicates via the dedup logic above

Re-run detection keys on the `report-id` marker: on a same-report re-run the orchestrating session closes orphan `vulnfix/*` PRs; on a new report it preserves them.

## Delivery Triage — Choose Artifact Type Per Finding *(fork mode only)*

> **In-place mode has only TWO buckets: Ready PR and Draft PR.** There is no Issue-only bucket in in-place mode, period. Skip the entire triage table below — see the "In-place delivery" section near the end of this document for the two-bucket version, and `implement.md`'s "CANNOT_AUTO_FIX — Interactive collaboration loop" for how blockers that would otherwise trigger Issue-only are resolved with the developer instead. If you find yourself in in-place mode considering "Issue only" or "out-of-scope" or "deferred", you've taken a wrong turn — go back to the collaboration loop.

The three-bucket table below applies only when the skill is running in fork mode (no human at the console to resolve blockers). Each finding gets classified into exactly one of:

| Bucket | Criteria | Artifact |
|--------|----------|----------|
| **Ready PR** | Fully non-breaking. No caller changes, no new config, no allowlist edits, no new env vars, no infra setup. Security test and regression suite pass standalone. | PR **without** `--draft` |
| **Draft PR** | Non-breaking at the code level **but requires setup** before it can take effect: e.g., new env var/config key, allowlist entry, endpoint registration, feature flag, secret to provision, infra change. Setup steps are well-defined and small. | PR **with** `--draft`, plus a **Setup Required** section in the body listing every step an operator/reviewer must complete before merge |
| **Issue only** *(fork only)* | Either (a) design decisions still outstanding (algorithm choice, contract negotiation, multiple valid approaches), or (b) setup is non-trivial enough to need its own design conversation (cross-team coordination, schema migration, etc.). | GitHub issue only — no PR. Update the relevant spec (`docs/SPEC.md` in target repo, or this skill's `docs/SPEC.md` if upstream lacks one) with the open question, and outline a plan in the issue body |

How this maps to existing classifications *(again, fork only — in-place lacks both `CANNOT_AUTO_FIX` and `BREAKING_CHANGE` as terminal states; the collaboration loop resolves them)*:
- `VERIFIED` → Ready PR or Draft PR depending on whether setup is required.
- `NEEDS_MANUAL_REVIEW` → Draft PR (setup or review required) by definition.
- `CANNOT_AUTO_FIX` → Issue only (this is the design-unresolved / non-trivial-setup case).
- `FIX_NOT_NEEDED` → No artifact (branch deleted, see Step 5c).

If unsure between Draft PR and Issue only, prefer Issue only and surface the design question — a draft PR with unresolved design churns more than an issue does.

## Actions

### For each finding (verified, manual-review, and CANNOT_AUTO_FIX):

**Step 1: Create a GitHub issue for the finding.**

Every finding gets an issue — whether it has a PR or not. Create the issue first, before the PR.

```bash
gh issue create \
  --repo <fork_org>/<fork_repo> \
  --title "Security Finding: VULN-NNN — Short Title" \
  --body-file .work/delivery/issue-body-VULN_NNN.md \
  --label "security,vulnhunter-fix"
```

The issue body must be **self-explanatory as a standalone document** — a reader with no prior context must be able to understand:
- What the vulnerability is (CWE, severity, location, root cause)
- How it was proven (exploit description — not the exploit code itself, just what it does)
- What fix is proposed (strategy summary)
- Current status: `Automated fix in PR #N` / `Requires human action` / `Cannot auto-fix — see details`

For `CANNOT_AUTO_FIX` findings, the issue body additionally includes:
- Why automation cannot complete the fix
- What a human reviewer must do
- For cross-repo cases: what both services must change and in what order

Record the created issue number: `ISSUE_NUMBER=$(gh issue view --repo <fork_org>/<fork_repo> --json number -q .number)`

**Step 2: Create Pull Request (for VERIFIED and NEEDS_MANUAL_REVIEW findings only).**

> **First complete the Pre-delivery gates** (end of this file): honesty guards at render time, the completeness checklist, and `run-gates.py` reporting `pass: true` — before this `gh` call.

Apply the **Delivery Triage** above to choose Ready PR vs Draft PR. Issue-only cases skip this step entirely.

PRs target `main` within the fork repo itself (NOT the upstream). Use `--draft` only for the Draft PR bucket; omit it for Ready PRs:
```bash
# Ready PR (fully non-breaking, no setup required)
gh pr create \
  --repo <fork_org>/<fork_repo> \
  --head vulnfix/VULN-NNN-description \
  --base main \
  --title "fix(security): VULN-NNN — Short Title" \
  --body-file .work/delivery/pr-body-VULN_NNN.md

# Draft PR (non-breaking but requires setup — body MUST include Setup Required section)
gh pr create \
  --repo <fork_org>/<fork_repo> \
  --head vulnfix/VULN-NNN-description \
  --base main \
  --title "fix(security): VULN-NNN — Short Title" \
  --body-file .work/delivery/pr-body-VULN_NNN.md \
  --draft
```

The PR body must include (from `templates/pr_body.md`):
- `Closes #<ISSUE_NUMBER>` on the first line
- Finding summary table (CWE, severity, location, root cause)
- Exploit description (what the exploit does and what it proves — **not** the exploit code itself)
- Security test code (the actual test from Step C)
- What the fix does and why
- Verification results (RED → GREEN)
- **For Draft PRs only:** a `Setup Required` section listing every operator/reviewer step needed before merge (env vars, config keys, allowlist edits, endpoint registration, etc.) with concrete commands or values where possible

The PR body must be **complete and self-explanatory** — see Description Completeness Checklist below.

**Step 3: Link PR back to issue.**

After the PR is created, post a comment on the issue linking to the PR:
```bash
PR_URL=$(gh pr view --repo <fork_org>/<fork_repo> vulnfix/VULN-NNN-description --json url -q .url)
gh issue comment <ISSUE_NUMBER> \
  --repo <fork_org>/<fork_repo> \
  --body "Automated fix submitted: ${PR_URL}"
```

**Step 4: Create finalization issues for breaking changes.**

For each PR that contains a backward-compatible breaking change fix, create a linked "Pending Finalization" issue:
```bash
gh issue create \
  --repo <fork_org>/<fork_repo> \
  --title "Pending Finalization: VULN-NNN — Remove legacy fallback" \
  --body-file .work/delivery/finalize-body.md \
  --label "pending-finalization"
```

The finalization issue body must include:
- Which PR introduced the backward-compatible fix
- The exact condition that must be met before finalization (e.g., "orchestrator forwards x-trusted-user-id header on POST /passkey/register")
- What code to remove (the legacy fallback path, the deprecation log, the TODO)
- What the final secure interface looks like
- Any registration actions needed (e.g., Exchange major version bump)

**Step 5: Create tracking issue in the fork.**

After all per-finding issues and PRs are created, create a single tracking issue that links everything:
```bash
gh issue create \
  --repo <fork_org>/<fork_repo> \
  --title "Security Remediation: VulnHunter Findings (N vulnerabilities, M PRs)" \
  --body-file .work/delivery/issue-body.md
```

The tracking issue body must include:
- PR table with finding IDs, severity, issue link, PR link (or "issue only" for CANNOT_AUTO_FIX), status
- **Needs Human Review** section (if any findings have `needs-human-review`): list each with attempt summary, failure reason, and suggested next steps
- **Cannot Auto-Fix** section (if any findings are CANNOT_AUTO_FIX): list each with reason and what human action is needed
- **Already Fixed Upstream** section (if any findings were marked `FIX_NOT_NEEDED`): list with evidence of upstream fix
- Recommended merge order (for ready PRs only)
- CWE coverage list

**Step 5b: Label and comment on human-review PRs.**

For each finding in `.work/delivery/pending-human-reviews.json`:

```bash
gh pr edit <pr_number> \
  --repo <fork_org>/<fork_repo> \
  --add-label "needs-human-review"
```

After the tracking issue is created, add a detailed comment per finding:

```bash
gh issue comment <issue_number> \
  --repo <fork_org>/<fork_repo> \
  --body-file .work/delivery/human-review-VULN-NNN.md
```

**Step 5c: Delete branches for FIX_NOT_NEEDED findings.**

```bash
git push origin --delete vulnfix/VULN-NNN-short-description 2>/dev/null || true
```

Add an informational comment to the tracking issue:

```bash
gh issue comment <issue_number> \
  --repo <fork_org>/<fork_repo> \
  --body "ℹ️ **VULN-NNN**: Fix not needed — vulnerability already remediated upstream. Branch deleted."
```

**Step 6: Report.**

After all findings are delivered, present summary:

| VULN ID | Severity | Issue | Delivery | URL |
|---------|----------|-------|----------|-----|
| VULN-001 | Critical | #1 | PR (ready) ✓ | https://github.com/fork-org/fork-repo/pull/2 |
| VULN-002 | High | #3 | PR (draft — setup required) ⚠️ needs-human-review | https://github.com/fork-org/fork-repo/pull/4 |
| VULN-003 | Medium | #5 | Issue only (design unresolved) | https://github.com/fork-org/fork-repo/issues/5 |
| VULN-004 | Low | — | ⊘ Not needed (upstream fixed) | — |

Include the tracking issue URL and remind the user:
> All PRs and issues are in your private fork. When ready to submit to the target team, re-create PRs against `<target_org>/<target_repo>`.

## Description Completeness Checklist

Before finalizing any PR or issue, verify every item below is present and complete. An incomplete description must be finished before publishing — do not leave placeholder text:

**For PRs:**
- [ ] `Closes #N` reference at the top
- [ ] Finding summary: CWE, severity, file location, root cause (1–2 sentences each)
- [ ] Exploit description: what the attacker can do and what it proves (no code required, but must be concrete)
- [ ] Security test: full code block, explains what it asserts and why
- [ ] Fix description: what changed and why it closes the vulnerability
- [ ] Verification: confirmation that test was RED before fix, GREEN after; no regressions
- [ ] Triage bucket reflected correctly: Ready PR has no `--draft`, Draft PR has `--draft` AND a Setup Required section listing every step
- [ ] Breaking change section (if applicable): interface change, what callers must do, known callers

**For per-finding issues:**
- [ ] Finding summary: CWE, severity, file location, root cause
- [ ] Status: is a PR pending, is human action required, or is automation blocked?
- [ ] For CANNOT_AUTO_FIX: exact blocker, what human must do, cross-repo dependencies if any
- [ ] For Issue-only-due-to-design: Open Design Questions section + Plan to Resolve section + reference to spec file the questions were added to

## Important: Do NOT deliver to upstream

- Never create PRs against the target (upstream) repo
- Never create issues in the target repo
- All delivery artifacts stay in the fork
- The user decides when/if to alert the target team

## Cleanup

After successful delivery (all issues created, all branches pushed, PRs created, tracking issue created):

1. Delete the work directory:
```bash
rm -rf ./work
```

This is safe because all code is on the remote fork. The local clone is just a cache.

By default the work dir is deleted after a successful fork-mode delivery; if you want it kept for diagnosis, set the env var `VULNFIX_KEEP_WORKDIR=1` before invoking the skill.

---

## In-place delivery

Use this section instead of the fork-mode steps above when the skill is running in **in-place mode** (see `SKILL.md`). Triage, PR-body conventions, and dedup logic from earlier in this document still apply; this section covers only what differs.

> **Read the "`git` + `gh` failure policy" section of `SKILL.md` before continuing.** Every `gh` and `git` call below — push, dedup search, PR create, issue comment — must follow the same rule: if you see `tls: failed to verify certificate`, `OSStatus -…`, `SSL certificate problem`, a sandbox copy denial in `git push`/`git clone`, or any non-zero exit you didn't explicitly expect, STOP and ask the user to run the single failing command in their own terminal. Wait for their paste, then continue. Do not retry, do not substitute `curl` / `git push` for `gh pr create` / vice versa, do not batch.

### Where artifacts go

- **One PR per cluster** (the unit the developer picked in Phase 1) — not one PR per finding. The cluster's branch carries N commits, one per finding, each with its own RED→GREEN evidence. The PR closes every source issue in the cluster via `Closes #N1, #N2, ...`.
- PRs are opened on `origin` (the user's checkout) against the repo's default branch.
- The source `vulnhunter`-labeled issues on `origin` are the per-finding tracking issues. The PR's `Closes #N1, #N2, …` keywords link them, and **GitHub auto-closes them when the PR merges** — the skill never calls `gh issue close` itself (closing before merge would trigger verify against unmerged code; see Step 6). Do not create parallel issues.
- No separate run-level tracking issue is created — `.vulnhunter-fix/work.json` already groups the run.
- Fork org, collaborators, fork-privacy configuration: not used.

### Per-cluster flow

For each cluster the developer selected in Phase 1, after Phase 4 verified its branch GREEN end-to-end:

**Step 1: Push the cluster's branch.**

The worktree was created by `scripts/setup_worktree.sh` under `.vulnhunter-fix/worktrees/<CLUSTER_KEY>/` on branch `vulnfix/<cluster-slug>`. Push it to `origin`:

```bash
git -C "$WT_PATH" push -u origin "$BRANCH" 2>&1
```

If push fails with permission denied: fall back to pushing to the user's personal fork and opening a cross-fork PR — same fallback `scripts/check_repo_access.sh` already handles for fork mode.

**Step 2: Apply triage (Ready PR / Draft PR).**

A cluster's PR is Draft only if **any** of its member findings required operator setup (new env var, allowlist entry, etc.). Otherwise it's Ready. (Issue-only doesn't exist in in-place mode — see Step 6 below.)

**Step 3: Dedup check.**

For each finding in the cluster, search open PRs on `origin` for an existing PR carrying that finding's `vulnfix-key` marker:

```bash
for VULNFIX_KEY in $(jq -r '.items[].finding.vulnfix_key' .vulnhunter-fix/work.json); do
    gh pr list --repo "$OWNER_REPO" --state all --search "$VULNFIX_KEY in:body" \
        --json number,title,state,url
done
```

- If ALL members' keys appear in one existing PR: update that PR's body instead of creating a new one.
- If SOME members are in an existing PR: warn the user — a previous run may have split the cluster differently. Ask whether to (a) close the prior PR and reopen as a unified one, or (b) keep them split.
- If state=closed for the prior PR(s), reopen + update.

**Step 4: Create the cluster PR.**

> **First complete the Pre-delivery gates** (end of this file): honesty guards at render time, the completeness checklist, and `run-gates.py` reporting `pass: true` — before this `gh` call.

```bash
# Re-derive DEFAULT_BRANCH from intake.json — this is a fresh shell
# from Phase 1's perspective; bash variables don't survive across
# phases. OWNER_REPO is set by SKILL.md's mode dispatch at the top
# of the run and is expected to be in env.
DEFAULT_BRANCH="$(jq -r .default_branch .vulnhunter-fix/intake.json)"

# Pre-flight validate the PR body — count `Closes #N` references
# against the cluster's member list. GitHub's auto-close keywords
# only fire on merge if every source issue is referenced; a missed
# one stays open forever. Better to fail here than to discover it
# post-merge.
EXPECTED_CLOSES="$(jq -r '[.items[].issue.number] | join(",")' .vulnhunter-fix/work.json)"
python3 "${SKILL_DIR}/scripts/validate_pr_body.py" \
    ".vulnhunter-fix/delivery/pr-body-${CLUSTER_KEY}.md" \
    --expected-issues "$EXPECTED_CLOSES"

gh pr create \
    --repo "$OWNER_REPO" \
    --head "$BRANCH" \
    --base "$DEFAULT_BRANCH" \
    --title "fix(security): <cluster name> — <N> findings" \
    --body-file ".vulnhunter-fix/delivery/pr-body-${CLUSTER_KEY}.md" \
    $DRAFT_FLAG
```

**Use `templates/pr_body_cluster.md` as the body template** (not the single-finding `pr_body.md` — that one is fork-mode only).

**Branch on `work.json.no_source_issues`.** In-place mode has two variants:

- **Standard (`no_source_issues != true`)** — findings came from `vulnhunter`-labeled GitHub issues. Use `Closes #N1, #N2, ...` (GitHub auto-close). Follow the "Standard" rules below.
- **Local-report (`no_source_issues == true`)** — findings came from a `RESULTS_PATH` supplied via `parse_issues.md` § Step 0; no source issues exist on `origin`. Use `Addresses VULN-N per <results_path>` (no auto-close keyword). Skip Step 5 (source-issue commenting). Follow the "Local-report" adaptation below.

Read the flag once at the top of Step 4:

```bash
NO_SOURCE_ISSUES=$(jq -r '.no_source_issues // false' .vulnhunter-fix/work.json)
RESULTS_PATH_FOR_BODY=$(jq -r '.results_path // ""' .vulnhunter-fix/work.json)
```

Required content:

1. **First line of the body** — pick one shape:
   - Standard: **`Closes #<n1>, #<n2>, #<n3>, …`**, one entry per source issue in the cluster, comma-separated. GitHub's auto-close keywords (`Closes` / `Fixes` / `Resolves`) only fire when listed inline like this — bullet lists do not auto-close. This is how every source `vulnhunter` issue auto-closes when the PR merges.
   - Local-report: **`Addresses VULN-<n1>, VULN-<n2>, VULN-<n3>, … per `<results_path>` (no source issues published on origin at scan time).`** The word `Addresses` is intentionally NOT a GitHub keyword — nothing auto-closes on merge because there is nothing to close.
2. A per-finding subsection for each member, rendered as **H4 (`####`) headings** so they nest under the cluster-level `## Fix Description` H2 without terminating it (Gate 2's section scan ends a section at the next `##`/`###`, not `####`). In standard mode each heading carries an inline `Closes #<N>` (e.g., `#### VULN-005 — Header-trust fail-open (Closes #5)`); in local-report mode drop the `(Closes #N)` suffix entirely — the VULN id in the heading is the only reference needed.
3. All three machine markers (`vulnfix-key`, `vulnhunt-finding-id`, `vulnhunt-results-dir`) per finding, in HTML comments so verify can correlate. One marker block per finding subsection.
4. Cluster summary: name, rationale (from `clusters.json`), member table (VULN | CWE | Severity | File | Source issue in standard mode / `—` in local-report mode) — this fills the `## Finding Summary` cluster H2.
5. Per-finding subsection — for each, the standard Description Completeness fields: exploit description, security test code, fix description, RED→GREEN verification result. These H4 blocks live under the `## Fix Description` H2.
5b. **Cluster-level H2 sections (required for Gate 2 — `templates/pr_body_cluster.md` carries them):** `## Finding Summary`, `## Attacker Capability`, `## Security Test`, `## Fix Description` (wraps the per-finding H4 blocks), `## Verification Results`, `## Verification Table`, `## Residual Risk`, `## Sweep Summary`, `## Breaking Change`. Fill the cluster placeholders: `{VERIFICATION_TABLE}` (aggregate 9-column table, one row per finding); `{CLUSTER_RESIDUAL_RISK}` (union of per-finding residuals, or "None — all findings verified FULL" when every member is FULL); `{CLUSTER_SWEEP_ROWS}` (one sweep row per finding, or a single `| — | none ran | — | — | — | — | — |` row when sweep did not run); `{CLUSTER_BREAKING_CHANGE}` ("None — no breaking changes in this cluster." when no member is BREAKING_CHANGE, else the per-member breaking-change detail with a **bare** `## Breaking Change` heading — never the em-dash form). None of these sections may be left empty or carry a `TBD`/`TODO` token — Gate 2 rejects both.
6. If any finding is Draft-bucket, a top-level Setup Required section listing every setup step the developer specified during the collaboration loop. Tag each step with the VULN it belongs to.

**Validation before submit** (standard mode): count the `Closes #` references and confirm it equals the cluster member count. If they don't match, one or more source issues won't auto-close on merge — fix the body before invoking `gh pr create`.

**Validation before submit** (local-report mode): count the `VULN-` references on the first line and confirm it equals the cluster member count. Also confirm `Closes #` is ABSENT — an accidental `Closes` in local-report mode would try to auto-close issue numbers that either don't exist or belong to unrelated issues.

**Step 5: Comment on each source issue (do not close).** — *Standard mode only; skip entirely when `NO_SOURCE_ISSUES == true`.*

For each finding in the cluster, post the link to the unified PR on the source issue. **Do NOT close the issue here** — see Step 6.

```bash
if [[ "$NO_SOURCE_ISSUES" != "true" ]]; then
  for ITEM in $(jq -c '.items[]' .vulnhunter-fix/work.json); do
      ISSUE_NUMBER=$(echo "$ITEM" | jq -r '.issue.number')
      gh issue comment "$ISSUE_NUMBER" \
          --repo "$OWNER_REPO" \
          --body "Bundled into cluster PR: $PR_URL (alongside other findings in the same topic). The PR's \`Closes #${ISSUE_NUMBER}\` keyword will auto-close this issue when the PR merges."
  done
fi
```

**Step 6: Do NOT close source issues at delivery time.**

The PR body emitted in Step 4 contains `Closes #N1, #N2, #N3, …` for every source issue in the cluster. GitHub auto-closes those issues **when the PR merges** — that's the only legitimate closure event for source `vulnhunter` issues.

**Why not close now**: closing a `vulnhunter` issue is the signal `--mode=verify` keys on. Verify clones the target repo at HEAD of the default branch and re-runs the security tests. If we close the issue at PR-creation time (before merge), verify runs against unmerged `main` — the vuln is still present, verify correctly rejects the fix, and reopens the issue. We then look like we shipped a broken fix when in fact the merge just hadn't happened yet.

The `close_issue_on_deliver` config flag is **deprecated for in-place mode** for this exact reason and is ignored regardless of its value. If a user really wants the issue closed immediately (e.g., they're shipping the PR as a draft and want it off the open-issues list for project-tracking reasons), they can close it manually — but the skill won't do it for them. The merge → auto-close path is the only one that's safe with verify.

**Task tracking note**: the Phase 5 task subject should read `Deliver cluster <name>: push, PR, comment source issues` — never "close N issues" — and the task flips to `completed` after `gh pr create` returns a URL AND every source issue has been commented. Closure is a future event the skill does not own.

**Step 7: In-place has no Issue-only bucket.** Canonical statement in § Delivery Triage above. By the time delivery runs, every cluster the developer selected in Phase 1 either:

- shipped as a Ready PR / Draft PR (the GREEN paths above), or
- was abandoned by the developer mid-run (terminal closed, "/stop", off-band work blocking) — in which case the partial worktree is left in place, the source `vulnhunter`-labeled issues stay open as-is, and the next `/vulnhunter-fix` run resumes from where this one stopped.

Do not synthesize a "needs-human-review" comment or label on source issues when the developer walks away. They know they didn't finish; the open GitHub issues and the partial worktree on disk are sufficient state — synthesized comments create the false impression that automation gave up rather than the human pausing.

The `needs-human-review` labeling pattern still applies in **fork mode** (async path). In-place mode uses neither the label nor the comment.

### Final report

After all items in `work.json` have been processed, present a summary table similar to fork mode. Columns:

| VULN ID | CWE | Severity | Issue | Delivery | URL |

Then remind the user: PRs are on their own repo's default branch; reviewers see them like any other PR.

### Cleanup

`.vulnhunter-fix/` stays in place after delivery — the user owns it under their repo root and `.git/info/exclude` keeps it out of commits. They can `rm -rf .vulnhunter-fix/` manually when satisfied. The skill does NOT delete it automatically in in-place mode, because if delivery partially failed (e.g., one PR didn't push) the user needs the work tree to diagnose.



## Pre-delivery gates (both modes — mandatory before any `gh` call)

Run before any `gh pr create` / `gh issue create`, in both fork and in-place mode. These are hard gates on delivery, not optional add-ons. Honesty-guard exceptions + the Description Completeness Checklist are detailed in `references/remediation-rigor.md § Phase 5 (Deliver) rigor`.

**1. Honesty guards before rendering (REQ-HON-005..009).** Import from `vulnhunter_fix.delivery`:

```python
from vulnhunter_fix.delivery import (
    render_residual_risk_section,
    render_pr_body_with_residuals,
    pr_draft_state_for_tier,
    HandWaveResidualError,
    EmptyResidualError,
    FullTierWithResidualsError,
)
```

Renderer refuses to ship on: empty `residual_vectors` when tier != FULL (REQ-HON-007); non-empty `residual_vectors` when tier == FULL; any residual matching the hand-wave regex (REQ-HON-006). WORKAROUND fixes open as **Draft**; FULL and MITIGATION open **Ready** (`pr_draft_state_for_tier`, REQ-HON-008).

**2. Description Completeness Checklist (REQ-GAT-003)** — required level-2 headings per artifact: `## Finding Summary`, `## Attacker Capability`, `## Security Test`, `## Fix Description`, `## Verification Results`. PRs also require `## Verification Table`; non-FULL tiers require `## Residual Risk`; `BREAKING_CHANGE` requires `## Breaking Change` (**heading MUST be bare on its own line — put "Caller Action Required" or any descriptive phrase in the first body paragraph, not after the heading text**, because Gate 2's anchored regex `^## Breaking Change\s*(?:$|:)` rejects em-dash / word suffixes on the heading line); if Sweep ran, `## Sweep Summary` is required. Enforced mechanically by `scripts/check-body-completeness.py` (Gate 2).

**3. Full delivery gate suite** — before invoking `gh`, run `python3 scripts/run-gates.py ...` (invocation in `prompts/verify.md` Step 8 — Mechanical delivery gates). All seven gates must report `pass: true`.

**Phase-exit criteria — do not call `gh pr create` / `gh issue create` until ALL hold:**
- [ ] honesty guards ran at PR-body render time (no hand-wave / empty-residual / FULL-with-residuals)
- [ ] every required `##` section present per the completeness checklist
- [ ] `run-gates.py` reported `pass: true` (all seven gates)

