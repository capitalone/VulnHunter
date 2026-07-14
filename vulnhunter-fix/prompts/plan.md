# Phase 2: Remediation Plan

## Mode-aware

This phase plans the implementation of the findings the developer selected in Phase 1. The grouping rules differ by mode:

- **In-place mode**: clusters are already the delivery unit. Each cluster the developer picked = one branch = one PR. Findings within a cluster are sequenced for sane diff order; they are NOT split into separate branches/PRs. Skip the strict "same root cause / same file" grouping rules below; they don't apply.
- **Fork mode**: no clusters exist. Apply the strict grouping rules in Steps 3-4 — one PR per finding unless the rules explicitly permit combining.

If you're not sure which mode is running, check `SKILL.md` mode dispatch — `OWNER_REPO` + presence of `.vulnhunter-fix/work.json` means in-place; explicit `TARGET_REPO`/`RESULTS_PATH` args mean fork.

## Inputs

- **In-place**: `.vulnhunter-fix/work.json` (finding↔issue join, includes cluster membership via the user's Phase 1 selection)
- **Fork**: parsed findings manifest from Phase 1 (`findings.json`) + Target repo URL

## Actions

### In-place mode

> **Plan-phase enforcement (in-place):** never carve findings out as "scaffolding only", "lands here / full fix in a follow-up", "out-of-scope", "deferred", or "Issue only" in the plan. In-place mode has only two delivery buckets (Ready PR and Draft PR) — the general invariant lives in `deliver.md § Delivery Triage`. Every finding the developer picked in Phase 1 will be driven to a real fix by Phase 3's interactive collaboration loop. If you're tempted to write a follow-up category, you're applying fork-mode triage to interactive mode — re-read `implement.md`'s "CANNOT_AUTO_FIX — Interactive collaboration loop".

**Step IP-1: Read the work list.** `.vulnhunter-fix/work.json` has the selected items already. The cluster the developer picked is implicit: every item in `work.json` is in scope, and they all belong to the cluster(s) selected in Phase 1 Step 3.

**Step IP-2: Live code pre-check (per finding).** For each item, verify the vulnerable pattern still exists in CWD's current code (you're in the target repo's working tree — no clone needed):

```bash
grep -n "<vulnerable_pattern>" <target_file>   # from finding.location
```

If the file is missing or substantially rewritten, mark the item `ALREADY_FIXED` and drop it from the cluster. (`ALREADY_FIXED` is fine — it's a factual statement that the code no longer has the bug. It is NOT the same as "out-of-scope" or "Issue-only".) If the cluster ends up empty after pre-check, tell the developer and skip to Phase 5 with nothing to deliver.

**Step IP-3: Sequence findings within the cluster.** Order findings so the implementation produces a clean diff:

1. Findings touching the same file go consecutively (their commits diff cleanly).
2. Findings whose fix touches a shared helper go FIRST so later findings can call the helper.
3. Within a file, fix lower line numbers first (so subsequent edits aren't perturbed by line-shift).

The sequence becomes the order Phase 3 commits them on the cluster's branch. **All findings in the cluster land on ONE branch** — `vulnfix/<cluster-slug>`. Do not propose splitting a cluster into multiple branches; that contradicts the contract Phase 1 sold the developer.

**Step IP-4: Assess fix approach per finding.** For each finding determine:

- Language/framework of the target file.
- Test framework + location (most projects: `tests/`, `src/test/java/`, `spec/`, `__tests__/`).
- Concrete assertion that defines "secure behavior."
- Whether the fix is auto-patchable (no external secrets, no cross-repo coordination required to be effective, no post-merge manual steps).

For any finding that's NOT auto-patchable: do NOT split it out. Phase 3's interactive collaboration loop (in `implement.md`) drives the developer through it on the same branch. The cluster's branch absorbs the work.

**Step IP-5: Present the cluster plan.** Show the developer:

| Order | VULN | CWE | Severity | File | Strategy |
|-------|------|-----|----------|------|----------|

…followed by per-finding notes (test assertion + fix approach + any flags). Then proceed to Phase 3 (no confirmation gate; the developer already picked the cluster in Phase 1).

### Fork mode (strict per-finding grouping)

Fork mode uses strict grouping rules (never group different root causes even in the same file), the masked `fix/code-quality-<descriptor>-<hash>` branch pattern, and no interactive collaboration loop. Full Phase 2 fork flow — prioritize → pre-check → group → conflict-detect → assess → present — lives in `prompts/plan_fork.md`.

Read `plan_fork.md` when mode dispatch resolves to `mode=fork`; the in-place flow above does not apply.

### Rigor actions (both modes — mandatory)

These run in every plan — in-place and fork — and are the exit criteria of this phase, not optional add-ons. Do not proceed to Phase 3 until each has run and its artifact validates. Error semantics and rationale for each script live in `references/remediation-rigor.md § Phase 2 (Plan) rigor`.

1. **Build the graph substrate once per target repo (REQ-GRA-002/015):**

   ```bash
   # In-place: work-dir is <repo>/.vulnhunter-fix/
   # Fork:     work-dir is .work/<repo-name>/
   python3 ${SKILL_DIR:-.}/scripts/build_graph.py \
       --repo-root <target-repo-root> \
       --work-dir <work-dir> \
       --findings <findings.json-from-parse-phase>
   ```

2. **For crypto findings, enrich the sidecar with `crypto_trust_chain` (REQ-CWE-005/007):**

   ```bash
   python3 ${SKILL_DIR:-.}/scripts/crypto-trust-chain-checkers.py \
       --diff <planned-fix-diff> --emit-sidecar VULN-N \
       | jq '.crypto_trust_chain' \
       > /tmp/vulnfix_crypto_$$.json
   ```

3. **Validate each triage sidecar before dispatching its worker (REQ-SCH-006).** The sidecar must match `references/triage-schema.json` (including `crypto_trust_chain` for crypto findings) — a malformed sidecar would silently break the graph-citation and column-7 caller-coverage checks downstream:

   ```bash
   python3 ${SKILL_DIR:-.}/scripts/validate-triage.py \
       <work-dir>/graph_context/VULN-N.json
   ```

   Failures route to the schema-repair loop (REQ-SCH-004).

4. **Pre-classify completeness tier before any code is written (REQ-HON-002):**

   ```bash
   python3 scripts/compute-completeness-tier.py \
       --diff <planned-diff-or-strategy-text> \
       --plan <fix_plan.json> \
       --phase plan
   ```

   Output actions (FULL/MITIGATION/WORKAROUND → record; LLM_REVIEW → invoke `prompts/tier_judgment.md`) are documented in the reference. Every fix plan MUST emit `callers_routed_coverage` on `fix_plan.json` (SCH-2 / REQ-GRA-019) — enum `superset` / `subset` / `unknown`; only `superset` permits FULL projection.

5. **Detect target language for repo-type adapter selection:**

   ```bash
   python3 scripts/language-detect.py <target-repo-root>
   ```

   Route findings to the matching CWE-class worker prompt per `references/cwe-fix-patterns.md`. All CWE-class workers extend `prompts/worker_agent_common.md`.

6. **Anti-merge check (REQ-GAT-006)** — split the group into individual PRs before Phase 3 if `allowed: false`:

   ```bash
   python3 scripts/anti-merge-check.py \
       --files-grouped <count> --files-split <count> \
       [--test-files-grouped <count>] [--test-files-split <count>]
   ```

7. **Phase-transition validator (REQ-SCH-003):** each `fix_plan.json` must pass `python3 scripts/validate-fix-plan.py <path>`. Failures route to the schema-repair loop (REQ-SCH-004).

**Phase-exit criteria — do not proceed to Phase 3 until ALL hold:**
- [ ] graph substrate built for the target repo (step 1)
- [ ] every crypto finding's sidecar carries `crypto_trust_chain` (step 2)
- [ ] every triage sidecar passed `validate-triage.py` (step 3)
- [ ] every finding has a pre-classified tier + `callers_routed_coverage` on its `fix_plan.json` (step 4)
- [ ] anti-merge check run for any grouped PR (step 6)
- [ ] every `fix_plan.json` passed `validate-fix-plan.py` (step 7)

## Stopping Rules

- If a finding's proposed fix references a library/pattern not present in the target repo, flag it
- If two findings have contradictory fixes (e.g., one says "add sanitization" and another says "remove the endpoint"), flag for user decision
- Fork mode: do NOT proceed to Phase 3 without explicit user confirmation. In-place mode: proceed automatically; the developer already chose the cluster in Phase 1.
