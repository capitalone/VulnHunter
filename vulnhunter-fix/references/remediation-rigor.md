# Remediation-rigor cross-phase reference

**Companion to** the `## Remediation-rigor additions` stubs in `prompts/plan.md`, `prompts/implement.md`, `prompts/verify.md`, and `prompts/deliver.md`. Each stub lists the scripts the phase invokes; the details, error semantics, and rationale live here.

**Referenced by:** REQ-HON-002..009, REQ-GRA-002/011/015/017/018, REQ-CWE-003/005/007/008, REQ-SCH-003, REQ-SWP-001..009, REQ-GAT-001..013, SCH-2.

---

## Phase 2 (Plan) rigor

Convention: `<work-dir>` = `.vulnhunter-fix/` in in-place mode, `.work/<repo>/` in fork mode.

### `scripts/build_graph.py` — graph substrate (REQ-GRA-002/015)

Runs once per target repo; content-hash-cached (re-run is a no-op if source hasn't changed). Produces `<work-dir>/cache/graph.json` and one triage sidecar per finding at `<work-dir>/graph_context/<VULN>.json`. Every downstream phase reads these; the worker never invokes graphify directly.

The script emits JSON with `backend` (ast|grep|none) and per-sidecar counts. If `backend == "grep"` and any finding is in a CWE-class routed to the graph-heavy workers (authz, injection, crypto), warn the operator — column 7 of the verification table will be tagged `(grep_fallback)` and gates will require the annotation to be present in the PR body (REQ-GAT-011).

### `scripts/crypto-trust-chain-checkers.py` — crypto sidecar enrichment (REQ-CWE-008/009)

For crypto-CWE findings, enriches the triage sidecar with a `crypto_trust_chain` object (four booleans: `algorithm_approved`, `key_source_approved`, `key_rotation_present`, `transport_encrypted`). Downstream, the worker is forbidden from projecting `FULL` unless all four are `true` (REQ-CWE-007).

### `scripts/compute-completeness-tier.py` — deterministic classifier (REQ-HON-002..004)

Emits `FULL` / `MITIGATION` / `WORKAROUND` / `LLM_REVIEW` per finding. Signal catalogue in `references/fix-completeness-rubric.md`. Conservative-first walk: never silently promotes to FULL.

| Output | Action |
|---|---|
| `FULL` / `MITIGATION` / `WORKAROUND` | Record as `plan.projected_completeness_tier`. Continue. |
| `LLM_REVIEW` | Invoke `prompts/tier_judgment.md` (temperature=0, max 2 attempts per REQ-HON-014/015). Record LLM's `final_tier` + `rationale` under `plan.tier_judgment`. Two malformed outputs → `NEEDS_MANUAL_REVIEW` per REQ-HON-015. |

### `callers_routed_coverage` (SCH-2 / REQ-GRA-019)

Every fix plan emits this field on `fix_plan.json`. Read by `compute-completeness-tier.py` to gate `full.callers_routed_through_fix`.

| Value | Meaning | When to use |
|---|---|---|
| `"superset"` | Plan touches every caller in `triage.callers_of_sink`. | Required for FULL tier. |
| `"subset"` | Plan misses at least one caller. | Automatic cap at MITIGATION or below. |
| `"unknown"` | Graph backend was `grep`, or sink symbol didn't resolve. | Any confidence-low finding. |

The classifier reads `discrimination_evidence` from the worker result (verify phase). Plan phase does not carry that field; the plan therefore tops out at `LLM_REVIEW` on the deterministic walk and must escalate to `tier_judgment.md` for FULL projection.

### `scripts/language-detect.py` + `references/repo-type-adapters.md` (REQ-CWE-005)

Detects the target's primary language. Result selects the matching adapter section from `references/repo-type-adapters.md` for the worker's manifest.

### `scripts/anti-merge-check.py --strict` (REQ-GAT-006)

`--strict` exits non-zero when `allowed: false`. Wired into `scripts/run-gates.py` as Gate 5. If `false` at plan time, split the group into individual PRs before Phase 3.

### `scripts/validate-fix-plan.py` (REQ-SCH-003)

Phase-transition validator on the way out of Plan. Schema: `references/fix_plan-schema.json`. Failures route to the schema-repair loop (REQ-SCH-004).

---

## Phase 3 (Implement) rigor

### Step E.5 — discrimination evidence (REQ-GRA-017)

After the fix + security test pass, record how the test discriminates between pre-fix and post-fix code. Required for FULL tier.

Methods:
- **`stash-and-run`** (preferred): `git stash` → run test (expect FAIL) → `git stash pop` → run test (expect PASS). Record both outputs verbatim.
- **`trace`**: describe the code paths hit pre-fix vs. post-fix. Use when stash-and-run is impractical.

Emit to `.work/<repo>/discrimination/<vuln>.json`:

```json
{
  "vuln_id": "VULN-NNN",
  "method": "stash-and-run",
  "pre_fix_result": "fail",
  "post_fix_result": "pass",
  "assertion_target": "tests/test_authenticate_rejects_forged_token.py:15: assert authenticate(...) is False"
}
```

If `pre_fix_result != "fail"` or `post_fix_result != "pass"`, the test is non-discriminating (rubric R4 violation) — return to Step C.

### Step G.5 — pre-existing test updates (REQ-GRA-018)

Before committing, run the pre-existing test suite. If any test fails BECAUSE it encoded the vulnerable behavior:
1. Modify the assertion to expect the secure outcome.
2. Comment above: `# Updated for VULN-NNN: was asserting vulnerable behavior.`
3. Record the change in `.work/<repo>/preexisting_test_updates/<vuln>.json`.

If regressions appear that did NOT encode the vulnerable behavior, the fix is over-scoped — return to Step D and rework.

### CWE-class routing (REQ-CWE-003)

The plan orchestrator injects the matching worker-class prompt into the worker's context: `worker_agent_authz.md` / `worker_agent_injection.md` / `worker_agent_crypto.md` / `worker_agent_resource.md` / `worker_agent_config.md`. All extend `worker_agent_common.md`.

### Crypto trust-chain gate for FULL (REQ-CWE-007)

Under `worker_agent_crypto.md`, `completeness_tier: FULL` requires all four booleans in `plan.crypto_trust_chain` to be `true`. Any `false` forces `MITIGATION` with a `trust-chain:` residual entry per `references/residual-risk-rules.md` Rule R-5.

---

## Phase 4 (Verify) rigor

### Post-fix completeness re-classification (REQ-HON-003)

Re-run the classifier against the applied diff; compare to the plan-phase projection.

| Classifier output | Action |
|---|---|
| Same tier as projection | Record `result.completeness_tier` + `residual_vectors`. Proceed. |
| Different terminal tier | Trigger repair loop; fix brief cites tier mismatch. |
| `LLM_REVIEW` | Invoke `prompts/tier_judgment.md` (temp=0, max 2 attempts). |

`LLM_REVIEW` is never terminal (REQ-HON-013). Two malformed LLM outputs → `NEEDS_MANUAL_REVIEW`.

Crypto findings: any `false` in `crypto_trust_chain` forces `MITIGATION` (REQ-CWE-007) with a `trust-chain:` residual.

### Root-cause Sweep (REQ-SWP-001..009)

`scripts/sweep-root-causes.py` runs between validation and delivery for every VERIFIED finding. Sibling defects on files already in `result.files_modified` get amended into the PR (Path A). Others become `vulnfix-sweep-detected` follow-up issues (Path B). Sweep siblings on a previously-FULL fix downgrade to `VERIFIED_MITIGATION` with `sweep_revised: true` (REQ-SWP-006).

### 9-column verification table (REQ-GRA-011)

Assembled via `vulnhunter_fix.delivery.render_verification_table`. Every `yes` cell carries a `file:line` citation; `scripts/validate-verification.py` refuses uncited cells (REQ-GRA-012). Column 7 enumerates `graph.callers_of(sink_symbol)` per REQ-GRA-013 truncation policy; low-confidence cells carry `(grep_fallback)` annotation (REQ-GRA-020).

### Mechanical delivery gates (REQ-GAT-001..013)

`scripts/run-gates.py` runs all 7 gates (severity mask, body completeness, scope, idempotency, anti-merge `--strict`, verification-table, committed-test-naming) before any `gh` call. Any failing gate halts delivery. Before every repair-loop retry, `scripts/worktree-reset.py` hard-resets the worker worktree (REQ-GAT-009).

### Phase-transition validators (REQ-SCH-003)

On the way out of Verify, each `group-NNN_result.json` must pass `scripts/validate-result.py`. At delivery, additionally `scripts/validate-verification.py <pr-body>`. Failures → schema-repair loop (REQ-SCH-004).

---

## Phase 5 (Deliver) rigor

### Honesty guards (REQ-HON-005..009)

Import from `vulnhunter_fix.delivery` when composing PR/issue bodies:

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

The renderer refuses to ship on:
- Empty `residual_vectors` when `completeness_tier != FULL` (REQ-HON-007)
- Non-empty `residual_vectors` when `completeness_tier == FULL` (result-schema R-2)
- Any residual matching the hand-wave regex `(future work|more work needed|to be done|tbd|later)` (REQ-HON-006)

WORKAROUND fixes open as **Draft**; FULL and MITIGATION open Ready (`pr_draft_state_for_tier`, REQ-HON-008).

### Description Completeness Checklist (REQ-GAT-003)

Every PR body and issue body must carry these level-2 headings: `## Finding Summary`, `## Attacker Capability`, `## Security Test`, `## Fix Description`, `## Verification Results`. PRs additionally require `## Verification Table`. Non-FULL tiers require `## Residual Risk`. `BREAKING_CHANGE` status requires a bare `## Breaking Change` heading on its own line (put "Caller Action Required" in the body text — Gate 2's regex `^## Breaking Change\s*(?:$|:)` rejects an em-dash/word suffix on the heading line). If Sweep ran, `## Sweep Summary` is required. Enforced by `scripts/check-body-completeness.py` (Gate 2).
