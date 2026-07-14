## Security Finding: {VULN_ID} — {TITLE}

## Finding Summary

| Field | Value |
|-------|-------|
| **ID** | {VULN_ID} |
| **CWE** | {CWE}: {CWE_NAME} |
| **Severity** | {SEVERITY} |
| **Location** | `{LOCATION}` |
| **Root Cause** | {ROOT_CAUSE} |
| **Data Flow** | {DATA_FLOW} |

## Attacker Capability

{EXPLOIT_DESCRIPTION}

**Impact:** {EXPLOIT_IMPACT}

## Status

{STATUS_DESCRIPTION}

**Automated fix submitted:** #{PR_NUMBER} — review and merge when ready.

**Cannot auto-fix.** Reason: {CANNOT_FIX_REASON}

What is needed to resolve this:
{HUMAN_ACTION_REQUIRED}

**Cross-repo fix required.** This vulnerability requires coordinated changes across multiple services:
{CROSS_REPO_DETAILS}

**Requires human decision.** Multiple valid remediation approaches exist; review the Design Options section below and comment on this issue with the chosen approach.

**Breaking change.** No PR has been created. The fix would change a public interface in a way that requires external callers to update their code. See the Breaking Change section below for the proposed interface change, fix instructions, known callers, and migration plan.

**Issue only — design or setup unresolved.** No PR has been created because either (a) design decisions are still open, or (b) the required setup is non-trivial enough to need its own design conversation. See the **Open Design Questions** and **Plan to Resolve** sections below.

### Open Design Questions

{OPEN_DESIGN_QUESTIONS}

### Plan to Resolve

{RESOLUTION_PLAN}

## Fix Description

**Strategy:** {FIX_STRATEGY}

<details>
<summary>Proposed diff (if available)</summary>

```diff
{DIFF}
```

</details>

## Security Test

The following test validates the fix works correctly:

```{LANG}
{TEST_CODE}
```

## Verification Results

1. Apply the fix
2. Run the security test — it should PASS
3. Run existing tests — no regressions expected

## Breaking Change

**Caller Action Required.**

**Interface change:** {INTERFACE_CHANGE_DESCRIPTION}

**What callers must do:** {CALLER_ACTION_REQUIRED}

**Known callers (best-effort search):**
{KNOWN_CALLERS}

**Registration / gateway actions:** {REGISTRATION_ACTIONS}

## Residual Risk

{RESIDUAL_RISK_SECTION}

## Verification Table

{VERIFICATION_TABLE}

## Sweep Summary

| Root cause | Pattern | Found | Captured | Mitigated | Remaining |
|-----------|---------|-------|----------|-----------|-----------|
{SWEEP_ROWS}

### Priority

**{SEVERITY}** — {SEVERITY_RATIONALE}

---

VulnHunter-Finding: {VULN_ID}
Identified by VulnHunter scan on {SCAN_DATE}

<!-- vulnfix-key: {IDEMPOTENCY_KEY} -->
