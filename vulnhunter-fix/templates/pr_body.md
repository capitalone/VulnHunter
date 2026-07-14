## Security Fix: {VULN_ID} — {TITLE}

Closes #{ISSUE_NUMBER}

## Finding Summary

| Field | Value |
|-------|-------|
| **ID** | {VULN_ID} |
| **CWE** | {CWE}: {CWE_NAME} |
| **Severity** | {SEVERITY} |
| **Location** | `{LOCATION}` |
| **Root Cause** | {ROOT_CAUSE} |

## Attacker Capability

**What an attacker can do:** {EXPLOIT_DESCRIPTION}

**What this proves:** {EXPLOIT_PROOF_STATEMENT}

## Security Test

A test was written that defines the expected secure behavior. It **failed** before the fix and **passes** after:

```{LANG}
{TEST_CODE}
```

| State | Test Result |
|-------|-------------|
| Before fix | FAIL (vulnerable) |
| After fix | PASS (secure) |

## Fix Description

**Strategy:** {FIX_STRATEGY}

**Changes:**
{FILE_CHANGES}

**Why this works:** {FIX_WHY}

## Setup Required (Draft PR)

> This PR is **non-breaking at the code level** but cannot take effect until the steps below are completed. Do not mark this PR ready-for-review until every step is done.

{SETUP_STEPS}

## Breaking Change

**Caller Action Required.** This fix is backward-compatible but not complete. The vulnerability is mitigated (legacy path logged) but not fully resolved until external callers are updated.

**Interface change:** {INTERFACE_CHANGE_DESCRIPTION}

**What callers must do:** {CALLER_ACTION_REQUIRED}

**Known callers (best-effort search):**
{KNOWN_CALLERS}

**Once callers have migrated:**
- Remove the legacy fallback path (see the deprecation comment in source)
- Hard-enforce the secure interface
- {REGISTRATION_ACTIONS}

**Pending finalization issue:** #{FINALIZATION_ISSUE_NUMBER}

## Verification Results

- Security test: PASS (RED before fix, GREEN after)
- Existing tests: no regressions

## Verification Table

{VERIFICATION_TABLE}

## Residual Risk

{RESIDUAL_RISK_SECTION}

## Sweep Summary

| Root cause | Pattern | Found | Captured | Mitigated | Remaining |
|-----------|---------|-------|----------|-----------|-----------|
{SWEEP_ROWS}

---

VulnHunter-Finding: {VULN_ID}
Co-Authored-By: Claude Code (VulnFix)

<!-- vulnfix-key: {IDEMPOTENCY_KEY} -->
