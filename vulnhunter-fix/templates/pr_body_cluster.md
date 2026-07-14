## Security Fix Cluster: {CLUSTER_NAME}

{CLOSES_OR_ADDRESSES_LINE}

> Bundles {N} findings under one PR. Each finding is committed
> separately on this branch with its own RED→GREEN security test
> and exploit-blocked proof — see the per-finding subsections under
> **Fix Description** below for the authoritative detail.

## Finding Summary

**Rationale:** {CLUSTER_RATIONALE}

| VULN | CWE | Severity | Location | Source issue |
|------|-----|----------|----------|--------------|
{CLUSTER_MEMBERS_TABLE}

## Attacker Capability

Each finding in this cluster has its own attacker-capability statement in
its per-finding subsection under **Fix Description**. In aggregate, this
cluster closes {N} independently-exploitable weakness(es) sharing the
remediation theme above; no finding's exploit depends on another's.

## Security Test

Every finding carries a dedicated RED→GREEN security test committed on this
branch. Each test **failed** against pre-fix code and **passes** against the
committed fix (per-finding discrimination evidence is recorded in each
subsection). The aggregate before/after state is in **Verification Results**.

## Fix Description

<!-- Cluster PRs derive idempotency from the per-finding vulnfix-key markers
     embedded in each finding subsection below — Gate 4
     (scripts/check-idempotency.py) uses KEY_RE.search which matches anywhere
     in the body, so per-finding markers satisfy the contract without a
     separate cluster-level marker. NOTE: do not reference the finding-section
     placeholder token by name inside this comment — a naive global
     substitution would inject each finding's own vulnfix-key comment here,
     nest HTML comments, and dump the finding blocks as visible garbage. -->

{PER_FINDING_SECTIONS}

## Verification Results

| State | Security tests | Regression suite |
|-------|---------------|-----------------|
| Before fix | FAIL — every test in this cluster's branch was RED on `main` | PASS |
| After fix | PASS — all tests GREEN | PASS — no regressions introduced |

## Verification Table

{VERIFICATION_TABLE}

## Residual Risk

{CLUSTER_RESIDUAL_RISK}

## Sweep Summary

| VULN | Root cause | Pattern | Found | Captured | Mitigated | Remaining |
|------|-----------|---------|-------|----------|-----------|-----------|
{CLUSTER_SWEEP_ROWS}

## Breaking Change

{CLUSTER_BREAKING_CHANGE}

## Setup Required (Draft PR)

> This PR is **non-breaking at the code level** but cannot take effect until the steps below are completed. Do not mark this PR ready-for-review until every step is done.

{SETUP_STEPS}

---

Cluster: {CLUSTER_NAME}
Findings: {N}
VulnHunter-Run: {RESULTS_DIR_NAME}
Co-Authored-By: Claude Code (VulnFix)
