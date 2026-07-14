# Phase 2 (fork mode): Plan Remediation

**Referenced by:** `prompts/plan.md` mode-dispatch stub. Fork mode has no interactive collaboration loop, uses strict per-finding grouping, and applies the masked branch-naming pattern for GitHub visibility.

## Step 1: Prioritize findings

Order by severity, then by fix complexity:
1. Critical severity
2. High severity
3. Medium severity
4. Low severity

Within same severity, simpler fixes (fewer files touched) go first.

## Step 2: Live code pre-check

Before planning any fix, verify each finding's vulnerable pattern still exists in the target repo:

```bash
# For each finding, grep for the vulnerable function/pattern at the stated location
grep -n "<vulnerable_pattern>" <target_file>
```

| Result | Action |
|---|---|
| Pattern found at stated location | Proceed with fix planning |
| File missing or pattern not found | Mark as `ALREADY_FIXED` — skip, document in tracking issue |
| File exists but substantially rewritten | Mark as `ALREADY_FIXED` (diverged) — skip |

Avoids wasting effort on findings that are already resolved.

## Step 3: Group findings (strict rules)

Findings may be grouped into a single branch and PR **only if ALL of the following are true**:
- They share the **exact same root cause pattern** (not just the same CWE category).
- They affect the **same file(s)**.
- Fixing them together is strictly simpler than fixing them separately (e.g., one parameterized query call fixes three injection points in the same function).

**Never group** findings with different root causes, even if same file / same CWE. Each different root cause gets its own branch and its own PR.

Each group → one branch → one PR → one set of tests.

Branch names follow the masked pattern per REQ-SEC-002/003: `fix/code-quality-<descriptor>-<idempotency-hash-prefix>`. The descriptor is a generalized remediation category (e.g., `input-validation`, `crypto-handling`, `auth-handling`, `access-control`, `memory-handling`, `credential-handling`) — never the specific vulnerability class. Use `cwe_to_descriptor()` and `compute_masked_branch_name()` from `vulnhunter_fix.delivery`.

## Step 4: Detect conflicts

Check if multiple groups affect the same file or overlapping line ranges. If so:
- Note the dependency.
- Plan to fix the earlier-in-file finding first.
- After that fix, re-read the file before applying the next.

## Step 5: Assess each finding's fix approach

For each finding, determine:
- Language/framework of the target code.
- Test framework (pytest, jest, junit, go test, ...).
- Existing test directory (`tests/`, `src/test/java/`, `spec/`, `__tests__/`, ...).
- The assertion that defines "secure behavior".
- Auto-patchability: does the fix require external values, cross-repo coordination, or post-merge manual steps?

Flag any finding where the fix is NOT auto-patchable — routed to issues in Phase 5 without a fix attempt.

## Step 6: Present the plan

Show the user a table:

| Order | VULN ID | CWE | Severity | Location | Fix Strategy | Pre-check | Conflicts |
|-------|---------|-----|----------|----------|--------------|-----------|-----------|

Then for each finding, briefly describe:
- The security test assertion (1 sentence).
- The fix approach (from VulnHunter report).
- Auto-patchable, or routed to an issue.

Ask user to confirm before proceeding to Phase 3.
