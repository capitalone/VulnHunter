# Final Report Format

> **Context**: All phases are complete. Compile the final report with all confirmed
> findings, code smells, and the resolved input inventory.

## Final Report Format

**IMPORTANT**: All findings describe the original source code as it existed at
scan time. The audit does not modify source files.

**Each confirmed instance is a separate finding.** If the sweep produced 5 candidates
for the same root cause and 3 passed the full pipeline, the report contains 3
VULN-NNN entries — one per sink location, each with its own data flow, PoC, and
exploit test. They may share a root cause description and fix strategy, but each
gets its own ID and its own row in the summary table.

Start the report with a summary table of all confirmed findings.
**This table MUST have one row per exploit test PASS — not one row per root cause.**
If you have 2 root causes but 8 confirmed sink locations, the table has 8 rows.

**Universal Auth Gap exception**: if Phase 2b §9 emitted
`VULN-PLATFORM-AUTHN` or `VULN-PLATFORM-AUTHZ`, that row leads the
summary table. Its body lists every `SUBSUMED-BY: VULN-PLATFORM-*`
finding (ID, file:line, CWE that would have been raised) so post-fix
re-scan can confirm the expected-to-disappear set. Subsumed entries do
NOT get their own summary-table rows.

### Summary

| ID | Title | CWE | Severity | Exploit Test | Status |
|---|---|---|---|---|---|
| VULN-001 | [title] | CWE-XXX | High+/High/Medium/Low/Informational | PASS/FAIL | Confirmed/Fixed/Verified |
| ... | ... | ... | ... | ... | ... |

Then for each finding, provide the full detail:

### [VULN-NNN] Title
| Field | Value |
|---|---|
| **Title** | ... |
| **Input** | inventory # and description |
| **CWE** | CWE-XXX: [Name] |
| **Severity** | High+/High/Medium/Low/Informational |
| **Location** | file:line (primary instance) |
| **Entry Point** | ... |
| **Data Flow** | source -> ... -> sink |
| **PoC** | `${VULNHUNT_DIR}/poc/VULN-NNN_description.md` |
| **Exploit Test** | `${VULNHUNT_DIR}/exploit_tests/test_vuln_NNN.py` — PASS/FAIL + reason |
| **Fix** | [inline diff or link] |
| **Root Cause** | [shared root cause name, if this instance is part of a sweep group] |
| **Status** | Confirmed / Fixed / Verified |

When severity is **Informational** or **Medium** under the Authorization
Delegation Rule (phase2b_verify.md §8), include one extra row:
| **Trust Model** | one-line note recorded in Phase 2b |

Every finding MUST include a CWE identifier. Use the most specific CWE that applies
(e.g., CWE-89 for SQL injection, not CWE-74 for generic injection).

**VALIDATION RULE**: A finding is INVALID if either the **PoC** or **Exploit Test**
field is empty, says "N/A", or says "see above." Each field MUST contain a file path
to the saved artifact. If you cannot produce a PoC or exploit test, the finding has
not been proven and must be downgraded to Potential or eliminated.

**Code smells go in a separate section.** Findings where the exploit test showed
"code runs but attack is mitigated" are NOT vulnerabilities. List them after the
vulnerability findings under a "Code Quality / Defense in Depth" heading.

**Each code smell MUST include a downgrade rationale** explaining:
1. Which gate it failed or which exploit test defense blocked it
2. The specific evidence (file:line of the mitigation, or the test output showing
   the attack was blocked)
3. What condition would need to change for this to become exploitable (e.g.,
   "if the allowlist is removed," "if this route is exposed in production,"
   "if the downstream service stops validating")

Format:
| Field | Value |
|---|---|
| **Location** | file:line |
| **Pattern** | what the code does |
| **Downgrade reason** | which gate failed + evidence (file:line of mitigation) |
| **Risk if conditions change** | what would make this exploitable |
| **Recommendation** | why it should still be fixed |

They do not get VULN-NNN IDs or PoC files.

**Code smell generation (MANDATORY):** Before writing the Code Quality section,
systematically review these sources — not just findings that failed exploit tests:

| Source | What to look for |
|---|---|
| Gate 2b near-misses | Sanitizer correct for current sink but fragile (caller-dependent, wrong layer) |
| Gate 1 near-misses | Code exploitable if route were ever exposed; dev-only guard is the only protection |
| Security config | Missing SameSite, permissive trust proxy, missing security headers |
| Crypto inventory | Weak algorithm/mode where exploitation prerequisite is not currently met |
| Defense-in-depth gaps | Service-layer functions relying on caller sanitization with no own validation |

Each entry: location, risk, what prevents current exploitation, why it should be fixed.

**Include the sweep verification table.** After the code smells section, include
the final Phase 3d sweep table showing each root cause, the grep pattern used,
instances found/fixed/remaining. This demonstrates completeness — every root cause
was hunted across the entire codebase, not just at the initially-discovered location.

Save all artifacts to the `${VULNHUNT_DIR}/` directory:
```
${VULNHUNT_DIR}/
  README.md                         # Summary report with links (generated last)
  poc/
    VULN-001_sql_injection.md       # Static or runnable PoC
    VULN-002_path_traversal.md
  exploit_tests/
    test_vuln_001_sql_injection.py  # Executable exploit test
    test_vuln_002_path_traversal.sh
```

### Generating the README

After all findings are finalized, create `${VULNHUNT_DIR}/README.md` as the entry point.

**The README MUST begin with this exact header structure** (fill in values):

```markdown
# VulnHunter Security Audit Report

**Run ID**: <VULNHUNT_DIR basename>
**Repository**: <full repo URL>
**Audit Date**: <YYYY-MM-DD>
**Branch**: <branch [short-commit-hash]>
**Model**: <model identifier>
**Findings Summary**: <N High+, N High, N Medium, N Low, N Informational>
```

Field definitions:
- **Run ID** = basename of `VULNHUNT_DIR` (the results folder name, e.g.
  `smartops-cli_VULNHUNT_RESULTS_opus46_1m_2026-05-14-072642`).
- **Repository** = the `Repository URL` value supplied in the /vulnhunt
  kickoff prompt's pre-resolved metadata block. The agent layer already
  normalized SSH origins to https and stripped any `.git` suffix; use the
  value literally without running git or doing further parsing.
- **Branch** = the `VULNHUNT_BRANCH` value supplied in the same metadata
  block. Format: `branch-name [abc1234]`, or `unknown` if the source
  isn't a git repo. Do not run git to recompute.
- **Model** = the model used (e.g. `claude-opus-4-8`).

After the header, include:
- Summary table of findings (ID, title, severity, CWE, status)
- For each finding: input #, location, entry point, impact, links to PoC and exploit test files
- The resolved input inventory table showing every input's disposition
  (CANDIDATE / SAFE / DESIGN-INTENT) as a completeness artifact
- "Not Found / Excluded" section listing checked-but-clean vulnerability classes
- Artifacts table linking all files in `${VULNHUNT_DIR}/`

**Clickable links**: Every finding row in the summary table and every finding section
MUST include relative markdown links to the corresponding PoC file (`poc/VULN-NNN_*.md`)
and exploit test file (`exploit_tests/test_vuln_NNN_*`). Use the format
`[PoC](poc/VULN-001_desc.md) | [Test](exploit_tests/test_vuln_001_desc.py)`.
A finding without clickable links to both artifacts is incomplete.

**Cross-check**: The README summary table MUST list every VULN-NNN from the report.
Count the findings in the report and count the rows in the README table — they must
match. If they don't, you missed findings when generating the README.

After writing the README, add a footer to each PoC file linking to its exploit test
and back to the README.

## What NOT to Report

- Anything in test code, build scripts, vendored/third-party code, or generated code
  (see Operating Principle #5)
- Informational findings that aren't exploitable (exception: findings downgraded
  to Informational under the Authorization Delegation Rule ARE reported with
  full data flow and PoC — see phase2b_verify.md §8)
- Inputs with SAFE or DESIGN-INTENT dispositions in the inventory — these are not
  findings, but their dispositions ARE part of the audit record and should appear in
  the resolved inventory table in the report
- Dependencies with known CVEs — **do not perform deep analysis of dependency
  internals.** Instead: if you encounter a dependency CVE during hunting and the
  first-party code clearly invokes the vulnerable API path with attacker-controlled
  input (provable from the first-party call site alone), report it as a finding
  with the CVE reference. If exploitability would require analyzing the dependency's
  internal code to confirm, note it as a Code Smell with the CVE number and move on.
- Style issues or best-practice violations without security impact
- Theoretical vulnerabilities that require unrealistic preconditions
- Injection claims where the language/framework genuinely auto-sanitizes — but verify
  by reading the actual library, and check that the sanitizer matches the sink context
