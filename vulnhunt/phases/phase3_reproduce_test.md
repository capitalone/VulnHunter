# Phase 3: Reproduce and Exploit Test

> **Context**: You have completed Phase 2b (Verification) and have CONFIRMED
> findings only. The orchestrator's Operating Principles and Investigation
> Discipline are in effect.

## Output destinations

Write artifacts to these exact locations under `${VULNHUNT_DIR}` — do NOT
name files after a prompt (`phase3c_fixes.md`, `phase3_reproduce_test.md`,
etc.):

- PoCs: `${VULNHUNT_DIR}/poc/VULN-NNN_*.md` (one per finding)
- Exploit tests: `${VULNHUNT_DIR}/exploit_tests/test_vuln_NNN_*.py`
- Phase summary (VULN-NNN assignment table from the completeness check
  below + per-finding fix strategies from `phase3c_fixes.md`):
  `${VULNHUNT_DIR}/phase3_output.md` — that exact filename, at the
  results-dir top level.

## Pre-Phase 3 Completeness Check (MANDATORY)

Before writing any PoC, produce a VULN-NNN assignment table mapping every
CONFIRMED finding from Phase 2b (High and Medium severity) to a sequential ID:

| VULN-NNN | Phase 2b # | Title | Severity |
|---|---|---|---|

Row count MUST equal the total High + Medium CONFIRMED findings in Phase 2b.
If fewer: you dropped findings — add them. Every row MUST receive a PoC and
exploit test by end of phase. A CONFIRMED finding cannot be removed without an
explicit FAIL verdict from its exploit test.

## Phase 3a: Reproduce

For each confirmed vulnerability, create a proof of concept. Choose the appropriate
format based on context:

> **Universal Auth Gap (Phase 2b §9)**: for `VULN-PLATFORM-AUTHN` or
> `VULN-PLATFORM-AUTHZ`, produce ONE PoC against ONE representative
> endpoint and ONE exploit test. Do NOT generate per-endpoint PoCs or
> tests for `SUBSUMED-BY: VULN-PLATFORM-*` findings — the platform
> PoC stands in.

#### Runnable PoC (when a test environment is available)

The runnable form below is **only usable when the kickoff prompt says
"Bash is AVAILABLE for exploit-test execution"** (i.e. the operator
passed `--no-read-only --enable-bash`). Otherwise produce only the
Static Data Flow Trace form further down — the model has no Bash tool
to invoke it and the runnable script is illustrative only.

```bash
#!/bin/bash
# PoC for [VULN-NNN]: [Title]
# Preconditions: [what needs to be running]

curl -X POST http://localhost:8080/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{"field": "malicious_payload_here"}'

# Expected: [what a secure app would do]
# Actual: [what the vulnerable app does]
# Impact: [concrete impact demonstration]
```

#### Static Data Flow Trace (for source-only reviews)

When no running environment is available, demonstrate exploitability with a concrete
step-by-step data flow trace showing exactly how attacker input reaches the sink:

```
[VULN-NNN] Static PoC: [Title]

1. ENTRY: Attacker sends POST /api/search with body {"q": "' OR 1=1 --"}
   -> src/handlers/search.go:42  SearchHandler.Handle()
   -> parameter `q` assigned to variable `query`

2. PROPAGATION: `query` passed to buildFilter() without sanitization
   -> src/handlers/search.go:58  buildFilter(query)
   -> src/db/filters.go:23      buildFilter receives `query` as `input` param

3. SINK: `input` concatenated into SQL string
   -> src/db/filters.go:31      sql := "SELECT * FROM items WHERE name = '" + input + "'"
   -> Concrete payload: SELECT * FROM items WHERE name = '' OR 1=1 --'

4. IMPACT: Full table dump. Attacker retrieves all rows from `items` table.
   With UNION injection, can read arbitrary tables including `users`.
```

Requirements for static PoCs:
- Concrete attacker-controlled input value at step 1 (not abstract "malicious input")
- File:line at every step showing exactly where the data flows
- The literal dangerous string/value that reaches the sink
- Concrete impact statement

### Phase 3a Validation

After writing each PoC:
1. **Save the PoC to a file**: `${VULNHUNT_DIR}/poc/VULN-NNN_short_description.md`
   This is required — the report links to this file. If there is no file, the
   finding cannot be reported as Confirmed.
2. Verify the call chain from input source to sink using the forward trace
   already performed — use Grep to confirm any steps you're uncertain about
3. Explain step-by-step what happens when the PoC executes
4. Describe what the attacker gains (data exfiltration, RCE, privilege escalation, etc.)

---

## Phase 3b: Exploit Test (MANDATORY — DO NOT SKIP)

For each reproduced vulnerability, write an **executable test case** that proves the
exploit works END TO END. Static PoCs can be wrong — framework interceptors, type
coercion, or runtime guards may block the exploit. A passing test removes all doubt.
If you cannot write a test that demonstrates the attack succeeding, downgrade the finding.

### What "Succeeds" Means

The test must prove the **attacker's goal is achieved**, not just that a code pattern
exists. Ask: does the attacker actually get what they want?

- SQL injection: the query **returns unauthorized data** or **modifies data it shouldn't**
- Command injection: the attacker's command **actually executes** and produces output
- Path traversal: a file **outside the intended directory is actually read/written**
- SSRF/URL injection: the request **actually reaches a different endpoint/service**
- XSS: the payload **actually renders unescaped in the response**
- Crypto weakness: the attacker **can actually decrypt/forge** data (not just "weak algo used")
- IDOR: the attacker **retrieves or modifies another user's resource** without ownership
- CSRF: a cross-origin request **performs a state-changing action** as the victim
- Mass assignment: the attacker **sets a field they shouldn't have access to** (e.g., role escalation)
- Race condition: concurrent requests **produce an inconsistent state** the attacker benefits from (double spend, double vote, etc.)
- Open redirect: the victim **is redirected to an attacker-controlled domain**
- Email header injection: the attacker **injects additional headers or recipients**
- Identity spoofing: an action is **attributed to or authorized as a different user**
- Confused deputy: a request **reaches a downstream service with the service's elevated credentials** carrying attacker-controlled data
- Conditional validation bypass: a request **succeeds without the bypassed checks running**, using a credential that WOULD have been rejected if the checks had run (e.g., different IP, expired session, wrong audience). For each caller of the vulnerable function, identify the protected resource and whether any validation exists between the bypass and that resource.

For vulnerability classes not listed above, define what the attacker concretely
gains and assert on that outcome — the principle is the same.

A test that proves "the vulnerable code path runs" but the attack is blocked by
downstream defenses is a **FAIL**, not a PASS. Classify it as a code smell.

### What to Write

For each confirmed finding, write a test in the project's test framework (or a
standalone script if no test framework is available):

#### Test Structure

```
Test name: test_vuln_NNN_[short_description]

Setup:
  - Construct the minimum environment needed (mock DB, temp files, etc.)
  - Prepare the malicious input from the PoC

Action:
  - Call the vulnerable function/endpoint with the malicious input
  - Use the EXACT payload from the static PoC

Assertion — MUST prove the ATTACKER'S GOAL, not just the code pattern:
  - SQL injection: assert unauthorized data was returned
  - Command injection: assert attacker's command output appears
  - Path traversal: assert file content from outside allowed directory
  - SSRF: assert request reached unintended endpoint
  - XSS: assert payload appears unescaped in response body
  - Crypto: assert attacker can recover plaintext or forge valid ciphertext

Cleanup:
  - Remove temp files, restore state
```

#### Test Examples by Vulnerability Class

**SQL injection** — assert the payload reaches the query unescaped:
```python
def test_vuln_001_sql_injection():
    query = build_query("admin' OR '1'='1")
    assert "OR '1'='1" in query, f"Payload was sanitized: {query}"
```

**Path traversal** — assert a file outside the base directory was read:
```python
def test_vuln_003_path_traversal():
    result = read_file(base_dir, "../../../etc/passwd")
    assert "root:" in result
```

Adapt the pattern for command injection (assert command executed), deserialization
(assert arbitrary class instantiated), crypto (assert weak algorithm used), etc.

### Test Outcomes and Actions

After running (or mentally executing) each test:

| Test Result | Action |
|---|---|
| **PASS** (attacker's goal achieved) | Finding confirmed at current severity. Proceed to Phase 3c (Proposed Fixes). |
| **CODE RUNS but attack mitigated** | Downstream defenses block the exploit. Classify as **Code Smell** — report separately, not as a vulnerability. |
| **FAIL** (exploit blocked) | Investigate WHY. Read the code path the test actually hit. |
| **FAIL: framework prevents** | Downgrade to **Code Smell** — document the pattern but note the mitigation. |
| **FAIL: type system prevents** | Eliminate — the type system makes the payload impossible. |
| **FAIL: can't construct test** | Downgrade to **Potential** — explain what conditions would need to be true. Do NOT report as Confirmed. |
| **FAIL: exception before sink** | Check if the exception itself leaks info. If not, eliminate. |

**"Code Smell" means**: the code pattern is risky and should be fixed for defense
in depth, but the attacker cannot currently exploit it. Report these in a separate
"Code Quality / Defense in Depth" section of the report, NOT in the vulnerability
findings table. They do not get VULN-NNN IDs.

**MANDATORY: Exploitation attempt before classifying as Code Smell.** Before
downgrading any candidate to Code Smell, you MUST write the PoC file and the
exploit test file in `${VULNHUNT_DIR}/poc/` FIRST, then document why the exploit
fails. If you find yourself writing "Code Smell" without having created these
files, you are violating this requirement. The act of constructing the PoC often
reveals impact that abstract reasoning missed — this is the entire point.

You must show:
1. The exact payload you would send
2. The exact code path it would take
3. The specific defense that blocks it (with file:line and empirically verified
   behavior — see Gate 2b in phase2_shared.md; for full sanitizer verification
   methodology, see phase2_class_{class}.md for the relevant class)
4. Why the defense is effective for this specific sink context

If you cannot demonstrate a concrete defense that blocks exploitation, the finding
is NOT a Code Smell — it is a candidate that should proceed through the gates.
This rule exists because misclassifying a finding as a Code Smell based on assumed
mitigations is the #1 cause of missed vulnerabilities.

### Configuration-provable findings

When the vulnerability is the *absence* of a control (no auth on an endpoint, no
encryption on a port, no access restriction on a debug interface), the exploit test
is a **static verification test**: assert the insecure config is set, assert no
auth middleware is wired, assert activation is unconditional. Network reachability
proof is NOT required — the Phase 2 no-speculation rule applies. Do NOT downgrade
to Code Smell based on assumed network controls.

### Exploit Test Output

Present this table before proceeding to fixes:

| Finding | Test | Result | Action |
|---|---|---|---|
| VULN-001 | test_vuln_001_sql_injection | PASS — payload reaches query | Confirmed, proceed to fix |
| VULN-002 | test_vuln_002_class_load | FAIL — constructor sig mismatch | Downgrade to Informational |

**Only findings with PASS results proceed to Phase 3c.**

### Where to Put the Tests

Save exploit tests to `${VULNHUNT_DIR}/exploit_tests/` in the project directory:
```
${VULNHUNT_DIR}/exploit_tests/
  test_vuln_001_sql_injection.py
  test_vuln_002_class_load.scala
  test_vuln_003_path_traversal.sh
```

Use the project's native test language/framework when possible. Fall back to Python
or shell scripts for cross-language testing.
