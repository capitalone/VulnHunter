# Test-Quality Rubric — R1 through R5

**Referenced by:** REQ-GRA-016. **Enforced by:** the `reviewer-test`
agent (task-28: `prompts/reviewer_test.md`).

Generated security tests must satisfy all five rules below. A test that
fails any rule is `WEAK` at best and typically `WRONG`; the verification
agent (Phase 3b) refuses to accept it and enters the repair loop.

## R1 — Imports the production function

The test must `import` (or language equivalent) the actual production function. Reimplementing the function inside the test file is **WRONG** — the test bypasses the fix.

Detection:
- Python: `from <production_module> import <symbol>` or `import <production_module>` followed by attribute access.
- Go: same package as the fix, or imports via module path.
- Java: `import <fqcn>` for the fixed class.
- TypeScript: `import { <symbol> } from '<path>'` for the production module.

Anti-pattern: the test defines its own `def authenticate(...)` and calls that instead of the production `authenticate`.

## R2 — Discriminating payload

The test's payload must match the scan's PoC payload (or a demonstrably-equivalent shape). Sanitized inputs prove nothing.

Detection:
- The payload string / byte sequence / structured shape matches the finding's `PoC payload` field (parser-extracted).
- Scan says "SQLi via `' OR 1=1--`" → test uses the exact string, not `test_input`.

Anti-pattern: `assert authenticate("test_user", "test_pass")` when the scan reported an injection payload.

## R3 — Fail-closed assertion

The test's assertion must be **positively narrow**: only the secure behavior passes. Accepting "either success OR the safe outcome" leaks coverage.

Detection:
- Python: `assert result == expected_secure_value`, not `assert result != insecure_value`.
- Go: `if result != expected { t.Fatalf(...) }`, not "the test succeeds if we don't panic."
- `pytest.raises` (or equivalent) must specify the exception type, not a base class.

Anti-pattern: `assert response.status_code in (200, 401, 403)` when the scan reported a specific 200-return bypass.

## R4 — Not a standalone demo

The test must **fail** against pre-fix code and **pass** against post-fix code. The Step E.5 discrimination evidence (REQ-GRA-017) records this proof.

Detection:
- The plan artifact carries `discrimination_evidence` with both `pre_fix_result == "fail"` AND `post_fix_result == "pass"`. Missing either is `WRONG`.

Anti-pattern: `assert isinstance(result, dict)` — true regardless of whether the vulnerability was fixed.

## R5 — Mirrors the scan's PoC payload

The test's attack shape must correspond to the scan's stated vector, not a related-but-different attack.

Detection:
- Scan reports SSRF via `http://internal/`: test payload uses `http://internal/`-shaped URL, not `file:///etc/passwd`.
- Scan reports CSRF token bypass: test sends request without the token and asserts 403, not "some CSRF-adjacent payload."

Anti-pattern: scan reports XXE but the test asserts on XML parser config rather than sending an XXE payload. Configuration checks are R3 violations *and* R5 violations.

## Verdict matrix

The `reviewer-test` agent returns one of three verdicts:

| Condition | Verdict |
|---|---|
| R1..R5 all ✓ | `GOOD` |
| Any R fails but the test still discriminates (pre-fix fail / post-fix pass) with a fixable gap | `WEAK` — verification agent writes a fix brief |
| R1, R4, or R5 fails (standalone demo / non-discriminating / wrong attack) | `WRONG` — test must be rewritten |

Under `WEAK`, the fix agent may adjust the test with the verification agent's approval. Under `WRONG`, the test is rewritten from the finding's PoC — previous test discarded.
