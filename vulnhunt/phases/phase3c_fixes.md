# Phase 3c: Proposed Fixes

> **Context**: You have confirmed findings with passing exploit tests.
> Document fix strategies for the report — do NOT edit source files.

## Phase 3c: Proposed Fixes

For each confirmed vulnerability, document a proposed fix for the report. **Do NOT
edit the source files** — just describe the fix strategy.

#### Fix Principles

1. **Fix at the right layer**: Input validation at the boundary, parameterized queries
   instead of string sanitization, safe APIs instead of dangerous ones.
2. **Fix the root cause, not the instance.** If `xss()` is being misused as a URL
   sanitizer in 4 files, don't add `encodeURIComponent()` to 4 call sites — replace
   or wrap the root cause so ALL current and future callers are protected.
3. **Defense in depth**: Add multiple layers where severity warrants it.
4. **Minimal blast radius**: Change as little as possible while covering all instances.

#### Fix Documentation

For each finding, record:

**Strategy**: [1-2 sentence description of the fix approach]
**Files to change**: [list of file:line locations that need editing]
**Why this works**: [Why the fix eliminates the vulnerability class]

#### Class-specific guidance

**CWE-639 / Authorization Delegation pattern** (findings that landed at Medium
or original severity under phase2b_verify.md §8): propose the minimal
caller-scope check that mirrors the downgrade rule. Adding this check is what
lifts the finding to Informational on re-scan.

- **Internal / service-to-service APIs (no end-user principal present)**:
  validate the gateway-set caller-app header (e.g. `x-apigw-app-id` or equivalent)
  against an in-code trusted-caller allow-list. Reject unknown app IDs.
  This path only qualifies when `OAuth_ResourceOwnerUID` is NOT present in the
  request — if an end-user identity is available, use it instead.
- **Publicly accessible APIs (customer-facing or SSO-authenticated internal users through the GW)**:
  assert the `OAuth_ResourceOwnerUID` header is present. Reject requests without it.
  This header covers both external customer flows and SSO-authenticated internal users.
  This takes priority over app-id allow-listing when both are available.
- If the auth gate is bypassable (CVB, ENV branch, `require_uid_header=False`-
  style optionality), the prerequisite fix is to make the gate unconditional
  first, then add the caller-scope check above.
- **Alternative mitigation path**: Services that do not yet have PoP validation
  or mTLS can close IDOR findings by implementing service-level PoP token
  validation (e.g., the API gateway auth library) with a trusted-caller
  allow-list. This satisfies both the crypto origin auth and caller-scope
  criteria, bringing the finding to Informational on re-scan.

Do NOT propose new `caller_scope.assert_caller_can_act_on_account`-style
helpers, new caller-tenant predicates on the data layer, or per-account
ownership lookups in the service — those rebuild functionality the
entitlements platform already provides and are out of scope for the service
team. Verifiable propagation of the upstream entitlements decision (signed
claim consumption) and cryptographic caller-identity propagation downstream
are platform investments, not per-service fixes; reference them as follow-on
work in the **Why this works** field, not as the immediate fix.

**VULN-PLATFORM-AUTHN / VULN-PLATFORM-AUTHZ**: use the CWE-639 section
above (including the anti-pattern). AUTHN's fix needs BOTH
`*<your-gateway>*` PoP/mTLS AND caller-scope; AUTHZ's needs only
caller-scope (crypto already present per §9).

