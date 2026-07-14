# Class Group: Logic/Crypto (LOG)

## Dangerous Sink Reference

- **Cryptographic operations**: cipher creation, hashing, key derivation, random
  number generation
- **Deserialization**: pickle, ObjectInputStream, yaml.load, unserialize —
  anything that reconstructs objects from untrusted bytes

Adapt the specific API names to the detected language/framework.

## Vulnerability Classes

### Cryptographic Issues
- Hardcoded secrets/keys
- Weak algorithms (MD5, SHA1 for security, DES, RC4)
- Insecure random number generation
- Missing or disabled TLS validation: `rejectUnauthorized: false`,
  `NODE_TLS_REJECT_UNAUTHORIZED=0`, `verify=False` (Python requests),
  `InsecureTrustManagerFactory`, `AllowAllHostnameVerifier`, `-k`/`--insecure`.
  CWE-295

### Memory Safety (C/C++/Rust unsafe)
- Buffer overflows, use-after-free, double-free
- Integer overflow leading to undersized allocations
- Unsafe Rust blocks with unsound operations

### Logic Flaws
- **Race Conditions**: Check for these four patterns, each requiring different
  mitigations:
  - *Check-then-act*: A permission/balance/state check followed by a separate
    action that assumes the check still holds. Attacker sends concurrent requests
    to exploit the gap between check and act.
  - *Read-modify-write*: Read a value, compute a new value, write it back without
    atomic compare-and-swap. Concurrent requests cause lost updates (e.g., double
    withdrawals, double votes, duplicate resource provisioning where a
    one-to-one or count-limited invariant is violated).
  - *Fire-and-forget async*: Security-critical operation dispatched asynchronously
    (message queue, event bus, goroutine/thread, thread pool executor) where the
    response is sent before the async operation completes. **MUST proceed through
    full pipeline (PoC + exploit test) before any downgrade.** Construct a
    concurrent-request scenario showing what invariant the system violates when two
    requests exploit the temporal gap simultaneously (duplicate resource, inconsistent
    count, orphaned record, double-spend).
  - *TOCTOU across API boundaries*: A validation check on one API call, with the
    validated state consumed by a subsequent API call. Attacker modifies state
    between the two calls.
- **Rate-limit/counter scope bypass**: When a rate limit or attempt counter is
  scoped to an identifier the attacker can rotate (HTTP session, cookie,
  ephemeral token) and the endpoint requires no pre-existing authentication,
  the counter is bypassable regardless of atomicity — the attacker creates new
  identifiers to reset it. Evaluate whether the counter's binding identifier is
  attacker-controlled; if so, this is an authentication/authorization bypass
  (CWE-307), not merely a race condition. Assess severity based on what the
  rate limit protects (e.g., login attempts → account takeover).
- Integer overflow/underflow in business logic — check arithmetic on user-
  controlled values used in allocation sizes, array indices, financial
  calculations, or loop bounds. CWE-190
- Incorrect access control checks (OR vs AND, negation errors)
- Missing null/error checks on security-critical paths
- **Cache/State Isolation Failures**: When the codebase caches authorization
  decisions, credentials, or session state, verify that the cache key provides
  the same isolation guarantees as the authorization model:
  - *Cache key completeness*: Does the cache key include ALL fields that affect
    the authorization decision? If authorization depends on (clientId, userId,
    location, accessType) but the cache key only includes a subset, requests with
    different authorization contexts could share cached results.
  - *Cache key collision resistance*: If the cache key is formed by concatenating
    user-controlled fields, can different field values produce the same key?
    (e.g., `"ab" + "cd"` == `"abc" + "d"`). Delimiter-less concatenation of
    user-controlled values is a collision vulnerability.
  - *Revocation window*: If authorization can be revoked, how long does the cache
    continue serving the revoked authorization? A TTL cache that doesn't check
    for revocation creates an exploitation window after revocation.
- **Credential/Policy Scope Over-Permissioning**: When the codebase generates
  authorization artifacts (IAM policies, scoped tokens, OAuth scopes, capability
  grants, or equivalent), audit the *semantic content* of the generated artifact
  — not just whether user input can inject into it:
  - *Action wildcards*: Grep for wildcard permission constants (`All*Actions`,
    `"*"` in action arrays) in generated artifacts. For each, check whether a
    parallel branch uses a restricted action set — if yes, the wildcard branch
    is over-permissioned. Check whether the wildcard includes destructive
    operations (delete, disable, schedule deletion) beyond the feature's needs.
  - *Per-branch consistency*: When the generation has multiple branches (e.g.,
    by tenant type, by access level, by request type), verify that EVERY branch
    enforces the same security invariants. If one branch restricts actions to a
    specific set and the default branch grants a wildcard, that is a finding.
  - *Access-type leakage (MANDATORY)*: When credential-issuing and policy-only
    paths are gated by a `requestType` discriminator:
    1. Grep ALL callers of the credential-issuing function.
    2. For EACH, verify it branches on request type before calling the function.
       Any caller that doesn't branch → CANDIDATE (policy request reaches cred path).
    3. Check for indirect activation: can request type be set by secondary inputs
       that bypass the endpoint-level discriminator?
  - *Supplemental resource grants*: When a request parameter adds additional
    resource statements to a generated policy, verify that the added statement's
    permission scope matches the request's access type. A read-only path that
    adds write permissions for a supplemental resource is a privilege escalation.

### Resource Exhaustion (CWE-400)
- **ReDoS**: user-controlled input matched against regexes with catastrophic
  backtracking (nested quantifiers, alternation with overlap)
- **Unbounded allocation**: user-controlled size/count parameters passed to
  memory allocation, array creation, or query `LIMIT`/`OFFSET` without caps.
  **Request DTO collections (mandatory check):** For every collection-typed field
  in a request body (List, Array, Set, repeated protobuf field), verify a size
  constraint exists (`@Size`, `maxItems`, `@Length`, length validation in custom
  validator). An unbounded request-body collection is a DoS vector independent of
  what happens to each element — the allocation and iteration is the sink. This
  check applies even when another class group already evaluated the elements
  (e.g., NAV found IDOR on per-element authorization — the DoS from an unbounded
  list is a separate finding). CWE-400.
- **Recursive parsing**: XML/JSON parsing without depth limits (billion laughs),
  archive extraction without size limits (zip bombs)

### Prototype Pollution (CWE-1321, JS only)
- User input reaching recursive merge/extend/assign functions that write to
  `__proto__` or `constructor.prototype`. Check lodash `merge`/`defaultsDeep`,
  jQuery `$.extend(true, ...)`, and custom deep-merge utils.

### Other Vulnerability Patterns

The classes above are not exhaustive. Also consider: deserialization of untrusted
data, WebSocket message injection, HTTP request smuggling, cache poisoning,
sensitive data in log output (CWE-532: grep for logging calls adjacent to
variables named `password`, `token`, `secret`, `key`, `ssn`, `creditCard`),
or any other pattern where attacker-controlled data reaches a dangerous
operation. If a pattern passes the gates, report it.

## Gate 3: Do NOT Eliminate (LOG-specific)

**Business logic invariant violations are new capabilities.** Do NOT eliminate
based on "self-only impact" when the finding violates a system invariant the
application enforces. Duplicate provisioning, double-spend, bypassing count
limits, or creating duplicate active credentials/tokens are new capabilities
even on the attacker's own account — count-controlled resources have value
precisely because their count is controlled.
