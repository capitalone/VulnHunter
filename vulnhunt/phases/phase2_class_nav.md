# Class Group: Navigation/Auth (NAV)

## Mandatory Input Gates

### Request Body Gate (CWE-915)

When the input being traced is a request body (DTO, struct, model, interface),
you MUST perform cross-endpoint body analysis before recording any disposition.
This is not optional:

(a) Grep for ALL endpoints that deserialize into the same body type.
(b) Read the body type definition. For each field, classify by who should be
    allowed to set it. Financial fields (monetary values, offers, valuations,
    prices), status/flag fields, role/permission fields, and timestamp fields
    are common candidates for role-restricted access.
(c) For each endpoint found in (a), list which sensitive fields are explicitly
    overridden, nulled, or stripped in the controller/handler BEFORE the body
    reaches the service layer. Schema/format validation (bean validation, Joi,
    pydantic, JSON Schema, etc.) is NOT a mass assignment defense — it
    validates shape and format, not authorization.
(d) Read the mapper/builder source code that converts the body into the
    downstream payload or persistence model. List every field the mapper
    copies. If the mapper unconditionally copies all fields, then every field
    the caller should NOT control is a mass assignment candidate. A handler
    that processes some fields individually then forwards remaining fields
    via a catch-all function has an unfiltered mapper — every field NOT
    explicitly extracted is a candidate.
(e) Cross-endpoint comparison: any sensitive field that is overridden in a
    higher-trust endpoint but NOT in a lower-trust endpoint is a mass
    assignment candidate. The developer may have assumed the lower-trust
    caller would never send that field, but the attacker will.

Do NOT conclude safe based on some fields being overridden — the type may have
15 fields passing through unfiltered. Complete steps (a)-(e) before recording
any disposition. Each unauthorized sensitive field is a separate CANDIDATE.
CWE-915. Endpoint-level role gates do NOT satisfy this gate — authorization to
USE an endpoint ≠ authorization to modify ALL fields it accepts. Do NOT record
DESIGN-INTENT for body inputs based on caller role or trust level.

### Resource ID Gate (CWE-639)

When the input is a resource identifier (path params, query params, body fields
containing IDs) OR a value that selects an authorization scope, you MUST
evaluate it as an independent IDOR vector before recording any disposition:

(a) Does the code verify the authenticated caller owns or is authorized for
    THIS SPECIFIC ID? Authentication alone is not authorization.
(b) What credential is attached to the downstream call that uses this ID?
    If it is a service-level credential (service account, machine token,
    client_credentials grant), check whether user identity is ALSO forwarded
    through any channel (custom headers, session tokens, identity assertions).
    If the downstream receives only service credentials with NO user identity,
    the downstream cannot enforce per-caller authorization — flag as CANDIDATE.
    If user identity IS forwarded alongside the service credential, the
    confused deputy concern is eliminated, but the IDOR concern remains:
    verify the calling service checks that the authenticated user owns or is
    authorized for this specific resource ID before forwarding it.
(c) If the endpoint accepts multiple resource IDs in its path or parameters,
    evaluate EACH ID independently. Do NOT group them into one finding. Each
    ID that lacks an ownership check binding it to the caller is a separate
    CANDIDATE.

Format validation (regex, type checks, range constraints) does NOT satisfy (a).
Infrastructure-layer authentication (ALB, API Gateway, Lambda authorizers, WAF,
`/protected/` paths) proves the caller is *a* valid user — NOT that they own
*this* resource. A resource ID forwarded after infra-only auth is CANDIDATE.

**Severity adjustment.** Emit IDOR candidates at default severity (typically
High for state-changing operations). Phase 2b applies the Authorization
Delegation Rule (see phase2b_verify.md §8) which may downgrade to Medium or
Informational based on the audited code's crypto + caller-scope checks.

## Gate 0 Exemptions (NAV-specific)

The following are EXEMPT from Gate 0 dismissal:

- **CWE-639 in BFF/orchestrator/gateway services**: Forwarding is their purpose,
  but forwarding without verifying resource ownership is a missing authz check.
  Do not dismiss with "passthrough by design."
- **Identity Spoofing (CWE-290) / Security Signal Spoofing**: A request field
  flowing into an outbound identity or security-signal header breaks the trust
  binding regardless of whether the caller is authorized for the surrounding operation.

## Severity Floor (NAV-specific)

Unauthenticated management/admin/debug endpoint bound to a network-exposed
interface without application-layer authentication: **Medium** minimum (High
if the endpoint permits state modification — cluster membership, shutdown,
configuration changes). The absence of authentication in application code IS
the finding. Network-layer isolation is not a codebase-visible defense and
MUST NOT downgrade this. Per Phase 1: framework-managed endpoints that expose
operations without auth are findings even if they are not part of the
application's primary API routes.

## Missing Auth Assessment (all-NONE threat model)

When all three Phase 1 auth fields are NONE, evaluate each endpoint:

**CANDIDATE (CWE-306)** if the endpoint:
- Mutates or reads resources scoped to distinct principals (different account/user IDs), OR
- Uses a bearer-less identifier (correlation ID, reference ID in URL) as sole
  access control with no cryptographic session binding

**NOT a finding** if the endpoint:
- Is self-service initiation (caller IS the subject — e.g., submitting own application)
- Returns public information not scoped to any principal
- Is health/status/metrics

Severity: High for cross-principal state changes; Medium for cross-principal reads.

## Authorization Decision Points

Verify these are present, complete, and not bypassable:

- **Route/endpoint middleware**: auth decorators, role guards, permission annotations
- **Resource ownership queries**: DB lookups binding resource ID to caller
- **Session/token validation**: JWT verification, session store lookups, introspection
- **Field-level access control**: DTO filtering, role-based property stripping
- **Outbound security-signal headers**: headers conveying trust decisions to downstream
  services. If an attacker-controlled value is copied into a security-signal header,
  the attacker controls the downstream trust decision. An explicit copy is a separate
  finding from bulk header forwarding.

Adapt the specific API names to the detected language/framework.

## Vulnerability Classes

### Authentication & Authorization

- Missing or ineffective auth checks on sensitive endpoints (when a route
  declares an entitlement, role guard, or permission annotation, read the
  enforcing middleware/plugin source to verify it actually denies unauthorized
  callers — a declared annotation is not proof of enforcement; if the source
  is unreadable, treat as ineffective per Gate 2b rules)
- **Defined authorization helpers not invoked** (CWE-862): Grep for authorization
  helper functions in the codebase (`Can*`, `Has*Permission`, `check*Access`,
  `require*Role`, `authorize*`). For each state-changing handler that does NOT
  invoke any such helper while siblings in the same module DO, flag as CANDIDATE.
  This is an INDEPENDENT finding (CWE-862) — do NOT subsume it into, treat as
  "secondary to," or omit it because of co-located IDOR/CWE-639 findings at the
  same endpoint. Emit it as a full CANDIDATE entry with gate analysis.
- Broken session management
- Insecure password handling (plain text, weak hashing, no salting)
- JWT issues (none algorithm, weak secret, no expiry)
- **IDOR (Insecure Direct Object Reference)**: Apply the Resource ID Gate above.
  Every resource identifier must pass through that gate. A user-controlled identifier selecting which record a database
  operation reads or modifies is a NAV-class IDOR sink — do NOT classify as
  NO-MATCH because the downstream call is a database function. CWE-639.
- **Auth decisions on promotable server variables** (CWE-290): When session
  binding, IP-pinning, or rate-limiting compares against a server variable
  (remote_addr, client IP), cross-reference with Phase 1's promoted-variable
  inventory. If promoted via broad trust config, the auth decision is bypassable.
- **Conditional Validation Bypass**: Look for security-critical code blocks gated
  on the *presence* of a header, cookie, or parameter. If omitting it causes
  validation to be skipped rather than failing closed, that is a bypass.
  Also check **companion input** pattern: credential A used unconditionally, but
  validation of A only runs when companion B is present — omitting B bypasses A's
  validation. The fix must fail closed. Do NOT dismiss because "the downstream
  validates" — bypassed checks (session binding, IP binding, freshness, audience)
  enforce properties the downstream cannot. CWE-306.
- **CSRF**: For every state-changing endpoint (POST, PUT, DELETE, PATCH), verify
  that a CSRF token is validated. Check whether the framework provides automatic
  CSRF protection and whether it is enabled for all routes (not just a subset).
  Endpoints that accept JSON-only bodies with strict Content-Type checking may be
  exempt if the framework rejects cross-origin form submissions. CWE-352.
- **Identity Spoofing**: Look for user-supplied identifiers (user ID, employee ID,
  username, email) used for audit, attribution, or authorization without being
  cross-checked against the authenticated session/token. If the code trusts an
  identity from request body, custom header, or query param instead of extracting
  from verified session/JWT, that is impersonation. CWE-290.
  For each outbound identity header, enumerate ALL code paths that set it. If any
  path derives from an unverified source while another uses a verified source, the
  unverified path is a CANDIDATE.
- **Security Signal Spoofing**: Attacker-controlled values flowing into outbound
  headers used for risk decisions, rate limiting, automation detection, or trust
  classification. Common: inbound IP/client metadata → attribution headers, inbound
  flags → automation-detection headers. CWE-290. Distinct from bulk header
  forwarding (CWE-441) — an explicit copy into a security-relevant field is a
  specific sink.
- **Outgoing Credential Analysis (Confused Deputy)**: When the codebase makes
  outbound requests on behalf of a user, check what credentials are attached.
  Many services use a hybrid pattern: machine credentials for transport auth plus
  user-identity custom headers (session tokens, identity assertions, proof-of-possession
  tokens, user/profile reference IDs, on-behalf-of headers).
  **Evaluate each outbound call site independently.** If a call forwards user
  identity through custom headers, evaluate under the resource ID gate instead.
  Only flag as confused deputy when the downstream receives the service token AND
  no user identity through any channel.
- **Authorization-Scope Selection**: When user-controlled input selects from valid
  values (whitelist, enum, config key) that load different authorization policies
  or permission scopes: input validation (is value in set?) ≠ authorization (does
  caller have permission for this value?). Trace into the service layer to verify
  per-value authorization — and whether checks can be disabled by properties in the
  selected config (e.g., `skipValidation` flag).
- **Downstream Authorization Verification**: When tracing to an outbound API call,
  verify the downstream can enforce per-user authorization:
  (1) Does the request carry end-user identity via ANY mechanism — transport-layer
  token, custom headers (session tokens, identity assertions, user/profile IDs)?
  (2) Is the identity bound to the resource ID in a way the downstream can validate?
  If NEITHER a delegated token NOR custom-header identity is forwarded, do NOT
  credit downstream auth. When identity IS forwarded via custom headers, the
  confused deputy concern is eliminated but the IDOR concern remains.
- **Mass Assignment / Cross-Endpoint Field Injection**: Apply the Request Body
  Gate above. Every request body input must pass through that gate. CWE-915.
- **Parameter Pollution / Role Confusion**: Look for endpoints where fields
  intended for one actor type (admin, system, internal service) are modifiable
  by another actor through a shared endpoint or shared DTO. This differs from
  mass assignment in that the field may be explicitly defined on the DTO but
  should be restricted by role — the code just doesn't enforce role-based field
  filtering.

## MANDATORY Post-Trace Audit: Authorization Helper Coverage

Before finalizing partition results, compare auth calls across handlers in each
controller/module. Any handler that does NOT invoke authentication or authorization
functions while siblings DO → flag as CANDIDATE (CWE-306/862). This is a structural
absence check that forward-tracing alone cannot discover.

Exempt ONLY: CORS preflight (OPTIONS), login/auth-issuance endpoints, and literal
health-check endpoints. Emit each gap as a full CANDIDATE entry.

URL path conventions (`/protected/`, `/internal/`) are NOT proof of authentication.
Only credit verifiable middleware invocations, decorators, or guard code you can read.
