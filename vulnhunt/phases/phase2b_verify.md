# Phase 2b: Adversarial Verification

> **Context**: You have completed Phase 2 (Hunting) and produced candidate findings.
> Candidates were produced by **parallel trace agents**, each operating within a
> subgraph partition's file scope. Cross-subgraph defense visibility may be
> incomplete — a defense in one subgraph's shared infrastructure may not have been
> visible to another subgraph's trace agent. This is a primary reason this global
> verification phase exists.
> The severity tier definitions (High+/High/Medium/Low) from Phase 2 apply here.
> The orchestrator's Operating Principles and Investigation Discipline are in effect.

## Phase 2b: Adversarial Verification (MANDATORY — DO NOT SKIP)

**STOP. Before writing any report or presenting findings to the user, you MUST
complete this verification phase.** Every finding from Phase 2 is a *candidate*,
not a confirmed vulnerability. Your job now is to try to DISPROVE each one.

Historically, ~50% of candidate findings are false positives. If you skip this
step, you will embarrass yourself with bad findings. Take each candidate and
argue the opposing case — that it is NOT a real vulnerability.

### Candidate Manifest (MANDATORY — before any verification)

Before verifying anything, read every result file and build a flat list of all
CANDIDATE entries (one line per candidate: SG-N class VULN-ID, CWE, endpoint).
Count them. This count is your verification target — your final verdict table
MUST have exactly this many rows. If it has fewer, you silently dropped findings.
A candidate that was never listed in the table was never evaluated — that is a
verification failure, not an implicit rejection.

### Consensus-Skip (before full verification)

Before performing full source-level verification on each candidate, check trace
agent consensus:
- **Consensus Gate 1 fail** (all agents for that partition cite the same gating
  evidence at the same file:line): Record `"ELIMINATED — Gate 1 consensus
  [file:line]"` without re-reading source. No further verification needed.
- **Split decision** (agents disagree, or cite different evidence): Full
  verification required.
- **Any CANDIDATE disposition from any agent**: Full verification required.
- **Sink-driven agent candidates**: Always full verification.

Include consensus-skipped entries in the verification table marked
`"consensus-skipped"` for audit trail.

### For EACH remaining candidate finding, verify:

**Cross-subgraph visibility rule** (applies to all steps below): Trace agents
operated within their partition's file scope. Always search the FULL codebase
during verification — shared middleware/defenses may not have been visible to
the originating agent.

#### 1. Were all gates answered?

Check the candidate's Gate 0/1/2a/2b/3 fields. If any are blank, answer them now.
A blank gate is a red flag — it means the investigation shortcut past the checks.

**No-input elimination:** If a candidate has no attacker-controlled input (e.g.,
missing config field, error-handling default, operational failure mode), it fails
Gate 2a. Route to Code Quality, not VULN-NNN. Availability degradation under
operational failure is a reliability bug, not a security finding.

#### 2. Re-verify production reachability (Gate 1)

For each candidate, re-verify Gate 1 with fresh eyes. Now that all candidates are
assembled, you may notice patterns (e.g., multiple findings in the same module that
shares a dev-only route). Apply the same Gate 1 rules: route registration ≠ code
reachability, and shared library/middleware code is production code unless it
contains dev-only guards in its own source.

#### 3. What defenses exist between source and sink, and do they cover this attack?

Identify every defense between the attacker-controlled source and the sink.
For each defense, verify it actually blocks the attack — **read the actual library
source or docs**, don't assume. Search the **FULL codebase** for shared defenses
(middleware, auth, sanitizers, ORM base classes) — these may not have been visible
to the originating trace agent.

- **Auto-escaping**: Does the API auto-escape special characters? (regex quoting,
  ORM parameterization, template auto-escaping, URI encoding)
- **Type constraints**: Are values constrained by static types? (numeric columns →
  numeric values, not arbitrary strings)
- **Framework validation**: Does the framework validate at the boundary?

**Sanitizer scope mismatch is a vulnerability, not a mitigation.** If you find:
- `xss()` protecting a URL → HTML sanitizer doesn't encode `/`, `..`, `&`, `=`, `%`
- `encodeURIComponent()` protecting SQL → URL encoding doesn't prevent injection
- `htmlspecialchars()` protecting a shell command → HTML entities don't help

Then the sanitizer doesn't match the sink context. This is a finding, not a defense.

#### 4. Is the severity calibrated correctly?

Re-check the assigned tier against the severity definitions in Phase 2. Verify:
- Does the impact type match the tier? (e.g., RCE should be High+, not High)
- Is the attacker identity factored in? (unauthenticated → higher tier)
- Does exploitation require preconditions that warrant a tier adjustment?
  (race conditions, chained vulns, specific configurations → lower tier;
  single unauthenticated request → higher tier)
- For class-loading or deserialization findings, does a usable gadget actually
  exist? For crypto findings, is the weakness practically exploitable?

**IAM-delegated entry points:** When the only entry point requires a cloud IAM
permission and the IAM policy is out of scope, route unconstrained inputs to
Code Quality, not VULN-NNN. Promote only if this scan shows the permission is
broadly granted. This applies equally to AWS-managed queue/event consumers
(SQS, SNS, EventBridge) where producer access is gated by IAM / resource
policy — bare CWE-306 is Code Quality. IDOR via message contents (CWE-639),
cross-tenant confused-deputy, and downstream auth bypass remain in scope.

#### 5. Downgrade discipline

Before downgrading or eliminating ANY candidate, you MUST:
1. Grep for ALL call sites of the sink function (not just the path you traced)
2. Read each call site to verify what parameters are passed and whether
   attacker-controlled data reaches it
3. Trace callers of callers transitively if the sink is in a shared utility
4. Document each call site's reachability and exploitability status

A finding can only be downgraded when ALL call sites are verified non-exploitable.
If you checked one call site and it was safe, but there are 4 more you didn't
check, the finding is NOT cleared. Record this evidence in the verification table.

**Multi-writer property rule:** When dismissing a sink value as "server-controlled,"
grep for ALL write paths to that property (setter calls, storage key writes,
direct field assignments). A property with N writers is only server-controlled
if ALL N are server-controlled.

**SAFE spot-check:** For each subgraph, re-verify Gate 2b on the 2-3 SAFE
inputs closest to dangerous sinks (URL construction, redirects, template
rendering, outbound identity/audit headers, rate-limit/auth gating logic)
with a fresh Read/Grep call.

**Sink-coverage gap check:** After verification, grep for redirect sinks
(sendRedirect, response.redirect, Location header, res.redirect, window.location)
and authentication-sensitive operations (login, credential issuance, account
enumeration). For each sink found:
- No disposition at all → gap. Trace backward from sink.
- Has a disposition, but receives data from multiple distinct sources (different
  services, response fields, or state properties) → verify each source→sink
  path is independently traced. One finding covering one data flow does NOT
  clear other flows to that same sink.

**Co-parameter gap check:** For each confirmed or reduced-confidence finding,
list every user-controlled parameter at that endpoint. Each must have its OWN
disposition — mentioned in another parameter's data flow does not count.
Resource IDs need an ownership evaluation. Missing? Evaluate now.

**Sibling auth-pattern comparison:** For each controller/router file encountered
during verification, compare authentication across all handlers. Any handler
omitting auth while siblings require it is a CANDIDATE (CWE-306). If a trace
agent noted the gap in prose but did NOT emit a formal CANDIDATE entry, elevate
it to a CANDIDATE now.

#### 6. Conditional Validation Bypass verification

For each CVB candidate (CWE-306), enumerate every check skipped when the gating
input is absent. The finding is eliminated ONLY if ALL are covered downstream:

| Bypassed Check | What it enforces | This service validates? | Downstream covers? | Evidence (file:line) |
|---|---|---|---|---|

One "No" = finding stands. Do NOT dismiss with design-intent reasoning,
"downstream validates the credential," or "the input is optional" — these
are explicitly prohibited by Phase 2 CVB rules.

#### 7. Comment skepticism

For every dismissed or downgraded finding, check whether any gate was satisfied
by prose (code comments, naming, docs) rather than verified code behavior:

| Prose pattern | Gate it falsely satisfies |
|---|---|
| "by design" / "intentional" / "backward compat" | Gate 0 |
| `sanitize()`, `validate()`, `safe*()` naming | Gate 2b |
| "downstream validates" / "API gateway checks" | Gate 3 / elimination |
| "internal only" / "not user-facing" | Gate 1 |
| "type-safe" / "schema validated" | Gate 2b / mandatory gates |
| "ALB authenticates" / "infrastructure handles auth" / "pre-authenticated traffic" / `/protected/` path / Swagger Bearer definition | Resource ID gate (a) / Gate 0 for IDOR |
| "admin endpoint" / "management API" / "internal tool" / purpose implies restricted access | Gate 0 — endpoint naming is not proof of access control; cite enforcement code at file:line |

If any gate was satisfied by prose, re-verify it empirically.

#### 8. Authorization Delegation Rule (CWE-639 severity adjustment)

For each IDOR / Resource-ID-Gate candidate, apply this severity ladder ONCE.
Read the auth gate the handler calls (PoP/mTLS validator, header checks).

| Crypto origin auth | Caller-scope check | Severity |
|---|---|---|
| ✓ | ✓ | **Informational** |
| ✓ | ✗ (neither) | **Medium** |
| ✗ | — | Original (typically High) |

- **Crypto origin auth (✓):** PoP token signature OR mTLS client cert verified
  in audited code at file:line. Header-presence checks (`if OAuth_ResourceOwnerUID is not None`,
  `require_uid_header=False`-style optionality) do NOT qualify. If the gate is
  bypassable on any path (CVB, ENV branch), treat as ✗.
- **Known PoP library:** A dependency whose import path matches `*<your-gateway>*`
  is PoP token validation. When `Validate`/`validate` or a token-validation handler
  is called on a production path (not inside an ENV-skip guard), crypto origin
  auth = ✓. Do not require reading the library source to confirm.
- **Caller-scope check (✓):** EITHER:
  (a) A verified end-user identifier (`OAuth_ResourceOwnerUID` header, present for
  both customer/external and SSO-authenticated internal users) confirmed present and bound to
  the operation. Cite file:line. OR
  (b) the gateway-set caller-app header (e.g. `x-apigw-app-id` or equivalent) validated
  against an in-code trusted-caller allow-list, BUT ONLY when `OAuth_ResourceOwnerUID`
  is confirmed NOT present in the request. If an `OAuth_ResourceOwnerUID` header is
  present alongside the app-id, the allow-list path does not qualify — use option
  (a) instead. This prevents accidental allow-listing of upstream callers on flows
  where a real end-user principal is available.
- Comments/naming claiming "GW handles this" do NOT count. Cite executable code.

When downgrading, record a one-line trust-model note (e.g., "PoP-validated GW
+ OAuth_ResourceOwnerUID present → upstream entitlements enforces ownership before forwarding")
on the candidate. This note carries through to Phase 3 and the final report.

#### 9. Universal Auth Gap (rollup)

In-scope handlers = Phase 1 Step 1b entry points that read/write user
data, mutate state, or return identifiable-resource info, EXCLUDING
the authentication system itself (login, logout, token refresh,
password reset — these handle auth, they don't *consume* it). Run
ONCE before the verdict table.

**A — AUTHN absent** (zero handlers have valid auth code; all-weak
counts as absent — if every handler does `verify=False` or has
commented-out signature checks, rollup fires). Auth code = ANY of, in
the handler's call chain (body / middleware / decorator / framework
dependency): token-verify call (verification actually happens — not
`verify=False`, not commented-out signature checks), session validate,
mTLS check, auth decorator (`@login_required`,
`Depends(get_current_user)`, `@PreAuthorize`), `*<your-gateway>*`
PoP. If ZERO handlers have any valid auth code → emit ONE
`VULN-PLATFORM-AUTHN` (High, CWE-306). Subsume CONFIRMED CWE ∈
{287, 306, 441, 639, 862, 863, 915, 1390}.

**B — AUTHZ absent** (A doesn't fire AND no handler binds a verified
UID to the operation or allow-lists a caller-app header (§8)): emit
ONE `VULN-PLATFORM-AUTHZ` (Medium, CWE-862). Subsume CONFIRMED CWE ∈
{441, 639, 862, 863, 915}.

If both fire, only A fires. Zero in-scope handlers → §9 N/A. The
Anti-merge rule does NOT apply. Subsumed findings stay in the verdict
table marked `SUBSUMED-BY: VULN-PLATFORM-*` for Phase 3d / re-scan;
not surfaced as separate findings. Platform PoC + exploit test stand in.

### Verification Output

**You MUST present this table to the user before proceeding to Phase 3.**

For each candidate finding, record the verification result:

| Finding | Gates complete? | Production-reachable? | Defenses cover attack? | Severity correct? | All call sites checked? | Verdict |
|---|---|---|---|---|---|---|
| VULN-001 | Yes | 2 of 5 call sites reachable | No mitigation found | Yes — High | 5/5 verified | CONFIRMED (reduced scope) |
| VULN-002 | Yes | No — `txnLog` written by coordinator at engine.go:441 | N/A | N/A | 3/3 verified non-exploitable | FALSE POSITIVE |
| VULN-003 | Yes | Yes | xss() — scope mismatch, not a defense | Yes — High | 4/4 verified | CONFIRMED |

**FALSE POSITIVE verdicts require evidence.** Every FALSE POSITIVE must cite the
specific file:line of the defense, type constraint, or non-attacker origin that
eliminates it. "No — transaction log" is not sufficient; "No — `txnLog` written
by coordinator at engine.go:441, no user-reachable write path" is. If you cannot
cite a specific code location, the finding is not eliminated.

**Anti-merge rule:** (exception: §9 Universal Auth Gap rollup) Do NOT merge, subsume, or consolidate findings that differ in
any of: (a) attacker authentication level, (b) entry point / route, (c) gateway
or middleware context, or (d) the user-controlled parameter exploited. Findings
operating on different parameters at the same endpoint are separate vulnerabilities
even if they share a "chain" narrative. A finding is NOT subsumed by another merely
because it could form a second step — if pre-existing data (e.g., a built-in role
ID, a system-generated resource) makes the finding independently exploitable without
the "first step" finding, it stands alone. Each must have its own verdict row.
Silent omission IS merging — a candidate with no row in the verification table was
implicitly subsumed, which violates this rule. Common implicit-merge failure: mass
assignment (CWE-915) dropped when IDOR (CWE-639) exists at the same endpoint. These
have different exploited parameters (body fields vs. resource ID), different impacts,
and different fixes — they are always separate findings.

**Drop all FALSE POSITIVE findings.** Only CONFIRMED findings proceed to Phase 3.
If zero findings survive, report that no exploitable vulnerabilities were found
and list code quality recommendations instead.
