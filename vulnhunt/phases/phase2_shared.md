# Trace Agent Shared Instructions

These instructions apply to ALL class-group trace agents (INJ, NAV, LOG). Read your class-specific file AFTER reading this file.

### Iteration Rules

**For each input in the inventory:**

1. **Trace forward** from where the input enters the codebase. Follow it through
   every assignment, function call, and transformation until it either:
   - (a) reaches a dangerous sink without effective sanitization → **candidate**
   - (b) is proven sanitized or type-constrained before every sink → **safe**
   - (c) exits the codebase (returned to caller, logged, discarded) → **safe**
   - (d) reaches a store (DB, cache, queue, in-memory state, session/global
     variable) → grep for ALL readers and trace EACH forward independently
     (second-order flow). Do NOT record NO-MATCH at a store boundary. You must
     exhaust every consumer before concluding SAFE — one consumer being safe does
     NOT clear others.
     **Boolean-gate trap:** A presence check (`if (param) { ... }`) is NOT a
     disposition — the VALUE is often extracted and stored in the same block.
     Trace the stored value, not just the branch.

   **⚠ MANDATORY GATE — request body inputs:** If this is a request body (DTO,
   struct, model) AND your class group is **NAV**, execute the "Request Body Gate"
   in your class file BEFORE recording any disposition. CWE-915.
   **INJ/LOG agents:** Trace body fields to your class sinks normally. If the body
   type lacks field-level authorization filtering, flag as CROSS-CLASS(NAV, CWE-915).

   **⚠ MANDATORY GATE — resource ID inputs:** If this is a path param, query param,
   or body field containing an ID AND your class group is **NAV**, execute the
   "Resource ID Gate" in your class file BEFORE recording any disposition. CWE-639.
   **INJ/LOG agents:** Trace the ID to your class sinks normally. If you notice it
   lacks an ownership check before reaching a sensitive operation, flag as
   CROSS-CLASS(NAV, CWE-639).

2. **Check all code paths**, not just the first one. If the input is used in 3
   places, trace all 3. An input sanitized on one path may be unsanitized on another.
3. **Continue tracing past the first finding.** The same tainted variable may
   reach additional independent sinks — each is a separate CANDIDATE with its own
   CWE, severity, and gate evaluation. Sinks in different files, calling different
   APIs, or requiring different fixes are **separate candidates**. Test: if fixing
   one would NOT fix the other, they are separate findings.
4. **Record the disposition** for this input in the inventory:
   - **CANDIDATE** (input #, sink file:line, vuln class) → proceeds to gates
   - **SAFE** (input #, reason: sanitized / type-constrained / not reaching sink)
   - **DESIGN-INTENT** (input #, reason: this is the application's intended function)
   **Severity-context check:** Before recording a candidate's CWE, verify you
   classified under the **highest-severity context** the sink accepts. If the
   sink operates on a scheme, format, or mode selected by attacker input (URI
   scheme, content-type, file extension, serialization format), evaluate the
   most dangerous value the attacker can supply — not just the expected one.
   Cite the validation that restricts to the lower-severity context, or
   reclassify upward.
   **Sanitizer-sink match check:** Before recording SAFE based on sanitization,
   verify the sanitizer covers the sink's dangerous characters. Mismatches:
   - HTML sanitizer (xss, escape, htmlspecialchars) on URL sink → NO (`/`, `..`, `&`, `=`, `%` pass through)
   - URL encoder on SQL/command sink → NO
   - Format validator (regex, schema) on injection sink → NO (validates shape, not content)
   If mismatch → CANDIDATE, not SAFE.
5. Move to the next input.

**Absent-input analysis (MANDATORY after completing the inventory):**
After tracing all inputs that ARE present, go back and check what happens when
each input is **absent**. The attacker controls not just the values of inputs
but also which inputs are sent at all. For each input in the inventory that
gates a security-critical code block (authentication, authorization, session
validation, CSRF check, rate limiting), ask:

> "If this input is omitted from the request, does the security check
> **fail closed** (deny access) or **fail open** (skip validation)?"

Read the code path that executes when the input is missing/null/undefined.
If the code skips the security block entirely — e.g., `if (cookie) { validate(); }`
with no `else { deny(); }` — that is a **Conditional Validation Bypass** candidate.
The vulnerability is not in the input itself but in the code's behavior when
the input is absent.

This check catches a class of bugs that forward-tracing misses: when two inputs
interact (e.g., access_token is used unconditionally but session validation only
runs when sc_session is present), tracing each input individually marks both as
SAFE, but omitting one causes the other to be used without validation.

CVB findings are **immune to DESIGN-INTENT and Gate 0 dismissal** — the test is
"can an attacker exploit the conditional to bypass security checks?"
**Exception:** bypass gated by an environment-classification env var (`ENV`,
`NODE_ENV`, `STAGE`, etc.) firing only for non-production values (`dev`, `local`,
`localstack`, `test`, `mock`) → not production-reachable; eliminate via Gate 1.

**Completeness check after all inputs are traced:**
Every row in the inventory must have a disposition. If any input has no disposition,
it was not fully traced — go back and complete it before proceeding to verification.

**Authentication branch enumeration (MANDATORY for multi-auth endpoints):** When
an entry point supports multiple authentication methods via branching, enumerate
EVERY branch as a distinct authentication path. For each branch, verify:
1. What credential is required? (cryptographic token, API key, query parameter, nothing?)
2. Is the credential cryptographically verified?
3. What identity does the branch produce? (from verified token claim, unverified param, header?)
4. What authorization scope does this identity receive downstream?

A weaker-credential branch is a **distinct finding** even if gated behind a caller
whitelist — the whitelist validates the *caller*, not the *identity being asserted*.

For large codebases, work through the inventory in batches grouped by entry point
to keep context coherent. But every input must be resolved.

Do NOT switch to entry-point-driven or sink-driven hunting. Input-driven tracing
eliminates selection bias, ensures coverage (you know what you haven't traced), and
naturally discovers second-order flows when tracing into stores.

### HARD GATES — For Each Potential Vulnerability Found

Every candidate MUST pass these gates IN ORDER before being written up. Each gate
is cheap (1-2 tool calls). If a gate eliminates the finding, STOP immediately.
**If delegating to sub-agents, include these gates AND the "exhaust all callers"
rules in the sub-agent prompt.** Findings without recorded gate results are
automatically suspect.

**Gate 0: Is this the application doing what it is designed to do?**

Before evaluating whether input is "attacker-controlled," determine whether the
data flow is the application's **core design purpose**. A vulnerability is when
an application does something its designers did not intend. A feature working as
designed is not a vulnerability, even if the caller controls the input.

**Eliminate** if the data flow is an intentional feature serving the caller:
- **Reverse proxies, API gateways, and forwarding middleware** are designed to
  relay the caller's request (headers, body, query parameters, path) to a backend
  service. The caller controlling these inputs is the entire point — it is not
  "header injection" or "SSRF" for a proxy to forward what it was asked to forward.
  Only flag proxy forwarding if the proxy *adds trust-sensitive metadata of its own*
  (e.g., `X-Authenticated-User`, internal routing headers) that a caller could
  spoof, or if the proxy explicitly claims to sanitize/filter inputs but does so
  incompletely.
- **Caller-supplied keys, output formats, locales, callback URLs, webhook targets** —
  if the feature exists for the caller's own use, controlling it is by design. Only
  flag if it bypasses an authorization boundary (caller obtains data/access they
  wouldn't otherwise have).

**Decision test:** "If I removed this input, would the application lose an
intentional feature?" If yes → feature parameter, not attack vector. Move on.

**Gate 0 does NOT apply** when the "designed behavior" is a security check being
conditionally skipped. A feature that optionally disables validation is a
vulnerability in the validation, not a feature working as intended.

Your class-specific file may contain additional Gate 0 exemptions for your
vulnerability class. Apply those after this generic Gate 0 evaluation.

**Gate 1: Is the code reachable?**
Use the **Grep tool** to search for all call sites of the suspect symbol across
the codebase. Use the `glob` parameter to restrict to production source file
extensions and exclude test directories.

Exclude test files from the results. If 0 production usages are found, this is dead
code. Record as "dead code, not a vulnerability" and move on. Do not trace data flows,
construct PoCs, or propose fixes for dead code. This check is one tool call — never skip it.

**CRITICAL: Exhaust ALL callers — this applies to Gate 1 too, not just later gates.**
If a symbol has N call sites, check EVERY one for production reachability. A function
called from one dev-only route and one production route IS production-reachable. Do
not bulk-eliminate based on a single caller.

**Route registration ≠ code reachability.** A handler or library function is
production code unless it contains explicit dev-only guards in its own source.
A dev-gated route mounting it does NOT make the code dev-only — it may be
reachable via other routes or deployment configurations. When eliminating, verify
the **sink code itself** (not just the route) is unreachable.

**When the discovery path fails Gate 1, re-search from the sink function** — grep
for all importers transitively until you find a production path or exhaust the
chain. Only eliminate when ALL paths are verified non-production.

**Gate 2a: Is the input attacker-controlled?**

Verify from the forward trace that the input reaching this sink is genuinely
attacker-controlled. The forward trace already identified the data flow — this
gate confirms the origin:

- Does this value come from **user input** (HTTP body, query param, CLI arg,
  queue message, config set by user) — or from **framework/internal metadata**
  (transaction logs, partition discovery, ORM-generated values, internal state)?
- **Verify indirect control.** If the value comes from a store, trace who writes
  to it. Follow the chain through multiple hops — user input → store A → service
  reads A → store B → sink is still attacker-controlled. Stop only when you reach
  a provably trusted origin (hardcoded value, server-generated ID, framework-managed
  state) or confirm no attacker-reachable code path can write to the store.

If the input is NOT attacker-controlled, eliminate the finding. If it IS
attacker-controlled, proceed to Gate 2b. Do NOT check for sanitization here —
that is Gate 2b's job.

The following applies ONLY to **data processing frameworks** (Spark, Flink, Hadoop,
Delta Lake): If the value comes from the user's own query, they are attacking
themselves. If from stored data, check whether writing to that store requires
equal or higher privileges than the attack — if so, not a privilege escalation.

**Gate 2b: Is there effective sanitization between source and sink?**

Now that you know the input is attacker-controlled, check whether it is
neutralized before reaching the sink:

**Exhaust ALL callers for sanitization too.** If a sink has N call sites and the
first one sanitizes input, you MUST check the other N-1. A safe caller does NOT
clear the finding — only proving ALL callers sanitize clears it. Each unsanitized
caller is a separate finding.

**Empirically verify what the defense does — do NOT rely on your training
knowledge.** Your training data about library behavior may be wrong, stale, or
incomplete. For EVERY defense (sanitizer, middleware, framework feature) in the
data flow, you MUST:
  - **(a)** Read the defense's source code and confirm it actually blocks the
    attack, OR
  - **(b)** If the source is unavailable, **treat the defense as ineffective** —
    do NOT assume it works. Proceed to Gate 3 with the finding intact.

Verify the defense matches the context. A sanitizer for one context does NOT
protect a different context (e.g., HTML sanitizer on URL sink — does not encode
`/`, `..`, `&`, `=`, `%`). For URL-construction sinks specifically, verify that
path-separator characters (`/`, `..`, `%2f`) and query-separator characters
(`?`, `&`, `=`, `#`) are neutralized — encoding only HTML metacharacters is
insufficient.

- **Language-level auto-sanitization**: Does the language/framework auto-prevent
  this? (e.g., ORM parameterization, template auto-escaping, type constraints).
  Apply the same empirical standard — read the framework source to verify it
  covers this specific context.
- **Database constraints as mitigations**: Foreign keys, UNIQUE constraints,
  column type enforcement, CHECK constraints — verify by reading schema.

For INJ-class findings, your class file contains the full sanitizer verification
methodology (options a/b/c with executable test construction). Use that expanded
procedure for injection sinks.

If effective, context-matched defense exists between source and sink, the finding
is eliminated. If not, proceed to Gate 3.

**Gate 3: Does the attacker gain a NEW capability?**

You must AFFIRMATIVELY demonstrate what new outcome the attacker achieves.
"I could not find a path that gives the same outcome" is NOT sufficient for
confirmation — you must state concretely what the attacker GETS. If the
exploit test proves the mechanism works (crypto is reversible, injection
reaches the sink, redirect fires) but you cannot articulate a concrete
outcome the attacker could not already achieve, the finding is a Code Smell.

The exploit test for Gate 3 must prove the OUTCOME, not the MECHANISM.

**Eliminate** if you can cite the specific code path (file:line) that gives
the attacker the same outcome without this vulnerability:
- Config-setter who can already execute code via other config keys — cite the key
  and the code that executes it
- Storage-writer who can already corrupt reads by overwriting data files — cite the
  write path and the read path
- SQL-submitter who can already read the tables they'd access via injection — cite
  the query interface that already exposes the same data

**Also eliminate** if the finding proves a mechanism but not an outcome (e.g.,
reversible key but a plaintext fallback exists; injection reaches sink but value
is ignored; redirect fires but only to hardcoded safe domain).

You must show the attacker can already achieve the same *outcome* (same data
exfiltrated, same command executed, same service reached) via a specific existing path.

Your class-specific file may contain additional "Do NOT eliminate" rules for your
vulnerability class. Apply those after this generic Gate 3 evaluation.

- **Do NOT reduce severity, downgrade, or eliminate findings based on speculated
  defenses — upstream OR downstream.**
  "The API gateway probably normalizes path traversal," "the downstream service
  likely ignores unknown parameters," "there's probably an ALB in front that
  appends the real IP," "the port is probably not directly accessible" — these
  are all assumptions about infrastructure you haven't verified. Only count
  defenses you can cite at a specific file:line in the audited codebase.
  Network topology, load balancer behavior, security groups, WAF rules, and
  other infrastructure controls are NOT in the codebase and MUST NOT be used
  to downgrade or eliminate findings. If the code says `set_real_ip_from
  0.0.0.0/0`, report what the code does — do not speculate that a load balancer
  might mitigate it.
  This includes container/orchestrator-level isolation. If no enforcing manifest
  is in the repository AND wired into application startup, it does not exist.

**Gate 3 exemption:** CWE-306/639 findings are immune to Gate 3 elimination
when the baseline derives from all-NONE auth fields. Missing auth cannot
pre-authorize the operations it fails to protect. Route to NAV "Missing Auth
Assessment."

---

After passing all gates, complete the investigation:

**Document the full data flow** from input source to vulnerable sink, using the
forward trace already performed during hunting. Use the **Grep tool** to verify
any steps you're uncertain about. The documented flow must include file:line at
each step and confirm the data propagates without sanitization.

**Read the actual source code** to confirm it's real, not a false positive.
**If build-time code swapping exists (Phase 1, Step 4), read the production
source variant, NOT the build output.** Check for:
- Validation/sanitization between source and sink
- Framework-level protections (ORM parameterization, template auto-escaping)
- Security middleware that may not be visible in the direct call chain

**Classify severity** using the tier definitions below (not numeric CVSS). When a
vulnerable function has multiple callers, the worst-case caller determines tier.

**High+** — Unauthenticated or low-privilege attacker achieves:
- Remote code execution or OS command execution
- Full database read/write (SQL injection with no row-level restrictions)
- Authentication bypass granting access to any account
- Arbitrary file read/write on the server

**High** — Authenticated or constrained attacker achieves:
- Unauthorized data modification or deletion across trust boundaries
- Privilege escalation (user → admin, tenant A → tenant B)
- PII / credential exposure across trust boundaries
- SSRF reaching internal services with service-level credentials
- Audit trail manipulation (attacker can cover their tracks)

**Medium** — Exploitation requires user interaction or yields limited impact:
- Unauthorized read access to non-sensitive data
- Stored/reflected XSS requiring victim interaction
- CSRF on state-changing but non-critical actions
- Open redirect (phishing enabler, not direct data access)
- Information disclosure via error messages or debug endpoints

**Low** — Exploitation requires privileged position or yields minimal impact:
- Log injection (attacker can write misleading log entries)
- Findings requiring a compromised internal service as prerequisite
- Theoretical issues with no demonstrated practical exploit path
- Header injection with no proven downstream impact

**Informational** — Real authorization gap bounded today by a verifiable upstream
trust control in the audited code. Applied by the Authorization Delegation Rule
(phase2b_verify.md §8). Still gets VULN-NNN + full data flow + PoC; classification
only, not dismissal.

**Adjustment factors** (move up/down one tier): unauthenticated → higher, admin-only
→ lower; single request → higher, race/chain required → lower; all users affected
→ higher, self-only → lower.

**Minimum severity floors** (cannot be downgraded below these regardless of
adjustment factors or speculated impact limitations):
Your class-specific file may define additional severity floors. Apply those
in addition to the universal rule below.

Only count defenses visible and verified in the audited codebase. Do not reduce
severity based on assumed defenses — upstream or downstream — including load
balancers, API gateways, network segmentation, WAFs, security groups, or other
infrastructure you cannot inspect from the codebase. If attacker-controlled input
crosses a trust boundary with service credentials, treat the impact as if the
downstream system processes it as-received. If a config directive weakens a
security assumption (e.g., trusting all IPs for XFF), report what the config
does — do not speculate that network infrastructure might compensate.

**Narrow exception** — When the audited code itself cryptographically authenticates
the upstream caller (PoP signature OR mTLS cert verification, cited at file:line),
the Authorization Delegation Rule (phase2b_verify.md §8) MAY downgrade IDOR
findings to Informational or Medium. A dependency matching `*<your-gateway>*`
is PoP validation — cite the middleware mount at file:line. Header-presence checks
do NOT qualify; comments/naming do NOT count.

### Candidate Output Format

For each candidate vulnerability (these are NOT confirmed yet — Phase 2b will filter):

#### [VULN-NNN] Title
- **Input**: [inventory # and description — e.g., "#7: HTTP header x-correlation-id"]
- **Class**: [CWE-XXX: Name]
- **Severity**: High+ / High / Medium / Low / Informational
- **Location**: file:line
- **Gate 0 (intended behavior?)**: [is this the application's designed purpose?]
- **Gate 1 (reachable?)**: [Grep usages result — N production call sites found]
- **Gate 2a (attacker-controlled?)**: [who controls the input, traced to origin]
- **Gate 2b (sanitization?)**: [what sanitization exists, does it match the sink context]
- **Gate 3 (new capability?)**: [what attacker gains vs. what prerequisite already gives]
- **Entry Point**: [which route, CLI command, queue consumer, or other entry point receives this input]
- **Data Flow**: input source -> ... -> sink (with file:line at each step)
- **Root Cause**: [1-2 sentence explanation]
- **Exploitability**: [assessment of how practical exploitation is]
