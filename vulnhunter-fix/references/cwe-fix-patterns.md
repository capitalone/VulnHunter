# CWE Fix Patterns

**Referenced by:** REQ-CWE-002, REQ-CWE-003. Consumed by Phase 3
(Implement) CWE-routing logic in `prompts/plan.md` / `prompts/implement.md`
and by the five CWE-class worker prompts under
`prompts/worker_agent_*.md`.

Each section names one CWE class, its constituent CWE IDs, the canonical
fix shape, discrimination criteria, and the FULL-tier bar. Workers must
reference these patterns when authoring the fix; deviations require an
explicit rationale in the plan artifact.

---

## Class 1 — Authorization (`worker_agent_authz.md`)

**CWEs:** CWE-287, CWE-290, CWE-306, CWE-639, CWE-862, CWE-863, CWE-915.

**Canonical fix shape:**
1. Identify the resource the caller is attempting to touch (subject / object).
2. Move the authorization check to the earliest deterministic path
   (middleware, route decorator, or method entry — not deep inside the handler).
3. Fail closed: default `deny`; explicit `allow` only after an identity-and-role check
   resolves against the resource owner or an ACL.
4. Verify the check runs on the server, not on the client (never trust
   `X-User-Id` headers or query parameters as the sole identity signal
   without an authenticated context).

**Discrimination criteria (REQ-GRA-017):**
- Pre-fix: Request from user A can read/mutate user B's resource.
- Post-fix: Same request returns 403 (or 404 if enumeration is a concern).

**FULL-tier bar:**
- All callers of the sink are re-routed through the authorized entry path.
- No fallback code path exists that bypasses the check (`if is_admin or
  legacy_flag:` is not FULL).
- Discrimination test uses two distinct user contexts.

---

## Class 2 — Injection (`worker_agent_injection.md`)

**CWEs:** CWE-22, CWE-78, CWE-79, CWE-89, CWE-94, CWE-352, CWE-434, CWE-502, CWE-601, CWE-611, CWE-918.

**Canonical fix shape:**
1. Identify the sink (query builder, `subprocess`, `render_template_string`,
   `eval`, `pickle.loads`, HTTP client, XML parser).
2. Replace ad-hoc concatenation with a **structural separator** appropriate to
   the sink:
   - SQL → parameterized query / prepared statement.
   - Shell → argv list (`subprocess.run([...], shell=False)`) or a
     whitelist-validated argument.
   - HTML → context-aware auto-escape at render time.
   - Path → canonicalize + prefix-match against an allowlist root.
   - Deserialization → schema-validated JSON / Pydantic / equivalent — never
     `pickle` on untrusted input.
   - XML → parser with `resolve_entities=False`.
   - URL → allowlist scheme+host, or DNS+IP re-resolution against an
     internal-network blocklist.
3. Reject the input at the boundary rather than sanitize; sanitization is a
   MITIGATION signal, not FULL.

**Discrimination criteria:**
- Pre-fix: Payload from the finding's PoC executes / exfiltrates / redirects.
- Post-fix: Same payload is rejected at the boundary with a structured error.

**FULL-tier bar:**
- Sink is called only via the safe API; the unsafe API is removed or
  private-scoped.
- No ambient input reaches the sink (context-boundary crossings are
  re-validated).
- Discrimination test uses the scan's exact PoC payload.

---

## Class 3 — Crypto (`worker_agent_crypto.md`)

**CWEs:** CWE-295, CWE-326, CWE-327, CWE-328, CWE-330, CWE-345, CWE-347.

**Canonical fix shape:**
1. Replace the algorithm/mode with an approved one per
   `references/approved-crypto-algorithms.yaml`.
2. Source keys from Chamber of Secrets or AWS KMS
   (`references/approved-key-sources.yaml`); never from env vars, literals,
   or the filesystem.
3. Establish a rotation mechanism at the same commit (rotate call site,
   KMS `ScheduleKeyDeletion`, CronJob calling rotation, etc.).
4. Enforce TLS/mTLS at the transport boundary implicated by the fix.

**Discrimination criteria:**
- Pre-fix: Ciphertext can be forged, replayed, or brute-forced under the
  finding's threat model.
- Post-fix: The same forgery/replay attempt fails; the signature/HMAC
  verification is enforced.

**FULL-tier bar (REQ-CWE-007):**
All four booleans in `plan.crypto_trust_chain` must be `true`:
- `algorithm_approved`
- `key_source_approved`
- `key_rotation_present`
- `transport_encrypted`

If any boolean is `false`, the worker classifies `MITIGATION` and enumerates
the failing dimension as a `trust-chain:` residual entry (per
`residual-risk-rules.md` Rule R-5).

---

## Class 4 — Resource (`worker_agent_resource.md`)

**CWEs:** CWE-117, CWE-200, CWE-362, CWE-400, CWE-532.

**Canonical fix shape:**
1. Identify the resource being over-consumed or under-guarded (CPU, memory,
   file handles, log volume, sensitive fields).
2. For CWE-400: apply a bounded limit — timeout, semaphore, connection cap,
   memory ceiling. Emit a structured error on breach.
3. For CWE-362: replace check-then-act with an atomic operation (CAS, DB
   unique constraint, file-lock, transactional insert).
4. For CWE-117/CWE-532: apply PII masking at the log call site
   (never at the transport layer); use structured logging fields, not
   string interpolation.
5. For CWE-200: remove the sensitive field from the response, don't
   obfuscate it.

**Discrimination criteria:**
- Pre-fix: Resource-exhaustion payload succeeds within scan-stated bounds,
  or sensitive field appears in log / response.
- Post-fix: Payload is rejected with a bounded error / field is absent.

**FULL-tier bar:**
- The limit or masking is at the correct layer (sink, not upstream).
- No unbounded fallback exists (no "if limit fails, allow through").
- Discrimination test asserts the exhaustion or leak was actually observed.

---

## Class 5 — Configuration (`worker_agent_config.md`)

**CWEs:** IaC / IAM findings without a specific numeric CWE (typical: S3 public bucket, over-permissioned IAM role, missing IMDSv2, unencrypted RDS, permissive security group, missing WAF, missing MFA, etc.).

**Canonical fix shape:**
1. Modify the declarative artifact (Terraform, CloudFormation, Kubernetes
   manifest, Helm values) — never a runtime workaround.
2. Restrict to least privilege: explicit deny of the public/wildcard state,
   explicit allow of the required principals only.
3. Enable the C1-standard control (encryption at rest, IMDSv2, VPC
   endpoints, WAF, MFA) at the source, not via drift-corrector.

**Discrimination criteria:**
- Pre-fix: `tfsec` / `checkov` / equivalent asserts the finding is present.
- Post-fix: Same tool asserts the finding is gone.

**FULL-tier bar:**
- No drift-corrector or scheduled remediation loop compensates for the
  declarative artifact.
- No Python TDD is required for this class (config-only); the
  discriminating test is the static-analysis tool assertion in CI.

---

## Unmapped CWEs

If a finding's primary CWE is not listed above, the executor routes to
`worker_agent_common.md` alone with a diagnostic line
(REQ-CWE-003). The worker still applies the shared TDD cycle but lacks
class-specific guidance. Add the CWE to the appropriate class file in a
follow-up PR.
