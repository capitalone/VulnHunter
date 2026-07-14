# Worker Agent — Crypto (CWE-295/326/327/328/330/345/347)

**Extends:** `worker_agent_common.md`. Read that file first.

**Canonical fix pattern (per `references/cwe-fix-patterns.md` Class 3):**

1. Replace algorithm/mode with an approved one from
   `references/approved-crypto-algorithms.yaml`.
2. Source keys from Chamber of Secrets or AWS KMS
   (`references/approved-key-sources.yaml`).
3. Establish a rotation mechanism at the same commit.
4. Enforce TLS/mTLS at the transport boundary.

## Trust-chain gate for FULL tier (REQ-CWE-007)

**This class has a hard, mechanical bar.** Grant
`completeness_tier: FULL` if and only if the plan artifact's
`crypto_trust_chain` carries ALL four booleans set to `true`:

- `algorithm_approved`
- `key_source_approved`
- `key_rotation_present`
- `transport_encrypted`

Values come from the triage sidecar (REQ-CWE-008), which the executor
populated via mechanical checkers (REQ-CWE-009) at
`.work/<repo>/graph_context/<vuln>.json`. The worker MUST NOT compute
these itself — read them from the plan.

If any boolean is `false` (or missing), you MUST classify `MITIGATION`
with a `trust-chain:` residual entry per
`references/residual-risk-rules.md` Rule R-5:

- `trust-chain: algorithm not on approved list`
- `trust-chain: key source not approved (Chamber / KMS)`
- `trust-chain: rotation mechanism not detected`
- `trust-chain: transport encryption not detected at fix boundary`

Multiple `false` booleans → multiple residual entries (one per).

## Discrimination requirements (Step E.5)

- Pre-fix: ciphertext can be forged, replayed, or brute-forced under
  the finding's threat model.
- Post-fix: the same forgery/replay attempt fails; signature/HMAC
  verification is enforced.

## Anti-patterns

- Bumping key size without changing algorithm (e.g., RSA 1024 → 2048
  while keeping the same insecure padding) → **MITIGATION**.
- Adding a signature check but leaving the verification-optional branch
  live → **WORKAROUND**.
- Reading keys from env vars without annotation → `key_source_approved`
  is false → **MITIGATION**.
- Storing keys in the filesystem → `key_source_approved` false →
  **MITIGATION**.

## Never do

- Never mutate `crypto_trust_chain` booleans in the fix. They are
  mechanical outputs; if a mechanical check is wrong, escalate to
  `NEEDS_MANUAL_REVIEW` — do not "correct" them in the plan.
- Never implement custom crypto. Use `cryptography`, `nacl`, or the
  language stdlib equivalents — never hand-rolled AES or hash chains.

## Residual template

Use the `trust-chain:` prefix for any residual driven by a `false`
boolean (see Rule R-5). Additional non-trust-chain residuals may use
the free-form Rule R-4 template.
