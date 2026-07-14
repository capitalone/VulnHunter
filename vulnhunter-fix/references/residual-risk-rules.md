# Residual Risk Rules

**Referenced by:** REQ-HON-005, REQ-HON-006, REQ-HON-007, REQ-HON-009,
REQ-HON-010. Consumed by `vulnhunter_fix/delivery.py` (residual rendering,
hand-wave guard, empty-residual guard) and the follow-up-issue renderer.

Residual vectors are the exposed portion of an attack that remains open
after the fix. They are the disclosure component of `MITIGATION` and
`WORKAROUND` completeness tiers.

## Rule R-1: Non-empty when tier != FULL

If `completeness_tier` is `MITIGATION` or `WORKAROUND`, `residual_vectors[]`
must contain at least one entry (REQ-HON-005). Delivery halts on empty
residuals for a non-FULL tier (REQ-HON-007).

## Rule R-2: Empty when tier == FULL

If `completeness_tier` is `FULL`, `residual_vectors[]` must be empty. A
non-empty residual list under `FULL` is a self-contradicting artifact and
schema validation refuses it (see `references/result-schema.json`
`allOf` for the enforcement clause).

## Rule R-3: Hand-wave guard

Delivery refuses to render the PR body when any residual entry matches, in
case-insensitive substring form:

- `future work`
- `more work needed`
- `to be done`
- `tbd`
- `later`

Rationale: these phrases hide unquantified exposure behind procedural
language. A concrete residual entry names the vector (e.g., "SQLi via
`legacy_admin_endpoint.php` — endpoint not rewritten in this fix").

## Rule R-4: One vector per entry

Each entry in `residual_vectors[]` names exactly one open vector. Combining
vectors into a single string ("multiple issues remain") is not permitted.
The follow-up-issue renderer creates one GitHub issue per entry
(REQ-HON-010); combining prevents proper tracking.

Format recommendation (not enforced):
```
<Attack shape>: <Location> — <Reason unclosed>
```
Example:
```
XSS reflection: search results page /search?q= — encoding fix
covers HTML context only; JS-string context still vulnerable.
```

## Rule R-5: Crypto residuals cite the boolean

Crypto findings (routed to `worker_agent_crypto.md`) that ship as
`MITIGATION` because one of the four crypto trust-chain booleans is `false`
(REQ-CWE-007) must include a residual entry using the `trust-chain:` prefix:

- `trust-chain: algorithm not on approved list`
- `trust-chain: key source not approved (Chamber / KMS)`
- `trust-chain: rotation mechanism not detected`
- `trust-chain: transport encryption not detected at fix boundary`

Multiple booleans false = multiple residual entries. This makes the
mechanical decision visible to reviewers and downstream auditors.

## Rule R-6: `## Residual Risk` section is mandatory for non-FULL

The PR body and the per-finding issue body must each carry a
`## Residual Risk` section listing every entry as a Markdown bullet
(REQ-HON-009). Order: same as `residual_vectors[]`.

## Rule R-7: Follow-up issues track residuals long-term

Every residual entry auto-creates one follow-up GitHub issue with the
`vulnhunter-followup` label (REQ-HON-010). Issue body includes:
- The residual entry text verbatim
- Parent finding VULN-NNN and its issue link
- Suggested next step if known
- `<!-- vulnfix-followup-key: sha256(finding_id + residual_text) -->` for
  idempotent re-run behavior

## Rule R-8: Draft state for WORKAROUND

`WORKAROUND` PRs open in Draft state (REQ-HON-008). This provides a
mechanical fence to prevent auto-merge on the weakest tier. `MITIGATION`
and `FULL` open Ready.
