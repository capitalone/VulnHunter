# Fix Completeness Rubric

**Referenced by:** REQ-HON-001 through REQ-HON-004. Consumed by
`scripts/compute-completeness-tier.py` (task-12) as the source-of-truth signal
catalog. When any signal is added, updated, or removed, the classifier must
be updated in the same PR.

The classifier walks signals **conservative-first**: it looks for
WORKAROUND signals first, then MITIGATION, then FULL. If no terminal signal
matches, it returns `LLM_REVIEW` — never `FULL` (REQ-HON-004).

## Tiers

| Tier          | Meaning                                                                                                     |
|---------------|-------------------------------------------------------------------------------------------------------------|
| `FULL`        | The stated attack vector is mechanically blocked by default. Residual vectors must be empty.                |
| `MITIGATION`  | The stated attack vector is partially blocked. Residual exposure remains and is enumerated.                 |
| `WORKAROUND`  | Adjacent risk is reduced but the stated attack vector remains open (compensating control only).             |
| `LLM_REVIEW`  | **Intermediate signal only.** The classifier could not decide deterministically. Never appears in output.   |

## WORKAROUND signals (checked first)

Any single match promotes the finding to `WORKAROUND`. Order does not matter.

1. **Rate limiter upstream of unchanged sink.** Diff adds token bucket / semaphore / retry backoff without modifying the sink signature.
2. **Feature flag flipped off.** Diff toggles a config boolean; sink function body unchanged.
3. **Documentation warning only.** Diff modifies `.md` files or docstrings; no code path change at the sink.
4. **Header/log-based deterrent.** Diff adds logger call or `X-Warning` header without an early return / raise / abort.
5. **Alerting installed but not blocking.** Diff adds monitoring hook (Sentry, DataDog, custom notifier) without a control-flow change at the sink. *(LLM_REVIEW guidance only; the deterministic classifier's `log_or_header_without_reject` catches the generic logger pattern but not monitoring-hook SDKs.)*

## MITIGATION signals

Checked if no WORKAROUND signal matched. Any single match promotes to `MITIGATION`.

1. **Partial input sanitization.** Input validator whitelists some attack patterns while permitting others to reach the sink.
2. **Length or complexity cap.** `if len(x) > N:` guard added; content passes through unchanged.
3. **Post-hoc audit trail.** Audit sink inserted downstream of the vulnerable operation. *(LLM_REVIEW guidance only; not detected by the deterministic classifier.)*
4. **Compensating control on a different path.** Modified files do not include the finding's `location`. *(LLM_REVIEW guidance only; not detected by the deterministic classifier.)*
5. **Rate-limited fix on the correct sink.** Rate limiter added to the exact sink named in the finding — valid mitigation, but slow-and-low bypass remains. *(LLM_REVIEW guidance only; not detected by the deterministic classifier.)*
6. **Crypto trust-chain incomplete.** `crypto_trust_chain` object in plan artifact has any of the four booleans (`algorithm_approved`, `key_source_approved`, `key_rotation_present`, `transport_encrypted`) set to `false` for a crypto-CWE finding (REQ-CWE-007).

## FULL signals

Checked only if no WORKAROUND and no MITIGATION signal matched. All FULL signals must match cumulatively — a single signal is insufficient.

1. **Sink signature changed.** Diff modifies the sink's parameter list, return type, or removes the sink entirely — vulnerable call shape becomes a compile-time / type-check-time error.
2. **Callers routed through fix.** `plan.callers_routed_coverage == "superset"` — every caller of the sink reachable from an external entry point routes through the new safe pathway (REQ-GRA-019, REQ-GRA-020).
3. **Test discriminates.** `result.discrimination_evidence` records `pre_fix_result == "fail"` AND `post_fix_result == "pass"`, with the payload matching the scan's stated attack (REQ-GRA-017).
4. **No blocking WORKAROUND or MITIGATION signal present.**

## LLM_REVIEW fallback

Emitted when:
- No terminal signal matched (i.e., the fix diff does not match any of the
  documented WORKAROUND, MITIGATION, or FULL signals).
- The signals matched inconsistently (e.g., partial FULL signals without full
  coverage).

`LLM_REVIEW` is **never** written to `result.completeness_tier`. It routes to
the bounded LLM prompt at `prompts/tier_judgment.md` (REQ-HON-013 through
REQ-HON-016), whose output resolves to `FULL` / `MITIGATION` / `WORKAROUND` /
`NEEDS_MANUAL_REVIEW`.
