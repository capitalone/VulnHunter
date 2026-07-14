# Idempotency Key Rule (REQ-GAT-005)

**Consumed by:** `scripts/check-idempotency.py` (Gate 4) and `vulnhunter_fix.delivery.compute_idempotency_key()`.

## Marker format

Embedded as an HTML comment in every artifact body:

```
<!-- vulnfix-key: <16 hex chars> -->
```

Tracking issues additionally carry `<!-- vulnfix-report-id: <report-id> -->`.

## Key derivation

```
sha256(location + "|" + primary_cwe + "|" + root_cause)[:16]
```

- `location` — canonical repo-relative path (matches the `location` parameter of `compute_idempotency_key` in `vulnhunter_fix/delivery.py:323`)
- `primary_cwe` — first `CWE-<n>` match extracted via `re.search(r"CWE-\d+", cwe)` (handles multi-CWE strings like `"CWE-89, CWE-79"`)
- `root_cause` — passed through as-is; no normalization. Producers and consumers must feed byte-identical strings.

The three producers — `vulnhunter_fix/delivery.py:compute_idempotency_key`, `scripts/parse_results.py:compute_vulnfix_key`, `scripts/issue_intake.py:compute_vulnfix_key` — implement the same formula and emit byte-identical output for identical input.

## Gate 4 behavior

`scripts/check-idempotency.py` verifies:
1. Every PR body and issue body contains a `vulnfix-key:` marker.
2. Every tracking issue body additionally contains `vulnfix-report-id:`.
3. Both keys match `[0-9a-f]{16}` (exact-16, matching what all three producers emit).

Missing or malformed markers fail the gate; delivery halts.
