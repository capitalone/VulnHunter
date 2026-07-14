# Severity Mask Rule (REQ-GAT-002, REQ-SEC-001, REQ-GAT-008)

**Consumed by:** `scripts/check-severity-mask.py` (Gate 1, read-time) and `vulnhunter_fix/delivery.py:SAFE_PHRASE_PATTERNS` (write-time constant enforced through the worker manual-mask discipline documented in `prompts/worker_agent_common.md`).

## Rule

Every PR title, PR body, issue body, and commit message shall be regex-scanned for the word `critical`. Any occurrence outside the five-phrase safe-list fails the delivery gate.

Regex (Python `re` syntax, as compiled by `scripts/check-severity-mask.py:CRITICAL_RE`):

```
\bcritical\w*
```

Case-insensitive. The `\w*` suffix catches inflections ("critically") — a bare `\bcritical\b` would miss "critically important", which this rule requires to be blocked. Safe-phrase disambiguation is done as a **containment check** (not lookaround) in `_matches_safe_phrase()` — for each match of `\bcritical\w*`, the surrounding text is inspected against `SAFE_PHRASE_PATTERNS`; if the match falls inside any safe-phrase span, it is suppressed. ("criticism"/"critique" never match the stem at all.)

Masked replacement term: `High+` (per REQ-SEC-001).

## Safe-list (5 phrases)

Permitted literal strings — each is a linguistic false positive of `critical`, NOT a semantic override:

1. `non-critical`
2. `criticality`
3. `Critical Section` (exact capitalization)
4. `criticism`
5. `critique`

Never add a phrase that widens the semantic scope. E.g., "critically important" is NOT safe — that would defeat the mask.

## Where the constant lives

Machine-readable form:

```python
SAFE_PHRASE_PATTERNS = (
    "non-critical",
    "criticality",
    "Critical Section",
    "criticism",
    "critique",
)
```

The tuple appears in TWO places by design — write-time (`vulnhunter_fix/delivery.py`) and read-time (`scripts/check-severity-mask.py`). Sync between them is enforced by `scripts/safe-phrase-sync-lint.py` (REQ-GAT-008): CI byte-compares the two lists' string representations.
