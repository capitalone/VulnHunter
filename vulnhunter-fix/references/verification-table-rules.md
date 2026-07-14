# Verification Table Rules

**Referenced by:** REQ-GRA-011, REQ-GRA-012, REQ-GRA-013, REQ-GRA-014.
**Consumed by:** `vulnhunter_fix.delivery.render_verification_table` (task-30),
`scripts/validate-verification.py` (task-29), `templates/pr_body.md` and
`templates/issue_body.md`.

## Table shape (REQ-GRA-011)

Exactly nine columns, in this order (matches `vulnhunter_fix/delivery.py:VERIFICATION_TABLE_HEADERS` and `scripts/validate-verification.py:EXPECTED_HEADERS` byte-for-byte):

| # | VULN-NNN | Stated vector closed? | Test exercises real attack? | Default fail-closed? | Residual risk documented? | All call sites covered? | Sweep complete? | Verdict |

The column count and header spelling are contractually fixed. Additions or
reorderings require a spec amendment; the validator refuses tables that
do not match the header verbatim. When composing PR bodies by hand (not
via `render_verification_table`), workers MUST emit these exact 9 headers
in this order — any drift (renaming, dropping `#`, adding a `Sink`
column) is rejected at delivery time by `scripts/validate-verification.py`.

## Cell values (REQ-GRA-012)

Each cell is one of the following literal strings:

| Value | Meaning |
|-------|---------|
| `yes (file.py:42)` | Affirmative; the citation names the file and line where the evidence lives. |
| `no` | Negative; no citation permitted. |
| `n/a` | Not applicable for this finding class (e.g., column 7 for a config-only fix). No citation permitted. |
| `yes (grep_fallback) (file.py:42)` | Affirmative under low-confidence graph mode; annotation appears only when the sidecar `confidence == "low"`. |

**Every `yes` cell MUST carry a `file:line` citation.** The validator
opens each cited file at the worktree path, verifies the line exists, and
refuses delivery on any uncited `yes`.

## Column 7 — All call sites covered?

Special semantics per REQ-GRA-013:

- The citation must enumerate **every** symbol returned by
  `graph.callers_of(sink_symbol)`.
- Each entry is `file:symbol` form. The worker's
  `result.callers_routed_through_fix` list must be a superset of this
  enumeration for the cell to read `yes`.
- **Truncation:** when the graph returns more than 20 callers, list the
  first 20 lexicographically (by `file:line`), followed by the literal
  suffix `... N more via callers_of()` where `N` is the exact remaining
  count. `validate-verification.py` accepts this truncation iff the total
  caller count exceeds 20.

## Column 8 — Sweep complete?

Column 8 values are set by `scripts/sweep-root-causes.py` (see `references/sweep-algorithm.md § Verification-table integration`). Values: `yes (n/a)` when the finding had no siblings; `yes` when all captured siblings were mitigated; `no` when siblings remain.

## Verdict derivation (REQ-GRA-014)

The Verdict cell is mechanically computed, never free-text. Use this
truth table:

| Column 3 | Column 4 | Column 5 | Column 6 | Column 7 | Column 8 | Verdict     |
|----------|----------|----------|----------|----------|----------|-------------|
| yes      | yes      | yes      | yes/n/a  | yes/n/a  | yes/n/a  | **FULL**    |
| yes      | yes      | yes      | yes      | yes/n/a  | yes/n/a  | **MITIGATION** (with residuals documented) |
| yes      | yes      | no       | yes      | yes/n/a  | yes/n/a  | **WORKAROUND** (fail-closed not achieved; compensating control only) |
| no       | *        | *        | *        | *        | *        | **NEEDS_REWORK** — stated vector not closed |
| *        | no       | *        | *        | *        | *        | **NEEDS_REWORK** — test does not exercise real attack |
| *        | *        | *        | no       | *        | *        | **NEEDS_REWORK** — non-FULL tier missing residual documentation |

`NEEDS_REWORK` verdicts halt delivery (Gate 2 refuses).
