# Phase 4 — Emit Final JSON

Execute in your own context. By this point:

- `${OUT}/phase0_state.json` exists with `target_repo` (including
  `additional_repos`), `comments_evaluation`, `scan_id`,
  `verified_at`, `prompt_injection_attempted`,
  `agent_annotated_hints`, `fixed_ids_in_report`, and
  `fixed_ids_missing`.
- `${OUT}/disposition_VULN-NNN.json` exists for each ID in
  `fixed_ids_in_report` (may be empty when every ID was missing
  from the report — Step 4.2 handles that case).

## Step 4.1 — Read state

`Read ${OUT}/phase0_state.json`. Bind:

- `scan_id`
- `target_repo` (with `path`, `head_commit`, `head_ref`,
  `additional_repos`)
- `verified_at`
- `comments_evaluation`
- `prompt_injection_attempted` (run-level R7 flag — used in 4.3)
- `agent_annotated_hints` (run-level R6 list — used in 4.3)
- `fixed_ids_in_report` (the list of IDs phase 1/2 processed)
- `fixed_ids_missing` (IDs that weren't in the report)

## Step 4.2 — Read per-VULN dispositions

For each ID in `fixed_ids_in_report`, `Read
${OUT}/disposition_VULN-NNN.json` and append the parsed object to a
running `dispositions[]` array. If `fixed_ids_in_report` is empty
(every ID was missing from the report), skip this step — phase 1
and phase 2 did not run, and the only dispositions in this run come
from Step 4.3 below.

## Step 4.3 — Add INVALID_INPUT entries

For each ID in `fixed_ids_missing` (if any), append:

```json
{
  "finding_id": "VULN-NNN",
  "verdict": "INVALID_INPUT",
  "rationale": "VULN-NNN does not appear in the supplied report. Verify the report directory and the fixed-list argument.",
  "issue_comment": "<see template below>",
  "gates": {
    "sink_mitigated": "n/a",
    "reachability": "n/a",
    "class_eliminated": "n/a",
    "sweep_complete": "n/a"
  },
  "evidence": []
}
```

(`regressions` is omitted entirely — not `[]`. The schema accepts
the field's absence.)

**`issue_comment` template for INVALID_INPUT stubs.** Start with
the canonical body:

```markdown
**VulnHunter Fix-Verify: ⚠️ Invalid Input**

VULN-NNN does not appear in the supplied scan report. Confirm the
finding ID and re-invoke.
```

Then apply the same conditional Limitations rule that phase 2 uses
(see `phase2_verify.md` → "Limitations line (conditional)"): when
`prompt_injection_attempted` is `true` OR `agent_annotated_hints`
is non-empty, append the matching Limitations block immediately
after the canonical body. Use the same R7-then-R6 ordering and the
same fragment wording. Stubs and verdicts must surface the same
warnings, otherwise the developer sees inconsistent reports across
their issue thread.

## Step 4.4 — Order the dispositions

The final `dispositions[]` must be ordered to match the **original
`FIXED` argument**, not the working lists. In phase 0 the orchestrator
should have preserved the input order; if you have any doubt, re-derive
the order from `phase0_state.json` (which preserves it) and rearrange
the array before writing.

## Step 4.5 — Build the final document

Assemble:

```json
{
  "schema_version": "1",
  "scan_id": "<from phase0_state>",
  "target_repo": {
    "path": "<from phase0_state>",
    "head_commit": "<from phase0_state>",
    "head_ref": "<from phase0_state>",
    "additional_repos": ["<from phase0_state, copy through as-is>", ...]
  },
  "verified_at": "<from phase0_state>",
  "comments_evaluation": {
    "provided": <bool>,
    "claims": [...]
  },
  "dispositions": [...]
}
```

The run-level `prompt_injection_attempted` and
`agent_annotated_hints` flags are **not** copied into the final
document — they live in `phase0_state.json` only. Their effect is
already baked into each disposition's `issue_comment` Limitations
block by phase 2 (for verdicts) and by Step 4.3 (for
INVALID_INPUT stubs).

## Step 4.6 — Validate against the schema

Before writing, walk the document mentally against
`verify_disposition.schema.json` at the repo root. Confirm:

| Field | Rule |
|---|---|
| `schema_version` | Exactly the string `"1"`. |
| `scan_id` | Matches `^.+_VULNHUNT_RESULTS_.+$`. |
| `target_repo` | Object with exactly four keys: `path`, `head_commit`, `head_ref`, `additional_repos`. No extras. |
| `target_repo.head_commit` | Either 7-40 lowercase hex chars OR empty string. |
| `target_repo.head_ref` | Any string (empty allowed). |
| `target_repo.additional_repos` | Required array of strings. Empty array when none were supplied at kickoff. |
| `verified_at` | ISO-8601 date-time string. |
| `comments_evaluation.claims[].status` | One of `accepted`, `rejected_unverifiable`, `rejected_false`. |
| `dispositions[].finding_id` | Matches `^VULN-\d{3}$`. |
| `dispositions[].verdict` | One of `FIXED`, `NOT_FIXED`, `PARTIAL`, `INCONCLUSIVE`, `INVALID_INPUT`. |
| `dispositions[].gates` | Exactly the four keys: `sink_mitigated`, `reachability`, `class_eliminated`, `sweep_complete`. No extras. |
| `dispositions[].gates.*` | One of `pass`, `fail`, `skipped`, `n/a`. |
| `dispositions[].evidence[].kind` | One of `sink_inspection`, `data_flow_trace`, `sweep_grep`, `rule_check`. |
| `dispositions[].issue_comment` | Required, non-empty string. The downstream GitHub integration posts this verbatim. |
| Top-level | No extra fields (`additionalProperties: false`). |
| Disposition objects | No extra fields. |

If any field is malformed, fix it before writing. Don't write a
malformed document and hope downstream validation catches it — the
contract is that this file always validates.

## Step 4.7 — Write the disposition file

`Write ${OUT}/verify_disposition.json` with the assembled document.

## Step 4.8 — Update the run log

Append a final section to `${OUT}/verify_run.log.md`:

```markdown
## Summary

| ID | Verdict |
|---|---|
| VULN-001 | FIXED |
| VULN-003 | PARTIAL |
| ... | ... |

Counts: <N FIXED, N NOT_FIXED, N PARTIAL, N INCONCLUSIVE, N INVALID_INPUT>

Output: ${OUT}/verify_disposition.json
```

## Step 4.9 — Return control to SKILL.md

Phase 4 produces no further output. SKILL.md's Step 5 (final
user-facing message) takes over and reports the verdicts to the
user.
