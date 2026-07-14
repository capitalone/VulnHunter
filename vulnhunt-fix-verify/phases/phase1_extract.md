# Phase 1 — Extract Findings

Convert the prior `/vulnhunt` scan report into a structured
per-finding file that phase 2 will consume one section at a time.

The orchestrator may run this procedure inline or delegate it to a
subagent — the procedure is the same either way.

## Inputs

- `REPORT` — absolute path to the `*_VULNHUNT_RESULTS_*` directory.
- `OUT` — absolute path where output files go.
- `fixed_ids_in_report` — the IDs to extract, read from
  `${OUT}/phase0_state.json`.

Read-only over `REPORT`; write-only to `${OUT}`.

## Goal

Produce `${OUT}/extracted_findings.md` with one top-level
`## VULN-NNN` section per ID in `fixed_ids_in_report`, in the same
order. Each section must conform to the layout in §Layout below.

## Layout

```markdown
# Extracted findings

## VULN-001

| Field | Value |
|---|---|
| title | <one-line title> |
| cwe | CWE-NNN |
| severity | High+ / High / Medium / Low / Informational |
| location | path/to/file.ext:LINE |
| entry_point | <route / function / queue / etc.> |
| root_cause | <one-sentence root cause from the report> |
| data_flow | <source → ... → sink> |
| fix_strategy | <one-sentence summary from phase3_output.md / README> |
| sweep_root_cause | <name from phase3d_output.md, or "none"> |
| sweep_pattern | <grep pattern from phase3d_output.md, or "none"> |
| poc_path | <absolute path to poc/VULN-NNN_*.md, or "missing"> |
| exploit_test_path | <absolute path to exploit_tests/test_vuln_NNN_*, or "missing"> |

### Accepted comments claims for VULN-001

<copy verbatim from phase0_state.json any comments_evaluation.claims
entries whose excerpt or cited_location plausibly relates to this
VULN's location/sink. If none, write "(none)".>

## VULN-003

...
```

The `## VULN-NNN` heading at start-of-line is the anchor phase 2
subagents use to locate each section. Do not deviate from the heading
form.

## Procedure per VULN

For each ID in `fixed_ids_in_report`:

### 1. Source the core fields

**Preferred source — `scan_manifest.json`**:
- `Read ${REPORT}/scan_manifest.json`, find the matching `findings[]`
  entry, copy: `title`, `cwe`, `severity`, `location`, `entry_point`,
  `root_cause`, `data_flow`, `fix_strategy`.

**Fallback source — `${REPORT}/README.md` + `${REPORT}/phase3_output.md`**:
- Grep the README for the `## [VULN-NNN]` section heading.
- Read that section in a focused range (use `offset`/`limit` Read
  with the line numbers Grep returned).
- Pull the fields from the field table.
- Read `${REPORT}/phase3_output.md` for the `fix_strategy` text if
  the README didn't include it.

### 2. Source the sweep group fields

`Read ${REPORT}/phase3d_output.md`. Grep for `VULN-NNN` to find which
sweep group (if any) this finding belongs to. From the sweep table:

- `sweep_root_cause` = the row's root-cause name (e.g. "raw SQL via
  fmt.Sprintf").
- `sweep_pattern` = the grep pattern documented in the same row.

If the finding doesn't appear in any sweep group, both fields are
`"none"`.

### 3. Source the PoC and exploit-test paths

- `Glob ${REPORT}/poc/VULN-NNN_*.md`. Take the first match (there
  should only be one). Record the **absolute** path. If no match,
  record `"missing"`.
- `Glob ${REPORT}/exploit_tests/test_vuln_NNN_*`. Same handling.

These paths are recorded as **reference evidence** only — the phase 2
subagents do NOT execute the exploit test in v1 (per design §2.5).

### 4. Filter relevant accepted claims

`Read ${OUT}/phase0_state.json` once for the entire phase. For this
VULN, copy in the `comments_evaluation.claims[]` entries whose
`cited_location` or `excerpt` references:

- The file in `location` (e.g. claim cites `db/queries.go:88` and
  the VULN's location is `db/queries.go:42` → same file, include).
- The entry point name (e.g. claim mentions `/search` and the VULN's
  entry point is `GET /search` → include).
- The CWE or root-cause keywords (loose match; conservative — when
  in doubt, include).

Only claims with `status: accepted` are eligible — rejected/pending
claims are not used as hints. If no relevant accepted claims, write
`"(none)"` under the section heading.

## Validation before writing

After building the file content, do one sanity check:

- Every ID in `fixed_ids_in_report` has exactly one `## VULN-NNN`
  section.
- No ID outside that list appears as a heading.

Then `Write ${OUT}/extracted_findings.md`. Append a paragraph to
`${OUT}/verify_run.log.md` listing the IDs you processed.

## What NOT to do

- Do **not** read the full PoC or exploit-test file contents into
  `extracted_findings.md`. Just record the path; phase 2 will Read
  them when it needs the attack details.
- Do **not** read source files in the `REPO` checkout. That's phase
  2's job.
- Do **not** modify `REPORT` or its contents.

## If you delegated to a subagent

Verify `${OUT}/extracted_findings.md` exists via Glob; re-dispatch
once if missing. The subagent's return message should be under 20
words and just confirm which IDs were written.
