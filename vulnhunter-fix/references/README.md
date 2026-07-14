# References

Reference material consumed by phase prompts and gate scripts. Each file documents one rule, rubric, or pattern set. Prompts point at these files rather than restating their content.

## Files

- `anti-merge-math.md` — 0.6 grouping threshold + derivation (REQ-GAT-006)
- `committed-test-naming-rule.md` — Gate 7 scaffold-leak signature + promotion rule (REQ-GAT-013)
- `cwe-fix-patterns.md` — per-CWE-class fix patterns; feeds CWE-class dispatch (REQ-CWE-002)
- `fix-completeness-rubric.md` — FULL/MITIGATION/WORKAROUND signal rubric (REQ-HON-001..013)
- `idempotency-key-rule.md` — vulnfix-key derivation + marker shape (REQ-GAT-005)
- `remediation-rigor.md` — cross-phase remediation-rigor invocations, error handling, back-fill semantics
- `repo-type-adapters.md` — per-language adapter snippets (Go / Java / Python / TS / JS) (REQ-CWE-005)
- `residual-risk-rules.md` — residual_vectors formatting rules R-1..R-5 (REQ-HON-005)
- `severity-mask-rule.md` — Gate 1 mask regex + 5-phrase safe-list (REQ-GAT-002, REQ-GAT-008, REQ-SEC-001)
- `sweep-algorithm.md` — Pass-1 graph anchoring + Pass-2 regex walkthrough (REQ-SWP-001..009)
- `sweep-patterns.md` — CWE-class regex patterns for Pass-2 (REQ-SWP-005)
- `test-quality-rubric.md` — R1-R5 rules for reviewer_test.md (REQ-GRA-016)
- `verification-table-rules.md` — 9-column verification-table semantics + verdict truth table (REQ-GRA-013)
- `*-schema.json` (4 files) — JSON Schema for result / finding / triage / fix_plan (REQ-SCH-001..002)

## Update discipline (canonical — applies to every reference file)

- **Add a new rule, signal, or pattern:** update the reference file AND every consuming site (gate script, phase prompt, other reference) in the same PR. Consuming sites are named in the reference file's first section.
- **Change an existing rule:** the change must be backward-compatible OR require a migration plan documented in the PR description. Look for rule-ID citations in `scripts/*.py`, `prompts/*.md`, `references/*-schema.json` — every match is a caller.
- **Delete a rule:** first delete all consuming references, then delete from the rule file. CI (schema validators, sync-lints, prompt-lint, worker-preamble-sync-lint) fails on dangling references — use those failures as the caller inventory.
- **Rename a file:** grep-replace before the rename lands so no dangling links ship. Add the old name to the "Files" list above with a redirect stub for one release cycle if the file was long-lived.

Individual reference files no longer carry their own "Update discipline" footer — this section is authoritative for all of them.

## Sync-lints (mechanical enforcement)

Some references have byte-identical mirrors in `vulnhunter_fix/` or `scripts/` (write-time vs read-time enforcement of the same rule). These are guarded by dedicated sync-lints:

- `scripts/safe-phrase-sync-lint.py` — `SAFE_PHRASE_PATTERNS` in `delivery.py` vs `check-severity-mask.py` (REQ-GAT-008)
- `scripts/worker-preamble-sync-lint.py` — SYNC block markers between `worker_agent_common.md` and `implement.md`
- `scripts/heading-sync-lint.py` — required Gate-2 section headings in the body templates (`pr_body.md`, `pr_body_cluster.md`, `issue_body.md`) vs `check-body-completeness.py` `REQUIRED_ALWAYS` + conditionals, plus a corpus-wide guard against the `## Breaking Change —` em-dash heading form the gate rejects (REQ-GAT-003)

CI fails on drift. See each lint's docstring for the marker convention.
