# SG-2 — LOG class trace results

Partition: verify orchestration. Class group: LOG (race conditions, cache
isolation, credential scope, resource exhaustion, prototype pollution, crypto
issues, integer overflow). Repo root:
`/Users/srujankd/Temple_University/Senior Year/Capstone/workspace/code/VulnHunter`

Scope files traced: `agent/__main__.py`, `verify.py`, `verify_extract.py`,
`verify_refs.py`, `verify_resolve.py`, `verify_runner.py`, `verify_post.py`,
`_github_verify.py`, `_body_reconstruct.py`, `_github.py`, `clone.py`, `_url.py`,
`auth.py`, `config.py`, `build_settings.py`.

## Summary

No LOG-class candidate found. The verify path is single-threaded sequential
asyncio (no races), performs no authorization-decision caching, generates no
credential/policy artifacts, uses only `json.loads` (no pickle/yaml deserialize),
uses SHA-256 + `secrets.*` (no weak crypto, no insecure RNG), and never disables
TLS (`resolve_verify` returns `True` or a CA path only; `NODE_TLS_REJECT_UNAUTHORIZED`
is set to `""` in `build_settings.py:135`, which *neutralizes* an inherited value,
not disables — it is not `"0"`). Python integer arithmetic is arbitrary-precision
(no overflow). All CWE-400 collection sinks (comments/events/edits) carry explicit
caps. The regexes applied to attacker text (`_RE_VULNFIX_KEY`, `_RE_FINDING_ID`,
`_RE_RESULTS_DIR`, `_URL_LIKE_RE`, `_COMMIT_SHA_RE`, `_TIMESTAMP_RE`, `redact()`)
contain no nested quantifiers — no ReDoS.

Most inputs reach NAV/INJ sinks instead (SSRF via `api_base`, prompt injection via
comments, CWE-345 authenticity binding) — flagged CROSS-CLASS below.

## Dispositions

- **#2 targets[] (issue URLs)** — `__main__.py:109`
  - **NO-MATCH** (LOG) — no crypto/deser/race/cache/overflow sink. ReDoS-safe
    (`urlparse`/`.find` only).
  - **CROSS-CLASS** (NAV): host extracted by `issue_host()` → `api_base(host)`
    `_github.py:30-32` returns `https://{host}/api/v3` for non-github hosts, then
    requests go out with the Bearer `scan_token` (`_github_verify.py:246`).
    Suspected class: **NAV / CWE-918 SSRF**.

- **#9 --commit (SHA)** — `__main__.py:252`
  - **NO-MATCH** (LOG). No LOG sink. INJ-guarded: `_COMMIT_SHA_RE`
    (`^[0-9a-f]{7,40}$`, `clone.py:28`) + `--` separator, so no argv injection.

- **#10 --scratch-dir** — `__main__.py:258`
  - **NO-MATCH** (LOG). `expanduser().resolve()` → `_contained_run_dir` containment
    (`verify.py:751-764`). Path handling is NAV, and guarded.

- **#21 issue title/body/number** — `_github_verify.py:245`
  - **NO-MATCH** (LOG). Body → `extract_markers` (`verify_extract.py:109`) regexes
    are linear (no ReDoS); single GitHub-capped field, not an unbounded collection.
    `title` is fetched but unused downstream. `int(data["number"])` safe.
  - **CROSS-CLASS** (NAV): markers (`results_dir`/`finding_id`) steer `stage_report`
    download and the LLM verdict — CWE-345 authenticity-binding gap, explicitly
    documented as accepted risk in `verify_resolve.py:218-232`.

- **#22 issue comments** — `_github_verify.py:276`
  - **SAFE** (LOG, resource exhaustion): `list_comments` bounded by `max_pages=20`
    and `max_total_bytes=5MB` (`_github_verify.py:38-42, 268-330`).
  - **CROSS-CLASS** (NAV): comments → `_build_preflight_text` → `_llm.call_json`
    (`verify_refs.py:145`) and `comments.md` → verify skill — prompt injection.

- **#23 issue events** — `_github_verify.py:340`
  - **NO-MATCH** (LOG). Bounded (`max_pages=20`); only consumed for close-timestamp
    comparison (`verify_extract.py:181-192`). No LOG sink.

- **#24 user content edits** — `_github_verify.py:460`
  - **SAFE** (LOG, resource exhaustion): `first:100` + `max_diff_bytes` +
    `max_total_bytes` caps (`_github_verify.py:439-540`). `reconstruct_original`
    just sorts and picks oldest. No LOG sink.

- **#26 html_url / issue number** — `issues.py:841`, `_github_verify.py:128`
  - **NO-MATCH** (LOG). `html_url` captured into `FetchedIssue` but not consumed in
    the verify path (dead). `int(number)` safe.
  - **CROSS-CLASS** (NAV): issue host → `api_base` SSRF (same sink as #2).

- **#28 cross-repo refs in comments** — `verify_refs.py:69`
  - **NO-MATCH** (LOG). `sha256` in `_sanitize_clone_subdir` is non-secret naming;
    `_URL_LIKE_RE` ReDoS-safe.
  - **CROSS-CLASS** (NAV): LLM-extracted `repo_hint` → `resolve_repo_hint`
    (`verify_resolve.py:63-100`) → clone — SSRF, guarded by host allow-list.

- **#30 verify_disposition.json** — `verify_runner.py:156`
  - **NO-MATCH** (LOG). `json.loads` + `Draft202012Validator` schema validation;
    no unsafe deserialization. Verdict comment posting is the agent's designed
    output.

- **#31 fixed_ids (VULN-NNN markers)** — `verify.py`, `verify_extract.py`
  - **NO-MATCH** (LOG). Format-constrained; used in `build_kickoff_prompt` and
    `_verify_entry_count` set comparison.
  - **CROSS-CLASS** (NAV): steers which findings the LLM verifies (CWE-345,
    documented accepted risk).

- **#33 vulnhunt-results-dir marker** — `verify_extract.py` `_RE_RESULTS_DIR`
  - **NO-MATCH** (LOG). Regex-constrained (`[A-Za-z0-9._-]+_VULNHUNT_RESULTS_...` +
    `..`//`\` forbidden). ReDoS-safe.
  - **CROSS-CLASS** (NAV): path traversal — guarded (`_contained_run_dir`,
    `verify.py:751-764`; `stage_report` target under `destination_dir`).

- **#34 repo hint / additional-repo URL** — `verify_resolve.py`
  - **NO-MATCH** (LOG).
  - **CROSS-CLASS** (NAV/INJ): SSRF guarded by host allow-list
    (`verify_resolve.py:89-99`); git clone guarded by `_reject_option_like` + `--`
    (`clone.py:31-41, 119`). `inject_token` path-prefix scoping is correct (empty
    prefix set → token denied), so no credential over-scope.

## Absent-input (CVB) analysis

- `--commit` absent → HEAD clone (operator choice, not a security check).
- Missing markers → `extract_markers` raises, run aborts (fail-closed).
- `_enforce_homogeneity` mismatch → abort (fail-closed).
- `reopen` gated by verdict set + `allow_reopen`; no security check is skipped
  when an input is omitted.
No Conditional Validation Bypass findings.
