# SG-2 — Verify orchestration

Repo root (all paths below are relative to this): `/Users/srujankd/Temple_University/Senior Year/Capstone/workspace/code/VulnHunter`

**Entry point:** `vulnhunt --mode=verify <issue-url...>` (+ GitHub issue/comment/event/edit consumers)
**Production reachability:** PRODUCTION (shipped CLI; no env gate found).

## Assigned inputs

| # | Source Type | Location | Variable | Entry Point | Trust |
|---|---|---|---|---|---|
| 2 | CLI positional | `vulnhunter-agent/agent/__main__.py:109` | `targets[]` (issue URLs) | `vulnhunt --mode=verify <issue-url...>` | local |
| 9 | CLI flag | `vulnhunter-agent/agent/__main__.py:252` | `--commit` (SHA) | verify repo pin | local |
| 10 | CLI flag | `vulnhunter-agent/agent/__main__.py:258` | `--scratch-dir` | verify scratch dir | local |
| 21 | GitHub API body | `vulnhunter-agent/agent/_github_verify.py:245` | issue title/body/number | verify issue fetch | external |
| 22 | GitHub API body | `vulnhunter-agent/agent/_github_verify.py:276` | issue comments | verify comment fetch | external |
| 23 | GitHub API body | `vulnhunter-agent/agent/_github_verify.py:340` | issue events | verify event fetch | external |
| 24 | GitHub GraphQL | `vulnhunter-agent/agent/_github_verify.py:460` | user content edits | edit fetch | external |
| 26 | GitHub API body | `vulnhunter-agent/agent/issues.py:841`, `vulnhunter-agent/agent/_github_verify.py:128` | `html_url`, issue number | URL parse → owner/repo | external |
| 28 | GitHub API body | `vulnhunter-agent/agent/verify_refs.py:69` | cross-repo refs in comments | LLM extractor input | external |
| 30 | LLM output | `vulnhunter-agent/agent/verify_runner.py:156` | `verify_disposition.json` | verify verdict | external |
| 31 | LLM-derived | `vulnhunter-agent/agent/verify.py`, `vulnhunter-agent/agent/verify_extract.py` | `fixed_ids` (VULN-NNN markers) | verify kickoff | external |
| 33 | Issue-body marker | `vulnhunter-agent/agent/verify_extract.py` (`_RE_RESULTS_DIR`) | `vulnhunt-results-dir` marker (path) | verify staging | external |
| 34 | Issue-body marker | `vulnhunter-agent/agent/verify_resolve.py` | repo hint / additional-repo URL | clone | external |

## File scope (app-specific — define your trace scope)

`vulnhunter-agent/agent/__main__.py`, `vulnhunter-agent/agent/verify.py`, `vulnhunter-agent/agent/verify_extract.py`, `vulnhunter-agent/agent/verify_refs.py`, `vulnhunter-agent/agent/verify_resolve.py`, `vulnhunter-agent/agent/verify_runner.py`, `vulnhunter-agent/agent/verify_post.py`, `vulnhunter-agent/agent/_github_verify.py`, `vulnhunter-agent/agent/_body_reconstruct.py`, and `vulnhunter-agent/agent/_github.py` (contains the application-specific SSRF sink `api_base` — host interpolated into a URL). Also read `vulnhunter-agent/vulnhunter/app.py` (CLI entry wrapper).

## Shared infrastructure catalog (reference only — read when investigating defenses, do NOT treat as trace scope)

| Module | Files |
|---|---|
| Config reader + dataclasses | `vulnhunter-agent/agent/config.py` |
| Claude settings builder | `vulnhunter-agent/agent/build_settings.py` |
| URL helpers | `vulnhunter-agent/agent/_url.py` |
| LLM JSON client | `vulnhunter-agent/agent/_llm.py` |
| SDK event rendering | `vulnhunter-agent/agent/_stream_events.py`, `vulnhunter-agent/agent/_transient.py` |
| Auth/token managers | `vulnhunter-agent/agent/auth.py`, `vulnhunter-agent/agent/token_client.py` |
| Audit stream | `vulnhunter-agent/agent/audit.py`, `vulnhunter-agent/agent/audit_extract.py` |
| Skill version check | `vulnhunter-agent/agent/skill_version.py` |

## Threat model

- App-layer auth enforcement: **NONE**
- Caller identity binding: **NONE**
- Per-resource authorization: **NONE**
- Attacker profile: any party that can reach the entry point — the local CLI operator, plus any GitHub actor able to create/comment on issues (content not bound to a verified author identity), plus anyone able to influence LLM output via the cloned repo or issue bodies (prompt injection).
- Attacker controls: issue URLs, `--commit`/`--scratch-dir` flags, issue title/body/number, comments, events, edits, `html_url`/issue numbers, cross-repo refs, `verify_disposition.json`, `fixed_ids`, `vulnhunt-results-dir` marker paths, repo hints/additional-repo URLs.
- Attacker does NOT control: locally-provisioned secrets; trusted local config; `setting_sources=["user"]`; hardcoded DeepSeek base URL default.
- Existing attacker capabilities: baseline is "can reach the endpoint" only (all-NONE).
- Existing mitigations (input validation, NOT auth): CWE-88 option-injection rejection; CWE-22 contained-run/sanitize guards (`verify.py`, `verify_extract.py`); CWE-441 host-match + `allowed_path_prefixes` (`_url.py`); CWE-918 host-allowlist + exact-match alias map (`verify_resolve.py`); CWE-532 secret redaction; CWE-400 pagination caps; CANON-19 `setting_sources=["user"]` (`verify_runner.py`).
