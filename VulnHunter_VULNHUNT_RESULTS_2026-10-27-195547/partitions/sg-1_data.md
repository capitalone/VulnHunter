# SG-1 — Scan orchestration

Repo root (all paths below are relative to this): `/Users/srujankd/Temple_University/Senior Year/Capstone/workspace/code/VulnHunter`

**Entry point:** `vulnhunt --mode=scan <repo>` (+ GitHub issue/label/property consumers)
**Production reachability:** PRODUCTION (shipped CLI; no env gate found).

## Assigned inputs

| # | Source Type | Location | Variable | Entry Point | Trust |
|---|---|---|---|---|---|
| 1 | CLI positional | `vulnhunter-agent/agent/__main__.py:109` | `targets[0]` (git repo URL) | `vulnhunt --mode=scan <repo>` | local |
| 3 | CLI flag | `vulnhunter-agent/agent/__main__.py:91` | `--mode` | scan/verify dispatch | local |
| 4 | CLI flag | `vulnhunter-agent/agent/__main__.py:117` | `--config` (TOML path) | config loader | local |
| 5 | CLI flag | `vulnhunter-agent/agent/__main__.py:122` | `--model` | model override | local |
| 6 | CLI flag | `vulnhunter-agent/agent/__main__.py:131` | `--clone-dir` | scan clone target dir | local |
| 7 | CLI flag | `vulnhunter-agent/agent/__main__.py:141` | `--scan-id` | OTEL attr | local |
| 8 | CLI flag | `vulnhunter-agent/agent/__main__.py:196` | `--issues-target-repo` | issue target override | local |
| 9 | CLI flag | `vulnhunter-agent/agent/__main__.py:252` | `--commit` (SHA) | verify repo pin | local |
| 10 | CLI flag | `vulnhunter-agent/agent/__main__.py:258` | `--scratch-dir` | verify scratch dir | local |
| 11 | CLI flag | `vulnhunter-agent/agent/__main__.py:363` | `--repo-property NAME=VALUE` | findings metadata | local |
| 12 | CLI flag | `vulnhunter-agent/agent/__main__.py:342` | `--app-id` | audit field | local |
| 13 | CLI flag | `vulnhunter-agent/agent/__main__.py:348` | `--audit-actor` | audit field | local |
| 14 | CLI flag | `vulnhunter-agent/agent/__main__.py:317,322` | `--audit-events-path`, `--audit-findings-path` | audit JSONL paths | local |
| 15 | CLI flag | `vulnhunter-agent/agent/__main__.py:228,237` | `--no-read-only`, `--enable-bash` | code-exec toggles | local |
| 19 | Env var | `vulnhunter-agent/agent/auth.py`, `vulnhunter-agent/agent/config.py:463` | `ANTHROPIC_API_KEY` / `DEEPSEEK_API_KEY` / AWS Bedrock creds | token managers | secret |
| 20 | Env var / file | `vulnhunter-agent/agent/token_client.py` | GitHub tokens (env or `{broker_dir}/{role}.json`) | API auth | secret |
| 21 | GitHub API body | `vulnhunter-agent/agent/_github_verify.py:245` | issue title/body/number | verify issue fetch | external |
| 25 | GitHub API body | `vulnhunter-agent/agent/issues.py:241` | label name (encoded into URL path) | label upsert | external |
| 26 | GitHub API body | `vulnhunter-agent/agent/issues.py:841`, `vulnhunter-agent/agent/_github_verify.py:128` | `html_url`, issue number | URL parse → owner/repo | external |
| 27 | GitHub API body | `vulnhunter-agent/agent/repo_properties.py:89` | repo custom properties | findings metadata | external |
| 29 | LLM output | `vulnhunter-agent/agent/issues_extract.py` | scan findings JSON | issue posting | external |
| 32 | Cloned repo files | `vulnhunter-agent/agent/runner.py`, `harness/local_harness/scan.py` | repo content read by agent | scan session | external |

## File scope (app-specific — define your trace scope)

`vulnhunter-agent/agent/__main__.py`, `vulnhunter-agent/agent/clone.py`, `vulnhunter-agent/agent/runner.py`, `vulnhunter-agent/agent/publish.py`, `vulnhunter-agent/agent/issues.py`, `vulnhunter-agent/agent/issues_extract.py`, `vulnhunter-agent/agent/issues_fetch.py`, `vulnhunter-agent/agent/issues_dedup.py`, `vulnhunter-agent/agent/issues_render.py`, `vulnhunter-agent/agent/issues_remote_report.py`, `vulnhunter-agent/agent/manifest.py`, `vulnhunter-agent/agent/repo_properties.py`, and `vulnhunter-agent/agent/_github.py` (contains the application-specific SSRF sink `api_base` — host interpolated into a URL). Also read `vulnhunter-agent/vulnhunter/app.py` (CLI entry wrapper).

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
| Issue body reconstruction | `vulnhunter-agent/agent/_body_reconstruct.py` |
| Skill version check | `vulnhunter-agent/agent/skill_version.py` |

## Threat model

- App-layer auth enforcement: **NONE**
- Caller identity binding: **NONE**
- Per-resource authorization: **NONE**
- Attacker profile: any party that can reach the entry point — the local CLI operator (and any process with host shell/env access), plus any GitHub actor able to create/comment on issues or set repo custom properties (the API call is authenticated by `scan_token`/`reports_token`, but the *content* it returns is not bound to any verified author identity).
- Attacker controls: repo URL, CLI flags, GitHub issue title/body/number, label names, `html_url`/issue numbers, repo custom properties, LLM-derived findings JSON, cloned-repo file content.
- Attacker does NOT control: locally-provisioned secrets (`ANTHROPIC_API_KEY`, `DEEPSEEK_API_KEY`, Bedrock creds, GitHub tokens, broker token files); trusted local config; `setting_sources=["user"]` skill discovery; hardcoded DeepSeek base URL default.
- Existing attacker capabilities: baseline is "can reach the endpoint" only (all-NONE). No pre-authorization inferred.
- Existing mitigations (input validation, NOT auth — do not credit as auth): CWE-88 option-injection rejection (`clone.py`, `check-scope.py:24`); CWE-22 contained-run/sanitize guards; CWE-441 host-match + `allowed_path_prefixes` (`_url.py`); CWE-918 host-allowlist + exact-match alias map (`verify_resolve.py`); CWE-79 body sanitization (`issues_render.py`); CWE-532 secret redaction (`_url.py`, `build_settings.py`); CWE-400 pagination caps (`_github_verify.py`); CANON-19 `setting_sources=["user"]` (`runner.py`).
