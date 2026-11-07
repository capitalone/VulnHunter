# Phase 1 Reconnaissance — Attack Surface Report

**Target:** VulnHunter (a Claude Code security-scanning agent that clones repos, runs `/vulnhunt`, publishes results, and posts/verifies GitHub issues)
**Scan mode:** read-only (Glob/Grep/Read equivalents only — no deps installed, no build, no code executed)
**Date:** 2026-10-27

---

## Languages

- **Python 3.10+** — three packages: `vulnhunter-agent/agent` (orchestrator CLI + SDK drivers), `vulnhunter-fix/vulnhunter_fix` (graph/validation library) + `vulnhunter-fix/scripts` (CLI gate scripts), `harness/local_harness` (benchmark/batch runners)
- **Shell (bash)** — `install.sh`, `uninstall.sh`, `vulnhunt.sh`
- **GUI (Python/PyQt5)** — mock dashboard, `gui/dashboard.py`, `gui/designs/merged/app.py`
- **Config/data formats** — TOML (config), JSON (schemas, manifests, dispositions, sidecars), Markdown (skills, issue/PR bodies), YAML (collaborators.json references)

## Frameworks

- **claude_agent_sdk** (`ClaudeSDKClient`, `ClaudeAgentOptions`) — drives `/vulnhunt` and `/vulnhunt-fix-verify` LLM sessions (scan + verify)
- **httpx** (sync `Client` + async `AsyncClient`) — all GitHub REST/GraphQL calls
- **tenacity** — transient-error retry
- **jsonschema** (Draft 2020-12) — manifest/disposition/finding schema validation
- **argparse** — CLI entry points (`agent/__main__.py`, `vulnhunter-fix/scripts/*`, `harness/*`)
- **asyncio** — orchestration loops
- **graphifyy** (`graphify` import) — AST call-graph building in `vulnhunter-fix` (falls back to `grep` subprocess)
- **PyQt5** — GUI (mock only)
- **git / gh / claude CLIs** — invoked via subprocess

---

## Input Inventory

**49 inputs across 9 entry-point families.** Trust levels: `local` = operator with host shell access; `secret` = local credential material; `external` = attacker-influenceable remote content (no app-layer auth verified); `dev` = development harness only.

| # | Source Type | Location | Variable | Entry Point | Trust Level |
|---|---|---|---|---|---|
| 1 | CLI positional | `agent/__main__.py:109` | `targets[0]` (git repo URL) | `vulnhunt --mode=scan <repo>` | local |
| 2 | CLI positional | `agent/__main__.py:109` | `targets[]` (issue URLs) | `vulnhunt --mode=verify <issue-url...>` | local |
| 3 | CLI flag | `agent/__main__.py:91` | `--mode` | scan/verify dispatch | local |
| 4 | CLI flag | `agent/__main__.py:117` | `--config` (TOML path) | config loader | local |
| 5 | CLI flag | `agent/__main__.py:122` | `--model` | model override | local |
| 6 | CLI flag | `agent/__main__.py:131` | `--clone-dir` | scan clone target dir | local |
| 7 | CLI flag | `agent/__main__.py:141` | `--scan-id` | OTEL attr | local |
| 8 | CLI flag | `agent/__main__.py:196` | `--issues-target-repo` | issue target override | local |
| 9 | CLI flag | `agent/__main__.py:252` | `--commit` (SHA) | verify repo pin | local |
| 10 | CLI flag | `agent/__main__.py:258` | `--scratch-dir` | verify scratch dir | local |
| 11 | CLI flag | `agent/__main__.py:363` | `--repo-property NAME=VALUE` | findings metadata | local |
| 12 | CLI flag | `agent/__main__.py:342` | `--app-id` | audit field | local |
| 13 | CLI flag | `agent/__main__.py:348` | `--audit-actor` | audit field | local |
| 14 | CLI flag | `agent/__main__.py:317,322` | `--audit-events-path`, `--audit-findings-path` | audit JSONL paths | local |
| 15 | CLI flag | `agent/__main__.py:228,237` | `--no-read-only`, `--enable-bash` | code-exec toggles | local |
| 16 | Config file | `agent/config.py:357` | TOML (all `[sections]`) | `load_config` | local |
| 17 | Env var | `agent/config.py:357` | `VULNHUNT_AGENT_CONFIG` | config path | local |
| 18 | Env var | `agent/config.py:404` | `VULNHUNT_<SECTION>_<KEY>` | config overlay | local |
| 19 | Env var | `agent/auth.py`, `agent/config.py:463` | `ANTHROPIC_API_KEY` / `DEEPSEEK_API_KEY` / AWS Bedrock creds | token managers | secret |
| 20 | Env var / file | `agent/token_client.py` | GitHub tokens (env or `{broker_dir}/{role}.json`) | API auth | secret |
| 21 | GitHub API body | `agent/_github_verify.py:245` | issue title/body/number | verify issue fetch | external |
| 22 | GitHub API body | `agent/_github_verify.py:276` | issue comments | verify comment fetch | external |
| 23 | GitHub API body | `agent/_github_verify.py:340` | issue events | verify event fetch | external |
| 24 | GitHub GraphQL | `agent/_github_verify.py:460` | user content edits | edit fetch | external |
| 25 | GitHub API body | `agent/issues.py:241` | label name (encoded into URL path) | label upsert | external |
| 26 | GitHub API body | `agent/issues.py:841`, `agent/_github_verify.py:128` | `html_url`, issue number | URL parse → owner/repo | external |
| 27 | GitHub API body | `agent/repo_properties.py:89` | repo custom properties | findings metadata | external |
| 28 | GitHub API body | `agent/verify_refs.py:69` | cross-repo refs in comments | LLM extractor input | external |
| 29 | LLM output | `agent/issues_extract.py` | scan findings JSON | issue posting | external |
| 30 | LLM output | `agent/verify_runner.py:156` | `verify_disposition.json` | verify verdict | external |
| 31 | LLM-derived | `agent/verify.py`, `agent/verify_extract.py` | `fixed_ids` (VULN-NNN markers) | verify kickoff | external |
| 32 | Cloned repo files | `agent/runner.py`, `harness/local_harness/scan.py` | repo content read by agent | scan session | external |
| 33 | Issue-body marker | `agent/verify_extract.py` (`_RE_RESULTS_DIR`) | `vulnhunt-results-dir` marker (path) | verify staging | external |
| 34 | Issue-body marker | `agent/verify_resolve.py` | repo hint / additional-repo URL | clone | external |
| 35 | File content | `agent/token_client.py` | `{broker_dir}/{role}.json` | broker token | secret |
| 36 | CLI flag | `vulnhunter-fix/scripts/*.py` | `--repo-root` (many scripts) | gate scripts | local |
| 37 | CLI flag | `check-body-completeness.py:147`, `pr-body-check.py:144`, `run-gates.py:247` | `--body` / `--pr-body` / `--issue-body` | body lints | external |
| 38 | CLI flag / stdin | `compute-completeness-tier.py:229`, `crypto-trust-chain-checkers.py:353` | `--diff` / stdin diff | tier/trust checks | external |
| 39 | CLI flag | `check-scope.py:84` | `--branch`, `--base-ref`, `--files-modified` | scope gate | external |
| 40 | CLI flag | `worktree-reset.py:144` | `--worktree`, `--branch-baseline`, `--vuln-id`, `--reason` | worktree reset | local |
| 41 | CLI flag | `run-gates.py:250`, `validate-verification.py:294` | `--sidecars-dir`, `--result`, `--plan` | gate inputs | local |
| 42 | File content | `harness/local_harness/batch/utils.py:68` | repo list file | batch runner | dev |
| 43 | CLI flag | `harness/local_harness/benchmark/run.py:359` | `--repos`, `--findings` | benchmark | dev |
| 44 | File content | `harness/local_harness/benchmark/run.py:100` | `STATE_FILE` | benchmark resume | dev |
| 45 | CLI arg / stdin | `vulnhunt.sh:19-31` | `provider`, `read` choice | launcher | local |
| 46 | Env var | `vulnhunt.sh:15-17,44` | `DEEPSEEK_API_KEY`, `DEEPSEEK_BASE_URL`, `*_MODEL` | launcher | secret |
| 47 | Env var | `install.sh:6`, `uninstall.sh:7` | `HOME` (drives `rm -rf` dst) | installer | local |
| 48 | CLI passthrough | `vulnhunt.sh:41,58` | `"$@"` forwarded to `claude` | launcher | local |
| 49 | GUI field | `gui/designs/merged/app.py:178` | repo `QLineEdit` text | GUI (mock, live scan not implemented) | dev |

**Completeness check:** every entry point (scan CLI, verify CLI, GitHub API consumers, LLM-output consumers, cloned-repo consumers, vulnhunter-fix gate scripts, harness runners, shell installer/launcher, GUI) has ≥1 input. No synthetic `no-input endpoint` entries required.

---

## Step 1a / 1e Notes — Sink & Gate Pre-Pass Summary

Sink families enumerated (file:line anchors in source, cross-referenced in partitions):

- **Subprocess (git/claude/gh/python)** — `agent/clone.py` (shallow_clone, clone_at_commit), `agent/publish.py` (git init/remote/fetch/reset/add/commit/push), `agent/issues_remote_report.py` (git sparse-checkout), `harness/local_harness/scan.py` (`claude -p` Popen), `harness/local_harness/clone.py`, `vulnhunter-fix/scripts/preflight.py` (git/gh/claude `check_output`), `check-scope.py`, `worktree-reset.py`, `run-gates.py` (`[sys.executable, script, ...]`), `pr-body-check.py`, `vulnhunter_fix/graph/fallback.py` (`subprocess.run` grep fallback, `# nosec B603`). **Hardening observed:** static argv lists, `--` separator, leading-dash rejection (`clone.py:_reject_option_like`, `check-scope.py:24`), `shutil.which` absolute path resolution, token scrub from `.git/config`.
- **httpx HTTP clients** — `issues.py` (POST/GET issues, labels, comments), `issues_fetch.py`, `repo_properties.py`, `verify_post.py`, `_github_verify.py` (REST + GraphQL), `publish.py`, `_llm.py` (SDK). Pagination caps (CWE-400) in `_github_verify.py`.
- **URL-path-concatenation sinks (MANDATORY sweep)** — `_github.py:24 api_base(host)` → `f"https://{host}/api/v3"` (host from config, SSRF surface); every caller interpolates owner/repo/number/label into `f"{api}/repos/{owner}/{name}/..."` — `issues.py:241,256,268,336,382,424`, `issues_fetch.py:92`, `repo_properties.py:129`, `_github_verify.py:246,285,348,460,554,578`, `publish.py:91`, `__main__.py:557`. **owner/repo/number originate from attacker-influenceable issue URLs and label names** — application-specific sinks, NOT shared infrastructure.
- **File writes** — `manifest.py:104`, `audit.py:339` (0o600 JSONL), `verify_extract.py:render_comments_file`, `sweep-root-causes.py:358`, `build_graph.py:174`, `vulnhunter_fix/graph/build.py:101`.
- **Path traversal / symlink guards** — `verify.py:_contained_run_dir`, `verify.py:_sanitize_clone_subdir`, `verify_extract.py` (forbids `..`/`/`/`\` in results-dir marker), `harness/local_harness/scan.py` (`O_NOFOLLOW`, FIFO/symlink rejection), `harness/local_harness/benchmark/judge.py:55` (`O_NOFOLLOW` read).
- **Authorization gate audit (Step 1e)** — `_url.py:inject_token` host-match + `allowed_path_prefixes` (CWE-441); `verify_resolve.py:resolve_repo_hint` exact-match alias map, NO substring inference (no `.contains(` on host allowlists — clean). No `String.contains()` allowlist anti-pattern found.
- **XSS** — `issues_render.py:_sanitize_for_issue_body` (`html.escape` + backslash-escape) for issue bodies.
- **Secret redaction** — `_url.py:redact` (5-pass masking), `build_settings.py` (proxy blanking, telemetry).

---

## Application Call Graph (condensed, 2 levels)

| Entry Point | Inputs | App Functions Called | Sinks Reached | Files Touched |
|---|---|---|---|---|
| `vulnhunt --mode=scan <repo>` | #1,#3–#15,#17–#20 | `_run_scan_flow` → `shallow_clone/clone_at_commit` → `run_vulnhunt/_run_scan_session` → `publish_results` → `post_issues` → `write_manifest` | subprocess git, SDK, httpx, file write | `__main__.py`, `clone.py`, `runner.py`, `publish.py`, `issues.py`, `issues_extract.py`, `issues_fetch.py`, `issues_dedup.py`, `issues_render.py`, `issues_remote_report.py`, `manifest.py`, `repo_properties.py`, `skill_version.py` |
| `vulnhunt --mode=verify <issue-url...>` | #2,#9,#10,#21–#28 | `_amain_verify` → `_fetch_all_issues` → `extract_markers` → `resolve_repo_hint/clone_target_repo` → `extract_cross_repo_references` → `run_verify_session` → `_post_dispositions` | httpx REST/GraphQL, subprocess git, SDK, file write | `__main__.py`, `verify.py`, `verify_extract.py`, `verify_refs.py`, `verify_resolve.py`, `verify_runner.py`, `verify_post.py`, `_github_verify.py`, `_body_reconstruct.py` |
| GitHub API consumers (shared by both) | #21–#28 | `parse_issue_url` → `get_issue` → `list_comments` → `list_events` → `list_user_content_edits` | httpx, GraphQL, URL concat | `_github.py`, `_github_verify.py`, `issues_fetch.py`, `repo_properties.py` |
| Config/token resolution | #16–#20 | `load_config` → `make_token_manager` → `get_github_token` → `build_claude_settings` | env/file reads, httpx.Auth | `config.py`, `auth.py`, `token_client.py`, `build_settings.py`, `_url.py`, `_llm.py` |
| vulnhunter-fix gate scripts | #36–#41 | `preflight`, `check-scope`, `worktree-reset`, `run-gates` → child scripts | subprocess git/python, file read/write, AST parse | `vulnhunter-fix/scripts/*.py`, `vulnhunter_fix/graph/*.py` |
| Harness batch/benchmark | #42–#44 | `scan_folder` → `clone_at_commit` → `judge` → `tally` | Popen claude, subprocess, file write | `harness/local_harness/*` |
| Shell installer/launcher | #45–#48 | `build_vulnfix_venv`, `exec claude`, `rm -rf` | subprocess pip/venv, exec, rm | `install.sh`, `uninstall.sh`, `vulnhunt.sh` |
| GUI (mock) | #49 | `start_scan` (demo replay only) | none (live scan unimplemented) | `gui/*.py` |

---

## Threat Model

All entry points are **CLI/daemon/local** or consume **remote content without app-layer authentication of the source**. The audited code provisions *outbound* credentials (auth.py token managers, token_client.py broker tokens) to authenticate VulnHunter *to* GitHub/Anthropic — none of this authenticates a caller *to* VulnHunter. No entry point performs inbound credential rejection, cryptographic caller-identity binding, or per-resource authorization of the consuming caller. Per the skill's NONE-based evidence rule, all three fields are `NONE`.

| Entry-point group | App-layer auth enforcement | Caller identity binding | Per-resource authorization |
|---|---|---|---|
| Scan-mode CLI (`--mode=scan <repo>`) | NONE | NONE | NONE |
| Verify-mode CLI (`--mode=verify <issue-url...>`) | NONE | NONE | NONE |
| Config/env/token resolution (`load_config`, `make_token_manager`) | NONE | NONE | NONE |
| GitHub API content consumers (issues/comments/events/edits/labels/properties) | NONE | NONE | NONE |
| LLM-output consumers (findings, dispositions, cross-repo refs) | NONE | NONE | NONE |
| Cloned-repo file consumers (scan/verify sessions) | NONE | NONE | NONE |
| vulnhunter-fix gate scripts (CLI) | NONE | NONE | NONE |
| Harness batch/benchmark runners (CLI) | NONE | NONE | NONE |
| Shell installer/launcher (`install.sh`/`uninstall.sh`/`vulnhunt.sh`) | NONE | NONE | NONE |
| GUI dashboard (mock) | NONE | NONE | NONE |

- **Attacker profile (per row):** any party that can reach the entry point. CLI/harness/shell rows: the local operator (and any process with host shell/env access). GitHub-content rows: any GitHub actor able to create/comment on issues or set repo custom properties in the target repo (the API call itself is authenticated by `scan_token`/`reports_token`, but the *content* it returns is not bound to any verified author identity). LLM-output rows: anyone able to influence model output via the cloned repo or issue bodies (prompt injection). Cloned-repo rows: anyone controlling the target repository.
- **Attacker controls:** the input rows listed per group above (repo URLs, issue URLs, issue bodies/comments/events/edits, label names, repo properties, findings/disposition JSON, results-dir markers, repo hints, PR bodies, diffs, branches, file-modified lists, env/config).
- **Attacker does NOT control:** locally-provisioned secrets (`ANTHROPIC_API_KEY`, `DEEPSEEK_API_KEY`, Bedrock creds, GitHub tokens, broker token files), the CLI operator's trusted config when not attacker-editable, `setting_sources=["user"]` skill discovery (CANON-19 — prevents cloned-repo `.claude/settings*.json` from executing hooks), and the hardcoded DeepSeek base URL default.
- **Existing attacker capabilities (per row):** All three fields NONE ⇒ baseline is "can reach the endpoint" only. Operations remain subject to CWE-306/639/918/79/22/88 evaluation in Phase 2; no pre-authorization is inferred from the absence of auth.

Existing mitigations noted (these are *input validation*, not auth/binding/authorization, so they do not change the NONE fields): CWE-88 option-injection rejection (`clone.py`, `check-scope.py:24`), CWE-22 contained-run/sanitize guards (`verify.py`, `verify_extract.py`), CWE-441 host-match + `allowed_path_prefixes` (`_url.py`), CWE-918 host-allowlist + exact-match alias map (`verify_resolve.py`), CWE-79 body sanitization (`issues_render.py`), CWE-532 secret redaction (`_url.py`, `build_settings.py`), CWE-400 pagination caps (`_github_verify.py`), CANON-19 `setting_sources=["user"]` (`runner.py`, `verify_runner.py`).

---

## Trust Boundaries

| Boundary | Location | Input Source | Validation |
|---|---|---|---|
| CLI argv → parser | `agent/__main__.py:85-373` | #1–#15 | argparse types/choices; positional count validated in `main()`; repo URL normalized (`runner.py:_normalize_repo_url`) |
| Config file + env → dataclasses | `agent/config.py:357-505` | #16–#18 | TOML parse; base_url `/v1` suffix check (`config.py:502`); deepseek mode reads only `DEEPSEEK_API_KEY` |
| Credential env/file → token managers | `agent/auth.py`, `agent/token_client.py` | #19–#20,#35 | OAuth client-credentials, SigV4, broker file JSON read; broker role scoping |
| GitHub REST/GraphQL → parsers | `agent/_github.py`, `agent/_github_verify.py`, `agent/issues*.py` | #21–#28 | `parse_owner_repo` shape validation; `_COMMIT_SHA_RE`; `redact()`; pagination caps; response JSON assumed trusted after redaction |
| LLM SDK stream → classifiers | `agent/runner.py`, `agent/verify_runner.py`, `agent/issues_extract.py` | #29–#31 | jsonschema Draft 2020-12 validation; `_coerce_finding`; disposition classify |
| Cloned repo / results files → agent | `agent/runner.py`, `agent/verify_extract.py`, `harness/*/scan.py` | #32–#34 | `setting_sources=["user"]` (CANON-19); `_contained_run_dir`; `_RE_RESULTS_DIR` forbids `..`/`/`/`\`; `O_NOFOLLOW`/FIFO guards; `_reject_option_like` |
| Subprocess boundary (git/claude/gh/pip) | `agent/clone.py`, `agent/publish.py`, `harness/*/scan.py`, `vulnhunter-fix/scripts/*` | #1–#15,#36–#41 | static argv lists, `--` separator, `shutil.which` absolute path, token scrub, timeouts |
| File-system writes (reports, audit JSONL, dispositions) | `agent/publish.py`, `agent/manifest.py`, `agent/audit.py`, `agent/verify_runner.py` | #29–#31,#11,#12 | 0o600 audit open (`audit.py:339`); git push to dedicated `destination_repo` |
| Shell launcher/installer | `install.sh`, `uninstall.sh`, `vulnhunt.sh` | #45–#48 | HOME-set guard before `rm -rf`; `env -u ANTHROPIC_API_KEY` before DeepSeek exec |
| GUI (mock) | `gui/designs/merged/app.py` | #49 | demo replay only; "Live scan is not implemented yet." |

---

## Shared Infrastructure Catalog

Modules imported by >50% of entry points, or cross-cutting utilities. These define no trace scope for Phase 2 agents (read as reference only). **Exception:** `_github.py:api_base` interpolates `host` into a URL and is therefore an application-specific SSRF sink — it stays in the app-specific file lists of SG-1/SG-2.

| Module | Role | Files |
|---|---|---|
| Config reader + dataclasses | env/TOML → typed config | `vulnhunter-agent/agent/config.py` |
| Claude settings builder | SDK env/sandbox JSON (proxy blanking, allowlists) | `vulnhunter-agent/agent/build_settings.py` |
| URL helpers | token inject + secret redact | `vulnhunter-agent/agent/_url.py` |
| LLM JSON client | SDK JSON calls + fallback chain | `vulnhunter-agent/agent/_llm.py` |
| SDK event rendering | stream/totals logging | `vulnhunter-agent/agent/_stream_events.py`, `agent/_transient.py` |
| Auth/token managers | outbound credential provisioning | `vulnhunter-agent/agent/auth.py`, `agent/token_client.py` |
| Audit stream | JSONL lifecycle/findings emission | `vulnhunter-agent/agent/audit.py`, `agent/audit_extract.py` |
| Issue body reconstruction | body/title assembly | `vulnhunter-agent/agent/_body_reconstruct.py` |
| Skill version check | installed-skill staleness | `vulnhunter-agent/agent/skill_version.py` |
| Schema contracts | JSON schemas (repo root) | `verify_disposition.schema.json`, `scan_manifest` schema |

---

## Subgraph Partitions

| Partition | Inputs | Entry Points | App-Specific Files | Shared Nodes Used |
|---|---|---|---|---|
| **SG-1** Scan orchestration | #1,#3–#15,#19–#21,#25–#27,#29,#32 | `vulnhunt --mode=scan <repo>` (+ GitHub issue/label/property consumers) | `agent/__main__.py`, `agent/clone.py`, `agent/runner.py`, `agent/publish.py`, `agent/issues.py`, `agent/issues_extract.py`, `agent/issues_fetch.py`, `agent/issues_dedup.py`, `agent/issues_render.py`, `agent/issues_remote_report.py`, `agent/manifest.py`, `agent/repo_properties.py`, `agent/_github.py` (sink) | config, build_settings, _url, _llm, _stream_events, _transient, auth, token_client, audit, audit_extract, _body_reconstruct, skill_version |
| **SG-2** Verify orchestration | #2,#9,#10,#21–#24,#26,#28,#30,#31,#33,#34 | `vulnhunt --mode=verify <issue-url...>` (+ GitHub issue/comment/event/edit consumers) | `agent/__main__.py`, `agent/verify.py`, `agent/verify_extract.py`, `agent/verify_refs.py`, `agent/verify_resolve.py`, `agent/verify_runner.py`, `agent/verify_post.py`, `agent/_github_verify.py`, `agent/_body_reconstruct.py`, `agent/_github.py` (sink) | config, build_settings, _url, _llm, _stream_events, _transient, auth, token_client, audit, skill_version |
| **SG-3** vulnhunter-fix gate scripts + library | #36–#41 | `preflight.py`, `check-scope.py`, `worktree-reset.py`, `run-gates.py` (dispatch to child scripts), `build_graph.py`, `sweep-root-causes.py`, `validate-*` | `vulnhunter-fix/scripts/*.py`, `vulnhunter_fix/graph/*.py`, `vulnhunter_fix/delivery.py` | (self-contained; schema files, jsonschema, graphifyy) |
| **SG-4** Harness batch/benchmark | #42–#44 | `batch/run.py`, `benchmark/run.py`, `benchmark/judge.py`, `benchmark/tally.py`, `benchmark/analyze_misses.py`, `benchmark/finding_history.py` | `harness/local_harness/**` | harness config, clone, scan |
| **SG-5** Shell installer/launcher | #45–#48 | `install.sh`, `uninstall.sh`, `vulnhunt.sh` | `install.sh`, `uninstall.sh`, `vulnhunt.sh` | (none) |
| **SG-6** GUI dashboard | #49 | `gui/dashboard.py`, `gui/designs/merged/app.py` | `gui/**` (+ `mock_data.py`) | (none — mock) |

**Production Reachability annotation:**
- SG-1, SG-2, SG-3, SG-5 — `PRODUCTION` (reachable via the shipped CLI/scripts/shell; no env gate found).
- SG-4 — `DEV-ONLY` (harness is a local benchmark tool; not part of the deployed agent — `harness/local_harness/config.py` constants, no production wiring).
- SG-6 — `DEV-ONLY` (mock GUI; `gui/designs/merged/app.py:266-268` "Live scan is not implemented yet.", demo replay only).

**Pathological partition check:** SG-1 and SG-2 each exceed 15 app-specific files but each has ≤20 distinct input rows and is split cleanly along the scan/verify mode boundary (already separated). No single application function (outside the shared catalog) joins all entry points into one component — `_github.py:api_base` is the only shared URL sink and is promoted as an application-specific sink in both SG-1 and SG-2 as required. No `SEQUENTIAL-FALLBACK` or `DEPTH-SPLIT` markers needed.

**Partition coverage check (MANDATORY):**
- `vulnhunter-agent/agent` → **PASS** (SG-1, SG-2)
- `vulnhunter-fix` (scripts + library) → **PASS** (SG-3)
- `harness/local_harness` → **PASS** (SG-4, DEV-ONLY)
- shell scripts → **PASS** (SG-5)
- `gui` → **PASS** (SG-6, DEV-ONLY)

---

## Step 4: Build-Time Code Swapping Detection

None found. `install.sh` copies skills from the repo into `~/.claude/skills/` (not a mock/prod swap), and `gui/dashboard.py` vs `gui/designs/merged/app.py` are two independent mock variants (both DEV-ONLY), not build-selected production alternates. No `prod-impl`/`mock-impl` parallel structure with build-time selection exists.

---

## Auth Bypass / Indirect Dispatch Candidates (for Phase 2)

- **Indirect dispatch:** `agent/__main__.py` mode dispatch (`--mode=scan` → `_run_scan_flow`, `--mode=verify` → `_amain_verify`); `vulnhunter-fix/scripts/run-gates.py:293` dispatches gate scripts by `sys.executable [script, ...]` list; `harness` benchmark `--scan-only/--judge-only/--tally-only` stage dispatch.
- **Auth bypass paths:** No `bypass`/`skip auth`/`without auth`/`no token` comments found in production code; `--no-post`/`--no-reopen` are dry-run toggles, not auth bypasses. Verify-mode `read-only` envelope (`_VERIFY_ALLOWED_TOOLS`, no Bash) is the primary permission control.
- **Classification consistency:** owner/repo derived in two places — `_github.py:parse_owner_repo` (scan) and `_github_verify.py:parse_issue_url` (verify) — both shape-validated; no divergent substring-vs-prefix classifier found. Flag for Phase 2 cross-check anyway.
