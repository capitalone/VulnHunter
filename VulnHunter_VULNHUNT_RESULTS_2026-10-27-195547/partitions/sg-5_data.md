# SG-5 — Shell installer/launcher

Repo root (all paths below are relative to this): `/Users/srujankd/Temple_University/Senior Year/Capstone/workspace/code/VulnHunter`

**Entry point:** `install.sh`, `uninstall.sh`, `vulnhunt.sh` (and Windows `install.cmd`, `uninstall.cmd`)
**Production reachability:** PRODUCTION (shipped shell scripts; no env gate found).

## Assigned inputs

| # | Source Type | Location | Variable | Entry Point | Trust |
|---|---|---|---|---|---|
| 45 | CLI arg / stdin | `vulnhunt.sh:19-31` | `provider`, `read` choice | launcher | local |
| 46 | Env var | `vulnhunt.sh:15-17,44` | `DEEPSEEK_API_KEY`, `DEEPSEEK_BASE_URL`, `*_MODEL` | launcher | secret |
| 47 | Env var | `install.sh:6`, `uninstall.sh:7` | `HOME` (drives `rm -rf` dst) | installer | local |
| 48 | CLI passthrough | `vulnhunt.sh:41,58` | `"$@"` forwarded to `claude` | launcher | local |

## File scope (app-specific — define your trace scope)

`install.sh`, `uninstall.sh`, `vulnhunt.sh`, `install.cmd`, `uninstall.cmd`.

## Shared infrastructure catalog

None (self-contained shell scripts).

## Threat model

- App-layer auth enforcement: **NONE**
- Caller identity binding: **NONE**
- Per-resource authorization: **NONE**
- Attacker profile: the local operator and any process with host shell/env access.
- Attacker controls: `provider`/`read` choices, `DEEPSEEK_API_KEY`/`DEEPSEEK_BASE_URL`/`*_MODEL` env vars, `HOME`, and arbitrary args forwarded to `claude` via `"$@"`.
- Attacker does NOT control: hardcoded default base URL.
- Existing attacker capabilities: baseline is "can reach the endpoint" only (all-NONE).
- Existing mitigations (input validation, NOT auth): HOME-set guard before `rm -rf`; `env -u ANTHROPIC_API_KEY` before DeepSeek exec.
