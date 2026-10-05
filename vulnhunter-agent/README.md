# VulnHunter Agent

A config-driven runtime that automates the [`/vulnhunt`](https://github.com/capitalone/vulnhunter)
scanner **headlessly** — no interactive model session required. Point it at a
repository and it will clone the target, run the scanner, publish the results, and file
each confirmed finding as a GitHub issue. It also has a `verify` mode that drives the
read-only fix-verification flow.

It is the automation layer around the skills: the skills define *how* to hunt and fix;
this agent makes a scan runnable unattended (CI, a scheduled job, a fleet worker, or a
container) and wires the results into GitHub.

## Purpose

- **Scan** — clone a target repo and run `/vulnhunt` through the Claude Agent SDK,
  a direct OpenAI-compatible Responses runtime, or Codex CLI, producing the standard
  `*_VULNHUNT_RESULTS_*` output directory.
- **Publish** *(optional)* — copy that results directory into a separate git repository
  and push a commit, so reports live outside the scanned repo.
- **Issues** *(optional)* — post one deduplicated GitHub issue per confirmed finding on
  the target repo, linking back to the published report; emit a "clean scan" receipt when
  there are no findings.
- **Verify** *(`--mode=verify`)* — orchestrate the `/vulnhunt-fix-verify` skill over a
  checkout and post a per-finding verdict.

The agent hardcodes nothing sensitive: every host, credential, and path comes from a
TOML config file and/or `VULNHUNT_*` environment variables, so the same image runs across
environments without rebuilding.

## Requirements

- Python 3.12+.
- The Claude Agent SDK and its bundled CLI for the default Anthropic backend. The
  direct OpenAI backend uses the existing `httpx` dependency. The Codex backend
  requires Codex CLI 0.144.1+ on `PATH` (or `[codex].executable`).
- `git` and, for the publish/issues stages, the GitHub CLI or a GitHub token.
- Access to either Claude or a Responses-compatible API.

```bash
cd vulnhunter-agent
python -m pip install -e ".[dev]"
cp agent/config.example.toml agent/config.toml   # then edit, or use env vars
```

An editable source checkout discovers both scanner skills directly from this
repository. Packaged/container deployments should run the repository's
`install.sh` during image construction so the canonical and Codex skills are
available under the user skill directories.

For Codex CLI installation, direct interactive skill invocation, and a focused
compatible-endpoint walkthrough, see
[`docs/codex-cli.md`](../docs/codex-cli.md).

## Quick start

```bash
# Direct Anthropic API (default): export your key, then scan.
export ANTHROPIC_API_KEY=sk-...
python -m agent --mode=scan https://github.com/your-org/your-service

# Scan only, no publish/issues:
python -m agent --mode=scan https://github.com/your-org/your-service --no-publish --no-issues
```

### OpenAI-compatible GPT-5.6 Sol

Select the OpenAI backend and point `base_url` at an API root that implements
`POST /responses` with function calling and stateless replay of response output items:

```toml
[runtime]
provider = "openai"

[openai]
base_url = "https://api.openai.com/v1" # or your compatible gateway's /v1 root
model = "gpt-5.6-sol"
reasoning_effort = "xhigh"
request_timeout_seconds = 3600
max_tool_rounds = 200
max_concurrent_agents = 6
```

Then provide the key and run a static scan:

```bash
export OPENAI_API_KEY=sk-...
python -m agent --mode=scan https://github.com/your-org/your-service \
  --no-publish --no-issues
```

The OpenAI backend is deliberately static-analysis only: `--enable-bash` and
`--no-read-only` are rejected. It exposes repository read/search tools, an output-only
write tool, and bounded same-model subagents. Repository code never executes in the
credential-bearing process. Refusals, incomplete responses, missing `README.md`, and
failed subagents fail the scan instead of being reported as clean.

### Codex + OpenAI-compatible GPT-5.6 Sol

Use the Codex backend when you want Codex's native shell/search tools, skills,
and subagents to drive the same canonical VulnHunter phase prompts. The gateway
must implement the streamed Responses API and pass through function/tool calls:

```toml
[runtime]
provider = "codex"

[openai]
base_url = "https://api.openai.com/v1" # or your compatible /v1 root
model = "gpt-5.6-sol"
reasoning_effort = "xhigh"

[codex]
executable = "codex"
request_timeout_seconds = 14400
max_concurrent_agents = 6
```

```bash
export OPENAI_API_KEY=sk-...
python -m agent --mode=scan https://github.com/your-org/your-service \
  --no-publish --no-issues
```

The process uses `codex exec --json --ephemeral` with a one-run custom model
provider. It ignores user config and rules, disables plugins/apps/web search,
runs from a disposable workspace, keeps the target read-only, and adds only the
results directory as a durable writable root. The provider key is present in the
Codex process but removed from every model-launched subprocess. Static scans do
not install dependencies or execute target code.

The repo-scoped `$vulnhunt-codex` skill supplies the phase graph and bounded
subagent steps. Codex subagents inherit the parent `gpt-5.6-sol` + `xhigh`
settings; the skill dispatches them in waves of at most six. Pure JSON issue
extraction/dedup and verify mode still use the direct Responses envelope to avoid
CLI startup overhead.

## Configuration

Settings load from a TOML file (`--config`, then `$VULNHUNT_AGENT_CONFIG`, then
`agent/config.toml`) and are overlaid by environment variables named
`VULNHUNT_<SECTION>_<KEY>` (env wins). See
[`agent/config.example.toml`](agent/config.example.toml) for every option.

### Selecting a runtime — `[runtime] provider`

`anthropic` is the backwards-compatible default. `openai` uses the direct Responses
runtime. `codex` uses Codex CLI for the scan and the same `[openai]` endpoint/model.
Both read the key from `openai.api_key`, `VULNHUNT_OPENAI_API_KEY`, or
`OPENAI_API_KEY`. A blank key is allowed for an operator-controlled gateway that
authenticates another way.

### Authenticating to Claude — `[anthropic] auth_mode`

| `auth_mode` | How it authenticates | What to set |
|-------------|----------------------|-------------|
| `api_key` *(default)* | Direct Anthropic API | `[anthropic].api_key` or the standard `ANTHROPIC_API_KEY` env var |
| `bedrock_oauth` | Routes through an AWS Bedrock proxy fronted by an OAuth2 client-credentials token endpoint | `[anthropic].bedrock_base_url` + the `[oauth]` block (`token_endpoint`, `client_id`, `client_secret`) |
| `bedrock_sigv4` | Calls Amazon Bedrock directly with SigV4 request signing via the standard AWS credential chain — no proxy, no bearer token | `[anthropic].aws_region`; optionally `aws_profile` (named profile) and `bedrock_base_url` (VPC/custom endpoint). No `[oauth]` block. |

`bedrock_oauth` exists for environments that front Claude with a Bedrock proxy and mint
short-lived bearer tokens. `bedrock_sigv4` is for AWS-native setups that call Bedrock
directly (use a cross-region inference-profile model ID, e.g. `us.anthropic.claude-...`);
credentials resolve from the usual AWS chain — env vars, shared config/credentials file,
SSO, or an instance/task role. Most users want the default `api_key` mode.

### Other sections (abridged)

- `[github]` — `scan_token` (clone + issues) and `reports_token` (publish), injected into
  URLs only when the parsed host matches `host`. Set `broker_token_dir` to read tokens
  from `{dir}/{role}.json` written by an external broker instead (see below).
- `[publish]` — `destination_repo` + `branch` for pushing results.
- `[issues]` — labels, dedup, clean-scan receipts, extraction/dedup models.
- `[sandbox]` — OS-level filesystem/network sandbox for the CLI's tools.
- `[telemetry]` — optional OTLP export; `otel_exporter_otlp_endpoint` +
  `resource_attributes` (neutral default; set your own owner/org tags).
- `[scan]` — cloned-repo dir, allowed tools (`Bash` is stripped unless `--enable-bash`),
  `no_proxy`, autocompact threshold, stall timeout.
- `[verify]` — scratch dir and a `repo_aliases` table for cross-repo hint resolution.
- `[openai]` — Responses base URL, Sol model, reasoning effort, request timeout, tool-loop
  bound, and subagent concurrency cap.
- `[codex]` — Codex executable, whole-session timeout, and scan wave concurrency cap.

## Architecture

```
CLI (python -m agent)
  └─ config.load_config()            TOML + VULNHUNT_* env  → AgentConfig
  └─ make_token_manager(config)      Anthropic/OpenAI key or Claude Bedrock auth
  └─ runner.run_vulnhunt()
        ├─ Claude Agent SDK          existing Claude skills/tools/event stream
        ├─ OpenAI Responses runtime  read/search/write tools + bounded Sol subagents
        └─ Codex CLI runtime         isolated workspace + repo skill + native subagents
  └─ manifest.write_manifest()       scan_manifest.json (validated against schema)
  └─ publish.publish_results()       optional: push results to destination_repo
  └─ issues stage                    optional: extract → dedup → render → post issues
  └─ audit                           optional JSONL lifecycle + finding events
```

- **Auth is a single chokepoint.** `build_claude_settings` renders the Claude Code
  settings JSON (environment + sandbox) and is the only place that knows whether to set
  `ANTHROPIC_API_KEY` (api_key mode), the Bedrock env + `ANTHROPIC_AUTH_TOKEN`
  (bedrock_oauth mode), or the Bedrock env *without* any token (bedrock_sigv4 mode —
  omitting `CLAUDE_CODE_SKIP_BEDROCK_AUTH` / `ANTHROPIC_AUTH_TOKEN` is what makes the
  bundled CLI sign requests itself). Both the scan loop and the issues-LLM calls go
  through it. Direct OpenAI mode forwards its API key only on Responses HTTP requests.
  Codex mode injects its key into the Codex process through a dedicated provider env var,
  then applies a clean shell environment policy so model-launched commands cannot read it.
- **Token providers share one interface.** `ApiKeyTokenManager`, `OAuthTokenManager`,
  and `SigV4TokenManager` all expose `get_valid_token()`; `make_token_manager(config)`
  returns the right one, so the rest of the code is auth-mode agnostic.
- **Contracts are schema-validated.** `scan_manifest.schema.json` (agent → scan-worker)
  and `verify_disposition.schema.json` (verify output) are validated before write.
- **The `vulnhunter` package** is the thin CLI entry point around the `agent` package.

## Customizing via a base-agent / container pattern

The agent is designed to be used as a **base** that you extend for your own environment,
rather than forked. Because all environment-specific inputs are config/env-driven, you can
build a derived agent without touching the code:

1. **Publish (or use) a base image** that installs this package and sets a neutral default
   entrypoint (`python -m agent`).
2. **Derive your own image `FROM` that base** and layer in only your environment:
   - a baked or mounted `config.toml` (or the corresponding `VULNHUNT_*` env vars);
   - `auth_mode` + credentials for how *you* reach Claude;
   - `[github]` tokens, or a `broker_token_dir` if a sidecar/parent process mints and
     refreshes tokens onto disk (the agent is then a pure token *consumer*);
   - a custom CA bundle via `[tls].ssl_cert_path`;
   - telemetry endpoint + `[telemetry].resource_attributes` tagged for your org.
3. **Wrap, don't fork.** Put org-specific orchestration (job discovery, queueing,
   result routing) in a thin parent process that shells out to `python -m agent ...` and
   reads its exit code + `scan_manifest.json`. The manifest is the stable integration
   contract; build your automation against it instead of the agent's internals.

This keeps your customizations (credentials, hosts, policy, telemetry identity) entirely
in your derived layer, so you can track upstream releases of the base agent cleanly.

## Tests

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

## License

Part of the VulnHunter project; licensed under the Apache License, Version 2.0. See the
repository-root `LICENSE`.
