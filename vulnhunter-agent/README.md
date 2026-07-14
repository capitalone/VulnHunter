# VulnHunter Agent

A config-driven runtime that automates the [`/vulnhunt`](https://github.com/capitalone/vulnhunter)
scanner **headlessly** — no interactive Claude Code session required. Point it at a
repository and it will clone the target, run the scanner, publish the results, and file
each confirmed finding as a GitHub issue. It also has a `verify` mode that drives the
read-only fix-verification flow.

It is the automation layer around the skills: the skills define *how* to hunt and fix;
this agent makes a scan runnable unattended (CI, a scheduled job, a fleet worker, or a
container) and wires the results into GitHub.

## Purpose

- **Scan** — clone a target repo and run `/vulnhunt` against it via the
  [Claude Agent SDK](https://docs.claude.com/en/docs/claude-code), producing the standard
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
- The [Claude Agent SDK](https://docs.claude.com/en/docs/claude-code) (installed as a
  dependency) and the bundled Claude Code CLI it drives.
- `git` and, for the publish/issues stages, the GitHub CLI or a GitHub token.
- Access to Claude — by default a direct **Anthropic API key**.

```bash
cd vulnhunter-agent
python -m pip install -e ".[dev]"
cp agent/config.example.toml agent/config.toml   # then edit, or use env vars
```

## Quick start

```bash
# Direct Anthropic API (default): export your key, then scan.
export ANTHROPIC_API_KEY=sk-...
python -m agent https://github.com/your-org/your-service

# Scan only, no publish/issues:
python -m agent https://github.com/your-org/your-service --no-publish --no-issues
```

## Configuration

Settings load from a TOML file (`--config`, then `$VULNHUNT_AGENT_CONFIG`, then
`agent/config.toml`) and are overlaid by environment variables named
`VULNHUNT_<SECTION>_<KEY>` (env wins). See
[`agent/config.example.toml`](agent/config.example.toml) for every option.

### Authenticating to Claude — `[anthropic] auth_mode`

| `auth_mode` | How it authenticates | What to set |
|-------------|----------------------|-------------|
| `api_key` *(default)* | Direct Anthropic API | `[anthropic].api_key` or the standard `ANTHROPIC_API_KEY` env var |
| `bedrock_oauth` | Routes through an AWS Bedrock proxy fronted by an OAuth2 client-credentials token endpoint | `[anthropic].bedrock_base_url` + the `[oauth]` block (`token_endpoint`, `client_id`, `client_secret`) |

`bedrock_oauth` exists for environments that front Claude with a Bedrock proxy and mint
short-lived bearer tokens; most users want the default `api_key` mode.

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

## Architecture

```
CLI (python -m agent)
  └─ config.load_config()            TOML + VULNHUNT_* env  → AgentConfig
  └─ make_token_manager(config)      api_key → ApiKeyTokenManager
                                     bedrock_oauth → OAuthTokenManager
  └─ runner.run_vulnhunt()
        └─ build_claude_settings()   env (auth + proxy + telemetry) + sandbox JSON
        └─ Claude Agent SDK          runs /vulnhunt, streams events, retries on 429
  └─ manifest.write_manifest()       scan_manifest.json (validated against schema)
  └─ publish.publish_results()       optional: push results to destination_repo
  └─ issues stage                    optional: extract → dedup → render → post issues
  └─ audit                           optional JSONL lifecycle + finding events
```

- **Auth is a single chokepoint.** `build_claude_settings` renders the Claude Code
  settings JSON (environment + sandbox) and is the only place that knows whether to set
  `ANTHROPIC_API_KEY` (api_key mode) or the Bedrock env + `ANTHROPIC_AUTH_TOKEN`
  (bedrock_oauth mode). Both the scan loop and the issues-LLM calls go through it.
- **Token providers share one interface.** `ApiKeyTokenManager` and `OAuthTokenManager`
  both expose `get_valid_token()`; `make_token_manager(config)` returns the right one, so
  the rest of the code is auth-mode agnostic.
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
