# VulnHunter Agent

A config-driven runtime in the
[Multi-VulnHunter fork](https://github.com/JJsilvera1/Multi-VulnHunter) that
automates the [`/vulnhunt`](https://github.com/capitalone/VulnHunter)
scanner **headlessly** — no interactive Claude Code session required. Point it at a
repository and it will clone the target, run the scanner, publish the results, and file
each confirmed finding as a GitHub issue. It also has a `verify` mode that drives the
read-only fix-verification flow.

It is the automation layer around the skills: the skills define *how* to hunt and fix;
this agent makes a scan runnable unattended (CI, a scheduled job, a fleet worker, or a
container) and wires the results into GitHub.

## Standalone provider-neutral scanner

The `vulnhunter` command is the new provider-neutral scanner. The existing
`python -m agent` command remains available for the Claude Agent SDK publishing
workflow described later in this document.

```bash
python -m pip install \
  "git+https://github.com/JJsilvera1/Multi-VulnHunter.git#subdirectory=vulnhunter-agent"
vulnhunter init
vulnhunter doctor
vulnhunter scan .
```

For a local editable checkout on Windows PowerShell:

```powershell
cd Multi-VulnHunter\vulnhunter-agent
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
vulnhunter init
vulnhunter doctor
vulnhunter scan .
```

Each new PowerShell session must activate `.venv` again. If script activation
is unavailable, run `.\.venv\Scripts\vulnhunter.exe` directly. On macOS or
Linux, create the environment with `python3.12 -m venv .venv` and activate it
with `source .venv/bin/activate`.

Discover the available commands and options from the CLI itself:

```bash
vulnhunter help
vulnhunter help scan
vulnhunter --help
vulnhunter scan --help
```

`vulnhunter scan .` asks exactly two questions:

1. Quick, Standard, Deep, or Exhaustive?
2. How many independent core models?

`vulnhunter init` also queries each provider's live model catalog and opens a
paginated, searchable model picker. The chosen IDs are retained in
`~/.vulnhunter/config.models.json` without rewriting the TOML or storing
credentials. Each catalog entry shows its provider-reported context window (or
`unknown` when unavailable) in compact form such as `131k` or `1M`.
Provider prices are displayed per million tokens, for example
`$.05/M in - $1/M out`, and retained for scan estimates. After choosing each
model, answer `y` to
add the next independent core model or `n` to finish the roster. Reopen it at
any time with:

```bash
vulnhunter models
vulnhunter models --provider openrouter
vulnhunter models --list --json
```

For models that advertise reasoning controls, the catalog stays compact and the
picker shows the effort selector only after model selection. `auto` preserves
the provider/model default;
otherwise the selected effort is saved with that model. OpenRouter effort
choices come from each model's live `reasoning.supported_efforts` metadata.
Reasoning level is included in preflight output and increases the estimate's
token/runtime allowance.

OpenRouter zero-cost models receive a `FREE` badge, with three pinned above the
normal alphabetical catalog. The picker distinguishes the documented free
quota (50 requests/day by default, up to 1,000/day for eligible funded
accounts) from dollar usage; the API does not expose a dependable free-request
remaining count. It also shows provider-reported input-cache capability and
cache-read pricing. During scans, `429` responses honor `Retry-After`, retry up
to the bounded engine limit with exponential backoff and jitter, and recommend
a paid model after repeated failure. An all-free core team runs one assignment
at a time and spaces free-model requests by at least 3.2 seconds to remain under
the documented 20 RPM limit; the preflight warns that this is slower.
The final summary and manifest include request count, rate-limit retries,
cached/cache-write tokens, and accumulated API cost.
For OpenRouter, that cost comes from the billed `usage.cost` returned with each
completion, so prompt-cache discounts and the actual routed provider are
included. If a completion omits cost, VulnHunter queries its generation ID at
`/api/v1/generation`; catalog token pricing is only the final fallback. Live
output and artifacts label billing as provider-reported, estimated, or mixed.

Terminal output uses cyan model names, yellow context sizes, and green pricing.
Colors are automatic for interactive terminals and disabled when redirected.
Override that behavior with `vulnhunter --color always ...`,
`vulnhunter --color never ...`, or the `NO_COLOR` environment variable.
Live scans use blue for active phases, green for success, yellow for warnings
and resumed/incomplete work, red for failures, and magenta for candidate and
review activity. The CLI reports provider checks, inventory, model assignment
starts/completions, aggregation, review, disagreement resolution, and report
generation without using transient spinner output.

Long provider calls print a heartbeat every 15 seconds. `--verbose` adds each
provider round and repository-tool batch; `--log-file PATH` appends every event
as JSONL and works with `--json` without contaminating stdout. For example:

```powershell
vulnhunter scan . --verbose --log-file .\vulnhunter-progress.jsonl
Get-Content .\vulnhunter-progress.jsonl -Wait
```

The first-run estimate models repository partitions, hunt/sweep/review
assignments, and repeated agent/tool turns rather than pricing the repository
once. The compact live line groups elapsed time with ETA, actual spend with the
adaptive high estimate, and cumulative provider responses with repository tool
calls. Live dollar amounts use two decimal places; detailed provider-response
lines and final artifacts retain precise billing values. A warning appears if
observed spend exceeds the original high estimate. Because candidate and review
counts are unknowable before discovery, treat the forecast as approximate.
`--max-cost-usd` stops new assignment scheduling at the cap, but an
already-running multi-turn assignment can finish slightly above it.

If a model returns malformed JSON or a result that does not satisfy the required
schema, VulnHunter makes up to three visible, tool-free repair attempts before
marking that assignment as missing coverage. Retry usage remains included in
the scan's request, token, and cost totals.

On the ordinary scan's second screen, enter `m` to change these defaults and
then continue selecting the team size. Pressing Enter keeps the saved roster,
so the normal scan still needs only the level and model-count answers.

For CI:

```bash
vulnhunter scan . --level standard --models 3 --yes --json
```

The stable machine output is `<results>/run_manifest.json`. A complete scan
exits 0; an incomplete scan exits 2 and must never be interpreted as clean.
After an interactive incomplete scan, VulnHunter offers to resume immediately
from its checkpoint. Completed assignments are reused and only failed or
unfinished work is dispatched again. Automation can request one bounded retry:

```bash
vulnhunter scan . --level standard --models 3 --yes --retry-incomplete
```

### Model providers

The provider-neutral config defaults to `~/.vulnhunter/config.toml`. Run
`vulnhunter init` to detect environment credentials and local runtimes without
writing secrets to disk. An annotated all-provider example is available at
[`config.multi.example.toml`](config.multi.example.toml).

Production adapters:

- `anthropic`
- `openai`
- `openrouter`
- `codex_cli` through an installed, authenticated Codex CLI
- `gemini` through Google's OpenAI-compatible API
- `ollama`
- `openai_compatible` for vLLM, llama.cpp, LM Studio, LocalAI, and compatible
  gateways

Credentials can be exported normally or placed in the dedicated
`~/.vulnhunter/providers.env` file. Copy `providers.env.example` as a starting
point, or run
`vulnhunter env-example --write ~/.vulnhunter/providers.env`. Repository `.env`
files are not loaded automatically. To use another
location, pass `--env-file` to `init`, `doctor`, or `scan`.

OpenAI's public API uses `OPENAI_API_KEY`; VulnHunter does not extract a token
from a ChatGPT or Codex login. Gemini accepts `GEMINI_API_KEY`. For Google Cloud
OAuth/ADC, configure a Vertex OpenAI-compatible provider with a
`credential_command`, as shown in `config.multi.example.toml`. Credential
commands are argument arrays executed without a shell and are cached for 45
minutes before refresh.

For ChatGPT/Codex subscription authentication, run `codex login` and then
`vulnhunter init --allow-remote`. VulnHunter detects `codex login status`, reads
only Codex's model-capability cache, and invokes `codex exec` for assignments.
It does not open or copy `~/.codex/auth.json`; Codex owns browser OAuth, token
refresh, workspace policy, and logout. These assignments are ephemeral and
read-only. Their billing is shown as `ChatGPT/Codex plan`, not a fabricated USD
API amount, so they cannot participate in `--max-cost-usd` enforcement.

Codex CLI has its own provider catalog; searching OpenRouter for `openai` does
not show Codex-plan models. When Codex CLI is added to an existing config,
VulnHunter opens its picker directly. Reconfigure it later with:

```bash
vulnhunter models --provider codex-cli
```

The saved alias is `codex-cli`. To scan with only that provider, use:

```bash
vulnhunter scan . --team-model codex-cli
```

An automatic roster with enough core models can include Codex CLI alongside
OpenRouter when both pass preflight.

Models are selected from the healthy configured pool, preferring provider
diversity and configured priority. The exact roster, locality, source exposure,
cost range, and time range are shown before work starts. Remote providers are
never silently substituted for local models.

### Scan levels and teams

Scan level and model count are independent:

| Level | Behavior |
|---|---|
| Quick | Broad hunt plus a fresh-context falsification pass |
| Standard | Blind independent hunts, candidate union, and ring cross-review |
| Deep | Standard plus failed-coverage recovery and additional review for unique or severe findings |
| Exhaustive | Deep plus every eligible reviewer, two sink/root-cause sweeps, and complete static evidence |

All core models are unrestricted generalists. Add supplemental specialist
passes with:

```bash
vulnhunter scan . --level deep --models 3 \
  --specialist crypto=local-coder \
  --specialist cloud-iam=openrouter-security
```

Candidate aggregation uses the union, not majority voting. A finding discovered
by one model can survive when another model independently confirms its evidence.

### Budgets, privacy, and execution

```bash
vulnhunter scan . --level deep --models 3 --yes \
  --max-cost-usd 100 \
  --max-tokens 12000000 \
  --max-duration 4h \
  --max-workers 4
```

- Pricing must be configured for every selected remote model before a USD cap
  can be enforced.
- Reaching a limit checkpoints the run and emits `INCOMPLETE_LIMIT`.
- `--resume <results-dir>` continues completed assignments idempotently.
- Every tier is static and read-only by default.
- `--execute` is rejected unless `sandbox.command_prefix` invokes an explicitly
  configured OS/container sandbox.

### Coding-tool walkthroughs

```bash
vulnhunter instructions opencode
vulnhunter instructions pi
vulnhunter instructions codex
vulnhunter instructions claude-code
vulnhunter instructions generic
```

These print copy-paste invocation and status-handling guidance. The universal
CLI and `run_manifest.json` are the integration contract; tool-specific plugins
are not required.

The repository root also contains a universal `SKILL.md`. A coding tool that
supports GitHub/Agent Skill imports can import the repository and use that file;
the skill delegates scanning to this CLI rather than duplicating orchestration.

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
