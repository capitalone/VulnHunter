# VulnHunter Agent

A provider-neutral security scanner and compatibility runtime in the
[Multi-VulnHunter fork](https://github.com/JJsilvera1/Multi-VulnHunter) that
works without an interactive Claude Code session. The `vulnhunter` command is
the canonical Python workflow engine. It snapshots a repository, creates a
threat model and security-surface ledger, runs deterministic seeds and blind
multi-model hunts, challenges clean results, validates candidates, analyzes
attack paths, and writes typed artifacts. The legacy Claude Agent SDK,
publishing, issue, and fix-verification paths remain available for compatibility.

## Standalone provider-neutral scanner

The `vulnhunter` command is the new provider-neutral scanner. The existing
`python -m agent` command remains available for the Claude Agent SDK publishing
workflow described later in this document.

```bash
python -m pip install \
  "git+https://github.com/JJsilvera1/Multi-VulnHunter.git#subdirectory=vulnhunter-agent"
vulnhunter init
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

### Guided first scan

Interactive `vulnhunter init` configures providers and then asks, in order:

1. Repository path or Git URL.
2. Optional Git branch, tag, or commit.
3. Quick, Standard, Deep, or Exhaustive depth.
4. One to three independent core models.
5. The exact models, selected from the shared live catalog.
6. Static/read-only analysis or optional Docker validation of suitable
   findings.
7. A review of source exposure, the post-selection workflow, execution
   permissions, artifacts, and incomplete-coverage behavior.
8. Final confirmation: continue through preflight and scan, change the
   configuration, or save setup only.

The confirmation screen discloses every provider that receives source. The scan
does not begin—and a remote Git target is not cloned—until the user confirms.
Use `vulnhunter init --setup-only` to configure providers without opening this
wizard. For later scans, `vulnhunter scan PATH` begins with two primary choices:

1. Quick, Standard, Deep, or Exhaustive?
2. How many independent core models?

After model selection, the confirmation screen explains the remaining workflow:

1. Resolve an immutable repository snapshot and complete provider preflight.
2. Classify the repository and build the threat model and mandatory surface
   ledger.
3. Run native rules and optional installed scanners, withholding their seeds
   from the independent blind hunters.
4. Challenge uncovered critical surfaces, reconcile candidates, validate
   source/control/sink claims, and analyze attack paths.
5. Close every mandatory ledger row and write the report, manifest v2, threat
   model, coverage, validation, and attack-path artifacts.

The preflight shown after confirmation includes model health, planned work,
estimated duration, and estimated/provider pricing where available. Scanning
then proceeds without another ordinary wizard question. Static/read-only is the
default; model selection never enables target execution. Explicit `--execute`
uses Docker only. The guided `init` walkthrough offers the same choice after
model selection. Its Change menu can revise the repository/ref, depth, model
team and reasoning settings, or validation mode before confirmation. Optional
static scanners run in `auto` mode when installed,
and `--static-tools required` turns their absence into a pre-dispatch
configuration failure. Failed assignments and unclosed mandatory surfaces
produce `INCOMPLETE_COVERAGE`, never `COMPLETE_CLEAN`.

Teams are capped at three core models. If the saved roster is larger than the
count chosen for a scan, a short follow-up lets you choose which saved models
will run.

Targets can be local directories or Git URLs. An optional ref creates an
isolated checkout for a branch, tag, or commit, leaving the current local
checkout unchanged:

```bash
vulnhunter scan https://github.com/example/project.git \
  --ref v2.4.1 --level deep --models 3 --yes
```

After the wizard asks for a team size, it queries each configured provider's
live model catalog and opens a
paginated, searchable model picker. Active providers share one continuously
numbered catalog with visible dividers, so Codex CLI, local models, and
OpenRouter choices remain distinguishable while being selectable from the same
screen. Codex and local catalogs are placed before large remote catalogs, and
search covers provider names as well as model IDs. The chosen IDs are retained in
`~/.vulnhunter/config.models.json` without rewriting the TOML or storing
credentials. Running `init` again builds a fresh roster and replaces the prior
saved team; it never appends a fourth or fifth model. Each catalog entry shows
its provider-reported context window (or
`unknown` when unavailable) in compact form such as `131k` or `1M`.
Provider prices are displayed per million tokens, for example
`$.05/M in - $1/M out`, and retained for scan estimates. After choosing each
model, the wizard advances to the next slot until the chosen team size is
complete. Reopen the catalog at any time with:

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

The first-run estimate uses production bytes, lines, approximate callable
symbols, security surfaces, boundary shards, reasoning effort, and expected
hunt/review/validation tool turns rather than pricing the repository once.
Catalog estimates account for cache-read and cache-write prices when a provider
publishes them. OpenRouter's provider-reported billed amount still overrides
token arithmetic. After a phase has completed assignments, its ETA is
recalculated from the observed median assignment duration instead of continuing
to show only the preflight window.

The compact live line groups elapsed time with ETA, actual spend with the
adaptive high estimate, and cumulative provider responses with repository tool
calls. With `--verbose`, each assignment also logs the estimated initial prompt
size split into the stable system prompt and dynamic task prompt. These are
tokenizer-independent four-characters-per-token estimates; authoritative
provider usage includes later repository-tool context and is therefore usually
much larger. Live dollar amounts use two decimal places; detailed
provider-response lines and final artifacts retain precise billing values. A
warning appears if observed spend exceeds the original high estimate. Because
candidate survival is unknowable before discovery, treat preflight forecasts as
approximate.
`--max-cost-usd` stops new assignment scheduling at the cap, but an
already-running multi-turn assignment can finish slightly above it.

If a model returns malformed JSON or a result that does not satisfy the required
schema, VulnHunter makes one constrained, tool-free schema repair attempt. If
that still fails, it retries the complete assignment in a fresh context up to
three times before recording missing coverage. Retry usage remains included in
the scan's request, token, and cost totals.

On the ordinary scan's second screen, enter `m` to change these defaults and
then choose a fresh team size of one to three models. The replacement picker
includes every configured provider, even if that provider was not part of the
previous active roster. Pressing Enter keeps the saved roster, so the normal
scan still needs only the level and model-count answers.

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

Scan preflight runs a tiny isolated Codex capability request before repository
work. This catches stale OAuth, unavailable models, and an outdated active CLI
before multiple hunts start. Codex assignments are serialized because parallel
`codex exec` processes can race shared OAuth refresh state. If preflight says a
model requires a newer Codex version, check which executable is active with
`where codex` on Windows or `which -a codex` on macOS/Linux. For an npm install:

```bash
npm install -g @openai/codex@latest
codex --version
codex login
vulnhunter doctor
```

If the version is current but refresh still fails, run `codex logout`, then
`codex login` again.

Codex CLI has its own provider catalog; searching OpenRouter for `openai` does
not show Codex-plan models. It appears as a separate section in the shared
picker. Reconfigure it later with:

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
| Quick | Lightweight threat model, native rules, boundary hunts, semantic reconciliation, fresh-context validation, attack-path analysis, and clean challengers for uncovered critical surfaces |
| Standard | Quick plus independent hunts from every core model, ring review, one sink/root-cause sweep, and mandatory-surface closure |
| Deep | Standard plus a second threat-model review, coverage-gap work, and second review for unique, disputed, severe, conditional, or configuration-dependent candidates |
| Exhaustive | Deep plus every non-origin review, two sweeps, focused disagreement resolution, and a PoC or explicit proof gap for each surviving instance |

All core models are unrestricted generalists. Add supplemental specialist
passes with:

```bash
vulnhunter scan . --level deep --models 3 \
  --specialist crypto=local-coder \
  --specialist cloud-iam=openrouter-security
```

Candidate aggregation uses the union, not majority voting. A finding discovered
by one model can survive when another model independently confirms its evidence.
Paraphrases that point to the same security mechanism and nearby source/sink
locations are consolidated before review, while every concrete affected
instance and discoverer remains attached to the grouped finding.

Independent work within a phase runs concurrently up to `--max-workers`:
boundary hunts can run together, followed by concurrent seed reviews, candidate
reviews, validations, and attack-path assignments. Dependency barriers remain
intentional: deterministic seeds are withheld until all blind hunts finish,
candidate review waits for union/deduplication, and attack-path analysis waits
for validation. Starting review as soon as one shard finishes would both waste
work on duplicates and weaken the blind-discovery contract. Codex CLI work is
serialized regardless of `--max-workers` because parallel `codex exec`
processes can race the shared OAuth refresh state. OpenRouter, direct APIs, and
healthy local servers can use parallel workers; an all-free OpenRouter team is
paced serially to respect shared rate limits.

Quick is the lowest rigor tier, not a one-request scan. Its runtime is driven by
repository boundaries and the number of consolidated root causes that survive
discovery. Semantic reconciliation happens before downstream work so
differently worded descriptions do not each trigger review, validation, and
attack-path assignments. Saved checkpoints from the legacy grouping retain
their original candidate IDs for safe resume; new runs use the semantic-v2
grouping automatically.

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
- `--resume <results-dir>` reuses completed phases only when the repository
  snapshot and methodology fingerprint still match.
- Every tier is static and read-only by default.
- `--execute` enables target commands only in the built-in Docker sandbox;
  target code is never executed directly on the host.

Build and diagnose the sandbox:

```bash
vulnhunter sandbox doctor
vulnhunter sandbox build
vulnhunter scan . --level deep --models 2 --execute
```

When `--execute` is selected, VulnHunter checks Docker before repository or
provider work begins. If Docker Desktop is installed but stopped, an interactive
scan offers to start it and waits for the engine. In automation, start it
explicitly with:

```bash
vulnhunter scan . --level deep --models 2 --execute --start-docker --yes
```

If the daemon is running but the versioned sandbox image is missing, VulnHunter
stops before model dispatch and tells you to run `vulnhunter sandbox build`.
If Docker is not installed, it reports that separately.

The sandbox mounts the source read-only, uses a disposable work copy, runs
non-root with dropped capabilities and `no-new-privileges`, applies CPU,
memory, PID, time, and output bounds, mounts no credentials or Docker socket,
and disables networking by default. Command output is redacted and written to
`validation_artifacts/`.

Provider-managed agents such as Codex CLI do not execute these commands
directly. They may propose a bounded argument-array reproduction during a
validation assignment; VulnHunter executes it through the engine-owned Docker
sandbox, records the redacted result, and returns that evidence to a fresh model
turn for the final verdict. This keeps provider tooling separate from execution
authority.

Optional static scanners can supplement the dependency-free native rules:

```bash
vulnhunter scan . --static-tools auto
vulnhunter scan . --static-tools required
```

Semgrep, Gitleaks, Trivy, and ast-grep output is treated as investigation
seeds, never as an automatic final finding. `required` fails preflight when an
expected tool is unavailable.

### Manifest v2 and compatibility

The native engine emits strict `run_manifest.json` schema version `2` plus:

- `threat_model.json` / `threat_model.md`
- `security_surfaces.jsonl` / `coverage_ledger.jsonl`
- `static_seeds.jsonl`
- per-candidate `validation/` and `attack_paths/` artifacts
- sandbox logs under `validation_artifacts/`
- a human-readable results `README.md`

Candidate verdict and final disposition are separate. Dispositions are
`REPORTABLE`, `DEFERRED`, `SUPPRESSED`, `NOT_APPLICABLE`, and `UNRESOLVED`.
Only `REPORTABLE` findings are projected into legacy `scan_manifest.json` v1.
An incomplete, conditional, unresolved, or failed v2 run maps to the legacy
failure state so a v1 consumer cannot report it as clean.

The transition engine remains available for Git URLs:

```bash
vulnhunter scan https://github.com/example/project --engine legacy
```

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
