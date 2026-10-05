# Using VulnHunter with Codex CLI

VulnHunter supports two Codex CLI workflows:

1. **Interactive scan** — launch Codex in an authorized target repository and
   invoke the `$vulnhunt-codex` skill yourself.
2. **Headless scan** — configure `vulnhunter-agent` with `provider = "codex"`.
   The agent invokes `codex exec` and can route it through an OpenAI-compatible
   Responses API.

Both workflows use `gpt-5.6-sol` with `xhigh` reasoning and perform static
analysis only. They must not execute or modify the target repository.

> [!WARNING]
> Scan only repositories you are explicitly authorized to assess. VulnHunter
> generates exploit evidence and proof-of-concept artifacts, but the Codex
> workflow writes them without executing them.

## Requirements

- [Codex CLI](https://developers.openai.com/codex/cli/) 0.144.1 or newer.
- Access to `gpt-5.6-sol` through Codex or a compatible streamed Responses API.
- `git`.
- Python 3.12+ when using the headless `vulnhunter-agent` workflow.

Install or update Codex on macOS or Linux with the official installer:

```bash
curl -fsSL https://chatgpt.com/codex/install.sh | sh
codex --version
```

Run `codex` once and follow its sign-in flow. See the
[Codex CLI documentation](https://developers.openai.com/codex/cli/) for other
installation and authentication options.

## Install the VulnHunter skills

From a VulnHunter checkout:

```bash
git clone https://github.com/capitalone/vulnhunter.git
cd vulnhunter
./install.sh
```

The installer copies:

- the Codex orchestrator to `~/.agents/skills/vulnhunt-codex`; and
- the canonical scan methodology to `~/.claude/skills/vulnhunt`, whose phase
  files are reused by the Codex orchestrator.

You can verify both required entry points without displaying any credentials:

```bash
test -f ~/.agents/skills/vulnhunt-codex/SKILL.md
test -f ~/.claude/skills/vulnhunt/phases/phase1_recon.md
```

Codex discovers user skills under `~/.agents/skills`. In an interactive Codex
session, run `/skills` and confirm that `vulnhunt-codex` appears. If a newly
installed skill does not appear, restart Codex. See OpenAI's
[skills documentation](https://developers.openai.com/codex/skills/) for skill
discovery and invocation behavior.

Re-run `./install.sh` after updating the VulnHunter checkout so the installed
copies stay current.

## Run an interactive scan

Launch Codex with the authorized target as its working root. `workspace-write`
is required so VulnHunter can create its results directory; the skill still
forbids modifying other target files.

```bash
codex \
  -C /absolute/path/to/authorized-target \
  -m gpt-5.6-sol \
  -c 'model_reasoning_effort="xhigh"' \
  -s workspace-write \
  '$vulnhunt-codex Run a deep static security scan of this authorized repository. Do not execute target code.'
```

Alternatively, start `codex` without an initial prompt, use `/model` to select
GPT-5.6 Sol with `xhigh` reasoning, confirm it with `/status`, and invoke the
skill by typing `$vulnhunt-codex`. Codex can also select the skill implicitly
when a request matches its description, but explicit invocation is preferred
for a security scan.

Do not pass `--dangerously-bypass-approvals-and-sandbox`. VulnHunter does not
need unrestricted host access.

The completed report is written beneath the target as:

```text
<target-name>_VULNHUNT_RESULTS_gpt56sol_<UTC timestamp>/README.md
```

A successful run reports that path and the confirmed finding count. A missing
phase artifact, failed subagent, refusal, timeout, or missing final `README.md`
is an incomplete scan—not a clean result.

## Use an OpenAI-compatible API through Codex

For an OpenAI-compatible endpoint, use the headless agent. It creates an
isolated, per-run Codex provider instead of asking you to place endpoint URLs or
credentials in project-level Codex configuration.

The endpoint must provide a streamed `POST /responses` API and pass through
function/tool calls. Start from the example configuration:

```bash
cd vulnhunter-agent
python -m pip install -e ".[dev]"
cp agent/config.example.toml agent/config.toml
```

Set these sections in `agent/config.toml`:

```toml
[runtime]
provider = "codex"

[openai]
base_url = "https://api.openai.com/v1" # or your compatible gateway's /v1 root
model = "gpt-5.6-sol"
reasoning_effort = "xhigh"
request_timeout_seconds = 3600
max_concurrent_agents = 6

[codex]
executable = "codex"
request_timeout_seconds = 14400
max_concurrent_agents = 6
```

Keep the API key out of the TOML file. Export it for the scan process, then run:

```bash
export OPENAI_API_KEY=sk-...
python -m agent --mode=scan https://github.com/your-org/your-service \
  --no-publish --no-issues
```

`VULNHUNT_OPENAI_API_KEY` can be used instead of `OPENAI_API_KEY`. A blank key
is supported when an operator-controlled gateway authenticates by another
mechanism.

The agent runs `codex exec --json --ephemeral` in a disposable workspace. It
ignores user configuration and rules, disables plugins, apps, and web search,
keeps the target read-only, and makes only the results directory writable. The
API key reaches the Codex process but is removed from every model-launched
subprocess.

For complete agent configuration, publishing, and GitHub issue options, see
[`vulnhunter-agent/README.md`](../vulnhunter-agent/README.md).

## Which workflow should I use?

| Need | Recommended workflow |
| --- | --- |
| Watch the scan, answer approvals, or inspect progress | Interactive `$vulnhunt-codex` |
| Use an OpenAI-compatible `/responses` gateway | Headless `provider = "codex"` |
| Run from CI, a scheduler, or a fleet worker | Headless `provider = "codex"` |
| Publish reports or file deduplicated GitHub issues | Headless `provider = "codex"` |

## Troubleshooting

### `codex: command not found`

Install Codex, open a new shell, and run `codex --version`. VulnHunter requires
0.144.1 or newer.

### `$vulnhunt-codex` is not listed by `/skills`

Re-run `./install.sh`, verify the two files in the installation section, and
restart Codex. Codex loads personal skills from `~/.agents/skills`.

### The skill stops because the model is wrong

Run `/model` in the interactive CLI, or relaunch with
`-m gpt-5.6-sol -c 'model_reasoning_effort="xhigh"'`. The scan intentionally
does not substitute Terra or Luna.

### A compatible endpoint returns 404 or streaming/tool errors

Confirm that `base_url` is the API root, normally ending in `/v1`, and that the
gateway implements streamed `POST /responses` requests plus function/tool
calls. A Chat Completions-only gateway is not sufficient.

### Codex produced partial output but no report

Treat the run as failed. Check the final runtime error and phase artifacts; do
not interpret partial output as a clean scan.

## Related OpenAI documentation

- [Codex CLI](https://developers.openai.com/codex/cli/)
- [Build and invoke skills](https://developers.openai.com/codex/skills/)
- [Codex configuration reference](https://developers.openai.com/codex/config-reference/)
- [GPT-5.6 model guidance](https://developers.openai.com/api/docs/guides/latest-model)
