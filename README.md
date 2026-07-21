# VulnHunter

> **From pattern-matching to provability.**

VulnHunter is an open-source, **agentic AI security tool** that applies proactive, attacker-first analysis directly to source code. 

> [!NOTE]
> **About this fork:** This repository is **Multi-VulnHunter**, an independent
> fork of [Capital One's original VulnHunter](https://github.com/capitalone/VulnHunter).
> Capital One created the original project and security methodology. This fork
> retains the **VulnHunter** application name, `vulnhunter` CLI command, legacy
> skill names, and Apache 2.0 license; it is not presented as an official
> Capital One release.

## What Multi-VulnHunter adds

This fork preserves the original Claude-oriented workflows and adds a
provider-neutral scanning engine that can:

- run directly from a terminal or CI job without Claude Code;
- use Anthropic, OpenAI, OpenRouter, Ollama, Codex CLI authentication, Gemini,
  or OpenAI-compatible local runtimes;
- run multiple independent generalist models side-by-side, union their
  candidates, and have isolated reviewers check one another's work;
- add optional specialists without replacing broad generalist coverage;
- select Quick, Standard, Deep, or Exhaustive scan rigor independently from
  the number of core models;
- track provider usage, caching, costs, rate limits, incomplete coverage, and
  resumable checkpoints; and
- integrate with Codex, Claude Code, OpenCode, Pi, or another coding tool
  through the root `SKILL.md` and the same universal CLI.

## Provider-neutral scanner

VulnHunter now includes a standalone, multi-model scanner in
`vulnhunter-agent/`. It does not require Claude Code and can be called from a
terminal, CI job, OpenCode, Pi, Codex, Claude Code, or any coding tool that can
run a command and read JSON.

Supported model paths include:

- Anthropic, OpenAI, and Gemini;
- OpenRouter;
- native Ollama;
- OpenAI-compatible local servers such as vLLM, llama.cpp, LM Studio, and
  LocalAI.

## Fastest setup: skill import or CLI

There is no single natural-language import phrase guaranteed by every coding
tool. Tools that support repository/Agent Skill imports can use the root
[`SKILL.md`](SKILL.md). For example, tell Pi, Claude Code, Codex, OpenCode, or a
similar agent:

> Install `https://github.com/JJsilvera1/Multi-VulnHunter` as an Agent Skill. Use the
> root `SKILL.md`, then follow the provider setup in the repository README. Do
> not select a remote provider without showing me the source-exposure notice.

If that tool supports GitHub skill imports, it can clone the repository and
discover the root skill. If it does not, use the universal CLI path below; the
coding tool only needs to run the command, wait, and read `run_manifest.json`.

```bash
python -m pip install \
  "git+https://github.com/JJsilvera1/Multi-VulnHunter.git#subdirectory=vulnhunter-agent"

vulnhunter init
vulnhunter doctor
vulnhunter scan .
```

To see every CLI command or detailed help for one command:

```bash
vulnhunter help
vulnhunter help scan
# Standard argparse forms also work:
vulnhunter --help
vulnhunter scan --help
```

During `init`, VulnHunter queries each configured provider's current model list.
The model browser supports numbered selection, `/text` filtering, and
next/previous pages, and shows each provider-reported context-window size.
Models whose provider does not publish a limit are labeled `unknown`.
Context is compacted (`131k`, `1M`) and available pricing is normalized as
`$.05/M in - $1/M out`; missing price metadata is labeled `pricing unknown`.
For OpenRouter, three zero-cost models are pinned at the top and marked `FREE`.
The picker explains that free-model limits are normally 50 requests/day or up
to 1,000/day for eligible funded accounts; OpenRouter does not currently expose
a reliable free-request-remaining counter. Available key spend/usage is shown
separately so it is not confused with request quota.
Provider-reported input-cache support and cache-read pricing are shown beside
each model. Scan output and manifests track API requests, rate-limit retries,
cached input tokens, cache writes, and actual or estimated API cost.
When every core hunter is a free remote model, VulnHunter automatically enters
free-team pacing: assignments run serially and calls are spaced by at least 3.2
seconds to stay below OpenRouter's documented 20 requests/minute. A `429`
honors `Retry-After` and adds bounded exponential backoff with jitter. The CLI
warns that this mode is intentionally slower.
Interactive terminals color model identities cyan, context yellow, and pricing
green. Control this globally with `vulnhunter --color auto|always|never ...`,
or set the standard `NO_COLOR` environment variable.
During a scan, blue marks active phases, green marks completed work, yellow
marks warnings or resumed/incomplete work, red marks failures, and magenta
marks review/candidate activity. Progress remains line-oriented and includes
text and symbols so meaning never depends on color alone.

For detailed live diagnostics and a log that can be tailed from another
PowerShell window:

```powershell
vulnhunter scan . --verbose --log-file .\vulnhunter-progress.jsonl
Get-Content .\vulnhunter-progress.jsonl -Wait
```

Provider calls emit a heartbeat every 15 seconds. Each completed response
updates observed API spend, token totals, elapsed time, and a live adaptive
estimate. The compact status line groups elapsed time with ETA, spend with its
estimated total, and cumulative provider responses with tool calls. The initial
forecast uses repository partitions, expected assignments,
and estimated agent/tool turns; its confidence is explicitly low until real
provider usage arrives. Use `--max-cost-usd` when a hard stop matters.
The cap stops new assignment scheduling; an already-running multi-turn
assignment can finish slightly above it.
After the first selection it offers to add a second,
third, or further core model. The complete roster is saved locally and shown
by provider/model identity on the scan's model-count screen. Run
`vulnhunter models` to change or extend it later, or choose `m` from the scan.

### Provider credentials

VulnHunter never writes API keys into its TOML configuration. Export provider
variables normally, or copy
[`providers.env.example`](vulnhunter-agent/providers.env.example) to
`~/.vulnhunter/providers.env`. That dedicated file is loaded automatically;
repository `.env` files are deliberately not loaded because they may contain
unrelated application secrets.

```bash
mkdir -p ~/.vulnhunter
vulnhunter env-example --write ~/.vulnhunter/providers.env
# Edit the file and set only the providers you want to use.
vulnhunter init
```

You can instead supply a particular file with `--env-file /secure/path/providers.env`.
Recognized credentials are `OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`,
`OPENAI_API_KEY`, and `GEMINI_API_KEY`. Ollama and unauthenticated local servers
need no key.

Gemini's OpenAI-compatible API is supported directly. Google Cloud OAuth/ADC is
supported for a Vertex OpenAI-compatible endpoint through a refreshable
`credential_command`; see
[`config.multi.example.toml`](vulnhunter-agent/config.multi.example.toml).
OpenAI's public API uses `OPENAI_API_KEY`. As a separate option, an installed
Codex CLI authenticated with `codex login` can be selected as a provider.
VulnHunter invokes ephemeral, read-only `codex exec` assignments and lets Codex
own OAuth storage and refresh; it never reads or copies `~/.codex/auth.json`.
Codex CLI is a separate provider, so its models do not appear when filtering
the OpenRouter catalog. When it is added to an existing configuration, setup
opens the Codex picker directly. Reopen that catalog later with
`vulnhunter models --provider codex-cli`. To run only the saved Codex model,
use `vulnhunter scan . --team-model codex-cli`; selecting a larger automatic
model count can include it alongside OpenRouter when both pass preflight.

Reasoning-capable models expose an `auto` or explicit thinking-effort selector
in `vulnhunter models`. OpenRouter choices come from its live model metadata;
Codex choices come from the current Codex-maintained model catalog. Interactive
incomplete scans offer to resume failed work from the checkpoint without
rerunning completed assignments. Automation can use `--retry-incomplete` for
one bounded retry.

An interactive scan asks only two questions: the scan level and number of core
models. Core models hunt independently as unrestricted generalists before they
see one another's work. Optional specialists supplement that coverage; they
never replace it. See [`vulnhunter-agent/README.md`](vulnhunter-agent/README.md)
for configuration, tiers, safety controls, and automation examples.

Unlike traditional, passive SAST scanners that flag suspicious patterns and often cause false positives, VulnHunter reasons like an adversary. It **identifies** which defects are actually exploitable, maps prospective attack paths, and proposes targeted, evidence-backed fixes.

Modern software supply chains are deeply interconnected. A single vulnerability in a widely-used open-source component can ripple across thousands of enterprises simultaneously.

Developed internally at Capital One, VulnHunter is released to the community because no single organization can solve this challenge alone.

----

> [!WARNING]
> **Cyber-safeguard disclaimer**
> VulnHunter performs dual-use cybersecurity work (vulnerability discovery and exploitation). If you run it against an Anthropic account that is **not** enrolled in Anthropic's [Cyber Verification Program](https://support.claude.com/en/articles/14604842-real-time-cyber-safeguards-on-claude), real-time cyber safeguards may block requests and your usage may be flagged for cyber abuse. If you intend to use VulnHunter on Anthropic's first-party platforms (Claude API / Claude Code), we strongly recommend enrolling first via the [verification portal](https://portal.anthropic.com/programs/cvp).

---

> [!IMPORTANT]
> **Prerequisites & Model Requirements**
> The legacy prompt-only workflow was optimized for **Claude Opus** in
> **[Claude Code](https://docs.claude.com/en/docs/claude-code)**. The standalone
> scanner is provider-neutral, but security-review quality still depends heavily
> on the selected models. **You supply your own model access.**

---

## Why VulnHunter is Different

* **Attacker-First Forward Analysis:** Conventional tools often leverage "sink-first" analysis, looking at potentially dangerous code patterns to search backward for a hypothetical attacker, flooding teams with false positives. VulnHunter flips this model to simulate a bad actor's exact journey. It begins at potential attacker-accessible entry points (APIs, network messages, file uploads) and reasons *forward* to evaluate whether an attacker can truly break through.
* **Falsification Engine:** After finding a potential vulnerability, VulnHunter runs a structured reasoning workflow specifically designed to *disprove* its own argument. It searches for flawed assumptions, logic gaps, or security controls that would block the attack. It is designed to immediately discard findings that rely on unsupported assumptions. What reaches you is a high-priority, actionable defect.
* **Evidence-Backed Remediation:** When a defect survives the falsification engine, VulnHunter maps the exact exploit path, explains the structural flaw, details the specific capabilities or access an attacker would gain, and generates focused, targeted code changes for review.

---

## The Closed Loop: Hunt → Fix → Verify

VulnHunter ships as three composable [Claude Code](https://docs.claude.com/en/docs/claude-code) skills that form a complete, automated remediation loop:

| Skill | Phase | Core Responsibility |
| :--- | :--- | :--- |
| **`/vulnhunt`** | **Hunt** | Maps entry points to dangerous sinks. Filters findings through a multi-stage falsification pipeline (Recon → Parallel Hunt → Adversarial Disprove → Capability Filter). Emits only verified issues with an executable exploit and a proposed fix. |
| **`/vulnhunter-fix`** | **Fix** | Developer-led, test-driven remediation. It writes an exploit demo, creates a failing security test (**RED**), implements the code fix (**GREEN**), verifies the exploit is blocked without regressions, and cuts a reviewable PR. |
| **`/vulnhunt-fix-verify`** | **Verify** | A completely separate, read-only agent that independently validates whether a finding was successfully remediated. It emits a per-finding verdict so fixes are proven, not taken on faith. |

> **Note:** For running this loop unattended at scale, `vulnhunter-agent/` wraps the scanner in a headless runtime, while `harness/` drives it across multiple repositories in batch.

> **On the naming:** the suite is **VulnHunter**, but the core scanner command is `/vulnhunt` (and the verifier `/vulnhunt-fix-verify`) — the shorter form is intentional, not a typo. The `/vulnhunter-fix` remediation skill and the `vulnhunter-agent/` runtime keep the full spelling.

---

## Repository Layout

Each component is organized into a self-contained subtree:

| Path | Description |
| :--- | :--- |
| `SKILL.md` | Universal provider-neutral skill entry point for coding tools that can import Agent Skills. |
| `vulnhunt/` | The core `/vulnhunt` scanner skill (Prompt-only: `SKILL.md` + phases). See [`vulnhunt/README.md`](vulnhunt/README.md). |
| `vulnhunter-fix/` | The `/vulnhunter-fix` skill, its companion Python helper package, and tests. See [`vulnhunter-fix/README.md`](vulnhunter-fix/README.md). |
| `vulnhunt-fix-verify/` | The `/vulnhunt-fix-verify` standalone verification skill (Prompt-only). See [`vulnhunt-fix-verify/README.md`](vulnhunt-fix-verify/README.md). |
| `vulnhunter-agent/` | Config-driven headless runtime wrapper that runs scans and files GitHub issues. See [`vulnhunter-agent/README.md`](vulnhunter-agent/README.md). |
| `harness/` | Developer tooling for running large batch-scans and benchmarking detection accuracy. See [`harness/README.md`](harness/README.md). |

---

## Requirements & Setup

### Prerequisites
* Python 3.12+ for the provider-neutral CLI.
* Claude Code with Claude Opus only when using the legacy prompt-only workflow.
* *Responsibility Check:* Ensure you are only scanning code bases you are explicitly authorized to analyze.

### Installation

Provider-neutral CLI from GitHub:

```bash
python -m pip install \
  "git+https://github.com/JJsilvera1/Multi-VulnHunter.git#subdirectory=vulnhunter-agent"
vulnhunter init
```

For a local editable checkout on Windows PowerShell:

```powershell
git clone https://github.com/JJsilvera1/Multi-VulnHunter.git
cd Multi-VulnHunter\vulnhunter-agent
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
vulnhunter init
vulnhunter doctor
vulnhunter scan .
```

Activate the environment again whenever you open a new PowerShell window:

```powershell
cd Multi-VulnHunter\vulnhunter-agent
.\.venv\Scripts\Activate.ps1
```

If activation is unavailable, invoke the installed command directly with
`.\.venv\Scripts\vulnhunter.exe`. On macOS or Linux, use
`python3.12 -m venv .venv` followed by `source .venv/bin/activate`.

For editable development or the legacy Claude skills:

```bash
# Clone the repository
git clone https://github.com/JJsilvera1/Multi-VulnHunter.git
cd Multi-VulnHunter

# Copy the legacy skills into ~/.claude/skills/
./install.sh      

# (Optional) To clean up or remove installed skills
# ./uninstall.sh    
```

> [!NOTE]
> `install.sh` copies files directly (rather than symlinking) because symlinks can break `find`/`glob` functionality inside subagents. Re-run `./install.sh` after pulling updates to refresh your local environment.

---

## Usage Guide

### 1. Run the Scanner
```bash
claude --model opus --add-dir ~/.claude/skills/vulnhunt --add-dir ~/.claude/skills/vulnhunt/phases

# Inside the Claude Code session, invoke:
/vulnhunt
```

### 2. Run the Fixer
The fixer requires `git`, the GitHub CLI (`gh`) authenticated to your target repositories, and its Python helpers installed (`pip install -e ".[dev]"` inside the `vulnhunter-fix/` directory).

```bash
claude --model opus --add-dir ~/.claude/skills/vulnhunter-fix

# Inside the Claude Code session, invoke:
/vulnhunter-fix
```
*See [`vulnhunter-fix/README.md`](vulnhunter-fix/README.md) for advanced operational modes and configuration settings.*

### 3. Run the Fix Verifier
The verifier runs strictly read-only over trusted roots under a tight tool envelope (Read/Write/Edit/Glob/Grep/Agent—**no Bash execution, no network access**). The caller must pre-create the output (`out`) directory.

```bash
claude --model opus --add-dir ~/.claude/skills/vulnhunt-fix-verify \
       --add-dir ~/.claude/skills/vulnhunt-fix-verify/phases

# Inside the Claude Code session, invoke:
/vulnhunt-fix-verify repo=<abs_path> report=<abs_path> fixed=VULN-001,... out=<abs_path> [comments=<abs_path>] [additional_repos=<path1>,<path2>]
```

---

## Automation & Scale

### Headless Runtime Agent (`vulnhunter-agent/`)
For non-interactive or CI/CD pipelines, `vulnhunter-agent/` provides the
provider-neutral `vulnhunter` CLI as well as the transition-period legacy
Claude workflow. The native CLI emits compatible report and manifest artifacts;
the legacy agent retains its existing publishing and GitHub issue paths.

Review the [`vulnhunter-agent/README.md`](vulnhunter-agent/README.md) for deployment blueprints.

### Local Harness (`harness/`)
The `harness/` directory provides workstation-scale developer tooling. To initialize, run `cd harness && pip install -e ".[dev]"`.

#### Batch Scanning
Manage your target list in `harness/local_harness/batch/REPO_LIST.txt` (one GitHub URL per line, lines starting with `#` are ignored):

```bash
cd harness
python -m local_harness.batch.run scan                  # Clone and scan every repo in the list
python -m local_harness.batch.run scan --resume         # Skip repositories already processed
python -m local_harness.batch.run status                # Monitor progress across your batch
python -m local_harness.batch.run collect               # Gather all findings for centralized review
```

#### Benchmarking Mode
Evaluate scanner accuracy against a known-vulnerable vulnerability corpus (Clone → Scan → LLM-Judge → Tally Metrics):

```bash
python -m local_harness.benchmark.run                  # Execute full benchmark run
python -m local_harness.benchmark.run --repos "name"   # Benchmark a single target repository
python -m local_harness.benchmark.run --tally-only      # Re-generate the analytical report only
```

> **Bring Your Own Corpus:** This repository ships with a minimal synthetic example (`harness/local_harness/benchmark/ground_truth/EXAMPLE.json`) mapped to public targets like OWASP NodeGoat, Juice Shop, and WebGoat. Build out your own testing suites inside `ground_truth/<repo>.json`. Define your target scanning/judging engines in `harness/local_harness/config.py`.

---

## Running Tests

Each Python component maintains its own isolated testing suite. Run them using `pytest`:

```bash
cd harness          && pip install -e ".[dev]" && python -m pytest tests/ --cov=local_harness
cd vulnhunter-fix   && pip install -e ".[dev]" && python -m pytest -q
cd vulnhunter-agent && pip install -e ".[dev]" && python -m pytest -q
```

---

## Contributing, Security & License

* **A Note on Models:** VulnHunter was precision-tuned for **Claude Opus** and **Claude Code**. Its low false-positive discipline relies heavily on frontier-class reasoning, though the underlying orchestration patterns can be adapted to other advanced foundation models.
* **Contributing:** See [CONTRIBUTING.md](CONTRIBUTING.md) to propose core framework improvements, prompt updates, or wider model support configurations.
* **Security:** Review [SECURITY.md](SECURITY.md) for instructions on how to safely report security vulnerabilities found within VulnHunter itself.
* **License:** Distributed under the terms of the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
