# VulnHunter

> **From pattern-matching to provability.**

VulnHunter is an open-source, **agentic AI security tool** that applies proactive, attacker-first analysis directly to source code. 

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
> Built and optimized for **Claude Opus** running in **[Claude Code](https://docs.claude.com/en/docs/claude-code)**. 
> The framework depends on deep, multi-step reasoning and requires frontier Opus-class models. **You supply your own model access.**

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
| `vulnhunt/` | The core `/vulnhunt` scanner skill (Prompt-only: `SKILL.md` + phases). See [`vulnhunt/README.md`](vulnhunt/README.md). |
| `vulnhunter-fix/` | The `/vulnhunter-fix` skill, its companion Python helper package, and tests. See [`vulnhunter-fix/README.md`](vulnhunter-fix/README.md). |
| `vulnhunt-fix-verify/` | The `/vulnhunt-fix-verify` standalone verification skill (Prompt-only). See [`vulnhunt-fix-verify/README.md`](vulnhunt-fix-verify/README.md). |
| `vulnhunter-agent/` | Config-driven headless runtime wrapper that runs scans and files GitHub issues. See [`vulnhunter-agent/README.md`](vulnhunter-agent/README.md). |
| `harness/` | Developer tooling for running large batch-scans and benchmarking detection accuracy. See [`harness/README.md`](harness/README.md). |

---

## Requirements & Setup

### Prerequisites
* [Claude Code CLI](https://docs.claude.com/en/docs/claude-code), authenticated with access to **Claude Opus**.
* Python 3.12+ (Required only for the runtime agent and the benchmarking harness).
* *Responsibility Check:* Ensure you are only scanning code bases you are explicitly authorized to analyze.

### Installation

```bash
# Clone the repository
git clone https://github.com/capitalone/vulnhunter.git
cd vulnhunter

# Copy skills into ~/.claude/skills/
./install.sh      

# (Optional) To clean up or remove installed skills
# ./uninstall.sh    
```

On Windows, use the `.cmd` equivalents from a `cmd.exe` or PowerShell prompt:

```bat
git clone https://github.com/capitalone/vulnhunter.git
cd vulnhunter

REM Copy skills into %USERPROFILE%\.claude\skills\
.\install.cmd

REM (Optional) To clean up or remove installed skills
REM .\uninstall.cmd
```

> [!NOTE]
> `install.sh`/`install.cmd` copy files directly (rather than symlinking) because symlinks can break `find`/`glob` functionality inside subagents. Re-run the install script after pulling updates to refresh your local environment.

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
For non-interactive or CI/CD pipelines, `vulnhunter-agent/` wraps the scanner into a headless workflow. It clones targets, executes `/vulnhunt`, publishes results, and opens GitHub issues for confirmed bugs. It connects natively via the direct Anthropic API. 

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
