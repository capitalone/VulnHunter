# VulnHunter

> **From pattern-matching to provability.**

VulnHunter is an open-source, **agentic AI security tool** that applies proactive, attacker-perspective analysis directly to source code. 

Unlike traditional, passive SAST scanners that flag suspicious patterns and leave you to drown in the noise, VulnHunter reasons like an adversary. It **proves** which defects are actually exploitable, provides an executable proof-of-concept, and proposes targeted, evidence-backed fixes.

Developed and battle-tested internally at Capital One, VulnHunter is released to the community to help secure our deeply interconnected modern software supply chain. Find and fix exploitable defects before an adversary's models find them for you.

---

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

* **Attacker-First Forward Analysis:** Conventional tools work "sink-first"—they spot a dangerous pattern and try to guess a path backward to a hypothetical attacker, flooding teams with false alarms. VulnHunter flips this: it starts at attacker-reachable entry points (APIs, network messages, file uploads) and reasons *forward* to see what an adversary can actually achieve.
* **The Self-Falsification Engine:** After finding a potential vulnerability, VulnHunter runs an adversarial workflow designed specifically to *disprove* it. It hunts for flawed assumptions, logic gaps, or security controls that would block the attack. If a finding can be debunked, it is discarded. What reaches you is a verified exploit path, not a guess.
* **Evidence-Backed Remediation:** When a defect survives the falsification engine, VulnHunter maps the exact exploit path, explains the structural flaw, details the capability an attacker gains, and generates targeted code changes for review.

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
