# Working with non-Anthropic models

VulnHunter's skills (`/vulnhunt`, `/vulnhunter-fix`) run inside Claude Code. Claude
Code normally speaks the Anthropic Messages API, and gateways such as
[OpenRouter](https://openrouter.ai) expose an Anthropic-compatible endpoint. With a
few model overrides, we can run the same VulnHunter workflow against selected
third-party models (GLM, Kimi, DeepSeek, Gemma, Nemotron, OpenAI's open models, …).

This doc explains **how** to do that and **which models actually work**.

> TL;DR — in our evaluations as of 2026-07-19, the models we'd consider for a real scan
> are **Claude Opus 4.8** (native), **GLM-5.2**, and — on a single strong run — **Kimi
> K3** (both via OpenRouter). GLM-5.2 and Kimi K3 led on severe-vulnerability coverage
> and cost-effectiveness; Opus produced the most polished and consistent reports. No
> single run should be treated as complete. Other completed evaluations — including
> **Qwen 3.7 Max** — were noisy, incomplete, or non-starters. OpenAI frontier models
> have not yet completed the same evaluation.

---

## How it works

Before launching Claude Code, configure OpenRouter's Anthropic-compatible endpoint,
supply credentials, and pin both the main agent and subagents to the model under test.
The following shell commands follow OpenRouter's current
[Claude Code integration guide](https://openrouter.ai/docs/guides/coding-agents/claude-code-integration):

```bash
export ANTHROPIC_BASE_URL="https://openrouter.ai/api"
export ANTHROPIC_AUTH_TOKEN="$(<"$HOME/.openrouter/api_key")"
export ANTHROPIC_API_KEY=""
export ANTHROPIC_MODEL="z-ai/glm-5.2"          # <- the model under test
# ...other candidates commented out...
export ANTHROPIC_DEFAULT_OPUS_MODEL="$ANTHROPIC_MODEL"
export ANTHROPIC_DEFAULT_HAIKU_MODEL="$ANTHROPIC_MODEL"
export ANTHROPIC_DEFAULT_SONNET_MODEL="$ANTHROPIC_MODEL"
export CLAUDE_CODE_SUBAGENT_MODEL="$ANTHROPIC_MODEL"

# Treat third-party and open-weight models as untrusted tool callers. Do not assume
# they provide Anthropic-equivalent safety behavior; deny arbitrary command execution.
claude --verbose \
  --allowedTools "Read,Write,Edit,Grep,Glob,Agent,AskUserQuestion" \
  --disallowedTools "Bash"
```

Three things to understand:

1. **The main agent, aliases, and subagents are pinned separately.** `ANTHROPIC_MODEL`
   selects the main model. The three `ANTHROPIC_DEFAULT_*` variables map Claude Code's
   Opus, Sonnet, and Haiku aliases to that model. `CLAUDE_CODE_SUBAGENT_MODEL` forces
   every subagent to use it as well; without that variable, subagent definitions or
   per-invocation settings can select a different model. See Anthropic's
   [model configuration reference](https://code.claude.com/docs/en/model-config).
2. **`Bash` is explicitly blocked for static mode.** `--allowedTools` only
   pre-approves tools; omitting `Bash` from that list does **not** remove it. The
   `--disallowedTools "Bash"` flag removes it from the model's toolset. This is a
   containment measure, not just a convenience: third-party and open-weight models do
   not necessarily have the same safety training, runtime safeguards, or
   instruction-following behavior as Anthropic's models. An unexpected tool call or a
   failure to follow VulnHunter's protocol must not turn a static scan into arbitrary
   command execution. Blocking `Bash` also causes `/vulnhunt` to take its static path:
   it writes exploit tests and PoCs but does not install dependencies or execute tests.
   Remove the deny and add `Bash` to `--allowedTools` only when the model, target, and
   execution environment are trusted.

   "Static" is more accurate than "read-only" here. `Write` and `Edit` remain
   available so VulnHunter can create result artifacts, which means a misbehaving model
   can still alter files. This configuration limits process execution but does not
   enforce source-tree immutability or provide a complete security boundary. Use a
   disposable checkout or an OS-level sandbox, grant access only to the target and
   results paths, and inspect `git diff` after the run.
3. **`Agent` is load-bearing.** The pipeline fans out to 19–30 subagents via the
   `Agent` (Task) tool. Without it, `/vulnhunt` cannot run its recon/hunt/verify/sweep
   phases. Never drop `Agent` from the allow-list.

## Quick start

```bash
# 1. Store the OpenRouter key used by the launch configuration without placing it
#    in shell history.
install -d -m 700 ~/.openrouter
read -rsp 'OpenRouter API key: ' router_key && printf '\n'
(umask 077; printf '%s\n' "$router_key" > ~/.openrouter/api_key)
unset router_key

# 2. Pre-create the results directory and record the metadata VulnHunter cannot
#    collect while Bash is blocked.
cd /path/to/target-repo
scan_dir="$PWD/$(basename "$PWD")_VULNHUNT_RESULTS_$(date '+%Y-%m-%d-%H%M%S')"
mkdir -p "$scan_dir"
printf 'Results: %s\nBranch: %s [%s]\nRepository: %s\n' \
  "$scan_dir" \
  "$(git branch --show-current 2>/dev/null || printf unknown)" \
  "$(git rev-parse --short HEAD 2>/dev/null || printf unknown)" \
  "$(git remote get-url origin 2>/dev/null || basename "$PWD")"
```

From the target repository, run the environment exports and `claude` command shown in
"How it works." If Claude Code has a cached Anthropic login, run `/logout` once, exit,
and relaunch with the same configuration. Then invoke:

```text
> /vulnhunt in read-only mode, mock up your metadata, bypass model check
```

This invocation explicitly opts into the non-recommended model and tells VulnHunter to
bypass its interactive model gate. Because `Bash` is blocked, use the pre-created
results directory and repository metadata printed in step 2 if the model asks for
concrete values.

Native Claude models (Opus 4.8, etc.) don't need the OpenRouter configuration — just
run `claude` normally; `/vulnhunt` already gates itself to Opus-class models by default.

---

## Currently recommended models

| Model | Access | Verdict |
|---|---|---|
| **Claude Opus 4.8** | native `claude` | **Recommended for report quality and consistency.** Reliably completed the pipeline and produced the most polished reports. Its main weakness was recon coverage: both evaluated runs missed some of the most severe findings. It was also the most expensive option. |
| **GLM-5.2** | `z-ai/glm-5.2` (OpenRouter) | **Recommended for severity-weighted coverage and value.** It produced the strongest severe-vulnerability coverage at substantially lower cost than Opus, with generally strong precision. Run-to-run variance is the main caveat. |
| **Kimi K3** | `moonshotai/kimi-k3` (OpenRouter) | **Recommended, on a single run.** In one evaluation it led the field on true-positive count and cost-effectiveness with strong precision, and it **uniquely discovered two exploitable High-severity vulnerabilities no other model found** (a token path-prefix bypass and an ambient-credential clone). Caveats: only one run so far; it was slow (~5.5 h); and its severe-vuln credit came from findings it discovered rather than the previously-known set. A clear generational jump over Kimi k2.7-code (below) — do not confuse the two. |

**Caveat on GLM (and any single run):** finding overlap between runs was low. The most
severe issue appeared consistently, but the secondary findings changed substantially.
The sample is too small to call that behavior reliable. For thoroughness, **run it 2–3
times and union the results**. In our evaluation, repeated GLM runs still compared
favorably with a single Opus run on both cost and severe-vulnerability coverage.

These recommendations come from a limited evaluation, not a general model benchmark.
Opus agents also participated in adjudicating the results while Opus was one of the
models under evaluation. Blind voting reduced that conflict but did not eliminate it;
see the full report's objectivity caveat.

### Completed evaluations not recommended

| Model | OpenRouter id | Why not |
|---|---|---|
| Kimi k2.7-code | `moonshotai/kimi-k2.7-code` | Completed, but was noisy and slow. It repeatedly treated trusted or operator-controlled inputs as attacker-reachable and was outperformed by GLM. **Superseded by Kimi K3 (recommended, above) — a distinct, much stronger model.** |
| Qwen 3.7 Max | `qwen/qwen3.7-max` | **Failed in practice.** Recon was strong, but the hunt stage mass-dismissed nearly every real finding: 1 true positive (plus 1 false positive) against 37 known vulnerabilities, missing all five High-severity ones — despite spawning 40 subagents and 1,100+ tool calls. It also self-mislabeled its own model in the report and declared the codebase "well-hardened." High effort, near-zero yield. |
| Nemotron-3-ultra | `nvidia/nemotron-3-ultra-550b-a55b` | Produced low-precision, incomplete output with invalid citations and internal inconsistencies. Not usable. |
| Gemma-4-31b | `google/gemma-4-31b-it` | **Failed.** Misunderstood the threat model, missed the real attack surface, and emitted a false all-clear. A null result presented as a clean bill of health is worse than no scan. |
| DeepSeek-v4-pro | `deepseek/deepseek-v4-pro` | **Failed.** Could not follow the pipeline instructions and produced no usable output. |

Full data, methodology, and per-stage scoring: [`eval_rep/EVAL_REPORT.md`](../eval_rep/EVAL_REPORT.md)
and the live scorecard dashboard linked from it.

---

## What makes a model "work"

A model needs **all** of the following to run VulnHunter's pipeline usefully. The first
four are table-stakes capabilities; the last four are the ones our eval showed actually
separate the working models from the failures — a model can look capable on a benchmark
and still fail here on stamina, orchestration, consistency, or judgment.

### Baseline capabilities

1. **A 1M-class context window was necessary, but not sufficient, in our evaluation.**
   Every model that both completed the pipeline and maintained acceptable
   false-positive discipline had at least a 1M-token context window. Models with
   smaller windows either produced substantial noise or failed the workflow. That is
   an observed correlation, not proof that context size caused the difference; one
   1M-class model also produced low-precision, incomplete output. Treat 1M as a
   screening requirement for the current pipeline, not as a guarantee of
   instruction-following or security judgment.
2. **Strong instruction-following.** The pipeline is a strict multi-phase protocol with
   ordered gates, disposition rules, and exact output-file naming. Models that improvise
   (e.g. redefining the threat model) derail immediately — this is what sank Gemma.
3. **Multi-step reasoning.** Every finding is a data-flow trace from an
   attacker-controlled source through assignments/calls/transforms to a dangerous sink.
   That's sustained deductive chaining, not pattern-matching.
4. **Code understanding.** Must read the target languages, follow call graphs and
   indirect dispatch, and reason accurately about API and runtime semantics.

### Eval-derived requirements (where models actually fail)

5. **Agentic subagent orchestration.** `/vulnhunt` dispatches 19–30 `Agent` subagents
   (recon, per-partition INJ/NAV/LOG traces, verify, sweep) and must integrate their
   structured results. This is the backbone of the pipeline. Strong models orchestrated
   the full subagent set cleanly; weaker models stalled or collapsed early. If a model
   can't reliably spawn, delegate to, and merge subagents, nothing else matters.
6. **Long-horizon stamina.** Real runs span six phases and hundreds of tool calls, often
   taking well over an hour. Models must stay coherent to the end. Some evaluated
   models stopped after early phases or failed to produce a final report. Completing
   the pipeline at all is a real, discriminating bar.
7. **Output consistency & valid citations.** Every artifact must be internally
   self-consistent — summary counts matching the number of PoC files, stable finding
   IDs, and `file:line` citations that point at code that actually exists. Duplicate
   IDs, count mismatches, or invalid citations make the output unsafe to trust and can
   poison downstream automation such as `/vulnhunter-fix`.
8. **Trust-boundary judgment & false-positive discipline.** The security-specific
   reasoning skill: distinguishing attacker-controlled input from operator/trusted
   input, and dismissing non-issues *with cited evidence* rather than flooding the
   report. The recommended models were substantially more precise than the weaker
   candidates, which repeatedly treated trusted inputs as attacker-controlled. A
   high-recall model with poor trust-boundary judgment is a false-positive generator,
   not a scanner.

**Rule of thumb:** if a model can't reliably orchestrate subagents (#5) and finish the
run (#6), it fails outright regardless of raw intelligence. If it can, then consistency
(#7) and trust-boundary judgment (#8) determine whether its output is trustworthy.

---

## Roadmap

- **OpenAI frontier models — planned, not yet evaluated.** The intended target is an
  OpenAI frontier model, not the open `gpt-oss` weights. This is not just another model
  slug in the OpenRouter configuration above: current approved access is path-specific
  (for example, Responses API or Codex). We
  expect the harness to be either Codex or one of the existing harnesses—Claude Code
  or the Claude Agent SDK—connected through an Anthropic-compatible API adapter. The
  chosen path must preserve VulnHunter's orchestration, tool, permission, and model
  semantics before its results can be called apples-to-apples. The open
  `openai/gpt-oss-120b` model is available separately, but it is a different model and
  access path. Evaluate the frontier run with the same methodology once the harness is
  selected and validated; until then, treat OpenAI results as unknown.

To score a new model consistently with the existing evaluation, use the incremental
harness documented in
[`eval_rep/eval/README.md`](../eval_rep/eval/README.md): run the model with the chosen
launch configuration, then `add_run_workflow.js` → `merge_run.py` → `score.py` →
`make_dashboard.py`.

## Gotchas

- **Cost is not perfectly cross-provider comparable.** The recorded non-Anthropic
  runs did not expose prompt-cache accounting comparable to Anthropic's, so their token
  totals do not line up. Compare billed dollars for these runs, not raw token counts.
- **Static by default, not filesystem read-only.** The launch configuration denies
  `Bash`, so exploit tests are written but not executed. "PASS (static)" means a
  data-flow trace, not a live reproduction. `Write` and `Edit` are still available for
  result artifacts.
- **One model, all tiers and subagents.** The `ANTHROPIC_DEFAULT_*` overrides pin the
  aliases; `CLAUDE_CODE_SUBAGENT_MODEL` pins subagents. Keep both.
- **Authentication can conflict with a cached login.** OpenRouter currently recommends
  `ANTHROPIC_AUTH_TOKEN` for its key and an explicitly empty `ANTHROPIC_API_KEY`. If
  `/status` still shows Anthropic authentication, run `/logout`, exit, and relaunch.
- **Pin one model at a time.** Set `ANTHROPIC_MODEL` exactly once in the launch
  configuration. If it is assigned more than once, the last value wins.
- **Prices and provider behavior move.** The costs above describe the recorded runs,
  not current quotes. Record model IDs, provider routing, Claude Code version, and
  timestamps with every new evaluation.
