# Working with non-Anthropic models

VulnHunter's skills (`/vulnhunt`, `/vulnhunter-fix`) run inside Claude Code. Claude
Code normally speaks the Anthropic Messages API, and gateways such as
[OpenRouter](https://openrouter.ai) expose an Anthropic-compatible endpoint. With a
few model overrides, we can run the same VulnHunter workflow against selected
third-party models (GLM, Kimi, DeepSeek, Gemma, Nemotron, OpenAI's open models, …).

This doc explains **how** to do that and **which models actually work**.

> TL;DR — in our evaluations as of 2026-08-22, the models we'd consider for a real scan
> are **Claude Opus 5** and **Opus 4.8** (native), **GLM-5.3**, **GLM-5.2**, and — on a
> single strong run — **Kimi K3** (the GLMs and Kimi via OpenRouter). **Opus 5 finds the most
> when it runs well**: its stronger run was the first to catch every known High-severity
> vulnerability and it leads on every answer key. **GLM-5.3 is the best value by a wide
> margin** — its stronger run found 37 real vulnerabilities and 4 of the 5 Highs for **$43**,
> the best cost-per-finding of any run we have scored. The dominant caveat is now
> **consistency**: every model we have run twice disagreed with itself badly — GLM-5.3
> overlapped **31%** run-to-run, Opus 5 **41%**, GLM-5.2 **46%**. **No single run should be
> treated as complete**, and unioning two cheap runs beats one expensive run per dollar
> spent: two GLM-5.3 runs found 52 real vulnerabilities for $97, against 32 for $110 from a
> weak Opus 5 run. Other completed evaluations — including **Qwen 3.7 Max** — were noisy,
> incomplete, or non-starters. OpenAI frontier models have not yet completed the same
> evaluation.

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
export ANTHROPIC_MODEL="z-ai/glm-5.3"          # <- the model under test
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
| **Claude Opus 5** | native `claude` | **Recommended when coverage matters more than budget or predictability.** Its stronger run found 67 adjudicated-real vulnerabilities — more than double any non-Opus run — and was the **first run ever to catch all five known High-severity issues**, leading on every answer key including the original one. That run cost **$203** ($3.03 per true positive — roughly 2.6× GLM-5.3's best run). Two serious caveats: **consistency** — two runs on identical code shared only 41% of their findings, with the weaker run finding half as much for $110 — and **noise**: 16 false positives (the most of any run), 11 of them arguments that VulnHunter's own gates are weak rather than actual vulnerabilities, plus only 4 of its 16 "High" calls surviving adjudication. Choose it when you need maximum single-run coverage and can absorb both the price and the variance. |
| **GLM-5.3** | `z-ai/glm-5.3` (OpenRouter) | **Recommended as the best value for a serious scan, and the best value overall.** Across two runs it produced 31 and 37 adjudicated-real findings at ~0.82 precision with **zero invalid citations**. The stronger run cost **$43** — **$1.17 per true positive and 0.855 findings per dollar, the best figures in the entire corpus** — caught **4 of the 5 known Highs**, and showed the best severity discipline of any high-yield run (only 4 findings called High, half of which held; Opus 5's stronger run called 16 High and kept 4). It delivers **2.7× Opus 5's severity-weighted coverage per dollar**. Caveats: it is slow (~6–7 h), and it is the **least self-consistent model measured** — its two runs shared only 31% of their findings, so treat one run as a sample, not a scan. Both runs missed the same High (the symlink `copytree` disclosure), which looks like a genuine blind spot rather than variance. |
| **Claude Opus 4.8** | native `claude` | **Recommended for report quality and consistency.** Reliably completed the pipeline and produced the most polished reports. Its main weakness was recon coverage: both evaluated runs missed some of the most severe findings, and neither caught a single High-severity issue. At $28 it is mid-priced — Opus 5 is now the expensive option. |
| **GLM-5.2** | `z-ai/glm-5.2` (OpenRouter) | **Recommended for value, and still worth running alongside 5.3.** It produced strong severe-vulnerability coverage at $10–14 per run with generally strong precision. GLM-5.3 outscores it on almost every axis, but does **not** subsume it — the 5.2 runs still hold eight vulnerabilities 5.3 missed, including one High. Run-to-run variance is the main caveat, and the reason three cheap 5.2 runs are a credible alternative to one 5.3 run. |
| **Kimi K3** | `moonshotai/kimi-k3` (OpenRouter) | **Recommended, on a single run.** In one evaluation it led the field on true-positive count and cost-effectiveness with strong precision, and it **uniquely discovered two exploitable High-severity vulnerabilities no other model found** (a token path-prefix bypass and an ambient-credential clone). Caveats: only one run so far; it was slow (~5.5 h); and its severe-vuln credit came from findings it discovered rather than the previously-known set. A clear generational jump over Kimi k2.7-code (below) — do not confuse the two. |
| **Muse Spark 1.3** | `meta/muse-spark-1.3` (OpenRouter) | **Recommended only as a fast triage pass, not as a scan.** One run at **$10.79 in 40 minutes** — by far the fastest run in the corpus — returned 6 findings, **all 6 adjudicated real, zero false positives** (one of only three runs ever to hit perfect precision) with zero invalid citations. Half were exploitable, and it recovered one finding otherwise seen only in the $203 Opus 5 run. But coverage is the whole problem: 6 of 104 known vulnerabilities is **5.8% recall**, whole classes went unhunted (no DoS/ReDoS, resource-exhaustion or symlink tracing), and it affirmatively cleared surfaces the answer key marks exploitable. It also **adds nothing to an ensemble** — every one of its six findings was already covered by another model. Treat the low false-positive rate as its selling point: findings you can hand straight to an engineer without triage. One further caution: its six exploit tests are **tautologies that never import the target code** (one ends in `assert ... or True`), yet all six are labelled `PASS (static)` in its report. Do not read that column as verification. |

**Caveat on any single run — this is the most important finding in the evaluation:**
every model we have run more than once disagreed with itself badly. Measured overlap
between two runs of the same model: **GLM-5.3 31%**, **Opus 5 41%**, **GLM-5.2 46%**. (Kimi K3 and Muse Spark 1.3 have one run each, so they have no measured self-consistency figure — assume they are no better.) Opus 5
found 67 real vulnerabilities on one run and 32 on another; GLM-5.3 found 37 and 31 with only
16 in common. The most severe issues tend to recur; the secondary findings change
substantially. So: **run 2–3 times and union the results**, and prefer unioning *different*
models over repeating one.

Measured combinations on the current 104-vulnerability key:

| Combination | Reals found | Cost |
|---|--:|--:|
| Opus 5 + GLM-5.3 ×2 | 89/104 | $300 |
| Opus 5 + GLM-5.3 + Kimi K3 | 87/104 | $273 |
| Opus 5 (best single run) | 67/104 | $203 |
| GLM-5.3 ×2 | 52/104 | $97 |
| GLM-5.3 + GLM-5.2 ×2 | 46/104 | $67 |

The cheapest combination covering **every** known High-severity vulnerability is a single
Kimi K3 run plus the one GLM-5.2 run that caught all three of the Highs GLM finds — about
**$29** together, though that pair reaches only 19 of the 104 known vulnerabilities overall.

These recommendations come from a limited evaluation, not a general model benchmark.
Opus agents also participated in adjudicating the results while Opus was one of the
models under evaluation. Blind voting reduced that conflict but did not eliminate it;
see the full report's objectivity caveat.

### Completed evaluations not recommended

| Model | OpenRouter id | Why not |
|---|---|---|
| Kimi k2.7-code | `moonshotai/kimi-k2.7-code` | Completed, but was noisy and slow. It repeatedly treated trusted or operator-controlled inputs as attacker-reachable and was outperformed by GLM. **Superseded by Kimi K3 (recommended, above) — a distinct, much stronger model.** |
| Qwen 3.7 Max | `qwen/qwen3.7-max` | **Failed in practice.** Recon was strong, but the hunt stage mass-dismissed nearly every real finding: 1 true positive (plus 1 false positive) against the 37 vulnerabilities known at the time, missing all five High-severity ones — despite spawning 40 subagents and 1,100+ tool calls. It also self-mislabeled its own model in the report and declared the codebase "well-hardened." High effort, near-zero yield. |
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
