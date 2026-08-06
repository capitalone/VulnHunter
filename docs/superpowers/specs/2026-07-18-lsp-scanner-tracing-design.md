# RFC: LSP-Preferred Tracing for `/vulnhunt` Phase 2

**Status:** RFC — decision proposal for maintainer review. This document
contains no runtime changes; it seeks agreement on scope, reconciliation
semantics, and evaluation strategy before implementation planning.
**Scope:** Sub-project B of a two-part contribution. It is **independent** of
Sub-project A (LSP backend for the `vulnhunter-fix` graph substrate); either
may be implemented first. This spec covers only `/vulnhunt`'s Phase 2 trace
instructions (`vulnhunt/phases/phase2_shared.md`,
`vulnhunt/phases/phase2_hunt.md`).

## Summary

`/vulnhunt`'s Phase 2 dispatches trace subagents that hunt for vulnerabilities
by tracing attacker-controlled inputs forward to dangerous sinks. Several steps
are, at their core, **exhaustive reference-enumeration problems** — "find every
call site of this symbol," "find every reader of this store" — and the
instructions explicitly direct agents to solve them with **Grep**. Grep matches
symbol **names**, not symbol **identity**: it can't distinguish same-named
methods on different classes, resolve interface dispatch, or follow aliased
imports. This caps the completeness of exactly the gates this skill leans on
for its low-false-positive claim.

Claude Code provides a native LSP tool that resolves symbols semantically. Its
existence, mechanism, tool name, and core operations are **verified** (see
[Verified evidence](#verified-evidence)). The gap is prompt-level: the
instructions name Grep as the method, so even when the tool is present the
model has no instruction to prefer it.

## Verified evidence

- **Mechanism is plugin-based**, not a single env-var toggle. An operator
  installs a per-language LSP plugin (`pyright-lsp`, `typescript-lsp`, ...)
  from the plugin marketplace; the language server binary itself must be
  installed separately — Claude Code does not bundle `pyright`/`gopls`.
  Confirmed against official docs
  ([Claude Code plugins reference](https://code.claude.com/docs/en/plugins-reference))
  and a maintainer statement in
  [claude-agent-sdk-typescript#123](https://github.com/anthropics/claude-agent-sdk-typescript/issues/123):
  *"The LSP tool should be present if there's an LSP plugin enabled... no env
  vars needed."* Earlier draft references to `ENABLE_LSP_TOOL` reflect a
  transitional state, not the sanctioned gating mechanism.
- **Tool name and operations, confirmed by direct empirical test:** this
  author installed `pyright-lsp` + the real `pyright` binary and drove a
  headless Python `claude_agent_sdk.query()` session against this repository.
  The `init` handshake's `tools` list (authoritative inventory, not
  self-report) contains a tool named literally **`LSP`**. Told to enumerate
  callers of a real method, the model called it with `findReferences`,
  `prepareCallHierarchy`, and `incomingCalls` — and reported that
  `findReferences` alone *only returned the definition*, while `incomingCalls`
  (call-hierarchy) actually surfaced the callers. Results agreed with a Grep
  cross-check.
- **SDK availability:** on this repo's current pair — `claude` CLI `2.1.215`,
  Python `claude-agent-sdk` `0.2.123` — the LSP tool is present and functional
  in a headless SDK session. An earlier race condition reported for the
  TypeScript SDK (tool list built before the LSP manager finished init) lives
  in the shared CLI bundle and does not reproduce on this version pair. This is
  **one environment's evidence**, not a blanket guarantee for pinned-older
  deployments.
- **Not verified:** the ~1.1%-of-navigation-calls adoption figure (third-party
  origin) and Java/JavaScript plugin coverage for the benchmark corpus.

## Decisions

### D1. Prompt-only rewrite, not a custom integration

No MCP bridge, no custom tool, no new client. This spec assumes Claude Code's
native `LSP` tool is used as-is. Building a parallel integration for a
capability the platform already provides would be redundant engineering.

### D2. Provisioning is operator responsibility

VulnHunter's changes are **prompt-only**. It **detects availability** (the
dispatched agent sees its own toolset) and **falls back to Grep** when the tool
is absent. Nothing in this change installs LSP plugins or language server
binaries; provisioning them for `vulnhunter-agent` (path A) is the deployment
operator's responsibility and a **separate, follow-up change** — not a
contradiction with the prompt-only scope. If a plugin/binary is missing, LSP is
simply absent and Grep runs as today.

### D3. Mandatory instruction, scoped, conditionally applied

The instruction is **mandatory where LSP genuinely resolves the symbol** — not
a soft "prefer LSP when convenient" (soft language is the known reason
availability doesn't shift behavior), and not a blanket rewrite (dilutes
attention and touches steps where LSP is the wrong tool). Applied to every
occurrence of the exhaustive-enumeration pattern:

- **Gate 1 (reachability)** and **Gate 2b ("exhaust ALL callers")** — see D5.
- **Store/second-order reader tracing** and the **sink-driven audit agent's
  "EACH caller" steps** — conditional split:
  - Store/symbol is a **language-level symbol** → LSP-primary + Grep
    cross-check.
  - Store is an external system addressed by a **string literal** (Redis key,
    SQL column, queue topic), or the step is **name-pattern discovery** of
    not-yet-identified functions → **Grep only, unchanged** — LSP has nothing
    to resolve.

### D4. Detection: name the tool, keep capability fallback

Prompt text names the tool directly (`"if your available tools include `LSP`,
use it as primary here"`), since the name is verified. A capability-based
clause is retained as secondary phrasing in case the name differs in an
environment this test didn't cover.

### D5. Reconciliation: union with provenance

The caller/reader set is the **union** of LSP and Grep results, never the
intersection — a site found by only one method is still traced. Each result
records **which method(s) contributed** (`lsp+grep | grep-only`). This matches
the skill's existing completeness-over-precision bias, preserves Grep's
language/build independence, and provides the evidence to later decide whether
either source can become authoritative. Grep runs **unconditionally** in every
rewritten step — it is a required cross-check, never a fallback-only participant.

### D6. Gate 1 sequence

1. Identify the suspect symbol.
2. If `LSP` is available, call it using **call-hierarchy**
   (`prepareCallHierarchy` + `incomingCalls`), **not `findReferences` alone** —
   the live test showed the latter under-delivers for exactly this gate's
   purpose.
3. **Always** run the existing Grep call-site search (glob-restricted to
   production extensions, excluding test dirs), regardless of step 2.
4. Union both sets; exclude test files from the union.
5. Empty union of production usages → dead code, unchanged from today.
6. Every site in the union proceeds through existing downstream logic.

### D7. Gate 2b inherits Gate 1's set

The "N-1 other call sites" rule operates on the **same set Gate 1 produced**,
not a fresh enumeration. Only change: a one-line cross-reference clarifying the
reuse.

### D8. Error handling: never treat LSP failure as absence

| Situation | Guidance |
|---|---|
| `LSP` not available at all | Expected default state (opt-in). Grep runs as today — not an error path. |
| LSP call fails/errors/times out for one symbol | Proceed with the Grep result; retry at most once. **Never** treat failure as evidence of absence — it must not suppress a candidate Grep still finds. |
| Systematically empty/degraded results | Agent-local heuristic: after ~3 consecutive unusable results, stop LSP for the rest of *this agent's* trace, note it in the return summary, continue on Grep. Scoped per agent — there is no cross-agent shared state. |
| LSP resolves a wrong call site (shadowing/overload) | Caught by the existing unconditional rule: *"Always verify your analysis by reading the actual source code."* Extend that line to include LSP. |

The Grep cross-check needs its own un-skippable framing (mirroring Gate 1's
existing *"never skip it"*), not a soft "also run Grep" aside — a clean-looking
LSP result is the plausible failure mode for satisficing.

### D9. Audit field added to Gate 1 output

Extend `Gate 1 (reachable?)` from `[Grep usages result — N production call
sites found]` to `[N production call sites found; method: lsp+grep |
grep-only]`. This is the eval instrumentation (§E1) — without it, a flat
benchmark result is ambiguous between "LSP didn't help" and "the agent never
invoked it." The sink-driven audit agent reuses this candidate format and
inherits the field automatically.

## Evaluation

### E1. Benchmark-based, before/after

`/vulnhunt` is prompt-only with no automated test suite; validation is
inherently behavioral. Use `harness/local_harness/benchmark/` with the existing
corpus (Juice Shop/WebGoat/NodeGoat — TypeScript/Java/JavaScript):

- Run clone → scan → LLM-judge → tally **twice per repo**: current phase files
  vs. rewritten ones, with the matching LSP plugin installed and server running
  for the "after" run. Java/JavaScript plugin coverage must be confirmed against
  the plugin marketplace before assuming WebGoat/NodeGoat are covered.
- Compare recall/precision on confirmed findings; cost/latency as a secondary
  metric. Run each condition multiple times — LLM-agent runs are
  non-deterministic.
- **Regression check:** one pass with no LSP plugin installed must reproduce
  pre-change behavior. Additive by construction, but "provable by construction"
  isn't "empirically confirmed" given prompt non-determinism.
- For path A, the benchmark environment itself must have the LSP plugin and
  binary provisioned, or the "after" condition silently tests nothing.

### E2. Success criterion: measured complement

Success is measured by complement and provenance, not a fixed accuracy bar:
on the corpus, LSP must surface callers/readers that Grep misses, while the
Grep cross-check preserves baseline coverage and the audit field exposes the
difference. Predefined precision/recall thresholds are deferred to
implementation planning where corpus ground truth is pinned.

### E3. Detailed verification plan

LSP is plumbing. It improves the product only if it changes detection
*outcomes*, so verification must measure outcomes against ground truth — never
"did LSP get called" or "did we find more text matches."

1. **Outcome metric (the gate):** ratio of newly-confirmed *true positive*
   vulnerabilities attributable to LSP over the baseline. Surface-level
   matches or unconfirmed candidate findings do not count as product gain.
2. **Audit-field instrumentation (D9):** split benchmark findings into three
   provenance buckets: `grep-only`, `lsp+grep` (both found), and `lsp-only`
   (in union). Then evaluate: **of the sites only LSP found, how many were
   confirmed vulnerabilities by the LLM-judge?** That's the product's real
   gain.
3. **Adoption check:** verify that `method` in audit fields is not always
   `grep-only`. This distinguishes "LSP didn't help" from "the agent ignored
   the instruction."
4. **Baseline regression check:** run the post-change prompts with no LSP
   plugin installed. The recall/precision profile must match the pre-change
   baseline (proving D5's additive-by-construction property holds under prompt
   non-determinism).

#### Confounds to control

- **LLM non-determinism** — run each condition multiple times (at least 3–5
  passes per repo), interleaved, with identical prompt seeds where possible.
- **Provisioning asymmetry** — for path A (`vulnhunter-agent`), verify that
  the benchmark runner actually has the LSP plugin and language server binary
  installed; otherwise the "after" condition silently tests pre-change Grep.
- **Cost/latency trade-off** — track token usage and run duration alongside
  finding counts. If recall is flat at higher cost/latency, the prompt change
  is not justified.

## Rollout

Incremental, separate PRs after this design is accepted:

1. Prompt rewrites (this spec's implementation PR) — `phase2_shared.md`,
   `phase2_hunt.md`.
2. Benchmark evaluation against E1/E2.
3. Separate operator-side provisioning change for `vulnhunter-agent` (path A),
   if the evaluation justifies it.

With no plugin installed, every rewritten step behaves as today.

## Open risks for reviewers

- **Adoption-despite-availability** — the ~1.1% figure remains unverified
  (third-party origin). If even roughly accurate, a mandatory instruction may
  still not fully overcome the underlying tendency; E1 treats "instruction
  ignored" as a first-class possible outcome. Reviewers should weigh whether
  the un-skippable framing is sufficient.
- **Prompt-regression risk** — the phase files are dense, tightly-specified
  procedures; a benchmark run is the only way to detect regression. This spec
  claims no verified multi-round review history for `vulnhunt`'s phase files.
- **Version generalization** — the empirical test ran on one CLI/SDK version
  pair, headlessly. Older-pinned deployments could still lack the tool; the
  detection-and-fallback design absorbs that without error.
