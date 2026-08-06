# RFC: LSP Backend for `vulnhunter-fix` Graph Substrate

**Status:** RFC — decision proposal for maintainer review. This document contains
no runtime changes; it seeks agreement on architecture, confidence/fallback
semantics, and evaluation strategy before implementation planning.
**Scope:** Sub-project A of a two-part contribution. It is **independent** of
Sub-project B (LSP-preferred tracing for `/vulnhunt` Phase 2) — see
[Relationship to scanner tracing](#relationship-to-scanner-tracing). Either may
be implemented first.

## Summary

Add a third, **opt-in**, gracefully-degrading backend to `vulnhunter-fix`'s
pluggable code-graph substrate (`vulnhunter_fix/graph/`), using real Language
Server Protocol (LSP) servers (`pyright`, `gopls`) for the security-purpose
query primitives `callers_of`, `callees_of`, `reachable_from`, and
`blast_radius`. Today's two backends are **name-based, not semantics-based**:

1. **`ast`** — via `graphify`, `confidence: "high"`.
2. **`grep`** — regex fallback when graphify is unavailable or fails,
   `confidence: "low"`.

Neither resolves overloads, interface dispatch, polymorphic calls, or import
aliasing correctly. This caps the achievable precision of
`callers_routed_coverage` (the gate deciding whether a fix plan touched every
caller of a vulnerable sink) and of `reachable_from`, which today isn't even
wired into sidecar generation.

## Decisions

### D1. Generic protocol client; Python reference implementation

The backend is a single generic LSP client with per-language adapters
(startup command, workspace detection, symbol quirks). **Python is the
reference implementation**; Go and the remaining graphify languages are
explicitly extensible through the same adapter seam, not built in this first
change. This keeps expansion open without committing the first PR to wiring
and testing 6+ language servers.

### D2. Opt-in, default unchanged

Env var `VULNFIX_GRAPH_BACKEND`, default `auto` (= today's `ast → grep` chain,
byte-for-byte unchanged). Value `lsp` enables per-finding LSP resolution with
baseline fallback always available. Matches the existing override convention
(`VULNFIX_GH_HOST`, `VULNFIX_BASE_BRANCH`); no changes to `plan.md` or
`config.json` schema.

### D3. Per-finding resolution by sink-file language

The baseline `GraphDocument` (`build_or_load`, `ast → grep`) is **always built
first** and remains the fallback for every finding. When `lsp` is opted in,
resolution is **per finding**, keyed by the sink symbol's file language:

- First use of a language → try starting an LSP session (binary on PATH,
  `multilspy` handshake). Failure marks that language unavailable for the
  **rest of the run** (no per-finding retry), logged once.
- Success → the session is reused for every subsequent finding in that
  language, torn down at process exit.
- A single finding's query failing does **not** kill the session; only full
  session death (process exit, closed pipe) does.

A single run can therefore resolve Python findings via `lsp` and Go findings
via `ast`/`grep` — `graph_backend` is recorded **per sidecar**, not per run.

### D4. Query shape: eager nodes, lazy edges

Nodes/files are populated **eagerly** at session start via `workspace/symbol`
(comparable cost to AST enumeration). Edges are resolved **lazily**, per query,
via call-hierarchy / find-references, matching how the fixer actually calls
these primitives (a handful of finding-scoped lookups, never a full-repo dump).
Successful per-symbol results are cached in memory for the session's lifetime;
failures are never cached.

### D5. Wire `reachable_from_entry` into the sidecar

`reachable_from()` is implemented in `query.py` but `_build_sidecar` never
calls it — every backend emits `reachable_from_entry: None` today. This change
wires it for **both** `ast` and `lsp` paths, since raising confidence on
reachability is the stated motivation for the LSP backend.

**Input contract:** `finding-schema.json`'s `entry_point` is an unconstrained
nullable string (`vulnhunter-fix/references/finding-schema.json:40`), while
`reachable_from` requires a file and integer line. The accepted representation
is `<file>:<line>`. Values that don't parse cleanly are treated as absent
(`reachable_from_entry` stays `None`) and logged once — never fabricated and
never fatal. A schema tightening (e.g. a `pattern` on `entry_point`) is a
possible follow-up, not a requirement of this change.

### D6. Failure and confidence semantics: fallback and downgrade

All failures degrade without crashing the run (consistent with
`_try_graphify_build`'s philosophy). The load-bearing rule: **a failed or
incomplete LSP query must never be recorded as high-confidence.**

| Failure | Detected | Effect |
|---|---|---|
| `multilspy` not installed | Import time | `lsp` mode behaves identically to `auto` for the whole run. Logged once. |
| Language server binary missing | First use of that language | Language marked unavailable for the rest of the run; findings use baseline `GraphQuery`. |
| Session dies mid-run | Health check before each use | Same as binary-missing: language marked dead, logged once. |
| Single query fails (timeout / malformed response), session alive | Per call | Session **not** killed. Fall back to the baseline graph for that operation and **downgrade the sidecar's provenance/confidence** — empty-on-error is never recorded as `graph_backend: "lsp", confidence: "high"`, because it is indistinguishable from a genuine no-callers result and would poison strict downstream coverage checks. Timed-out calls are never cached (30s per-call timeout, matching `grep_callers_of`'s subprocess convention). |
| Symbol not found (not an error) | Per call | Same empty/`False` contract as today. |

Confidence semantics are inherited, not invented: `confidence: "high"` under
`lsp` means "semantic resolution was used," the same tier-level guarantee `ast`
carries. It does not certify zero indexing gaps (e.g. `pyright` without a
resolvable venv).

**`REQ-GRA-004`'s cloud-LLM isolation guard does not apply:** `pyright`/`gopls`
are local static-analysis binaries with no network/cloud call path regardless
of `ANTHROPIC_API_KEY` being set.

### D7. Schema fix ships atomically with this change

`triage-schema.json` hard-codes `graph_backend: {"const": "ast"}` under the
`confidence: "high"` branch, which would reject a valid
`confidence: "high", graph_backend: "lsp"` sidecar. Fix: `graph_backend`'s
top-level `enum` becomes `["ast", "grep", "lsp", "none"]` and the
`confidence == "high"` branch's `const: "ast"` becomes `enum: ["ast", "lsp"]`.
This must ship in the same commit as the backend, because an LSP sidecar
produced against the unpatched schema would fail validation.
`validate-triage.py` and `compute-completeness-tier.py` were checked and have
no hardcoded backend-string logic outside this schema file.

### D8. No persistent on-disk cache for LSP results

`cache/graph.json`'s content-hash invalidation model belongs to the
static-document backends. LSP produces partial, per-symbol, session-scoped
results — conflating them would corrupt the cache's invalidation story. LSP
results live only in the in-memory per-run cache. The re-query cost is accepted
because `build_graph.py` runs once per repo per Plan phase.

## Relationship to scanner tracing

Claude Code ships a native LSP capability surfaced **to the model** as a tool
during a live agent turn. Sub-project B (scanner tracing) operates at that
layer and uses Claude Code's native tool as-is.

This backend operates at a **different layer**: a plain Python library
(`vulnhunter_fix/graph/`) called by a headless helper script (`build_graph.py`)
via Bash, entirely outside any live agent turn. The model never sees an LSP
server directly — only the sidecar's pre-computed output. The two are
**architecturally independent**: neither reuses the other's client, and neither
must be sequenced before the other. Any prior draft statements tying one's
rollout to the other are superseded by this section.

## Testing

**Hermetic by default** — `tests/test_lsp_backend.py`:

- A scripted fake LSP server (fixed JSON-RPC over stdio) drives
  `LSPGraphQuery` through `workspace/symbol`, call-hierarchy, and the
  `reachable_from` BFS. No real binaries; runs in every environment.
- **Protocol conformance** parametrized over both `GraphQuery` (existing golden
  fixtures) and `LSPGraphQuery` (fake server): both satisfy the same
  shape/error contract for all 5 methods.
- **Session lifecycle:** fake server records exactly one `initialize` across N
  findings of the same language.
- **Failure taxonomy,** one test per `D6` row: binary missing (mocked
  `shutil.which` → `None`), session death, per-query timeout — asserting
  correctly scoped fallback and that failures aren't cached.
- **Mixed-language:** one Python + one Go finding, one server available, one
  missing — asserts each sidecar's `graph_backend` reflects the backend that
  actually answered.
- **Schema regression** (`contract`-marked): `confidence: "high",
  graph_backend: "lsp"` validates; existing `ast`/`grep` cases still validate.

**Live tier, explicitly marked and skipped by default** — new pytest marker
`lsp_live`; runs real `pyright`/`gopls` against the existing
`tests/graph_fixtures/{python,go}/sample_auth.{py,go}`, guarded by
`shutil.which`, matching the idiom `grep_callers_of` already uses.

## Success criterion

**Measured complement, not operational-only.** On a representative corpus the
LSP backend must:

1. Find useful references that the `ast`/`grep` baseline misses (semantic
   resolution — aliases, overloads, dispatch);
2. Never regress baseline coverage — any operation whose LSP query fails
   returns to the baseline result with downgraded provenance;
3. Expose the difference in the sidecar (`graph_backend`, per-finding
   provenance) so gains and gaps are inspectable.

An accuracy threshold is deliberately deferred to implementation planning,
where the corpus and ground truth are pinned.

## Verification plan

LSP is plumbing. It improves the product only if it changes remediation
*outcomes*, so verification must measure outcomes against ground truth — never
"did LSP get called" alone.

### V1. Caller ground-truth differential (unit-level, cheapest signal)

For each symbol in `tests/graph_fixtures/{python,go}/sample_auth.{py,go}`,
build three caller sets: `ast`, `grep`, `lsp`, plus a **hand-verified
authoritative set**. Compute recall and precision of each backend vs. ground
truth. This directly tests D6 fallback (LSP missing a caller must be caught
by Grep, and vice versa) and proves the union improves coverage over either
backend alone.

### V2. Coverage-gate delta on real findings (integration-level)

Run the fixer's Plan phase on a small corpus twice: once with
`VULNFIX_GRAPH_BACKEND=auto`, once with `=lsp`. Measure:

- Did `callers_routed_coverage` pass where it previously failed (new true
  callers discovered)?
- Did the fix plan touch more true callers?
- Did cost/latency change materially?

The **gate metric** for the PR: the ratio of newly-covered *true* callers
attributable to LSP over the baseline. Zero improvement = no product gain.

### V3. False-high guard (regression-critical)

Assert that a killed/timeout LSP session **never** yields
`confidence: "high"` sidecars. A single false-high would silently poison the
downstream `callers_routed_coverage` gate — this is the riskiest regression
and must be part of every hermetic and live test run.

### Confounds to control

- **Non-determinism** — N/A for the fixer (deterministic Python library), but
  relevant if the downstream plan phase uses LLM reasoning over sidecars.
- **Provisioning asymmetry** — the `lsp` run must actually have the server
  binary present, or it silently tests nothing and reports baseline results.
- **Cost/latency** — LSP sessions index slowly on large repos. Equal recall at
  3× cost is a real trade-off, not a win; report wall-clock time alongside
  caller counts.

## Rollout

Incremental, with separate implementation PRs after this design is accepted:

1. LSP backend + schema fix (this spec's implementation PR).
2. Evaluation on the benchmark corpus against the success criterion above.
3. Any language-server pinning/compat strategy that evaluation justifies.

The backend is opt-in, so no existing user changes behavior.

## Open risks for reviewers

- **`multilspy` maturity/maintenance** — a smaller, less battle-tested
  dependency than `graphify`. Worth a second opinion vs. a thinner LSP client.
- **`pyright`/`gopls` version drift** — unlike `graphify`'s tight version pin
  (`GRAPHIFY_VERSION_RANGE`), server behavior can vary across versions in ways
  that silently change confidence guarantees. No pinning strategy is proposed
  yet.
- **Cold-start cost at scale** — large monorepos index slowly; the one-time
  per-language session start has no timeout today (only per-query calls do).
  Worth flagging if an abort-to-baseline path is needed for session start
  itself.
