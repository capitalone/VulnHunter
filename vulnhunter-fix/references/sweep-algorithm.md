# Sweep algorithm reference

**Companion to** `prompts/sweep.md`. This file documents the two-pass algorithm, per-ROOT summary shape, routing paths, tier-downgrade rule, verification-table integration, and PR-diff mode handling. `prompts/sweep.md` carries the invocation and short flow; details live here.

**Referenced by:** REQ-SWP-001 through REQ-SWP-009.

## Two-pass algorithm (REQ-SWP-002)

**Pass 1 — Symbol pass (graph-anchored):**

For each ROOT cause:
1. Read the sink symbol from the triage sidecar at `.work/<repo>/graph_context/<VULN>.json` (`sink_symbol` field per REQ-GRA-008 / SCH-5).
2. `callers = graph.callers_of(sink_symbol)`.
3. For each caller, check whether it routes through the safe pathway using `result.callers_routed_through_fix`.
4. Any caller in `callers` but NOT in `callers_routed_through_fix` is a **sibling defect**.

**Pass 2 — Pattern pass (regex fallback):**

For each ROOT cause:
1. Determine the CWE class per `references/cwe-fix-patterns.md`.
2. Load regex patterns for that class from `references/sweep-patterns.md`.
3. Scan every source file the Pass 1 didn't already flag. Record hits as candidate siblings.
4. If the graph is in fallback mode (`graph.backend == "grep"` or `sidecar.confidence == "low"`), Pass 1 is skipped and Pass 2 alone runs. The sweep row annotates `Captured (regex-only)` per REQ-SWP-007.

## Per-ROOT summary (REQ-SWP-003)

One row per ROOT cause:

```
| Root cause | Pattern | Found | Captured | Mitigated | Remaining |
|-----------|---------|-------|----------|-----------|-----------|
| VULN-001  | SQL concat | 7  | 7        | 5         | 2         |
```

- `Found` — total siblings detected across both passes
- `Captured` — siblings the executor decided to include (Pass 1 within worktree + Pass 2 regex-verified)
- `Mitigated` — siblings amended into the PR (Path A) or emitted as follow-up issues (Path B)
- `Remaining` — `Found − Mitigated`. Non-zero triggers scope amendment or follow-up per REQ-SWP-004/005

## Routing paths (REQ-SWP-004, REQ-SWP-005)

For each captured sibling:
- **Path A — scope amendment.** Sibling is in the same worktree as the current PR, in files already listed in `result.files_modified`. Amend the PR to cover the sibling.
- **Path B — follow-up issue.** Sibling is in a different file or worktree. Open a `vulnfix-sweep-detected` labelled issue per sibling; do NOT amend the PR.

## Tier downgrade (REQ-SWP-006)

When Sweep surfaces siblings after a fix was classified `VERIFIED_FULL`:
- Downgrade to `VERIFIED_MITIGATION`.
- Set `result.sweep_revised = true`.
- Update `result.residual_vectors` with entries naming each unmitigated sibling.
- Re-render the Residual Risk section (`vulnhunter_fix.delivery` detects the tier change and re-runs the honesty guards).

## Verification-table integration (REQ-SWP-008)

Column 8 (`Sweep complete?`):
- `yes (n/a)` — the ROOT cause had no siblings (`Found == 0`)
- `yes` — all captured siblings were mitigated (`Remaining == 0`)
- `no` — `Remaining > 0`. Verdict cell downgrades from FULL to MITIGATION.

## PR-diff mode PRE-EXISTING handling (REQ-SWP-009)

When scan mode is PR-diff and Sweep surfaces findings marked `PRE-EXISTING`:
- List them as informational entries in the tracking issue.
- Do NOT auto-fix (out of scope for the PR-diff run).
- Do NOT create follow-up issues (they belong to the next full scan).
