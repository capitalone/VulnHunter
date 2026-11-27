# Phase 2: Vulnerability Hunting

> **Context**: You have completed Phase 1 (Reconnaissance) and built the input
> inventory and subgraph partitions. The orchestrator's Operating Principles and
> Investigation Discipline are in effect throughout this phase.

> **Porting note (revision 2):** VS Code Copilot Chat's Agent mode supports
> genuine parallel subagent dispatch (the `agent`/`runSubagent` tool — see
> VS Code's "Subagents" docs). This revision uses that to run the same
> parallel procedure the Claude Code version uses. If your session doesn't
> have a subagent tool available at all (older client, or disabled by
> policy), use the **Sequential Fallback (only if subagent dispatch is
> unavailable for the entire session)** section at the end of this file
> instead — do not skip partitions or class groups to compensate. A single
> partition marked `SEQUENTIAL-FALLBACK` by Phase 1 (subagents otherwise
> available) uses the separate **Partition Fallback** section instead.

## Phase 2: Vulnerability Hunting

Phase 2 dispatches **parallel trace subagents by class group** — for each
subgraph partition from Phase 1, spawn one subagent per vulnerability class
group (INJ, NAV, LOG). Each subagent traces ALL inputs in its partition but
only evaluates sinks for its assigned class group. The orchestrator merges
results across class groups and proceeds to Phase 2b (global verification).

### Orchestration Strategy

**DISPATCH PROCEDURE (follow exactly):**

For each PRODUCTION partition (e.g., SG-1 with inputs #1-#5):
  → Dispatch: "INJ trace subagent SG-1" with `phase2_class_inj.md` + inputs #1-#5
  → Dispatch: "NAV trace subagent SG-1" with `phase2_class_nav.md` + inputs #1-#5
  → Dispatch: "LOG trace subagent SG-1" with `phase2_class_log.md` + inputs #1-#5

Skip DEV-ONLY partitions entirely (already marked SAFE in Phase 1).
Also dispatch 1 sink-driven audit subagent.

Do NOT dispatch per-candidate, per-hypothesis, or per-finding subagents.
Do NOT combine class groups. Do NOT skip class groups for any partition.
Do NOT analyze partitions "inline" — every production partition gets subagents.
**Minimum subagent count = (3 × production_partition_count) + 1 sink-driven.**
If you dispatched fewer, you violated the procedure.

---

1. **Read the subgraph partitions** from the Phase 1 Recon Output. Each partition
   specifies: partition ID (SG-N), assigned input numbers, entry points,
   app-specific files, shared infrastructure nodes used, and any markers
   (SEQUENTIAL-FALLBACK).

2. **Dispatch trace subagents by class group.** For each normal partition, dispatch
   one subagent per **class group** (see below). Each subagent traces ALL inputs in
   the partition but only evaluates sinks and patterns for its assigned class group.
   This keeps per-subagent instruction volume manageable while maintaining full
   input coverage.

   **Class Groups:**

   | Group | ID | Vulnerability Focus |
   |---|---|---|
   | Injection | INJ | SQL, command, path traversal, SSRF/URL injection, XSS (all variants), open redirect, XXE, LDAP, API query lang, code eval/SSTI, file upload |
   | Navigation/Auth | NAV | CSRF, IDOR, auth bypass, conditional validation bypass, identity spoofing, confused deputy, security signal spoofing, mass assignment, parameter pollution |
   | Logic/Crypto | LOG | Race conditions, cache isolation, credential scope, resource exhaustion, prototype pollution, crypto issues, integer overflow |

   **Dispatch in waves of at most 6** — request up to 6 subagents in a single
   parallel batch, wait for all 6 to produce results files, then dispatch the
   next wave. Do NOT dispatch all subagents in one batch regardless of
   partition count — this cap is a prudent default carried over from the
   Claude Code version's production experience with concurrent-agent limits;
   VS Code's subagent docs don't publish a specific concurrency ceiling, so
   treat 6 as a starting point and back off further if you see dispatch
   failures or throttling.

   Example: 6 partitions = 19 subagents → wave 1: SG-1 INJ/NAV/LOG + SG-2
   INJ/NAV/LOG (6 subagents), wait → wave 2: SG-3 INJ/NAV/LOG + SG-4
   INJ/NAV/LOG (6 subagents), wait → wave 3: SG-5 INJ/NAV/LOG + SG-6
   INJ/NAV/LOG (6 subagents), wait → wave 4: sink-driven (1 subagent). Always
   dispatch the sink-driven subagent as its own final wave after all
   partition subagents complete.

   - **Normal partitions**: one subagent per class group (3 subagents per partition).
   - **SEQUENTIAL-FALLBACK partitions**: process sequentially in the orchestrator's
     context, but iterate through class groups for each entry point group — see
     **Partition Fallback: Sequential Processing with Checkpointing** below.

3. **After all subagents return**, run the aggregation procedure (see Results
   Aggregation below).

   **Dispatch checklist (MANDATORY — verify before proceeding to Phase 2b):**
   - [ ] All class-group subagents for all partitions — dispatched and **produced a results file**
   - [ ] One sink-driven audit subagent — dispatched and returned
   - [ ] Results merged per aggregation procedure
   If any subagent was not dispatched, or dispatched but failed/stalled/produced no
   results file, STOP and re-dispatch it now. A failed subagent is not "no
   findings" — it is unknown coverage. Do NOT proceed with gaps.

### Trace Subagent Task Template

Each subagent is dispatched with a short, self-contained task description.
Subagent calls are **stateless** — the orchestrator cannot send it follow-up
messages, so the task must include everything the subagent needs and the
exact output location. The subagent reads its own instruction files — the
orchestrator does NOT interpolate their content into the task description.

For each subagent, use this task (substitute {CLASS}, {CLASS_FOCUS}, {SG_ID},
{VULNHUNT_DIR}, and {PHASES_DIR}):

```
You are a {CLASS} trace subagent for partition {SG_ID}. Your class group focus:
{CLASS_FOCUS}

You are responsible ONLY for vulnerability classes in your class file. If an
input reaches a sink for a DIFFERENT class group, flag as:
  CROSS-CLASS (input #, sink file:line, suspected class: INJ/NAV/LOG)

Read these files IN ORDER before starting work:
1. {PHASES_DIR}/phase2_shared.md — iteration rules, generic gates, severity, output format
2. {PHASES_DIR}/phase2_class_{class}.md — vulnerability classes, mandatory input gates, class-specific gate methodology
3. {VULNHUNT_DIR}/partitions/sg-{SG_ID}_data.md — your assigned inputs and file scope

Follow the iteration rules in the shared file. For each input, return:
- CANDIDATE (input #, sink file:line, vuln class)
- SAFE (input #, reason — only for YOUR class group's sinks)
- NO-MATCH (input #) → input does not reach sinks in your class group
- CROSS-CLASS (input #, sink file:line, suspected class group)
- DESIGN-INTENT (input #, reason)

Write results to: {VULNHUNT_DIR}/results/sg-{SG_ID}_{class}_results.md

Keep your return summary brief — the orchestrator reads your results file,
not your response.
```

**Class group IDs and focus:** See Class Groups table above.

---

### Trace Subagent Instructions (in separate file)

The iteration rules, HARD GATES, severity classification, and candidate output
format are in `{PHASES_DIR}/phase2_shared.md`. Each trace subagent reads this file
directly — the orchestrator does NOT include it in the dispatch task.

---

## Orchestrator-Only Sections

The sections below are instructions for the **orchestrator** (the main agent
running the audit), NOT for trace subagents. Do not include these in subagent
task descriptions.

### Sink-Driven Audit Subagent

In parallel with trace subagents, dispatch one additional subagent that
performs **backward-trace audits from dangerous sinks**. This catches
findings that input-forward tracing misses — over-permissioning, missing
response-type branching, and authorization gate logic errors.

The sink-driven subagent's task:

```
You are a sink-driven audit subagent. Your job is NOT to trace inputs forward.
Instead, search for specific dangerous patterns by starting at the sink and
tracing backward to determine who can reach it and under what conditions.

Perform these audits:

1. ACTION-SCOPE AUDIT: Search the codebase for wildcard permission constants
   in the detected cloud/auth SDK:
   - AWS: grep for AllS3Actions, AllKMSActions, All.*Actions, or "*" in
     policy action arrays
   - GCP: grep for "*" in IAM bindings
   - Azure: grep for "*" in role definitions
   For EACH wildcard found: (a) read the function using it, (b) check if a
   parallel branch for a different role/access-level uses a restricted set —
   if yes, the wildcard branch is over-permissioned, (c) check if the wildcard
   includes destructive operations beyond what the feature requires.

2. CREDENTIAL-ISSUING SINK AUDIT: Grep for all credential-issuing functions
   (STS AssumeRole, token minting, key generation, credential vending).
   For EACH caller of the credential-issuing function, verify it branches on
   request type / access level before issuing credentials. If ANY caller does
   not branch, a policy-only or read-only request could reach the credential
   path — that is a CANDIDATE.

3. CRYPTOGRAPHIC SINK AUDIT: Grep for crypto API calls (adapt to detected stack).
   For EACH call in production code, check:
   (a) Algorithm/mode/key size: weak by current standards?
   (b) Context: security-sensitive (auth, PII, sessions, signatures) vs non-sensitive?
   (c) Key storage: Flag `extractable: true` CryptoKeys serialized to web storage,
       cookies, logs, or network — any same-origin XSS can read them. CWE-312.
   (d) Key-adjacent entropy: auth factors or binding values generated with
       non-cryptographic PRNGs (`Math.random()`) instead of `crypto.getRandomValues()`? CWE-330.
   Weak crypto + security-sensitive context = CANDIDATE (CWE-327).
   Attacker-controlled input is NOT required — weak crypto is a flaw in the
   protection mechanism itself. Do NOT apply Gate 2a to eliminate crypto findings.

4. SENSITIVE DATA STORAGE AUDIT: Grep for `sessionStorage.setItem`,
   `localStorage.setItem`, `document.cookie` assignments. If the value contains
   private keys, tokens, credentials, or PII → CWE-312. Check for fallback paths
   where protected data degrades to plaintext web storage.

5. CONCURRENCY / RACE CONDITION AUDIT: Grep for async dispatch patterns:
   Python: `ThreadPoolExecutor`, `asyncio.create_task`, `executor.submit`
   Java: `ExecutorService.submit`, `CompletableFuture.runAsync`, `@Async`
   Go: `go func()` goroutine launches
   Node.js: fire-and-forget promises (no `await`), `setImmediate`
   For EACH async dispatch in production code:
   (a) What state does the async op modify (delete, create, update)?
   (b) Does any subsequent synchronous operation depend on that state change?
   (c) Is there locking/transaction/sync ensuring completion before the
       dependent operation? If not → CANDIDATE (CWE-367).

6. RATE-LIMIT / ATTEMPT-COUNTER AUDIT: Grep for session-attribute writes tracking
   attempt counts (`session.setAttribute`, `session.set`, `req.session.`, `HttpSession`
   combined with `attempt`, `count`, `limit`, `tries`, `lockout`, `max`). For EACH
   counter on an unauthenticated endpoint: verify the binding identifier cannot be
   rotated to reset it. If rotatable (HTTP session without prior auth, ephemeral
   cookie) → CANDIDATE (CWE-307).

For each finding, return the candidate format used by trace subagents (but do
NOT assign VULN-NNN IDs). Include gate results where applicable.

Write results to: {VULNHUNT_DIR}/results/sink_driven_results.md
```

Merge the sink-driven subagent's candidates into the main results alongside
trace subagent candidates during aggregation.

### Results Aggregation

After all trace subagents AND the sink-driven audit subagent return their
results, the orchestrator merges them:

1. **Merge input dispositions** across class groups. For each input, collect
   dispositions from all 3 class-group subagents. An input's final disposition is:
   - **CANDIDATE** if ANY subagent returned CANDIDATE for it
   - **SAFE** if ALL subagents returned SAFE or NO-MATCH (no subagent found a sink)
   - **CROSS-CLASS**: Cross-reference against the target class subagent's results for
     that partition. If the target subagent evaluated the flagged sink (returned
     CANDIDATE or SAFE for it), use that disposition. Only re-dispatch if the
     target class subagent did not evaluate that specific sink.
   If an input has no disposition from any subagent, re-dispatch it.

2. **Assign VULN-NNN IDs** to all candidates across all subgraphs. Number
   sequentially (VULN-001, VULN-002, ...) in the order subgraphs were dispatched,
   then by input number within each subgraph.

3. **Deduplicate**: If two subagents found candidates pointing to the **same sink at
   the same file:line** (possible when shared infrastructure functions are called
   from multiple subgraphs), merge into one candidate. Keep the most pessimistic
   severity assessment and the union of all data flows.

4. **Completeness check**: Count dispositions. The total must equal the input
   inventory count from Phase 1. If any inputs are unresolved, investigate and
   re-dispatch before proceeding.

5. **Present the merged candidate list** and the resolved inventory to the user
   before proceeding to Phase 2b.

6. **Absent-input verification checkpoint (MANDATORY)**: Before proceeding to
   Phase 2b, verify every cookie/header/parameter that gates a security-critical
   block (auth, session validation, CSRF, rate limiting). For each, answer:
   "If omitted, does the security check fail closed or fail open?"
   Every "fail open" = Conditional Validation Bypass CANDIDATE (CWE-306).
   This requires cross-input reasoning that single-partition subagents cannot do.

### Partition Fallback: Sequential Processing with Checkpointing

When a partition is marked `SEQUENTIAL-FALLBACK` by Phase 1 (too large to
parallelize effectively, even though subagent dispatch is otherwise
available this session), the orchestrator processes that one partition
directly instead of dispatching subagents for it:

1. Group the partition's inputs by entry point.
2. For each entry point group, iterate through class groups (INJ, NAV, LOG),
   tracing all inputs against that class group's vulnerability classes.
3. After completing each entry point × class group, save intermediate candidates to
   `${VULNHUNT_DIR}/candidates/sg-N_entrypoint_classgroup.md` before proceeding.
4. This limits context accumulation — each pass starts with only one class group's
   gate definitions and its own inputs in active context.
5. After all entry point groups are processed, collect all saved candidates
   and merge them into the main aggregation flow.

This is distinct from the session-wide fallback below: a single
`SEQUENTIAL-FALLBACK` partition gets this treatment while every other
partition in the same run still dispatches subagents normally.

### Sequential Fallback (only if subagent dispatch is unavailable for the entire session)

If your Copilot Chat session doesn't have a subagent tool available at all,
process every partition directly instead — not just ones marked
`SEQUENTIAL-FALLBACK`:

1. Group the partition's inputs by entry point.
2. For each entry point group, iterate through class groups (INJ, NAV, LOG),
   tracing all inputs against that class group's vulnerability classes.
3. After completing each entry point × class group, save intermediate candidates to
   `${VULNHUNT_DIR}/candidates/sg-N_entrypoint_classgroup.md` before proceeding.
4. This limits context accumulation — each pass starts with only one class group's
   gate definitions and its own inputs in active context.
5. After all entry point groups are processed, collect all saved candidates
   and merge them into the main aggregation flow.
6. Process partitions one at a time, all 3 class groups before moving to the
   next partition, then run the sink-driven pass last. Checkpoint every
   pass's results to disk immediately after it completes. If this session's
   context fills up before all passes are done, stop at a partition boundary
   (never mid-pass), tell the user which partition/class-group pass to
   resume from, and continue in a new chat — Phase 1's recon output and any
   completed results files are already on disk and don't need regenerating.
