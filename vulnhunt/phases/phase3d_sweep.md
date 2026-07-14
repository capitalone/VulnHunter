# Phase 3d: Sweep Verification

> **Context**: All confirmed findings have passing exploit tests and proposed fixes.
> The orchestrator's Operating Principles and Investigation Discipline are in effect.

## Phase 3d: Sweep Verification (MANDATORY — DO NOT SKIP)

After all findings are confirmed via exploit tests, verify that every root cause has
been fully enumerated across the entire codebase. This prevents the pattern where one
instance is found but 5 others are missed, requiring another audit round.

**Sweep operates on the FULL codebase regardless of subgraph partitions.** A root
cause discovered in SG-1 may have additional instances in SG-2's file scope, in files
not assigned to any subgraph, or in shared infrastructure modules. Do NOT limit sweep
searches to the originating subgraph's files.

The input inventory already traced every known input to a disposition. The sweep's
value is catching root cause instances that were NOT reached by any inventoried
input — e.g., a dangerous sink called from a cron job, a background worker, an
internal RPC handler, or any other code path that doesn't start at an entry point
the inventory covered.

**Pre-sweep validation**: Before grepping, count distinct sink file:line values
across all confirmed findings. If that count exceeds the VULN-NNN count, findings
were collapsed — expand them into separate entries before proceeding.

### For each distinct root cause:

1. **List the root cause function/pattern.** Example: "`xss()` output interpolated
   into URL paths without `encodeURIComponent()`"

   **Grep for the PATTERN, not just the sink.** Construct two patterns:
   - **Source pattern**: the vulnerable construction (e.g., `${param}` in URL
     template literals, `/${input}.json` config path interpolation)
   - **Sink pattern**: the dangerous operation (e.g., `window.location.assign`)
   The source pattern catches instances where the same construction feeds a
   different sink than the original finding.

2. Use the **Grep tool** to search the entire codebase for both patterns. Use the
   `glob` parameter to target the relevant file extensions.

3. **Trace callers transitively.** For each instance found, grep for all modules
   that import or call the root cause function. Then grep for all modules that
   import *those* modules. Continue until you reach entry points or exhaust the
   chain. Utility modules, wrapper functions, and re-export patterns frequently
   create indirect paths that a direct grep misses.

4. **For each instance**, check: does this instance flow into the same
   kind of sink? If yes, it's a candidate — run it through the full pipeline.

5. **Verify the receiver type of the method call**, not just the method name.
   When the root cause involves a method that exists on multiple types with
   different semantics (e.g., `String.contains()` is a substring match,
   `Set.contains()` is an exact membership check), trace the variable declaration
   to confirm its type. Do NOT infer the type from surrounding code patterns —
   sibling variables in the same scope may have different types even if they are
   loaded from the same config source.

### Also sweep for related patterns:

- **Unprotected management/debug endpoints**: If any finding involves an
  unauthenticated management or debug endpoint, sweep for ALL additional
  listeners or route registrations that bind without authentication. Each
  unprotected instance is a separate finding.

- **Hardcoded secrets**: If you found one hardcoded key, grep for ALL hardcoded
  keys, tokens, passwords, and license keys across config files and source code.
  Search for common secret-indicating variable names and string patterns
  (`apikey`, `secret`, `password`, `token`, `credential`, `private_key`, etc.)
  in both source and configuration files.

- **Weak crypto**: If you found one weak algorithm, audit ALL crypto usage —
  check entropy levels, KDF iterations, padding modes, cipher modes. Search for
  all cryptographic API calls in the detected language's crypto libraries and
  verify each uses a strong algorithm with adequate parameters.

- **Sanitizer misuse**: If you found one mismatched sanitizer, find ALL calls
  to that sanitizer and verify each one matches its sink context.

### Sweep Output

Write the sweep results to `${VULNHUNT_DIR}/phase3d_output.md` — that
exact filename, at the results-dir top level. Do NOT use the prompt
filename (`phase3d_sweep.md`) as the output filename.

Present this table before proceeding:

| Root Cause | Grep Pattern | Total Found | Candidates | Mitigated | Dev-Only | Remaining |
|---|---|---|---|---|---|---|
| [sanitizer] in [sink] context | `[pattern]` in `*.[ext]` | 20 | 3 | 15 | 2 | 0 |
| Hardcoded secrets | `[pattern]` in [paths] | 5 | 3 | 0 | 2 | 0 |
| Weak entropy | `[pattern]` | 4 | 1 | 3 (adequate) | 0 | 0 |

Use the **total count from grepping**, not the count of instances you chose to
highlight. If you found 20 instances and 3 are candidates, the table says
"20 found, 3 candidates, 15 mitigated" — not "3 found, 3 fixed."

### Sweep Instance Validation

For EVERY instance found by the sweep grep, triage it:
- File:line and the interpolated variable(s)
- Whether user-controlled or from a trusted source — **trace backward through
  state services, storage reads, and property getters** to verify the ultimate
  origin. "Looks server-controlled" at the immediate call site is not sufficient
- What mitigation exists (if any): sanitizer, encoding, type coercion, dev-only route
- Triage verdict: **CANDIDATE** / **MITIGATED** (with reason) / **DEV-ONLY**

Every CANDIDATE instance must go through the full finding pipeline — gates, PoC,
and exploit test (Phases 2b, 3a, 3b) — the same as any finding discovered during
hunting. A sweep instance is not confirmed until it has its own exploit test with
a PASS result. Do NOT assume an instance is exploitable because it shares a root
cause with a confirmed finding — different call sites may have different data flows,
different upstream validation, or different sink behavior.

Instances that pass the full pipeline become separate VULN-NNN findings in the
report. Instances that fail become Code Smells or are eliminated, same as any
other candidate.

**If any row has Remaining > 0, those are unaccounted instances — investigate and
triage them before proceeding to the report.**

### Pipeline Reference for Sweep Candidates

For each CANDIDATE instance found during the sweep, apply the full pipeline:
1. **HARD GATES** (Gate 0 through Gate 3) — read `${PHASES_DIR}/phase2_shared.md`
   for core gate logic. Then read `${PHASES_DIR}/phase2_class_{class}.md` ONLY
   for classes represented in your confirmed findings (you know these from the
   poc/ files you already read). Apply class-specific gate refinements (Gate 0
   exemptions, Gate 2b methodology, Gate 3 "Do NOT eliminate" rules, severity
   floors) when triaging candidates of that class.
2. **PoC** (Phase 3a format) — save to `${VULNHUNT_DIR}/poc/VULN-NNN_description.md`
3. **Exploit Test** (Phase 3b format) — save to `${VULNHUNT_DIR}/exploit_tests/test_vuln_NNN.*`

Only instances with PASS exploit test results become VULN-NNN findings.
