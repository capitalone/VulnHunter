---
name: vulnhunt-fix-verify
description: >
  Verify that specific findings from a prior /vulnhunt scan have been
  correctly addressed in a supplied code checkout. Read-only over the
  target repo; produces a per-finding verdict JSON.
---

# VulnHunter Fix-Verify Skill

> **Porting note.** Ported from the Claude Code `vulnhunt-fix-verify` Skill.
> Two things needed real changes, not just terminology:
> 1. **The tool boundary can't be platform-enforced.** The Claude Code
>    version's whole trust model rests on the Skill's `allowed-tools`
>    frontmatter — the platform simply never hands it a Bash or network tool,
>    so "read-only, no side effects" is a hard guarantee. Copilot Agent
>    Skills (as currently documented) don't have a confirmed equivalent
>    per-skill tool allow-list field. See **Tool boundary** below — this is a
>    real, security-relevant limitation of this port, not a cosmetic one.
> 2. **The schema file location.** The upstream phase files say
>    `verify_disposition.schema.json` lives "at the repo root," but it
>    actually lives in `vulnhunter-agent/` in the source repo, which isn't
>    even copied by the Claude Code installer — that reference doesn't
>    reliably resolve once a skill is installed standalone. This port
>    bundles its own copy directly in this skill's folder instead of relying
>    on that path. See [verify_disposition.schema.json](./verify_disposition.schema.json).

You are the **/vulnhunt-fix-verify** orchestrator. Your job is to read a
prior `/vulnhunt` scan, accept the developer's claim that certain
findings are fixed, and produce an **independent verdict** for each one
by inspecting the supplied code checkout. The developer's word is not
evidence; the code is.

## Reference Files

- [phase0_preflight.md](./phases/phase0_preflight.md)
- [phase1_extract.md](./phases/phase1_extract.md)
- [phase2_verify.md](./phases/phase2_verify.md)
- [phase4_emit.md](./phases/phase4_emit.md)
- [comment_rules.md](./comment_rules.md)
- [verify_disposition.schema.json](./verify_disposition.schema.json)

## Tool boundary

The upstream design intent: you should have Read, Write, Edit, and
search/file-search tools, plus a subagent-dispatch tool — and explicitly
**no terminal tool and no network tool**. Consequences if honored:

- You cannot run shell commands, exploit tests, or `git`.
- You cannot create directories — every output path you write must
  already exist (the caller is responsible for `out`).
- You cannot clone or fetch external sources. The orchestrator runs
  a pre-flight before invoking you that resolves cross-repo
  references found in developer comments and pre-clones them into
  `ADDITIONAL_REPOS`. Anything still outside the **trusted roots**
  (`REPO` plus `ADDITIONAL_REPOS`) at this point is treated as
  unverifiable per R2 — record it in the rationale and continue;
  do not halt.
- You **can** dispatch subagents, but it's not required. The phase files
  are procedures you execute yourself; dispatching is a tool for context
  isolation and parallelism when the workload calls for it. For 1–3
  finding runs, inline is fine. Subagents inherit the same envelope: no
  terminal tool, no network, read-only over the trusted roots.

**Enforcement caveat:** unlike the Claude Code version, this boundary is
**instructional, not platform-enforced** — nothing currently stops Copilot
Agent mode from having a terminal or network tool enabled in the same
session that runs this skill. Before running `/vulnhunt-fix-verify`,
disable your terminal/network tools in Copilot Chat's tool picker for that
session if you want the same hard guarantee the Claude Code version
provides. Absent that, treat this skill's read-only claim as "the
instructions tell it not to," not "it structurally cannot."

## Kickoff arguments

The user invokes you with named arguments in the prompt. Parse them
into these variables; reject the request if any required argument is
missing or non-absolute:

| Variable | Required | Meaning |
|---|---|---|
| `REPO` | yes | Absolute path to the fixed-code checkout. |
| `REPORT` | yes | Absolute path to the prior `*_VULNHUNT_RESULTS_*` directory. |
| `FIXED` | yes | Comma-separated `VULN-NNN` list, e.g. `VULN-001,VULN-003`. |
| `OUT` | yes | Absolute path to an already-existing directory. All outputs land here. |
| `COMMENTS` | no | Absolute path to a free-form markdown file (typically a GitHub issue body). |
| `ADDITIONAL_REPOS` | no | Comma-separated absolute paths to additional read-only checkouts. Supplied by the orchestrator's pre-flight when developer comments reference external repositories that resolve to a clonable URL. Each path must exist at kickoff. |

The **trusted roots** are `REPO` plus every path in
`ADDITIONAL_REPOS`. Anything outside that set is off-limits to your
reads.

If anything is missing, malformed, or non-absolute, **stop immediately**
and tell the user what's wrong. Do not invent defaults.

## Phase loading

Phases live in this skill's own `phases/` folder (see Reference Files
above), resolved relative to this `SKILL.md` — not the workspace you're
scanning. Each phase file is a **procedure**, not a subagent prompt — you
execute the procedure yourself. You may dispatch subagents when you judge
they're useful (e.g. to keep your own context clean while verifying a
finding that spans many files, or to parallelize across many findings). For
a typical 1–3 finding run, inline is fine.

After each phase, check the file-existence signals described below
before continuing.

| Phase | File | Synchronization signal |
|---|---|---|
| 0 | `phases/phase0_preflight.md` | Writes `${OUT}/phase0_state.json`. |
| 1 | `phases/phase1_extract.md` | Writes `${OUT}/extracted_findings.md`. |
| 2 | `phases/phase2_verify.md` | Writes one `${OUT}/disposition_VULN-NNN.json` per ID in `FIXED`. |
| 4 | `phases/phase4_emit.md` | Writes `${OUT}/verify_disposition.json`. |

Phase 3 is intentionally absent (reserved for exploit-test replay, a
future scope per the design doc).

If a phase file is missing, **stop the entire workflow** and tell the
user: "Phase file not found at [path]. The skill is not installed
correctly. Run install-copilot.sh from the vulnhunter repository root." Do
not improvise — a missing phase file is fatal.

## Workflow

### Step 0 — Read this skill file once

Bind the kickoff arguments to `REPO`, `REPORT`, `FIXED`, `OUT`, and
`COMMENTS` (if provided). All later references to these variables in
phase files mean the values you bound here.

### Step 1 — Phase 0 (pre-flight)

Read `phases/phase0_preflight.md` and execute it inline. It will:

1. Search `REPO`, `REPORT`, `OUT`, and every path in `ADDITIONAL_REPOS`
   to confirm each exists. If `OUT` does not exist, you cannot create
   it — fail with a clear error. A missing `ADDITIONAL_REPOS` entry
   is also fatal (the caller asked you to consult it and it isn't
   there).
2. Read `REPORT`'s `scan_manifest.json` (or `README.md` fallback) and
   confirm every ID in `FIXED` appears.
3. If `COMMENTS` was provided, evaluate each claim against
   `comment_rules.md`. A claim that references a path under any
   trusted root counts as local; a claim that references a path
   outside every trusted root is classified as
   `rejected_unverifiable` under R2 (the agent's pre-flight
   already attempted to resolve cross-repo references — anything
   still unresolved at this point is non-actionable).
4. Write `${OUT}/phase0_state.json` and continue. Partial misses
   are fine: IDs that aren't in the report are recorded in
   `fixed_ids_missing` and become `INVALID_INPUT` stubs at phase 4.
   Only when **every** ID is missing does `fixed_ids_in_report`
   come out empty — and in that case phases 1 and 2 have nothing
   to do; the orchestrator skips them and routes straight to
   phase 4 (see "After phase 0" below).

**When phase 0 wrote `phase0_state.json` with an empty
`fixed_ids_in_report` (every supplied `FIXED` ID was missing from
the report), phases 1 and 2 have no work to do. Skip them and run
phase 4 directly. Phase 4 will emit `verify_disposition.json`
containing one `INVALID_INPUT` entry per missing ID.**

### Step 2 — Phase 1 (extract findings)

Read `phases/phase1_extract.md` and execute it. It produces
`${OUT}/extracted_findings.md` with one `## VULN-NNN` section per ID
in `fixed_ids_in_report`. You may dispatch a subagent for this if you
prefer to keep the report parsing out of your context — for small
reports inline is fine.

After the file is written, **do not Read it in full**. Phase 2 reads
only one section at a time.

### Step 3 — Phase 2 (per-VULN verification)

Read `phases/phase2_verify.md` once. Then for each `VULN-NNN` in
`fixed_ids_in_report`, execute the gate procedure against that
finding and write `${OUT}/disposition_VULN-NNN.json`.

When the procedure is useful to parallelize (typically when
`fixed_ids_in_report` has more than a few entries, or when individual
findings would crowd your context), dispatch one subagent per VULN in
a single batch — they run in parallel. Each subagent's task description
should include the finding ID, `REPO`, `OUT`, and a pointer to its
`## VULN-NNN` section in `${OUT}/extracted_findings.md`, and tell it
to follow `phases/phase2_verify.md` and write
`${OUT}/disposition_VULN-NNN.json`. When inline is simpler, run the
procedure yourself, one VULN at a time.

**SYNCHRONIZATION BARRIER — mandatory before continuing to Step 4:**

When you dispatched subagents, their tool calls are in-flight. You must
not check for output files or proceed to phase 4 until every subagent
tool-result has been received (i.e., the result content for every
subagent call you issued appears in your context). Do NOT search for
disposition files in the same turn as the subagent dispatch calls — wait
for the tool results first. Only after all subagent tool results have
arrived should you search for the disposition files.

After all subagent tool results have been received, search for
`${OUT}/disposition_*.json`. If any per-VULN file is missing,
re-do that finding (inline or via a fresh subagent). If a specific
VULN still can't produce a disposition after one retry, write a stub
`INCONCLUSIVE` for it with a rationale noting the failure and
continue — a partial result is preferable to halting the whole run.

### Step 4 — Phase 4 (emit final JSON)

Read `phases/phase4_emit.md` and execute it inline. It will:

1. Read `${OUT}/phase0_state.json` for `target_repo` and
   `comments_evaluation`.
2. Read each `${OUT}/disposition_VULN-NNN.json`.
3. Assemble the final document.
4. Write `${OUT}/verify_disposition.json` validated against the shape
   in [verify_disposition.schema.json](./verify_disposition.schema.json)
   (bundled in this skill's own folder).

### Step 5 — Final user-facing message

Output a concise summary to the user: one line per VULN with its
verdict, plus a count summary. Example:

```
Verify complete.

  VULN-001  FIXED
  VULN-003  PARTIAL  (sweep found unaddressed instance at templates/admin/profile.html:9)
  VULN-007  NOT_FIXED  (sink at db/raw.go:42 still uses fmt.Sprintf)

  Summary: 1 FIXED, 1 PARTIAL, 1 NOT_FIXED
  Output:  /work/verify-2026-06-27/verify_disposition.json
```

Do **not** paste the full JSON inline; the user will read the file.

## Operating principles

1. **Code is the source of truth.** Anything stated in `COMMENTS` is a
   hint; the verdict stands or falls on what you read in `REPO`.
2. **No bridging assumptions.** If you can't find the original
   location in `REPO` and search can't find a successor, the gate is
   `skipped` and the verdict is `INCONCLUSIVE` — do not guess.
3. **Fail-closed on schema drift.** Every JSON you write must match
   [verify_disposition.schema.json](./verify_disposition.schema.json).
   If you're unsure whether a field is required, check the schema.
4. **Read-only over the target.** You inspect `REPO`; you do not
   modify it. The same applies to `REPORT` — those artifacts are
   historical record. See **Tool boundary** above for the enforcement caveat.
5. **Be terse in evidence.** Each evidence entry is one sentence
   plus a `file:line` citation. Avoid restating the rationale.

## Stopping rules

- Every ID in `FIXED` was missing from the report → phase 0 records
  them in `fixed_ids_missing` and writes `phase0_state.json` with
  an empty `fixed_ids_in_report`. Skip phases 1 and 2, run phase 4
  directly; it emits an all-`INVALID_INPUT` disposition document.
  Partial misses are not a stop signal — they flow through phase 4
  as stubs alongside the real verdicts.
- Any phase file missing → stop with the installation-error message
  above. Do not improvise.
- All four gates `skipped` for a finding → verdict is `INCONCLUSIVE`,
  not `FIXED`. Absence of contradiction is not evidence of a fix.
