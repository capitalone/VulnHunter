# Hermes headless validation evidence

This is a sanitized transcript of a real Hermes CLI run against the Hermes-only scope of PR #31. It is intended to make the new harness path independently reproducible without publishing a local session ID, provider credential, username, or machine-specific path.

## Run identity

| Field | Value |
|---|---|
| UTC timestamp | `2026-08-30T12:51:25Z` |
| VulnHunter commit installed | `306b74a03b0c76f5d3cf010a1d4165fe32c5cbef` |
| Hermes version | `0.20.6` |
| Mode | quiet, headless, Phase 1 only |
| Toolsets | `file,delegation` (no terminal execution) |
| Process exit | `0` |
| Delegation trace | 1 Phase 1 dispatch + 35 `action=list` polls |

`~/.hermes/skills/vulnhunt/.installed-from` matched the commit above. `hermes skills list` reported `vulnhunt` as a local, enabled skill.

## Install/render transcript

```text
$ ./install.sh --target hermes
Rendering hermes skill bundle (dist/hermes)...
rendered dist/hermes: 13 files (subs=11 prepends=12 fm=1 overrides=0 drops=0)
Installed vulnhunt
Installed for target: hermes
```

The rendered `SKILL.md` contained the Hermes metadata/toolset declaration and the Hermes vocabulary/delegation overlay.

## Synthetic fixture

The run used a deliberately tiny Flask application with two production inputs and two obvious sinks:

```python
@app.get("/read")
def read_file():
    filename = request.args.get("filename", "notes.txt")
    with open(os.path.join("/tmp/uploads", filename), encoding="utf-8") as handle:
        return handle.read()


@app.post("/diagnose")
def diagnose():
    host = request.form.get("host", "localhost")
    completed = subprocess.run(
        f"ping -c 1 {host}",
        shell=True,
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.stdout
```

A separate `tests/test_fixture.py` contained a test-only `request.args.get("not_production")` source that the production inventory had to exclude.

## Headless invocation

Paths are replaced with `<fixture>` below; the run used the checked-in rendered skill from the commit above.

```text
$ cd <fixture>
$ hermes chat -Q -s vulnhunt -t file,delegation -q \
  "Adapter validation run only. Execute Phase 1 reconnaissance from the \
   loaded vulnhunt skill against this repository; stop before Phase 2. \
   Treat <fixture>/HERMES_SMOKE_RESULTS as the pre-resolved output directory. \
   File search/read and output writes are allowed; shell execution is not. \
   Follow the Hermes delegation wait protocol and write phase1_output.md."
```

Sanitized final response:

```text
Phase 1 complete and verified.

Artifact: <fixture>/HERMES_SMOKE_RESULTS/phase1_output.md

It inventories both production inputs, identifies filesystem-read and
shell-command sinks, excludes tests/, and records the requested model tag.
Phase 2 was not started.
```

The omitted final line was the local Hermes session ID.

A secret-redacted export of the local session trace recorded 54 tool calls.
It included one `delegate_task` Phase 1 dispatch followed by 35
`delegate_task {"action":"list"}` calls before the final response. This
confirms that the Hermes-specific keep-the-turn-alive wait protocol was
executed rather than merely present in the prompt.

## Artifact verification

The generated report was 7,490 bytes and contained:

```text
Input Inventory: 2 inputs across 2 entry points

Filesystem open/read via open(os.path.join(...))
  app.py:14-15 — GET /read, input #1 (filename)

Shell command execution via subprocess.run with shell=True
  app.py:21-27 — POST /diagnose, input #2 (host)

Production analysis includes app.py only.
The entire tests/ tree was excluded from source, sink, input, and
entry-point inventories.

Partition coverage: app.py — PASS (covered by SG-1)
```

The report also included the required structural overview, sink inventory, complete input table, entry-point coverage, indirect-dispatch check, application call graph, shared-infrastructure catalog, subgraph partition, authentication/authorization audit, threat model, trust boundaries, and build-time source-swapping check.

## What this proves

This bounded run exercises the new Hermes-specific integration points rather than only testing string rendering:

1. the adapter renders and installs from the PR commit;
2. Hermes discovers and preloads the skill by name;
3. the adapted tool vocabulary works without a shell toolset;
4. the headless `-Q -s vulnhunt` contract exits successfully;
5. delegated work follows the wait-to-completion protocol (confirmed from
   the redacted session trace);
6. Hermes writes a methodology-conformant result artifact; and
7. the artifact inventories all planted production inputs/sinks while excluding test code.

It does **not** claim full-scan or benchmark parity. That remains explicitly experimental and is why this validation stops at a bounded Phase 1 fixture.

## Claude Code reference evidence

Claude Code is not a new adapter in this PR: `adapters/claude-code` is the identity transform and the production entry point retains the existing module-level `run_vulnhunt` path. The validation host did not have a Claude CLI available, so no new live Claude screenshot is claimed.

The unchanged reference path is protected by:

```text
python3 -m unittest discover -s tests -v
  TestClaudeCodeIdentity.test_byte_identical_to_sources ... ok

vulnhunter-agent test suite
  1 snapshot passed
  1,149 passed

harness test suite
  182 passed
```

The harness tests retain the historical Claude argv snapshot and the renderer checks every Claude skill file byte-for-byte against its repository source.
