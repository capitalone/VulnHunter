# Phase 3: Implement Fixes (TDD Approach)

## Mode-aware

The unit of work differs by mode:

- **In-place mode** — one branch per **cluster** (the unit the developer picked in Phase 1). Each finding in the cluster gets its own commit on the same branch, with the same per-finding TDD evidence (exploit demo → RED test → fix → verify exploit blocked → regression check). The cluster's branch lands as ONE cohesive PR. See the **In-place implementation** section below — it replaces the fork-mode setup + per-finding branch model.
- **Fork mode** — one branch per **finding** with strict no-grouping rules (per `plan_fork.md` Steps 3-4). Use the **Fork-mode implementation** section.

If you can't tell which mode you're in, check for `.vulnhunter-fix/work.json` — in-place mode created it in Phase 1.

## In-place implementation

### Inputs

- `.vulnhunter-fix/work.json` — finding ↔ issue join + cluster info
- Plan from Phase 2 (sequencing of findings within the cluster)
- CWD = target repo working tree (no clone, no `TARGET_REPO`)

### Pre-implementation setup (per cluster)

**IP-Step 1: Create the cluster's worktree + branch.**

One worktree per cluster, on a single branch named `vulnfix/<cluster-slug>` (the slug is the cluster name lowercased, spaces → dashes, special chars stripped). All findings in the cluster get committed to this same branch.

```bash
CLUSTER_KEY="<short stable id for the cluster, e.g., first 16 hex chars of sha256(cluster_name)>"
CLUSTER_SLUG="<lowercased dash-separated cluster name, e.g., 'authorization-checks'>"

bash "${SKILL_DIR}/scripts/setup_worktree.sh" "$CLUSTER_KEY" "$CLUSTER_SLUG"
# Returns JSON: { "path": "<project>/.vulnhunter-fix/worktrees/<CLUSTER_KEY>", "branch": "vulnfix/<CLUSTER_SLUG>", ... }

WT_PATH="<project_root>/.vulnhunter-fix/worktrees/$CLUSTER_KEY"
cd "$WT_PATH"
```

Do NOT use the masked `fix/code-quality-*` naming. That's fork-mode-only (REQ-SEC-002/003). In in-place mode the user already sees the actual finding titles on their own GitHub issues, so masking serves no purpose and the cluster-named branch is what the PR reviewer will read.

### Per-finding loop (all on the cluster's branch)

For EACH finding in the cluster, in the order Phase 2 sequenced them, perform Steps A-H below. **Do not create a new branch per finding.** Each finding produces one commit on the cluster's branch.

#### IP-Step A: Exploit demonstration (local only — never committed)

Write a standalone script that proves the vulnerability is exploitable. **Place it in `$TMPDIR/vulnfix-exploits/exploit_VULN_NNN.{ext}`** so it never lands inside the target repo's tree, never trips git's tracking, and is auto-cleaned on reboot. Do NOT use `security_tests/` under the project root — that path was a fork-mode artifact.

Requirements same as fork mode: self-contained, demonstrates the attacker capability, produces clear pass/fail output.

#### IP-Step B: Patchability check

**Read the fork-mode rules below for the "what does 'not auto-patchable' mean" definition. But in in-place mode you NEVER mark a finding `CANNOT_AUTO_FIX` or `BREAKING_CHANGE` as a terminal state.** Those classifications are fork-mode-only routing labels. In in-place mode they are *triggers* for the **Interactive collaboration loop** further down — not endpoints.

If any of the fork-mode "not auto-patchable" criteria apply (missing upstream lib API, ambiguous remediation, breaking change for callers, regression suite blocker, cross-repo coordination), enter the collaboration loop. The developer at the console resolves the blocker (picks an option, provides a contract, accepts a breaking change, etc.). The cluster's branch absorbs whatever they choose. Do not propose deferring the finding to a follow-up PR or describing it as "scaffolding only" — that contradicts the contract Phase 1 sold the developer when they picked the cluster. Phase 2's in-place section also explicitly forbids such framing; if you're tempted to use it, re-read `plan.md`'s in-place section banner.

#### IP-Step C: Security test (RED → FAIL)

Same requirements as fork mode:
- Use the project's existing test framework + test dir.
- Write in the project's language.
- Import + call the actual production function/class.
- Name: write it under a **transient** scaffold name `verify_VULN_NNN_<description>.{ext}` for the RED→GREEN cycle only. If the project's test dir isn't `tests/`, use that one — e.g., `src/test/java/`, `spec/`, `__tests__/`.
- **Also decide its final committed name now**, following the repo's discoverable test convention (`test_<behavior>.py`, `<module>.security.test.ts`, `*_test.go`, `*Test.java`, etc.) so the repo's own runner collects it and it counts toward coverage. You will rename `verify_…` → the final name at commit (IP-Step H); the `verify_` scaffold is **never committed**.

Run the test; confirm it fails.

#### IP-Step D: Fix implementation (GREEN)

Apply the fix per the finding's `proposed_fix.strategy`. Same placeholder check + interface-breaking-change check as fork mode — but on a breaking change, enter the **Interactive collaboration loop** instead of routing to issue-only. The developer decides whether to accept the break, add a compat shim, or split callers; the resulting fix still lands on the cluster's branch.

If the fix modifies a dependency manifest, also run the **dep-class checks** in fork Step D.3 below. In-place-mode caveat: surface every hit from D.3.a and D.3.b to the developer via the Interactive collaboration loop (`AskUserQuestion` per hit), not a `notes` field — the developer's picks either land in this same commit or become follow-up items. Do NOT auto-bump anything the developer didn't explicitly approve; auto-fixing companion packages violates the CANNOT_AUTO_FIX contract that says the developer, not the skill, decides how far the fix extends.

#### IP-Step E: Verify exploit is blocked

Re-run the exploit from `$TMPDIR/vulnfix-exploits/`. Then delete the exploit file:

```bash
rm "$TMPDIR/vulnfix-exploits/exploit_VULN_NNN."*
rmdir "$TMPDIR/vulnfix-exploits" 2>/dev/null || true
```

The exploit never enters the repo, so there's no `git rm`; just delete the temp file.

#### IP-Step E.5: Record discrimination evidence (REQ-GRA-017)

Same as fork **Step E.5** — before IP-Step F, record `stash-and-run` discrimination evidence to `.vulnhunter-fix/discrimination/<vuln>.json`. Non-discriminating (pre ≠ fail or post ≠ pass) → return to IP-Step C.

#### IP-Step F: Regression check

Same policy-aware regression suite invocation as fork mode (`--test-policy=best-effort` default).

#### IP-Step G: Pre-commit scope check

`git diff --name-only` — every modified file must be attributable to **this specific finding** (test + fix files, plus any in-cluster shared helper that earlier findings in the same cluster set up). If files unrelated to *any* finding in the cluster appear, stash or revert.

#### IP-Step G.5: Pre-existing test updates (REQ-GRA-018)

Same as fork **Step G.5** — before IP-Step H, update any pre-existing test that encoded the vulnerable behavior (with `# Updated for VULN-NNN`) and record to `.vulnhunter-fix/preexisting_test_updates/<vuln>.json`. Over-scoped regressions → return to IP-Step D.

#### IP-Step H: Commit (per finding)

**Promote the scaffold first.** The transient `verify_VULN_NNN_*` scaffold must become a discoverable, repo-convention test before commit so it counts toward coverage. Two promotion paths are equally acceptable — the delivery gate `check-committed-test-naming.py` enforces only the invariant that **no `verify_`/`exploit_` scaffold is committed**:
- **Preferred when a canonical test file exists** for the fixed module: move the scaffold's assertions into it (add a `describe`/test block) and delete the scaffold — same as `worker_agent_common.md` Step G.
- **Otherwise:** rename the scaffold to its own repo-convention file (chosen in IP-Step C) via `git mv`.

Never `git add` a `verify_`-prefixed file.

```bash
# <repo-convention-test-path> = the repo's own test convention (references/repo-type-adapters.md):
#   test_*.py · *.test.ts · *_test.go · <Class>Test.java  (Go/Java: rename the symbol, not just the file)
git mv tests/verify_VULN_NNN_*.{ext} <repo-convention-test-path>   # promote to the repo's convention
git add <repo-convention-test-path>       # the committed security test
git add <fixed_source_files>              # the fix
git commit -m "$(cat <<'EOF'
fix(security): VULN-NNN short description

Remediate CWE-XXX: description

- Added security test defining correct behavior (repo-convention test file)
- Applied fix: [strategy summary]

Validated: test was RED (vulnerable), now GREEN (secure)

VulnHunter-Finding: VULN-NNN
Co-Authored-By: Claude Code (VulnFix)
EOF
)"
```

Severity masking (REQ-SEC-001): write `High+` instead of `Critical` in commit messages.

### After all findings in the cluster commit

The cluster's branch now has N commits — one per finding, each with its own TDD evidence. Phase 4 verifies the whole branch (each test still passes, no regressions); Phase 5 opens ONE PR with all of them.

If a finding triggered the **Interactive collaboration loop** (next section) and the developer walked away mid-cluster, the worktree stays in place — partial commits already on the branch are preserved, and the next `/vulnhunter-fix` run can resume at the next un-fixed finding in the cluster.

## Fork-mode implementation

### Inputs

- Confirmed remediation plan from Phase 2 (strict per-finding grouping)
- Target repo URL
- Config from `config.json`

> **Read the "`git` + `gh` failure policy" section of `SKILL.md` before continuing.** All `git clone`, `gh repo fork`, `git push`, and `gh pr create` calls below follow the same rule: STOP on `tls: failed to verify certificate`, `OSStatus -…`, sandbox copy denials, or any unexpected non-zero exit. Do not retry, do not substitute tools.

## Pre-Implementation Setup

**Step 1: Check repo access.**
```bash
bash scripts/check_repo_access.sh "$TARGET_REPO"
```

If exit code 1 (no push access):
- If `auto_fork_on_no_access` is true: proceed with fork
- Otherwise: skip to Phase 5 (issue fallback)

**Step 2: Clone the target repo.**
```bash
bash scripts/clone_repo.sh "$TARGET_REPO" ".work/clone" [--fork]
```

**Step 3: Navigate into the clone.**
```bash
cd ".work/clone"
```

## Per-Finding Implementation (TDD Gate)

For EACH finding in the plan, perform all steps below on a fresh branch.
**One branch per finding — never combine findings with different root causes on the same branch.**

### Branch Creation

Use the masked naming pattern per REQ-SEC-002/003: `fix/code-quality-<descriptor>-<idempotency-hash-prefix>`. The descriptor is a generalized remediation category (`input-validation`, `crypto-handling`, `auth-handling`, `access-control`, `memory-handling`, `credential-handling`, `concurrency-handling`, `information-handling`, `network-handling`, `configuration-handling`, or `general-hardening` as fallback). Compute via:

```python
from vulnhunter_fix.delivery import compute_idempotency_key, compute_masked_branch_name
key = compute_idempotency_key(location, cwe, root_cause)
branch_name = compute_masked_branch_name(cwe, key)
```

```bash
git checkout main
git checkout -b "$branch_name"   # e.g. fix/code-quality-input-validation-39262cf0
```

Do NOT include the VULN ID, the CWE number, or any specific vulnerability hint in the branch name.

### Step A: Exploit Demonstration (local only — NOT committed)

Write a standalone script that PROVES the vulnerability is exploitable. This is for local verification only — it will be run, then deleted. It is never staged or committed.

Requirements:
- Self-contained and runnable
- Demonstrates the ATTACKER'S capability, not just that bad code exists
- Produces clear output showing the exploit succeeded

<!-- SYNC:implement.md:exploit-path:start -->
- Place temporarily at `$TMPDIR/vulnfix-exploits/exploit_VULN_NNN.{ext}` (will be deleted after Step D). Do NOT use `security_tests/` under the project root — that path was a fork-mode artifact.
<!-- SYNC:implement.md:exploit-path:end -->

Example for SQL injection:
```python
"""Exploit demo: VULN-001 SQL Injection in user lookup."""
from app.db import get_user  # import the vulnerable function

malicious_input = "admin' OR '1'='1' --"
result = get_user(malicious_input)
print(f"Exploit result: Got {len(result)} records (should be 0 or 1)")
print("EXPLOITABLE: Attacker can extract arbitrary data")
```

### Step B: Patchability Check

Before writing any fix, determine whether the proposed fix is actually implementable from the code alone.

A fix is **NOT auto-patchable** if it requires:
- External values that cannot be derived from the code (e.g., `$expectedHash`, secret keys, checksums from an external system)
- Coordination with another service or repository before the fix is effective (both sides must change simultaneously)
- Post-merge manual steps by the developer to become effective (e.g., provisioning new infrastructure, rotating keys)

If the fix is NOT auto-patchable:
- Do NOT write a partial or fake fix
- Mark this finding as `CANNOT_AUTO_FIX`
- Document exactly what is missing and why auto-patching is not possible
- Skip to Phase 5 to open a high-priority issue instead
- The issue body must describe: the vulnerability, what fix is needed, what external dependency blocks automation

### Step C: Security Test (RED → FAIL)

Write a test that defines the CORRECT secure behavior. This test MUST FAIL against the current (vulnerable) code.

Requirements:
- Use the project's **existing test framework** (pytest, jest, junit, go test, etc.)
- Place the test in the **repo's existing test directory** (e.g., `tests/`, `src/test/java/`, `spec/`, `__tests__/`) — NOT in a new `security_tests/` directory
- Write in the **same language as the repo** — if the repo is Python, write Python; if Go, write Go; if Java, write Java
- The test must **import and call the actual production function/class** under fix — not create a standalone demo that reimplements the logic
- If the vulnerable code is not directly importable or testable (e.g., embedded in a script with no module structure), **refactor** it first: extract the logic into a testable function/module in the same PR, then write the test against the refactored code. This refactor goes in `files_modified` but must not change behavior — only structure.
- Name the scaffold `verify_VULN_NNN_{description}.{ext}` within the existing test directory. This is a **transient RED→GREEN scaffold** — decide the test's final committed name now, following the repo's discoverable convention (`test_<behavior>.py`, `<module>.security.test.ts`, `*_test.go`, `*Test.java`, etc.) so the repo's own runner collects it and it counts toward coverage. You rename `verify_…` → the final name at commit (Step H); the `verify_` scaffold is **never committed**.
- The assertion must be specific to the vulnerability class
- The test must assert what SHOULD happen (secure behavior), not what currently happens

Example for SQL injection (Python repo with `tests/` directory):
```python
"""Security test: VULN-001 — user lookup must use parameterized queries."""
import pytest
from app.db import get_user  # actual production function

def test_sql_special_chars_do_not_alter_query():
    """Input with SQL metacharacters must not affect query logic."""
    malicious = "admin' OR '1'='1' --"
    result = get_user(malicious)
    assert result == [] or result is None, (
        f"SQL injection succeeded: got {len(result)} results for malicious input"
    )
```

Run the test to confirm it FAILS:
```bash
# run the scaffold with the repo's test command (references/repo-type-adapters.md); pytest shown as example — expected: FAIL
python3 -m pytest tests/verify_VULN_NNN_*.py -v 2>&1 || true
```

### Step D: Fix Implementation (GREEN)

Apply the fix described in VulnHunter's "Proposed Fix" section:
1. Read the target file(s) identified in the finding
2. Apply the fix using the Edit tool
3. Follow the strategy exactly as described in the report
4. If the strategy is ambiguous, implement the most conservative secure approach

**After writing the fix, scan it for fake or placeholder content:**
- Does it reference undefined variables (e.g., `$expectedHash`, `REPLACE_ME`, `<YOUR_VALUE>`)?
- Does it contain a TODO where actual logic should be?
- Is any required value hardcoded as a placeholder?

If any placeholder is found: revert the fix, mark as `CANNOT_AUTO_FIX`, and route to issue.

**Step D.1: Interface Breaking Change Check**

> **In-place mode**: do NOT mark `BREAKING_CHANGE` as a terminal state. Per the in-place flow (IP-Step B + the Interactive collaboration loop), a breaking change is a *trigger* for the collaboration loop — the developer at the console accepts the break, adds a compat shim, splits callers, or whatever fits. The cluster's branch absorbs the choice. The "Path B — issue only" outcome below is fork-mode only.

**BEFORE applying the fix**, determine if it changes the interface in a way that would require callers to update their code:
- Does it add a new required parameter, header, or request field?
- Does it remove a parameter, field, or method?
- Does it reject input that was previously accepted (tightened validation that breaks valid existing callers)?
- Does it change the auth mechanism, status code semantics, or response shape?

If NO interface change → apply the fix normally and continue.

If YES — search for all callers:
```bash
# In-repo caller search
grep -rn "functionName\|/endpoint/path" --include="*.{ext}" .

# Best-effort external caller search across the org
gh search code "functionName OR /endpoint/path" --owner=<target_org> --language=<lang> -L 20 2>/dev/null || true
```

Decide path based on caller scope:

**Path A — All callers are inside this repo AND can be updated atomically:**
- Apply the fix
- Update every call site in the same commit
- Continue normally (status: VERIFIED on success)

**Path B — Any caller is external, in another repo, or cannot be located:**
- Per policy, this is a **breaking change** that requires human-coordinated migration
- Do NOT apply the fix
- Do NOT create a branch
- Mark as `BREAKING_CHANGE` with structured `breaking_change_details` per `references/result-schema.json` `$defs.breakingChangeDetails`:
  - `interface_change` (string): one-sentence description of old → new
  - `caller_action_required` (string): what external callers must do to migrate
  - `known_callers` (array of strings): best-effort list of caller repos/paths (in-repo + external results from `gh search code`)
  - `final_secure_interface` (string): what the interface looks like post-migration
  - `registration_actions` (string): gateway / allowlist / config changes callers need
- The delivery script will create an **issue only** — no PR — with this content rendered in a "Breaking Change — Caller Action Required" section. The human owner will coordinate the cross-caller migration.

**Step D.2: Cross-Repo Coordination Check**

If the fix requires changes in a second repository to be effective (e.g., both producer and consumer must change the same algorithm/protocol), the fix is **not independently deployable**.

In this case:
- Do NOT apply a one-sided partial fix
- Mark as `CANNOT_AUTO_FIX`
- Open a comprehensive issue describing both sides of the required change, what each service must do, and why the fix requires coordination

**Step D.3: Dep-class checks (dependency-manifest fixes only)**

Fires when the fix modifies a dependency manifest — `package.json` / `package-lock.json`, `pyproject.toml`, `Pipfile` / `Pipfile.lock`, `requirements.txt`, `pom.xml`, `build.gradle`, `Gemfile` / `Gemfile.lock`, `go.mod` / `go.sum`, `Cargo.toml` / `Cargo.lock`. Skip for non-dep fixes.

Two checks below. **Both surface findings; neither auto-bumps.** Auto-bumping additional packages would violate the CANNOT_AUTO_FIX contract — the developer, not the skill, decides how far the fix extends.

**D.3.a: Out-of-manifest pin scan (mandatory).** Many repos pin the same package in 3+ places — `Dockerfile`, CI YAML, helm values, and separate CI tool-version configs. When only the manifest bump lands and other pins drift, CI/synth/deploy fails downstream in a way the manifest-scoped security test can't observe. Motivating case: a real CDK synth failure where `aws-cdk-lib` was bumped to 2.260 in `package.json` but a separate CI tool-version pin (the version the pipeline passes to `npx aws-cdk@<version> synth`) was left at 2.1125; the newer library emitted Cloud Assembly schema v54 that the older CLI couldn't parse. The local `npm test` passed; the pipeline broke.

For the primary package being bumped (`$PKG`), grep the repo for stale pins outside the manifest:

```bash
grep -rnE "${PKG}[@:=[:space:]].*[0-9]+\.[0-9]+" . \
  --include='Dockerfile*' \
  --include='.nvmrc' \
  --include='.tool-versions' \
  --include='.python-version' \
  --include='runtime.txt' \
  --include='*.yml' --include='*.yaml' \
  --include='*.tf' --include='*.tfvars' \
  --include='*.sh' \
  --include='*.env*' \
  --exclude-dir=node_modules --exclude-dir=.git \
  --exclude-dir=.venv --exclude-dir=vendor
```

Also inspect (grep alone doesn't always catch these — reason about the ecosystem):
- Helm chart `values.yaml` / `Chart.yaml` `image:` tags and `version:` fields.
- `.github/workflows/*.yml` — `setup-node with: node-version:`, `setup-python with: python-version:`, `uses: <action>@<ref>`.
- Dockerfile `RUN npm install -g <pkg>@X.Y.Z`, `RUN pip install <pkg>==X.Y.Z`, `RUN apt-get install <pkg>=X.Y.Z`.
- **CI tool-version pins:** on any `aws-cdk-lib` bump, check whether a separate CI/tooling config pins the CDK CLI version (the version the pipeline passes to `npx aws-cdk@<version>`) — such pins are commonly NOT tracked in `package.json` and drift silently.

**If any stale pin is found — in-place mode:** enter the Interactive collaboration loop and present each hit via `AskUserQuestion`. Concrete options per hit:
- `Update <file>:<line> from <old> to <new> in this same commit` (recommended)
- `Update the manifest only; open a follow-up issue for <file>:<line>`
- `Leave <file>:<line> as-is — pin is intentionally decoupled` (developer must justify)

Apply the developer's picks and re-run the security test.

**If any stale pin is found — fork mode:** add each hit to the finding's `notes` field with `file:line` + observed version + recommended version, so the human PR reviewer can act without re-running the scan. Do NOT auto-bump.

**If no hit:** record `out_of_manifest_scan: "clean"` in the fix's evidence trail (task description or PR body). "Scanned, clean" is audit evidence; silence is not.

**D.3.b: Companion-partner check (informational).** Some libraries ship as coordinated packages that must move in lockstep — bumping one in isolation passes local tests but breaks at build/synth/deploy. Read the same manifest and look for known companions at older versions.

| When you bump | Check companion(s) in same manifest |
|---------------|-------------------------------------|
| `aws-cdk-lib` | `aws-cdk` (CLI) |
| `typescript` | `ts-jest`, `ts-node`, `@types/*`, `@typescript-eslint/*` |
| `react` | `react-dom`, `@types/react`, `@types/react-dom` |
| `@babel/core` | every `@babel/preset-*`, `@babel/plugin-*`, `babel-loader` |
| `eslint` | `@typescript-eslint/*`, every `eslint-plugin-*` / `eslint-config-*` |
| `webpack` | `webpack-cli`, every `*-loader` and `webpack-*-plugin` |
| `vue` | `@vue/*`, `vue-template-compiler`, `vue-loader` |
| `@angular/core` | every other `@angular/*` (must match major) |
| `next` | `eslint-config-next` (major must match) |
| `vite` | `@vitejs/*` plugins |
| `jest` | `ts-jest`, `babel-jest`, `@types/jest`, every `jest-*` plugin |
| `django` | `djangorestframework`, `django-*` ecosystem |
| Java BOM bump | every coordinate that inherits from the BOM |
| Go `replace` directive | the replacement target version |

Also look for a project upgrade guide (`UPGRADE_GUIDE.md`, `MIGRATION.md`, `UPGRADING.md`, `docs/upgrade*.md`, `CHANGELOG.md`'s breaking-changes section). If it documents lockstep rules for the package you're bumping, cite them verbatim when surfacing to the developer.

**Handling matches — in-place mode:** include each older companion in the same `AskUserQuestion` round as D.3.a. Per companion:
- `Bump <companion> to <recommended> in this commit alongside <primary>`
- `Skip — <companion> at <observed> is already compatible` (developer confirms per-companion with a reason)
- `Skip — open follow-up issue`

**Handling matches — fork mode:** add to `notes` with observed vs. recommended. No auto-bump.

**If no companion applies:** record `companion_check: "n/a"` (bumped package has no known partner) or `companion_check: "clean"` (partner found but already compatible).

Then run the security test:
```bash
# run the scaffold with the repo's test command (references/repo-type-adapters.md); pytest shown as example
python3 -m pytest tests/verify_VULN_NNN_*.py -v
```

Expected: PASS. If it still fails:
- Commit the current state (fix + test) even if failing
- Phase 4 (Verify & Repair) will handle diagnosis and repair via the verification/fix agent loop

### Step E: Verify exploit is blocked

Re-run the exploit demo from Step A:
```bash
# Run exploit — expected: it should now fail, raise an exception, or return safe results
python3 "$TMPDIR/vulnfix-exploits/exploit_VULN_NNN.py" 2>&1 || true
```

After running, **delete the exploit file** — it must not be committed:
```bash
rm "$TMPDIR/vulnfix-exploits/exploit_VULN_NNN."*
rmdir "$TMPDIR/vulnfix-exploits" 2>/dev/null || true
```

### Step E.5: Record discrimination evidence (REQ-GRA-017) — mandatory

Between Step E and Step F, record how the security test discriminates the fix — do not proceed to Step F until this exists. Preferred method: `stash-and-run` — `git stash` the fix → run the test, expect FAIL → `git stash pop` → run the test, expect PASS; record both outputs verbatim. Emit to `.work/<repo>/discrimination/<vuln>.json` (in-place: `.vulnhunter-fix/discrimination/<vuln>.json`):

```json
{"vuln_id": "VULN-NNN", "method": "stash-and-run", "pre_fix_result": "fail", "post_fix_result": "pass", "assertion_target": "tests/test_authenticate_rejects_forged_token.py:15: assert authenticate(...) is False"}
```

`assertion_target` must name the **final committed** test path (the repo-convention name chosen in Step C), not the `verify_` scaffold — Phase 4 (Verify) locates the committed test from this field.

If `pre_fix_result != "fail"` OR `post_fix_result != "pass"`, the test is non-discriminating (rubric R4 violation) — return to Step C. Method choices + error semantics live in `references/remediation-rigor.md § Phase 3 (Implement) rigor`.

### Step F: Regression check (policy-aware)

Behavior depends on `--test-policy` (default: `best-effort`). Per REQ-INV-005 and REQ-TDD-005/006/007:

- **`best-effort`** (default): Run the existing test suite. Environmental errors (framework not found, missing deps, no test runner) are tolerated; the PR will carry a "Human-in-the-Loop Validation Required" banner. Real test failures still block.
- **`must-pass`**: Run the existing test suite. If it fails or env errors prevent execution, the fix is rejected.
- **`skip`**: Use only when the test environment cannot run at all. Do NOT run the existing test suite. The PR will carry an "Unverified — Manual Test Execution Required" banner. The security test from Step C still runs regardless of policy.

```bash
if [ "$TEST_POLICY" = "skip" ]; then
  echo "Skipping regression suite per --test-policy=skip"
else
  if [ -f "pytest.ini" ] || [ -f "setup.cfg" ] || [ -d "tests" ]; then
    python3 -m pytest --tb=short -q 2>&1 | tail -20
  elif [ -f "package.json" ]; then
    npm test 2>&1 | tail -20
  elif [ -f "go.mod" ]; then
    # Go modules need your corporate Go module proxy + netrc auth or
    # the sandbox call fails on proxy.golang.org. If the module cache
    # is empty, this still fails inside the sandbox — see SKILL.md
    # "Hand-off command templates per language / tool" and ask the
    # user to run `go mod download all` (with the same env vars) in
    # their own terminal first, then re-run.
    GO111MODULE=on \
        GOPROXY=https://<your-go-module-proxy> \
        GOAUTH=netrc \
        go test ./... 2>&1 | tail -20
  fi
fi
```

**If existing tests fail and the failures are caused by this fix** (i.e., they passed on `main` before this branch):
- Attempt to adjust the fix to preserve existing behavior while still passing the security test
- If a backward-compatible adjustment is not possible: **revert the fix**, mark as `CANNOT_AUTO_FIX`, and open a high-priority issue. A fix that breaks the application's happy path must not be merged. (This rule applies under `must-pass` and `best-effort`; under `skip` the regression suite is not run so this gate does not fire.)

**If env errors prevent execution under `best-effort`**: continue to Step G; the delivery script will attach the banner.

### Step G: Pre-commit scope check

Before committing, verify that all modified files are attributable to this single VULN ID. No unrelated changes should be on this branch:
```bash
git diff --name-only main
```

If any file in the diff is unrelated to the finding being fixed, stash or revert those changes before committing.

### Step G.5: Pre-existing test updates (REQ-GRA-018) — mandatory

Between Step G and Step H, run the pre-existing test suite before committing. If any test fails BECAUSE it encoded the vulnerable behavior, update it to the secure outcome (with a `# Updated for VULN-NNN` comment) and record the change in `.work/<repo>/preexisting_test_updates/<vuln>.json` (in-place: `.vulnhunter-fix/preexisting_test_updates/<vuln>.json`). If regressions appear that did NOT encode the vulnerable behavior, the fix is over-scoped — return to Step D.

### Step H: Commit

**Promote the scaffold first.** The transient `verify_VULN_NNN_*` scaffold must become a discoverable, repo-convention test before commit so it counts toward coverage. Two promotion paths are equally acceptable — the delivery gate `check-committed-test-naming.py` enforces only the invariant that **no `verify_`/`exploit_` scaffold is committed**:
- **Preferred when a canonical test file exists** for the fixed module: move the scaffold's assertions into it (add a `describe`/test block) and delete the scaffold — same as `worker_agent_common.md` Step G.
- **Otherwise:** rename the scaffold to its own repo-convention file (chosen in Step C) via `git mv`.

Never `git add` a `verify_`-prefixed file.

Stage only the relevant files (the promoted test and the fix — NOT the exploit, NOT the `verify_` scaffold):
```bash
# <repo-convention-test-path> = the repo's own test convention (references/repo-type-adapters.md):
#   test_*.py · *.test.ts · *_test.go · <Class>Test.java  (Go/Java: rename the symbol, not just the file)
git mv tests/verify_VULN_NNN_*.{ext} <repo-convention-test-path>   # promote to the repo's convention
git add <repo-convention-test-path>       # the committed security test
git add <fixed_source_files>              # the actual fix
# If refactoring was needed to make code testable:
git add <refactored_source_files>
git commit -m "$(cat <<'EOF'
fix(security): VULN-NNN short description

Remediate CWE-XXX: description

- Added security test defining correct behavior (repo-convention test file)
- Applied fix: [strategy summary]

Validated: test was RED (vulnerable), now GREEN (secure)

VulnHunter-Finding: VULN-NNN
Co-Authored-By: Claude Code (VulnFix)
EOF
)"
```

**Severity masking (REQ-SEC-001):** Any "Critical" severity in the commit message must be written as "High+". Do not include the word "Critical" in commit messages, branches, or PR titles. Use "High+" wherever the source finding is Critical severity.

## CANNOT_AUTO_FIX — Interactive collaboration loop (in-place mode)

In-place mode has no Issue-only outcome (canonical statement: `deliver.md § Delivery Triage`). Every finding the developer selected in Phase 1 must end as a Ready PR or Draft PR — a committed fix that has gone RED→GREEN. The skill drives the developer through whatever it takes. The async issue-fallback below is fork mode only.

### When to enter the loop

Enter as soon as you'd otherwise mark a finding `CANNOT_AUTO_FIX` or `BREAKING_CHANGE` for any of these reasons:

- Patchability check failed (missing dependency, framework version mismatch, language feature unavailable)
- Multiple valid remediation approaches and you can't pick without policy input
- Fix would change a public API or break callers in this repo
- Fix needs a config / env var / secret the developer must provide
- Regression suite broke and there's no obvious backward-compatible adjustment
- Cross-repo coordination required and the other repo's contract is unclear

### How the loop works

1. **State the blocker plainly.** Give the developer:
   - Finding ID + one-line title.
   - The specific code/file/test that's stuck.
   - The exact reason automation can't proceed (no hand-waving — name the missing piece).

2. **Offer concrete next moves via `AskUserQuestion`.** Each option must be specific enough that the developer doesn't have to guess what it entails. Examples:
   - For an ambiguous remediation: each candidate fix as one option, with the diff sketch in the description.
   - For a breaking change: "Accept the break (callers update)" vs. "Add backward-compat shim" vs. "Convert to a deprecation flag + dual-write".
   - For a missing dependency: "Vendor a minimal copy" vs. "Add the dependency to the project" vs. "Find an alternative the existing deps support".
   - For a regression: "Update the failing test to the new behavior" vs. "Rework the fix so existing test still passes" vs. "Quarantine the regression test and document why".
   - For cross-repo: "Tell me what the other service exposes / will accept and I'll write the fix to match" — and wait for the developer to gather that info, possibly running their own commands at the console.
   - **Always include "Pause this finding — resume in a future run"** as a fixed option in every round. The developer needs an off-ramp that isn't "walk away from the terminal" — they may need to gather information off-band (talk to another team, wait on a library release, etc.) and come back later. Picking this option freezes the cluster's branch where it is, leaves the source `vulnhunter` issue open, and ends the run cleanly. The next `/vulnhunter-fix` invocation resumes from the same point.
   - **No "Issue-only" option.** Do not offer it. Do not synthesize it. The developer is here to fix things; the skill's job is to make that possible.

3. **Apply the developer's choice and re-run verification.** Don't accumulate "trust me" promises — every collaboration round must end with the security test going RED→GREEN and the exploit demo confirming the vulnerability is blocked, exactly like the auto path.

4. **Loop until GREEN.** No `max_repair_attempts` cap in interactive mode — that cap exists for fork mode to bound automated retries. With a human in the loop, the developer is the one deciding when to keep trying. Each round:
   - Show the developer what changed since the last round and what verification said.
   - Ask the next question with the same `AskUserQuestion` shape, narrowed by what you learned.
   - On `GREEN`: commit. Triage to Ready PR or Draft PR — Draft PR only when the developer's chosen path requires operator setup (new env var, allowlist entry, etc.); the PR body's Setup Required section captures exactly the steps the developer specified.

5. **What if the developer explicitly walks away** (closes the terminal, says "stop"):
   - Do not synthesize an issue on their behalf — they will know they didn't finish and can re-run the skill later. The source `vulnhunter`-labeled issue stays open on GitHub; the partial worktree under `.vulnhunter-fix/worktrees/<cluster_key>/` stays in place so the next run can resume.
   - If the developer needs to pause for off-band work (cross-repo PR, sysadmin help), tell them how to resume: re-run `/vulnhunter-fix` and pick the same finding; the worktree picks up where it left off.

### What this section explicitly is NOT

- Not a chat. Don't ask the developer open-ended "what do you think?" — always present concrete options with concrete consequences. Free-form input via "Other" is fine; open dialog is not.
- Not a license to skip the TDD gate. The security test must still go RED→GREEN every round. The fix the developer chooses still gets committed with the same evidence trail.
- Not a substitute for the issue-fallback in fork mode. It's a *replacement* of it for in-place — the in-place run does not produce Issue-only outcomes.

## CANNOT_AUTO_FIX — Issue Fallback (fork mode only)

This fallback applies only when the skill is running in fork mode. In in-place mode, the interactive collaboration loop above replaces this — there is no Issue-only outcome.

When a finding is marked `CANNOT_AUTO_FIX` (patchability check failed, placeholder detected, cross-repo coordination required, or fix breaks happy path):

1. Delete any partial fix from the branch
2. Delete the branch
3. Proceed to Phase 5 to create a **high-priority GitHub issue** in the fork with:
   - Full finding context (CWE, severity, location, root cause)
   - What the automated fix attempted (if anything)
   - Exactly why automation cannot complete the fix
   - What a human reviewer needs to do to complete it
   - For cross-repo cases: what both sides must change and in what order

## Repeat for each finding on its own branch.


## Worker-class notes (REQ-CWE-003, REQ-CWE-007)

Steps E.5 (discrimination evidence) and G.5 (pre-existing test updates) are inline in the per-finding flow above — mandatory in both modes. The two routing/gate facts below apply to every finding; method choices + error semantics live in `references/remediation-rigor.md § Phase 3 (Implement) rigor`.

**CWE-class routing (REQ-CWE-003).** The plan orchestrator injects the matching worker-class prompt (`worker_agent_authz.md` / `worker_agent_injection.md` / `worker_agent_crypto.md` / `worker_agent_resource.md` / `worker_agent_config.md`); all extend `worker_agent_common.md`.

**Crypto trust-chain gate for FULL (REQ-CWE-007).** Under `worker_agent_crypto.md`, `completeness_tier: FULL` requires all four `plan.crypto_trust_chain` booleans (`algorithm_approved`, `key_source_approved`, `key_rotation_present`, `transport_encrypted`) to be `true`. Any `false` forces `MITIGATION` with a `trust-chain:` residual entry.

