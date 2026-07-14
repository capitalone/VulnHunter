#!/usr/bin/env python3
"""Gate orchestrator (REQ-GAT-011).

Loads state (PR body, issue body, result.json, triage sidecar), computes
per-gate CLI arguments via the GATE_ROUTING table, and invokes each gate
script registered there. Individual scripts remain stateless — they
receive all context via CLI flags.

Adding a new gate requires ONE change: add an entry to GATE_ROUTING with
its script, a callable that builds its CLI args from the shared context,
and a list of body-scope invocations (which bodies to run it against).

Usage:
    run-gates.py --pr-body <path> [--issue-body <path>] --result <path>
                 --sidecar <path> --branch <name> --repo-root <path>
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"


@dataclass
class GateContext:
    """Shared inputs the orchestrator gathers once and hands to each builder."""
    pr_body: Path
    issue_body: Path | None
    result: dict
    sidecar: dict
    branch: str
    repo_root: Path
    result_path: Path | None = None
    sidecars_dir: Path | None = None
    default_branch: str | None = None


# ---- CLI arg builders (REQ-GAT-011). Each builder returns the FULL argv for
# one invocation of the gate's script. Order in GATE_ROUTING determines run
# order; each entry may emit multiple invocations (e.g., Gate 2 runs once per
# body scope).

def _build_gate1_invocations(ctx: GateContext) -> list[list[str]]:
    bodies = [str(ctx.pr_body)]
    if ctx.issue_body:
        bodies.append(str(ctx.issue_body))
    return [bodies]


def _build_gate2_invocations(ctx: GateContext) -> list[list[str]]:
    tier = ctx.result.get("completeness_tier") or "FULL"
    status = ctx.result.get("status") or "VERIFIED"
    sweep_ran = "true" if ctx.result.get("sweep_ran") else "false"
    # `(grep_fallback)` annotation is enforced precisely in column 7 by
    # validate-verification.py; a body-wide enforce-strings check here would
    # be redundant and trivially bypassable (any occurrence in a code block
    # would satisfy it). Only status-driven section presence needs a hint.
    enforce: list[str] = []
    if status == "BREAKING_CHANGE":
        enforce.append("## Breaking Change")

    def _args_for(body: Path, kind: str) -> list[str]:
        args = ["--body", str(body), "--kind", kind,
                "--tier", tier, "--status", status, "--sweep-ran", sweep_ran]
        if enforce:
            args += ["--enforce-strings", *enforce]
        return args

    invocations = [_args_for(ctx.pr_body, "pr")]
    if ctx.issue_body:
        invocations.append(_args_for(ctx.issue_body, "issue"))
    return invocations


def _build_gate3_invocations(ctx: GateContext) -> list[list[str]]:
    files = ctx.result.get("files_modified") or []
    test_file = ctx.result.get("test_file")
    args = ["--repo-root", str(ctx.repo_root), "--branch", ctx.branch,
            "--files-modified", *files]
    if test_file:
        args += ["--test-file", test_file]
    return [args]


def _build_gate4_invocations(ctx: GateContext) -> list[list[str]]:
    invocations = [["--body", str(ctx.pr_body), "--kind", "pr"]]
    if ctx.issue_body:
        invocations.append(["--body", str(ctx.issue_body), "--kind", "issue"])
    return invocations


def _build_gate5_invocations(ctx: GateContext) -> list[list[str]]:
    """Gate 5 — anti-merge (REQ-GAT-006 in --strict mode).

    Reads the grouping counts from the sidecar's anti_merge block, which
    Phase 2 (Plan) writes when finalizing groups. If the sidecar lacks
    the block, the gate is a no-op (single-finding PRs don't trigger it).
    """
    anti_merge = (ctx.sidecar or {}).get("anti_merge") or {}
    if not anti_merge or "files_grouped" not in anti_merge:
        return []  # no-op — no grouping decision recorded
    args = [
        "--files-grouped", str(anti_merge["files_grouped"]),
        "--files-split", str(anti_merge.get("files_split", 1)),
        "--strict",
    ]
    if "test_files_grouped" in anti_merge:
        args += ["--test-files-grouped", str(anti_merge["test_files_grouped"])]
    if "test_files_split" in anti_merge:
        args += ["--test-files-split", str(anti_merge["test_files_split"])]
    return [args]


def _build_gate6_invocations(ctx: GateContext) -> list[list[str]]:
    """Gate 6 — verification-table validation (REQ-GRA-011..014, REQ-GRA-020).

    Runs `validate-verification.py` on the PR body with the sidecar dir +
    result path so the column-7 caller-coverage check actually fires. The
    validator fails closed on any 'yes' column-7 cell it cannot verify
    against a sidecar — so a fabricated coverage cell is rejected even when
    no sidecars-dir is available.
    """
    args = [str(ctx.pr_body), "--worktree", str(ctx.repo_root)]
    if ctx.sidecars_dir:
        args += ["--sidecars-dir", str(ctx.sidecars_dir)]
    if ctx.result_path:
        args += ["--result", str(ctx.result_path)]
    return [args]


def _build_gate7_invocations(ctx: GateContext) -> list[list[str]]:
    """Gate 7 — committed test-naming (REQ-GAT-013).

    Fails closed if a `verify_VULN*`/`exploit_VULN*` scaffold was committed on
    the branch instead of being promoted to a discoverable, repo-convention
    test name. A committed `verify_` scaffold is invisible to the repo's test
    runner, so the fix ships with zero coverage from its own security test.

    Passes the delivery base branch through as `--base` so the gate diffs the
    whole branch (`base...HEAD`) rather than degrading to a HEAD-only scan that
    misses scaffolds committed in earlier commits of a multi-finding cluster PR.
    When the base isn't known here, the gate auto-detects the repo's default
    branch and warns if it must fall back.
    """
    args = ["--repo-root", str(ctx.repo_root)]
    if ctx.default_branch:
        args += ["--base", ctx.default_branch]
    return [args]


# REQ-GAT-011: single source of truth for gate dispatch. Adding a new gate
# means adding one entry here — no changes to main().
GATE_ROUTING: dict[str, dict] = {
    "gate1_severity_mask": {
        "script": SCRIPTS / "check-severity-mask.py",
        "build_invocations": _build_gate1_invocations,
        "positional": True,   # invocation returns a positional list, not flags
    },
    "gate2_body_completeness": {
        "script": SCRIPTS / "check-body-completeness.py",
        "build_invocations": _build_gate2_invocations,
    },
    "gate3_scope": {
        "script": SCRIPTS / "check-scope.py",
        "build_invocations": _build_gate3_invocations,
    },
    "gate4_idempotency": {
        "script": SCRIPTS / "check-idempotency.py",
        "build_invocations": _build_gate4_invocations,
    },
    "gate5_anti_merge": {
        "script": SCRIPTS / "anti-merge-check.py",
        "build_invocations": _build_gate5_invocations,
    },
    "gate6_verification_table": {
        "script": SCRIPTS / "validate-verification.py",
        "build_invocations": _build_gate6_invocations,
    },
    "gate7_committed_test_naming": {
        "script": SCRIPTS / "check-committed-test-naming.py",
        "build_invocations": _build_gate7_invocations,
    },
}


class GateInputError(Exception):
    """A required orchestrator input could not be loaded.

    Raised only in strict mode. Non-strict callers (the optional --sidecar)
    still get {} on missing/corrupt input.
    """


# REQ-GAT-011: gates that MUST contribute at least one invocation. Gate 5
# (anti-merge) is intentionally omitted — it is a no-op for single-finding
# PRs (no grouping decision recorded). If any of these emits zero
# invocations, routing has drifted and the run fails closed rather than
# vacuously passing over the empty set (synthesized review S5, B1).
REQUIRED_GATES: tuple[str, ...] = (
    "gate1_severity_mask",
    "gate2_body_completeness",
    "gate3_scope",
    "gate4_idempotency",
    "gate6_verification_table",
    "gate7_committed_test_naming",
)


def _load_json(path: Path | None, *, strict: bool = False) -> dict:
    if not path or not path.is_file():
        if strict:
            raise GateInputError(f"required input not found: {path}")
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        if strict:
            raise GateInputError(f"required input failed to load ({path}): {exc}") from exc
        return {}


def _run(cmd: list[str], timeout: float = 60.0) -> tuple[int, str, str]:
    # cmd is built by GATE_ROUTING from a trusted rule table; first element
    # is sys.executable (bundled venv Python), remaining resolve to a script
    # under SCRIPTS/. Any user input is argparse-validated inside the gate
    # scripts. Timeout guards against a hung gate wedging the whole run.
    try:
        proc = subprocess.run(  # nosec B603
            cmd, capture_output=True, text=True, check=False, timeout=timeout
        )
    except subprocess.TimeoutExpired as exc:
        return -1, exc.stdout or "", (exc.stderr or "") + f"\ntimeout after {timeout}s"
    return proc.returncode, proc.stdout, proc.stderr


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Gate orchestrator (REQ-GAT-011).")
    ap.add_argument("--pr-body", required=True)
    ap.add_argument("--issue-body", default=None)
    ap.add_argument("--result", required=True)
    ap.add_argument("--sidecar", default=None)
    ap.add_argument("--sidecars-dir", default=None,
                    help="Directory of per-VULN triage sidecars (VULN-NNN.json) "
                         "for Gate 6 caller-coverage verification.")
    ap.add_argument("--branch", required=True)
    ap.add_argument("--default-branch", default=None,
                    help="Target repo's base/default branch (e.g. main, master) "
                         "so Gate 7 can diff the whole branch (base...HEAD) "
                         "instead of degrading to a HEAD-only scan.")
    ap.add_argument("--repo-root", required=True)
    args = ap.parse_args(argv[1:])

    # --result is the fail-closed anchor: it drives Gate 2's required-section
    # set (tier/status). A missing/corrupt result MUST halt, not silently
    # default to tier=FULL/status=VERIFIED — the weakest set (synthesized
    # review S5, B2). --sidecar stays best-effort ({} is legitimate).
    try:
        result = _load_json(Path(args.result), strict=True)
    except GateInputError as exc:
        print(json.dumps({"pass": False, "error": str(exc)}, indent=2))
        print(f"run-gates: {exc}", file=sys.stderr)
        return 2

    ctx = GateContext(
        pr_body=Path(args.pr_body),
        issue_body=Path(args.issue_body) if args.issue_body else None,
        result=result,
        sidecar=_load_json(Path(args.sidecar)) if args.sidecar else {},
        branch=args.branch,
        repo_root=Path(args.repo_root),
        result_path=Path(args.result),
        sidecars_dir=Path(args.sidecars_dir) if args.sidecars_dir else None,
        default_branch=args.default_branch,
    )

    outcomes: dict[str, dict] = {}
    for gate_name, spec in GATE_ROUTING.items():
        script = spec["script"]
        invocations = spec["build_invocations"](ctx)
        for idx, argv_tail in enumerate(invocations):
            # sys.executable is the bundled-venv Python (parent re-exec'd
            # through _skill_bootstrap); "python3" on PATH would bypass
            # the venv and lose jsonschema/graphifyy.
            rc, stdout, stderr = _run([sys.executable, str(script), *argv_tail])
            key = gate_name if len(invocations) == 1 else f"{gate_name}_{idx}"
            outcomes[key] = {"rc": rc, "stderr": stderr, "args": argv_tail}

    # Fail closed if a required gate contributed zero invocations (routing
    # drift or a builder regressing to []). Without this, all() over the
    # surviving outcomes — or over an empty dict — vacuously passes (B1).
    missing = [
        g for g in REQUIRED_GATES
        if not any(k == g or k.startswith(g + "_") for k in outcomes)
    ]
    if missing:
        print(json.dumps({
            "pass": False,
            "error": f"required gates contributed no invocations (routing drift): {missing}",
            "gates": outcomes,
        }, indent=2))
        print(f"run-gates: required gates did not run: {missing}", file=sys.stderr)
        return 1

    all_pass = all(o["rc"] == 0 for o in outcomes.values())
    print(json.dumps({"pass": all_pass, "gates": outcomes}, indent=2))
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
