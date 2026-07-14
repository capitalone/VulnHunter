#!/usr/bin/env python3
"""Worktree reset before repair-loop retry (REQ-GAT-009 / REQ-GAT-010).

Hard-resets a worker's worktree to the branch baseline, logs the event
to `.work/<repo>/retry_log.jsonl`, and never touches the manifest,
graph sidecar, or result history.

Usage:
    worktree-reset.py --worktree <path> --branch-baseline <sha>
        --vuln-id VULN-NNN --retry-number N --reason <text>
        [--repo-work-root <path>]
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


PROTECTED_PATTERNS = ("manifest.json", "graph_context/", "result_history/")


def _git_bin() -> str | None:
    """Resolve git's absolute path once; None if git is missing."""
    return shutil.which("git")


def _git(cwd: str, *args: str, timeout: float = 120.0) -> subprocess.CompletedProcess:
    git = _git_bin()
    if git is None:
        raise FileNotFoundError("git executable not found on PATH")
    # argv is a list, no shell interpretation; cwd + args are validated
    # by callers via _looks_like_sha_or_ref and Path checks. Timeout guards
    # against a hung fetch/clean wedging the whole executor between retries.
    try:
        return subprocess.run(  # nosec B603
            [git, "-C", cwd, *args],
            capture_output=True, text=True, check=False, timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        # Fabricate a CompletedProcess-shaped return so callers can inspect
        # returncode uniformly. rc=-1 is our convention for timeout.
        return subprocess.CompletedProcess(
            args=[git, "-C", cwd, *args], returncode=-1,
            stdout=(exc.stdout or "") if isinstance(exc.stdout, str) else "",
            stderr=((exc.stderr or "") if isinstance(exc.stderr, str) else "") + f"\ntimeout after {timeout}s",
        )


def _looks_like_sha_or_ref(value: str) -> bool:
    """Reject values that would be misread as flags by git."""
    return bool(value) and not value.startswith("-")


def _unsafe_worktree_reason(worktree: Path) -> str | None:
    """Return why `worktree` is unsafe to reset, or None if it is a linked
    worktree root.

    `git -C <path>` walks UP to the enclosing `.git`, so pointing reset at a
    subdir — or at the main checkout — hard-resets the enclosing/primary repo
    and destroys committed + uncommitted work (12-seg review S11). Refuse
    anything that is not the ROOT of a LINKED worktree.
    """
    top = _git(str(worktree), "rev-parse", "--show-toplevel")
    if top.returncode != 0:
        return f"{worktree} is not inside a git work tree"
    if Path(top.stdout.strip()).resolve() != worktree.resolve():
        return (f"{worktree} is not a git worktree root (toplevel is "
                f"{top.stdout.strip()}) — reset would walk up to the enclosing repo")
    git_dir = _git(str(worktree), "rev-parse", "--git-dir")
    common = _git(str(worktree), "rev-parse", "--git-common-dir")
    if git_dir.returncode == 0 and common.returncode == 0:
        def _abs(p: str) -> Path:
            path = Path(p)
            return path.resolve() if path.is_absolute() else (worktree / path).resolve()
        # In the MAIN worktree, --git-dir and --git-common-dir are the same
        # `.git`; in a linked worktree they differ (.git/worktrees/<name> vs .git).
        if _abs(git_dir.stdout.strip()) == _abs(common.stdout.strip()):
            return (f"{worktree} is the MAIN worktree, not a linked worktree — "
                    f"reset would destroy the primary checkout")
    return None


def reset(args) -> int:
    worktree = Path(args.worktree)
    if not worktree.is_dir():
        print(f"error: not a directory: {worktree}", file=sys.stderr)
        return 2
    if not _looks_like_sha_or_ref(args.branch_baseline):
        print(f"error: --branch-baseline looks like a flag: {args.branch_baseline!r}", file=sys.stderr)
        return 2

    unsafe = _unsafe_worktree_reason(worktree)
    if unsafe:
        print(f"error: refusing reset — {unsafe}", file=sys.stderr)
        return 2

    status = _git(str(worktree), "status", "--porcelain=v1")
    dirty_files = [line[3:] for line in status.stdout.splitlines() if line.strip()]

    # Hard reset + clean, scoped to the worktree. `--` ends option parsing.
    r = _git(str(worktree), "reset", "--hard", args.branch_baseline, "--")
    if r.returncode != 0:
        print(f"error: git reset failed: {r.stderr}", file=sys.stderr)
        return 2

    # Protected paths are excluded from clean. `git clean` expects
    # `--exclude=<pattern>`, not `-e=<pattern>`. A clean failure leaves the
    # worktree on contaminated state, so it must fail loud — not warn-and-pass
    # (12-seg review S11 MEDIUM).
    clean_cmd = ["clean", "-fdx"] + [f"--exclude={p}" for p in PROTECTED_PATTERNS]
    r = _git(str(worktree), *clean_cmd)
    if r.returncode != 0:
        print(f"error: git clean failed ({r.returncode}): {r.stderr}", file=sys.stderr)
        return 2

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "vuln_id": args.vuln_id,
        "retry": args.retry_number,
        "worktree": str(worktree),
        "branch_baseline": args.branch_baseline,
        "reason": args.reason,
        "aborted_files": dirty_files,
    }

    log_root = Path(args.repo_work_root or worktree.parent)
    log_path = log_root / "retry_log.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    print(json.dumps({"status": "ok", "reset_to": args.branch_baseline, "aborted_files": len(dirty_files), "log": str(log_path)}))
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Worktree reset (REQ-GAT-009/010).")
    ap.add_argument("--worktree", required=True)
    ap.add_argument("--branch-baseline", required=True)
    ap.add_argument("--vuln-id", required=True)
    ap.add_argument("--retry-number", type=int, required=True)
    ap.add_argument("--reason", required=True)
    ap.add_argument("--repo-work-root", default=None)
    args = ap.parse_args(argv[1:])
    return reset(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
