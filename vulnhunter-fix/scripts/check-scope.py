#!/usr/bin/env python3
"""Gate 3 — scope (REQ-GAT-004).

Compares the branch's `git diff` file set against the union of
`files_modified` and the test file path. Any file outside that union
fails the gate. Zero exceptions.

Usage:
    check-scope.py --repo-root <path> --branch <name>
        --files-modified <p1> <p2> ...
        --test-file <path>
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


def _looks_like_ref(value: str) -> bool:
    """Reject values that could be misread as git flags or option arguments."""
    return bool(value) and not value.startswith("-") and ".." not in value.split("..", 1)[0]


def check(args) -> int:
    base_ref = getattr(args, "base_ref", None) or "main"
    if not args.files_modified:
        print(
            "error: --files-modified must be non-empty (REQ-GAT-004 — every fix "
            "must declare which files it modified; a result with empty "
            "files_modified indicates a plan/verify phase bug or a fabricated "
            "result artifact)",
            file=sys.stderr,
        )
        return 1
    if not _looks_like_ref(args.branch):
        print(f"error: --branch value looks like a flag or malformed ref: {args.branch!r}", file=sys.stderr)
        return 2
    if not _looks_like_ref(base_ref):
        print(f"error: --base-ref value looks like a flag or malformed ref: {base_ref!r}", file=sys.stderr)
        return 2
    git = shutil.which("git")
    if git is None:
        print("error: git executable not found on PATH", file=sys.stderr)
        return 2
    try:
        # Inputs are argparse-validated (repo_root is a path, branch + base_ref
        # passed through _looks_like_ref); argv is a list, so no shell
        # interpretation. Three-dot (base...branch) diffs against the MERGE-BASE
        # so files main picked up after the branch forked aren't counted as
        # scope violations (12-seg review S5).
        result = subprocess.run(  # nosec B603
            [git, "-C", args.repo_root, "diff", "--name-only",
             f"{base_ref}...{args.branch}", "--"],
            capture_output=True, text=True, check=True, timeout=60,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
        print(f"error: git diff failed: {exc}", file=sys.stderr)
        return 2

    diff_files = {line.strip() for line in result.stdout.splitlines() if line.strip()}
    allowed = set(args.files_modified or ())
    if args.test_file:
        allowed.add(args.test_file)

    unexpected = diff_files - allowed
    if unexpected:
        for f in sorted(unexpected):
            print(
                f"scope violation: {args.branch} modifies {f!r} which is not in "
                f"files_modified ∪ test_file. Enumerate every touched file in "
                f"result.files_modified per REQ-GAT-004.",
                file=sys.stderr,
            )
        return 1
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Gate 3 scope (REQ-GAT-004).")
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--branch", required=True)
    ap.add_argument("--base-ref", default="main",
                    help="Base ref for the three-dot merge-base diff (default: main).")
    ap.add_argument("--files-modified", nargs="*", default=[], required=True)
    ap.add_argument("--test-file", default=None)
    args = ap.parse_args(argv[1:])
    return check(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
