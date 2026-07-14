#!/usr/bin/env python3
"""Committed-test-naming gate (REQ-GAT-013).

The security test is authored under a transient `verify_VULN_NNN_*` scaffold
name during the RED->GREEN cycle (the prefix keeps it out of the repo's
default test collection while the agent iterates). Before commit it MUST be
promoted to a discoverable, repo-convention name (test_*, *.test.ts, *_test.go,
...) so the repo's own runner collects it and it counts toward coverage.

This gate fails closed if that promotion did not happen: any file added on the
branch whose basename is a `verify_VULN*` or `exploit_VULN*` scaffold is a leak.
A committed `verify_` scaffold is invisible to the project's test runner, so the
fix ships with zero coverage from its own security test.

Usage:
    check-committed-test-naming.py --repo-root <path> [--base <ref>]

Exit codes: 0 = clean, 1 = scaffold leak found, 2 = usage / git error.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

# Matches the tool's own scaffold artifacts by their signature prefix, e.g.
# `verify_VULN_005_dom_xss.py`, `verify_VULN-9.ts`, `exploit_VULN_005.py`.
# Anchored on `VULN` so a target repo's own `verify_email.py` /
# `exploit_helpers.go` are NOT flagged — only VulnHunter-Fix scaffolds are.
_SCAFFOLD_RE = re.compile(r"^(?:verify|exploit)_VULN[-_]?", re.IGNORECASE)


def offending_files(paths: list[str]) -> list[str]:
    """Return the subset of paths whose basename is a leaked scaffold.

    Pure function (no git) so the naming rule is unit-testable in isolation.
    """
    hits = []
    for p in paths:
        base = os.path.basename(p.strip())
        if base and _SCAFFOLD_RE.match(base):
            hits.append(p.strip())
    return hits


def _git(repo_root: str, *args: str) -> subprocess.CompletedProcess:
    # A hung git (timeout) or a missing/unusable binary (OSError) must not
    # escape as an uncaught traceback — surface it as returncode=2 so the
    # existing git-error handling in _added_files fails closed with a
    # diagnostic instead of a stack trace.
    try:
        return subprocess.run(  # nosec B603 B607
            ["git", "-C", repo_root, *args],
            capture_output=True, text=True, check=False, timeout=30,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return subprocess.CompletedProcess(args, returncode=2, stdout="", stderr=str(exc))


def _resolve_base(repo_root: str, base: str) -> str | None:
    """Resolve a usable base ref to diff the branch against, or None.

    Tries, in order: the caller's `--base` and its `origin/` form; the remote's
    advertised default branch (`origin/HEAD`); then the common `main`/`master`
    defaults. VulnHunter-Fix targets arbitrary repos, many of which default to
    `master` — so hardcoding `main` alone would leave the gate unable to diff
    the branch and force the HEAD-only fallback (multi-finding cluster PR case).
    """
    candidates: list[str] = []
    if base:
        candidates += [base, f"origin/{base}"]
    sym = _git(repo_root, "symbolic-ref", "--short", "refs/remotes/origin/HEAD")
    if sym.returncode == 0 and sym.stdout.strip():
        candidates.append(sym.stdout.strip())
    candidates += ["origin/main", "origin/master", "main", "master"]
    for cand in candidates:
        if cand and _git(repo_root, "rev-parse", "--verify", "--quiet", cand).returncode == 0:
            return cand
    return None


def _added_files(repo_root: str, base: str) -> tuple[list[str], str | None]:
    """Files added on this branch vs base. Returns (paths, error)."""
    ref = _resolve_base(repo_root, base)
    if ref is None:
        # No base resolved (e.g. shallow/detached CI clone with no default
        # branch advertised). Fall back to HEAD's added files rather than
        # blocking delivery — but WARN loudly: in a multi-commit cluster PR a
        # scaffold committed in an earlier commit would be invisible here, so a
        # "pass" in this mode is NOT the same as a clean full-branch scan
        # (multi-finding cluster PR case).
        # `--diff-filter=A` lists only additions. A scaffold promoted in HEAD
        # can't be a false positive: if git detects the rename it shows as R
        # (excluded); if not, the old verify_ name shows as D (also excluded)
        # and only the clean promoted name shows as A. Either way the scaffold
        # name never appears here.
        proc = _git(repo_root, "show", "--name-only", "--diff-filter=A",
                    "--pretty=format:", "HEAD")
        if proc.returncode != 0:
            return [], proc.stderr.strip() or "git show failed"
        print(
            "check-committed-test-naming: WARNING — could not resolve a base ref "
            f"(tried '{base}', origin/HEAD, main/master); scanned only files added "
            "by HEAD. A scaffold committed in an earlier branch commit would NOT be "
            "detected. Pass --base <default-branch> for a full branch scan.",
            file=sys.stderr,
        )
        return [ln for ln in proc.stdout.splitlines() if ln.strip()], None

    # Three-dot diff is merge-base relative, so it enumerates every file added
    # across the branch even if the base has advanced. A scaffold created and
    # then promoted within the branch is absent at both merge-base and HEAD, so
    # it never appears as an addition here — only the clean promoted name does.
    proc = _git(repo_root, "diff", "--name-only", "--diff-filter=A", f"{ref}...HEAD")
    if proc.returncode != 0:
        return [], proc.stderr.strip() or "git diff failed"
    return [ln for ln in proc.stdout.splitlines() if ln.strip()], None


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Committed-test-naming gate (REQ-GAT-013).")
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--base", default="main",
                    help="Base ref to diff the branch against (default: main). "
                         "If it does not resolve, the gate auto-detects the "
                         "repo's default branch (origin/HEAD, then main/master) "
                         "before falling back to a HEAD-only scan with a warning.")
    args = ap.parse_args(argv[1:])

    paths, err = _added_files(args.repo_root, args.base)
    if err is not None:
        print(f"check-committed-test-naming: git error: {err}", file=sys.stderr)
        return 2

    hits = offending_files(paths)
    if hits:
        print("committed test-naming gate failed (REQ-GAT-013):", file=sys.stderr)
        print(
            "  a verify_/exploit_ scaffold was committed instead of being "
            "promoted to a discoverable, repo-convention test name.\n"
            "  Rename it (e.g. test_<behavior>.py, <module>.security.test.ts) "
            "and delete the scaffold before delivery.\n"
            "  Offending files:",
            file=sys.stderr,
        )
        for h in hits:
            print(f"    - {h}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
