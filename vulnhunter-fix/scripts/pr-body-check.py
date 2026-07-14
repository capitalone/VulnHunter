#!/usr/bin/env python3
"""PR-body honesty check.

Regenerates authoritative test-count and coverage numbers by running
the suite, then optionally diffs those numbers against claims parsed
from a PR body file. Locks in the lesson from peer review 1 B2:
"PR body test-plan numbers don't match the branch."

Usage:
    pr-body-check.py stats                       # emit JSON stats
    pr-body-check.py check --body <file.md>      # verify body vs reality
    pr-body-check.py check --body-stdin          # read body on stdin

Exit codes: 0 clean, 1 drift, 2 error.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent

# Regexes that match pytest/coverage output shapes.
PYTEST_SUMMARY_RE = re.compile(
    r"(?P<passed>\d+)\s+passed"
    r"(?:,\s+(?P<failed>\d+)\s+failed)?"
    r"(?:,\s+(?P<skipped>\d+)\s+skipped)?"
    r"(?:,\s+(?P<xfailed>\d+)\s+xfailed)?"
    r"(?:,\s+(?P<xpassed>\d+)\s+xpassed)?"
)
COVERAGE_TOTAL_RE = re.compile(
    r"^TOTAL\s+\d+\s+\d+\s+\d+\s+\d+\s+(?P<pct>\d+(?:\.\d+)?)%",
    re.MULTILINE,
)

# Claim patterns in PR bodies — deliberately narrow to reduce false-positives.
BODY_PASSED_RE = re.compile(r"(?P<n>\d+)\s+passed", re.IGNORECASE)
BODY_COVERAGE_RE = re.compile(r"(?P<pct>\d+(?:\.\d+)?)\s*%\s*(?:coverage|cov)", re.IGNORECASE)


def _run_suite() -> dict:
    """Run pytest with coverage, return canonical stats dict."""
    pytest_bin = shutil.which("pytest")
    if pytest_bin is None:
        return {"error": "pytest not on PATH; run inside pipenv shell"}
    cmd = [
        pytest_bin,
        "--tb=no",
        "-q",
        "--cov=scripts",
        "--cov=vulnhunter_fix",
        "--cov-report=term",
    ]
    proc = subprocess.run(  # nosec B603 — pytest binary resolved via shutil.which
        cmd, cwd=REPO_ROOT, capture_output=True, text=True, timeout=300
    )
    combined = proc.stdout + "\n" + proc.stderr
    summary_match = None
    for line in combined.splitlines():
        m = PYTEST_SUMMARY_RE.search(line)
        if m and "passed" in line:
            summary_match = m
    cov_match = COVERAGE_TOTAL_RE.search(combined)
    stats = {
        "passed": int(summary_match["passed"]) if summary_match else None,
        "failed": int(summary_match["failed"] or 0) if summary_match else None,
        "skipped": int(summary_match["skipped"] or 0) if summary_match else None,
        "xfailed": int(summary_match["xfailed"] or 0) if summary_match else None,
        "xpassed": int(summary_match["xpassed"] or 0) if summary_match else None,
        "coverage_pct": float(cov_match["pct"]) if cov_match else None,
        "returncode": proc.returncode,
    }
    return stats


def _parse_body_claims(body: str) -> dict:
    """Extract test/coverage claims from a PR body."""
    passed_match = BODY_PASSED_RE.search(body)
    cov_match = BODY_COVERAGE_RE.search(body)
    return {
        "claimed_passed": int(passed_match["n"]) if passed_match else None,
        "claimed_coverage": float(cov_match["pct"]) if cov_match else None,
    }


def cmd_stats(_args: argparse.Namespace) -> int:
    stats = _run_suite()
    print(json.dumps(stats, indent=2, sort_keys=True))
    return 0 if stats.get("returncode") == 0 else 1


def cmd_check(args: argparse.Namespace) -> int:
    if args.body_stdin:
        body = sys.stdin.read()
    elif args.body:
        body = Path(args.body).read_text(encoding="utf-8")
    else:
        print("error: pass --body <file> or --body-stdin", file=sys.stderr)
        return 2
    claims = _parse_body_claims(body)
    reality = _run_suite()
    if reality.get("error"):
        print(f"error: {reality['error']}", file=sys.stderr)
        return 2
    drift = []
    if claims["claimed_passed"] is not None and reality["passed"] is not None:
        if claims["claimed_passed"] != reality["passed"]:
            drift.append(
                f"  passed count: body claims {claims['claimed_passed']}, "
                f"suite reports {reality['passed']}"
            )
    if claims["claimed_coverage"] is not None and reality["coverage_pct"] is not None:
        # Allow 1-point tolerance to avoid false positives on rounding.
        if abs(claims["claimed_coverage"] - reality["coverage_pct"]) > 1.0:
            drift.append(
                f"  coverage: body claims {claims['claimed_coverage']:.2f}%, "
                f"suite reports {reality['coverage_pct']:.2f}%"
            )
    if drift:
        print("PR body drift detected:", file=sys.stderr)
        for line in drift:
            print(line, file=sys.stderr)
        return 1
    print(
        f"OK: body claims match suite "
        f"({reality['passed']} passed, {reality['coverage_pct']}% coverage)"
    )
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_stats = sub.add_parser("stats", help="emit JSON stats from a live run")
    p_stats.set_defaults(func=cmd_stats)
    p_check = sub.add_parser("check", help="verify PR body claims against reality")
    p_check.add_argument("--body", type=str, help="path to PR body markdown")
    p_check.add_argument("--body-stdin", action="store_true", help="read body from stdin")
    p_check.set_defaults(func=cmd_check)
    args = ap.parse_args(argv[1:])
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
