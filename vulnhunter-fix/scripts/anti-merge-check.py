#!/usr/bin/env python3
"""Anti-merge grouping check (REQ-GAT-006).

Applies the 0.6 threshold to a candidate grouping decision. Called
during Phase 3 (Plan) before finalizing groups, and as Gate 5 by
scripts/run-gates.py before delivery.

Usage:
    anti-merge-check.py \
        --files-grouped <count> --files-split <count> \
        [--test-files-grouped <count>] [--test-files-split <count>] \
        [--strict]

Emits JSON:
    {"allowed": bool, "source_ratio": float, "test_ratio": float, "reason": "..."}

Exit codes:
    Default (advisory mode):
        0 always — the decision is in the payload; the caller decides
        whether to act on `allowed: false`.
    With --strict:
        0 when allowed=true; 1 when allowed=false. Gate-appropriate
        return so run-gates.py can block delivery on a violation
        (peer review: mechanical enforcement, not prose).
"""

from __future__ import annotations

import argparse
import json
import sys


THRESHOLD = 0.6


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Anti-merge check (REQ-GAT-006).")
    ap.add_argument("--files-grouped", type=int, required=True)
    ap.add_argument("--files-split", type=int, required=True)
    ap.add_argument("--test-files-grouped", type=int, default=None)
    ap.add_argument("--test-files-split", type=int, default=None)
    ap.add_argument(
        "--strict", action="store_true",
        help="Exit 1 when allowed=false (mechanical gate mode). Default is advisory.",
    )
    args = ap.parse_args(argv[1:])

    # Reject negative counts: a negative grouped count yields a negative ratio
    # trivially <= THRESHOLD and games the gate to allowed:true (12-seg review
    # S5). split=0 is tolerated (handled as ratio 1.0 below).
    for name, val in (
        ("--files-grouped", args.files_grouped),
        ("--files-split", args.files_split),
        ("--test-files-grouped", args.test_files_grouped),
        ("--test-files-split", args.test_files_split),
    ):
        if val is not None and val < 0:
            print(f"error: {name} must be non-negative (got {val})", file=sys.stderr)
            return 2

    src_ratio = args.files_grouped / args.files_split if args.files_split else 1.0
    test_ratio = None
    if args.test_files_grouped is not None and args.test_files_split:
        test_ratio = args.test_files_grouped / args.test_files_split

    if src_ratio <= THRESHOLD:
        allowed = True
        reason = f"source ratio {src_ratio:.3f} <= {THRESHOLD}"
    elif test_ratio is not None and test_ratio <= THRESHOLD:
        allowed = True
        reason = f"test ratio {test_ratio:.3f} <= {THRESHOLD}"
    else:
        allowed = False
        parts = [f"source ratio {src_ratio:.3f}"]
        if test_ratio is not None:
            parts.append(f"test ratio {test_ratio:.3f}")
        reason = f"grouping inefficient: {', '.join(parts)} > {THRESHOLD}; split into individual PRs"

    print(json.dumps({
        "allowed": allowed,
        "source_ratio": round(src_ratio, 3),
        "test_ratio": round(test_ratio, 3) if test_ratio is not None else None,
        "threshold": THRESHOLD,
        "reason": reason,
    }, indent=2))
    if args.strict and not allowed:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
