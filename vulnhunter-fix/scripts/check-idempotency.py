#!/usr/bin/env python3
"""Gate 4 — idempotency (REQ-GAT-005).

Verifies every artifact body carries the `<!-- vulnfix-key: <hex> -->`
marker. Tracking-issue bodies additionally require
`<!-- vulnfix-report-id: <id> -->`.

Usage:
    check-idempotency.py --body <path> [--kind {pr,issue,tracking}]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


KEY_RE = re.compile(r"<!--\s*vulnfix-key:\s*([0-9a-f]{16})\s*-->")
REPORT_ID_RE = re.compile(r"<!--\s*vulnfix-report-id:\s*([^\s>]+)\s*-->")


def check(args) -> int:
    try:
        text = Path(args.body).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"{args.body}: <io>: {exc}", file=sys.stderr)
        return 2

    errors: list[str] = []
    if not KEY_RE.search(text):
        errors.append(f"{args.body}: missing <!-- vulnfix-key: <hex> --> marker (REQ-GAT-005)")

    if args.kind == "tracking" and not REPORT_ID_RE.search(text):
        errors.append(f"{args.body}: tracking issue missing <!-- vulnfix-report-id: <id> --> marker (REQ-GAT-005)")

    if errors:
        for e in errors:
            print(e, file=sys.stderr)
        return 1
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Gate 4 idempotency (REQ-GAT-005).")
    ap.add_argument("--body", required=True)
    ap.add_argument("--kind", default="pr", choices=("pr", "issue", "tracking"))
    args = ap.parse_args(argv[1:])
    return check(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
