#!/usr/bin/env python3
"""Safe-phrase sync lint (REQ-GAT-008).

Byte-compares SAFE_PHRASE_PATTERNS in `vulnhunter_fix/delivery.py`
against the definition in `scripts/check-severity-mask.py`. Any drift
fails CI.

Usage:
    safe-phrase-sync-lint.py
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
DELIVERY = REPO_ROOT / "vulnhunter_fix" / "delivery.py"
GATE1 = REPO_ROOT / "scripts" / "check-severity-mask.py"


def _extract_constant(path: Path, name: str) -> tuple[str, ...] | None:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    if isinstance(node.value, (ast.Tuple, ast.List)):
                        vals = []
                        for elt in node.value.elts:
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                vals.append(elt.value)
                        return tuple(vals)
    return None


def main() -> int:
    a = _extract_constant(DELIVERY, "SAFE_PHRASE_PATTERNS")
    b = _extract_constant(GATE1, "SAFE_PHRASE_PATTERNS")
    if a is None:
        print(f"error: SAFE_PHRASE_PATTERNS not found in {DELIVERY}", file=sys.stderr)
        return 2
    if b is None:
        print(f"error: SAFE_PHRASE_PATTERNS not found in {GATE1}", file=sys.stderr)
        return 2
    if a != b:
        print(
            "SAFE_PHRASE_PATTERNS drift detected (REQ-GAT-008):\n"
            f"  vulnhunter_fix/delivery.py: {a}\n"
            f"  check-severity-mask.py:      {b}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
