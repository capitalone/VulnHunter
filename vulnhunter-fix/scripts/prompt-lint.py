#!/usr/bin/env python3
"""CWE-class prompt lint (REQ-CWE-010).

Verifies that every CWE-class prompt file in
`prompts/worker_agent_*.md` references `worker_agent_common.md`.
Prevents drift from the shared preamble.

Usage:
    prompt-lint.py [--prompts-dir <path>]

Exits 0 on clean, non-zero on any violation with a diagnostic line per
offending file.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PROMPTS_DIR = REPO_ROOT / "prompts"

REQUIRED_REFERENCE = "worker_agent_common.md"

CWE_CLASS_FILES = (
    "worker_agent_authz.md",
    "worker_agent_injection.md",
    "worker_agent_crypto.md",
    "worker_agent_resource.md",
    "worker_agent_config.md",
)


def lint(prompts_dir: Path) -> int:
    violations: list[str] = []
    for name in CWE_CLASS_FILES:
        path = prompts_dir / name
        if not path.is_file():
            violations.append(f"{path}: missing CWE-class prompt file (REQ-CWE-002)")
            continue
        text = path.read_text(encoding="utf-8")
        if REQUIRED_REFERENCE not in text:
            violations.append(
                f"{path}: does not reference {REQUIRED_REFERENCE!r} — "
                "drift risk (REQ-CWE-010)"
            )
    common = prompts_dir / REQUIRED_REFERENCE
    if not common.is_file():
        violations.append(f"{common}: missing shared preamble (REQ-CWE-001)")

    stale = prompts_dir / "worker_agent.md"
    if stale.is_file():
        violations.append(
            f"{stale}: legacy worker_agent.md must be deleted after Bundle 3 "
            "refactor (REQ-CWE-001 clean refactor policy)"
        )

    if violations:
        for v in violations:
            print(v, file=sys.stderr)
        return 1
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="CWE-class prompt lint (REQ-CWE-010).")
    ap.add_argument("--prompts-dir", type=Path, default=DEFAULT_PROMPTS_DIR)
    args = ap.parse_args(argv[1:])
    return lint(args.prompts_dir)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
