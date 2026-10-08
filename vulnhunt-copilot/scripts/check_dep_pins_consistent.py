#!/usr/bin/env python3
"""Assert vulnhunter-fix's runtime dependency pins are identical across every
install script that defines its own copy.

install.sh and install-copilot.sh both source the shared _install_common.sh,
so they can't drift from each other -- but install.cmd and install-copilot.cmd
each still define their own VULNFIX_DEPS. An earlier revision of this port
tried unifying the .cmd side the same way, into a shared _install_common.cmd
called via cmd.exe's documented `CALL :label` cross-file form -- except that
form doesn't exist: `CALL otherfile.cmd :label` does not jump to :label in
otherfile.cmd, it runs otherfile.cmd from the top with ":label" passed as
%1. That broke both .cmd installers (venv creation would fail against a
literal ":build_vulnfix_venv" + ".venv" path). Reverted; the .cmd side goes
back to two independent copies of VULNFIX_DEPS, same as before that attempt.

So this checks three copies of the same value: _install_common.sh (shared by
both bash scripts), install.cmd, and install-copilot.cmd. Each file's
comments say to keep them in sync by hand -- nothing enforced it until this
script, run in CI on every PR.

Usage:
    check_dep_pins_consistent.py <repo-root>
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# One regex per file, each capturing the exact pin list text so a
# byte-for-byte comparison is possible despite the surrounding syntax
# differing (bash array literal vs. cmd `set` with quoted tokens).
FILES: dict[str, re.Pattern[str]] = {
    "_install_common.sh": re.compile(r'^VULNFIX_DEPS=\((.+)\)$', re.MULTILINE),
    "install.cmd": re.compile(r'^set VULNFIX_DEPS=(.+)$', re.MULTILINE),
    "install-copilot.cmd": re.compile(r'^set VULNFIX_DEPS=(.+)$', re.MULTILINE),
}


def extract_pins(text: str, pattern: re.Pattern[str]) -> list[str]:
    match = pattern.search(text)
    if not match:
        return []
    # Both syntaxes are space-separated "package>=x.y" tokens, each
    # double-quoted -- strip quotes and split on whitespace to get a
    # comparable, order-sensitive list of pin strings.
    return [tok.strip('"') for tok in match.group(1).split()]


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_dep_pins_consistent.py <repo-root>", file=sys.stderr)
        return 2
    repo_root = Path(sys.argv[1])

    pins_by_file: dict[str, list[str]] = {}
    for relpath, pattern in FILES.items():
        target = repo_root / relpath
        if not target.is_file():
            print(f"error: {target} not found", file=sys.stderr)
            return 1
        pins = extract_pins(target.read_text(encoding="utf-8"), pattern)
        if not pins:
            print(f"error: could not find VULNFIX_DEPS in {relpath}", file=sys.stderr)
            return 1
        pins_by_file[relpath] = pins

    reference_file, reference_pins = next(iter(pins_by_file.items()))
    mismatches = {
        relpath: pins
        for relpath, pins in pins_by_file.items()
        if pins != reference_pins
    }
    if mismatches:
        print(
            f"error: vulnhunter-fix dependency pins have drifted apart across "
            f"install scripts. {reference_file} has {reference_pins!r}; "
            f"mismatched file(s):",
            file=sys.stderr,
        )
        for relpath, pins in mismatches.items():
            print(f"  {relpath}: {pins!r}", file=sys.stderr)
        print(
            "Update _install_common.sh, install.cmd, and install-copilot.cmd's "
            "VULNFIX_DEPS to match, then re-run.",
            file=sys.stderr,
        )
        return 1

    print(f"All {len(pins_by_file)} install scripts agree: {reference_pins!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
