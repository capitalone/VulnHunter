#!/usr/bin/env python3
"""Gate 2 — body completeness (REQ-GAT-003).

Structurally pure. Verifies that the given PR body or issue body carries
every required section heading with non-empty non-placeholder content.

Usage:
    check-body-completeness.py --body <path> --kind {pr,issue}
        --tier {FULL,MITIGATION,WORKAROUND}
        --status <status>
        --sweep-ran {true,false}
        [--enforce-strings <str> ...]
        [--forbid-strings <str> ...]

Exit 0 on pass, non-zero on fail with a diagnostic.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


REQUIRED_ALWAYS = (
    "## Finding Summary",
    "## Attacker Capability",
    "## Security Test",
    "## Fix Description",
    "## Verification Results",
)

CONDITIONAL_TABLE = "## Verification Table"      # PR only
CONDITIONAL_RESIDUAL = "## Residual Risk"        # tier != FULL
CONDITIONAL_BREAKING = "## Breaking Change"      # status == BREAKING_CHANGE
CONDITIONAL_SWEEP = "## Sweep Summary"           # sweep_ran

DEFAULT_FORBIDDEN = ("TBD", "TODO", "FIXME", "[placeholder]", "<add here>", "<fill in>")


def _fence_ranges(text: str) -> list[tuple[int, int]]:
    """Return [start, end) offsets of fenced code blocks (including fences)."""
    ranges: list[tuple[int, int]] = []
    in_fence = False
    fence_start = 0
    offset = 0
    for line in text.splitlines(keepends=True):
        if line.lstrip().startswith("```"):
            if not in_fence:
                in_fence = True
                fence_start = offset
            else:
                in_fence = False
                ranges.append((fence_start, offset + len(line)))
        offset += len(line)
    if in_fence:
        ranges.append((fence_start, offset))
    return ranges


def _mask_fences(text: str, fences: list[tuple[int, int]]) -> str:
    """Replace fenced regions with same-length runs of newlines/spaces so
    positions map 1:1 to the original text. Fenced content is invisible to
    heading detection but the body-emptiness check (which uses the ORIGINAL
    text) still sees it as real content."""
    out = list(text)
    for start, end in fences:
        for i in range(start, end):
            if text[i] != "\n":
                out[i] = " "
    return "".join(out)


def _find_section_content(text: str, heading: str) -> tuple[bool, bool]:
    """Return (present, non_empty).

    Heading detection ignores content inside fenced code blocks (prevents
    heading spoofing). Body content is extracted from the ORIGINAL text so
    that a section containing only a code block still counts as non-empty.
    """
    fences = _fence_ranges(text)
    masked = _mask_fences(text, fences)
    # Anchor the heading end so `## Finding Summary` doesn't match
    # `## Finding Summary Details` as a prefix (peer review 1 minor). The
    # heading must be followed by end-of-line, whitespace-then-EOL, or a
    # colon; NOT by additional word characters.
    pattern = r"^" + re.escape(heading) + r"\s*(?:$|:)"
    match = re.search(pattern, masked, re.MULTILINE)
    if not match:
        return False, False
    idx = match.start()
    after = idx + len(heading)
    next_h = re.search(r"^(?:##|###)\s", masked[after:], re.MULTILINE)
    end = after + (next_h.start() if next_h else len(masked) - after)
    body = text[after:end].strip()   # from original — preserves code blocks
    return True, bool(body)


def check(args) -> int:
    try:
        text = Path(args.body).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"{args.body}: <io>: {exc}", file=sys.stderr)
        return 2

    errors: list[str] = []
    required = list(REQUIRED_ALWAYS)
    if args.kind == "pr":
        required.append(CONDITIONAL_TABLE)
    if args.tier != "FULL":
        required.append(CONDITIONAL_RESIDUAL)
    if args.status == "BREAKING_CHANGE":
        required.append(CONDITIONAL_BREAKING)
    if args.sweep_ran == "true":
        required.append(CONDITIONAL_SWEEP)

    for heading in required:
        present, non_empty = _find_section_content(text, heading)
        if not present:
            errors.append(f"{args.body}: missing required section: {heading!r}")
        elif not non_empty:
            errors.append(f"{args.body}: section {heading!r} is empty")

    forbidden = set(DEFAULT_FORBIDDEN)
    if args.forbid_strings:
        forbidden.update(args.forbid_strings)
    for term in forbidden:
        if term in text:
            line_no = text[:text.find(term)].count("\n") + 1
            errors.append(f"{args.body}:{line_no}: forbidden token: {term!r}")

    if args.enforce_strings:
        for term in args.enforce_strings:
            if term not in text:
                errors.append(f"{args.body}: required token missing: {term!r}")

    if errors:
        for e in errors:
            print(e, file=sys.stderr)
        return 1
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Gate 2 body completeness (REQ-GAT-003).")
    ap.add_argument("--body", required=True)
    ap.add_argument("--kind", required=True, choices=("pr", "issue"))
    ap.add_argument("--tier", required=True, choices=("FULL", "MITIGATION", "WORKAROUND"))
    ap.add_argument("--status", required=True)
    ap.add_argument("--sweep-ran", required=True, choices=("true", "false"))
    ap.add_argument("--enforce-strings", nargs="*", default=None)
    ap.add_argument("--forbid-strings", nargs="*", default=None)
    args = ap.parse_args(argv[1:])
    return check(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
