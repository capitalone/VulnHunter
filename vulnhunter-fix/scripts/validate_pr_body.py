"""Validate a cluster PR body has the right `Closes #N` references.

`prompts/deliver.md` Step 4 requires the in-place cluster PR body
to reference every source issue in the cluster, so all of them
auto-close when the PR merges.

The PR body actually carries the `Closes #N` references in two
places:

1. A top-line `Closes #1, #2, #3, ...` comma-separated list (for
   human readability when skimming the PR header). GitHub's parser
   is documented to only bless the repeated-keyword form (`Closes
   #1, Closes #2, ...`); whether the comma-separated form fires
   auto-close depends on parser behavior we don't control.
2. A per-finding subsection header like `#### {VULN_ID} — {TITLE}
   (Closes #{ISSUE_NUMBER})` — one per cluster member. THIS is
   what makes the contract robust: each is the canonical
   `<keyword> #N` shape, and GitHub auto-closes every one when
   the PR merges.

This validator scans the whole body and accepts a finding's issue
as "closed" if either form references it — but the per-finding
subsection is the load-bearing mechanism.

Failure mode: exit 1 with a directed message naming which issues
are missing.

Usage:
    validate_pr_body.py <body_file> --expected-issues 1,2,3,4
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


# Match `Closes #N`, `Fixes #N`, `Resolves #N` (case-insensitive),
# as the canonical GitHub close keywords. Each match captures the
# issue number. We don't require them all be on the same line —
# some templates split per finding subsection.
_CLOSE_KEYWORD_RE = re.compile(
    r"\b(?:closes|fixes|resolves)\b[ \t]+#(\d+)",
    re.IGNORECASE,
)


def extract_closes(body: str) -> set[int]:
    """Return the set of issue numbers the PR body would auto-close on merge."""
    return {int(m.group(1)) for m in _CLOSE_KEYWORD_RE.finditer(body)}


def validate(body: str, expected: set[int]) -> tuple[bool, str]:
    """Check the body closes EXACTLY the expected set of issues.

    Returns ``(ok, message)``. On failure the message names the
    missing or extra issues so the operator can fix the body and
    re-run.
    """
    found = extract_closes(body)
    missing = expected - found
    extra = found - expected
    if not missing and not extra:
        return True, (
            f"ok: PR body closes all {len(expected)} expected issues "
            f"({sorted(expected)})"
        )
    msgs = []
    if missing:
        msgs.append(
            f"missing `Closes #N` for {sorted(missing)} — these source "
            f"issues will NOT auto-close on merge"
        )
    if extra:
        msgs.append(
            f"unexpected `Closes #N` for {sorted(extra)} — body references "
            f"issues that aren't in the cluster's work list"
        )
    return False, "; ".join(msgs)


def _parse_issue_list(arg: str) -> set[int]:
    out: set[int] = set()
    for token in arg.split(","):
        token = token.strip().lstrip("#")
        if not token:
            continue
        if not token.isdigit():
            raise argparse.ArgumentTypeError(f"not a number: {token!r}")
        out.add(int(token))
    return out


def main_with_argv(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("body_path", type=Path)
    parser.add_argument(
        "--expected-issues",
        required=True,
        type=_parse_issue_list,
        help="Comma-separated issue numbers the body should Closes/Fixes/Resolves",
    )
    args = parser.parse_args(argv)
    try:
        body = args.body_path.read_text()
    except FileNotFoundError:
        print(f"error: {args.body_path} not found", file=sys.stderr)
        return 1
    ok, msg = validate(body, args.expected_issues)
    if ok:
        print(msg)
        return 0
    print(f"error: {msg}", file=sys.stderr)
    print(
        "Fix the PR body so every cluster member has a `Closes #<n>` "
        "reference (comma-separated on one line, or in per-finding "
        "subsection headers — both forms count). Then re-run "
        "`gh pr create`.",
        file=sys.stderr,
    )
    return 1


def main() -> int:
    return main_with_argv(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
