#!/usr/bin/env python3
r"""Heading sync lint (REQ-GAT-003).

Guards the class of drift an earlier peer review surfaced twice (cluster
template + remediation-rigor.md): a body-emitting template or a reference
doc that teaches a required-section heading the delivery-time Gate 2
(`check-body-completeness.py`) would reject.

Two checks, both sourced from ONE authority — the heading constants in
`scripts/check-body-completeness.py`:

  1. Presence — every body template that renders a `--kind pr`/`issue`
     body must carry each REQUIRED_ALWAYS heading at H2, and the PR
     templates must additionally carry all conditional headings so a
     cluster/single PR passes Gate 2 in every tier/status/sweep state.

  2. Em-dash form — no heading anywhere under prompts/, references/,
     templates/ may spell `## Breaking Change` with a trailing suffix
     (em-dash, words). Gate 2's regex is `^## Breaking Change\s*(?:$|:)`;
     the `— Caller Action Required` form fails it. This is the exact bug
     that shipped in pr_body_cluster.md (blocker) and remediation-rigor.md
     (major) despite deliver.md + pr_body.md being fixed.

Usage:
    heading-sync-lint.py
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
GATE2 = REPO_ROOT / "scripts" / "check-body-completeness.py"
TEMPLATES = REPO_ROOT / "templates"

# Body templates that must carry every REQUIRED_ALWAYS heading at H2.
BODY_TEMPLATES = ("pr_body.md", "pr_body_cluster.md", "issue_body.md")
# PR-rendering templates additionally carry all conditional headings so
# the body passes Gate 2 regardless of tier/status/sweep state.
PR_TEMPLATES = ("pr_body.md", "pr_body_cluster.md")

# Corpus scanned for the em-dash Breaking-Change heading form.
SCAN_DIRS = ("prompts", "references", "templates")

_BREAKING_HEADING = re.compile(r"^#{2,4}\s+Breaking Change(?P<suffix>.*)$", re.MULTILINE)


def _extract_str_constant(path: Path, name: str) -> str | None:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        return node.value.value
    return None


def _extract_tuple_constant(path: Path, name: str) -> tuple[str, ...] | None:
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


def _heading_present(text: str, heading: str) -> bool:
    """Mirror Gate 2's acceptance: `^<heading>\\s*(?:$|:)` (heading already
    includes the `## ` prefix)."""
    pattern = r"^" + re.escape(heading) + r"\s*(?:$|:)"
    return re.search(pattern, text, re.MULTILINE) is not None


def main() -> int:
    required_always = _extract_tuple_constant(GATE2, "REQUIRED_ALWAYS")
    cond_table = _extract_str_constant(GATE2, "CONDITIONAL_TABLE")
    cond_residual = _extract_str_constant(GATE2, "CONDITIONAL_RESIDUAL")
    cond_breaking = _extract_str_constant(GATE2, "CONDITIONAL_BREAKING")
    cond_sweep = _extract_str_constant(GATE2, "CONDITIONAL_SWEEP")

    if required_always is None or None in (cond_table, cond_residual, cond_breaking, cond_sweep):
        print(f"error: could not extract heading constants from {GATE2}", file=sys.stderr)
        return 2

    conditionals = (cond_table, cond_residual, cond_breaking, cond_sweep)
    errors: list[str] = []

    # Check 1 — presence in body templates.
    for name in BODY_TEMPLATES:
        path = TEMPLATES / name
        if not path.is_file():
            errors.append(f"{name}: body template missing")
            continue
        text = path.read_text(encoding="utf-8")
        for heading in required_always:
            if not _heading_present(text, heading):
                errors.append(f"{name}: missing required H2 heading {heading!r} (Gate 2 REQUIRED_ALWAYS)")
        if name in PR_TEMPLATES:
            for heading in conditionals:
                if not _heading_present(text, heading):
                    errors.append(
                        f"{name}: missing conditional heading {heading!r} — PR templates carry all "
                        f"conditionals so cluster/single PRs pass Gate 2 in every tier/status/sweep state"
                    )
        # Check 1b — no *block* placeholder inside an HTML comment. A naive
        # global substitution of a section placeholder that appears inside a
        # comment injects the substituted block (with its own nested HTML
        # comments) into the comment, terminating it early and dumping the
        # block as visible garbage in the rendered body. This shipped in every
        # multi-finding cluster PR via the idempotency comment referencing
        # {PER_FINDING_SECTIONS}. Discriminator: only flag a placeholder that
        # ALSO appears as content outside any comment (i.e. it expands to a
        # real block) — a scalar marker like {IDEMPOTENCY_KEY} that lives only
        # inside its own `<!-- vulnfix-key -->` comment is safe.
        content_wo_comments = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
        block_placeholders = set(re.findall(r"\{[A-Z_]+\}", content_wo_comments))
        for m in re.finditer(r"<!--.*?-->", text, re.DOTALL):
            for tok in re.findall(r"\{[A-Z_]+\}", m.group(0)):
                if tok in block_placeholders:
                    line_no = text[: m.start()].count("\n") + 1
                    errors.append(
                        f"{name}:{line_no}: HTML comment references block placeholder "
                        f"{tok!r} that also appears as content — global substitution injects the "
                        f"block (and its nested comments) here, breaking the comment. Reference the "
                        f"section in prose instead of by placeholder token."
                    )

    # Check 2 — em-dash Breaking-Change heading form anywhere in the corpus.
    for d in SCAN_DIRS:
        for path in sorted((REPO_ROOT / d).rglob("*.md")):
            text = path.read_text(encoding="utf-8")
            for m in _BREAKING_HEADING.finditer(text):
                suffix = m.group("suffix").strip()
                if suffix and not suffix.startswith(":"):
                    line_no = text[: m.start()].count("\n") + 1
                    rel = path.relative_to(REPO_ROOT)
                    errors.append(
                        f"{rel}:{line_no}: Breaking-Change heading has a suffix {suffix!r} — Gate 2 "
                        f"regex `^## Breaking Change\\s*(?:$|:)` rejects it. Use a bare heading and move "
                        f"the descriptive phrase into the body text."
                    )

    if errors:
        print("heading sync-lint failures (REQ-GAT-003):", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
