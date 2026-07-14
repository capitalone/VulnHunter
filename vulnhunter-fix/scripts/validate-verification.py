#!/usr/bin/env python3
"""Validate the 9-column verification table in a PR body.

Enforces REQ-GRA-011 through REQ-GRA-014 and REQ-GRA-020:

- Table header matches the exact 9-column contract.
- Every `yes` cell carries a `file:line` citation.
- Cited files exist at the worktree path and the cited line exists.
- Column 7 (`All call sites covered?`) enumerates callers matching the
  triage sidecar's `callers_of_sink`, with a truncation form accepted iff
  the total caller count exceeds 20.
- Column 7 matching mode depends on the sidecar's `confidence`:
  - `"high"` → strict case-sensitive `file:symbol` superset match.
  - `"low"`  → token-based (basename + symbol_name), case-insensitive.

Usage:
    validate-verification.py <pr_body.md> \
        --worktree <path>              # for citation file lookup
        --sidecars-dir <path>          # .work/<repo>/graph_context/
        --result <result.json>         # for callers_routed_through_fix

Exit codes:
    0 — table valid; delivery may proceed.
    1 — table invalid; delivery blocked. Diagnostic on stderr.
    2 — usage / IO error.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


EXPECTED_HEADERS = [
    "#",
    "VULN-NNN",
    "Stated vector closed?",
    "Test exercises real attack?",
    "Default fail-closed?",
    "Residual risk documented?",
    "All call sites covered?",
    "Sweep complete?",
    "Verdict",
]

CITATION_RE = re.compile(r"\(([^:()]+):(\d+)\)")
TRUNCATION_SUFFIX_RE = re.compile(r"\.\.\.\s+(\d+)\s+more\s+via\s+callers_of\(\)")
CELL_YES = re.compile(r"^\s*yes\b", re.IGNORECASE)
CELL_NO = re.compile(r"^\s*no\s*$", re.IGNORECASE)
CELL_NA = re.compile(r"^\s*n\s*/\s*a\s*$", re.IGNORECASE)


def _parse_table(text: str) -> tuple[list[str], list[list[str]]] | None:
    lines = text.splitlines()
    header_idx = None
    for i, line in enumerate(lines):
        if all(h.split("?")[0].strip() in line for h in EXPECTED_HEADERS[2:6]):
            header_idx = i
            break
    if header_idx is None:
        return None
    header_cells = [c.strip() for c in lines[header_idx].strip("|").split("|")]
    rows = []
    for line in lines[header_idx + 2:]:
        if not line.strip().startswith("|"):
            break
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) == len(header_cells):
            rows.append(cells)
    return header_cells, rows


def _check_header(header: list[str], errors: list[str]) -> None:
    if len(header) != 9:
        errors.append(f"header column count: expected 9, got {len(header)}")
        return
    for got, expected in zip(header, EXPECTED_HEADERS):
        if expected not in got:
            errors.append(f"header cell mismatch: expected substring {expected!r}, got {got!r}")


def _cell_kind(cell: str) -> str:
    if CELL_YES.match(cell):
        return "yes"
    if CELL_NO.match(cell):
        return "no"
    if CELL_NA.match(cell):
        return "n/a"
    return "unknown"


def _extract_citations(cell: str) -> list[tuple[str, int]]:
    return [(m.group(1), int(m.group(2))) for m in CITATION_RE.finditer(cell)]


def _check_citation_exists(worktree: Path, file: str, line: int) -> bool:
    p = worktree / file
    if not p.is_file():
        return False
    try:
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            return line <= sum(1 for _ in fh)
    except OSError:
        return False


def _load_sidecar_for_vuln(sidecars_dir: Path, vuln_id: str) -> dict | None:
    p = sidecars_dir / f"{vuln_id}.json"
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _load_result(result_path: Path | None) -> dict | None:
    if result_path is None or not result_path.is_file():
        return None
    try:
        return json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _parse_column7_callers(cell: str) -> tuple[list[str], int | None]:
    """Return (listed_callers, truncation_extra_count_or_None)."""
    m = TRUNCATION_SUFFIX_RE.search(cell)
    truncated = int(m.group(1)) if m else None
    # Extract inside-parens `file:symbol` pairs. Non-numeric second element.
    listed = re.findall(r"\(([^:()]+):([^\s()]+)\)", cell)
    callers = [f"{f}:{s}" for f, s in listed if not s.isdigit()]
    return callers, truncated


def _tokenize_caller(caller: str) -> tuple[str, str]:
    """Return (basename(file), symbol) with case-insensitive symbol."""
    file, _, symbol = caller.rpartition(":")
    return Path(file).name, symbol.lower()


def _check_column7(
    cell: str,
    sidecar: dict | None,
    result: dict | None,
    errors: list[str],
    row_label: str,
) -> None:
    """Validate the `All call sites covered?` cell per REQ-GRA-013/020."""
    if _cell_kind(cell) != "yes":
        return
    if not sidecar:
        errors.append(f"{row_label}: column 7 says 'yes' but no triage sidecar available")
        return

    graph_callers = list(sidecar.get("callers_of_sink") or [])
    raw_confidence = sidecar.get("confidence")
    if raw_confidence not in ("high", "low"):
        errors.append(
            f"{row_label}: sidecar missing/invalid 'confidence' field "
            f"({raw_confidence!r}); defaulting to low (conservative)"
        )
        confidence = "low"
    else:
        confidence = raw_confidence

    # A 'yes' coverage claim with no callers to verify against is
    # unsubstantiated — the strict/token match below would pass vacuously
    # (12-seg review S3). Accept it only when the cell explicitly annotates
    # the sink as a leaf ('(no callers)').
    if not graph_callers and "(no callers)" not in cell.lower():
        errors.append(
            f"{row_label}: column 7 says 'yes' but the sidecar lists no callers to "
            f"verify coverage against — the claim is unsubstantiated; annotate "
            f"'(no callers)' if the sink is genuinely a leaf (REQ-GRA-013)"
        )
        return

    listed_callers, truncated = _parse_column7_callers(cell)
    total_listed = len(listed_callers) + (truncated or 0)

    if truncated is not None:
        if len(graph_callers) <= 20:
            errors.append(
                f"{row_label}: column 7 uses truncation form but graph returned "
                f"only {len(graph_callers)} callers; must enumerate all (REQ-GRA-013)"
            )
        if len(listed_callers) != 20:
            errors.append(
                f"{row_label}: column 7 truncation form must list exactly 20 "
                f"callers; got {len(listed_callers)}"
            )
        if total_listed != len(graph_callers):
            errors.append(
                f"{row_label}: column 7 truncation counter mismatch — listed {len(listed_callers)} "
                f"+ '{truncated} more' = {total_listed}, graph returned {len(graph_callers)}"
            )
    else:
        if len(graph_callers) > 20:
            errors.append(
                f"{row_label}: column 7 must use truncation form when graph returns >20 callers "
                f"(returned {len(graph_callers)})"
            )

    routed = set((result or {}).get("callers_routed_through_fix") or [])

    if confidence == "high":
        missing = [c for c in graph_callers if c not in routed]
        if missing:
            errors.append(
                f"{row_label}: column 7 strict match failed — {len(missing)} caller(s) from "
                f"graph.callers_of() not present in result.callers_routed_through_fix "
                f"(REQ-GRA-020 high-confidence): {missing[:3]}"
            )
    else:
        routed_tokens = {_tokenize_caller(c) for c in routed}
        graph_tokens = {_tokenize_caller(c) for c in graph_callers}
        missing = graph_tokens - routed_tokens
        if missing:
            errors.append(
                f"{row_label}: column 7 token match failed under low-confidence "
                f"(REQ-GRA-020 fallback): {list(missing)[:3]}"
            )
        if "(grep_fallback)" not in cell:
            errors.append(
                f"{row_label}: column 7 under confidence=low must carry '(grep_fallback)' annotation"
            )


def validate(pr_body: Path, worktree: Path, sidecars_dir: Path | None, result_path: Path | None) -> int:
    try:
        text = pr_body.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"{pr_body}: <io>: {exc}", file=sys.stderr)
        return 2

    parsed = _parse_table(text)
    if not parsed:
        print(f"{pr_body}: <table>: 9-column verification table not found", file=sys.stderr)
        return 1
    header, rows = parsed

    errors: list[str] = []
    _check_header(header, errors)

    vuln_re = re.compile(r"VULN-(\d+)", re.IGNORECASE)
    for row in rows:
        m = vuln_re.search(row[1])
        row_label = f"row {row[0] or '?'} ({m.group(0) if m else 'no VULN id'})"
        vuln_id = m.group(0).upper() if m else None

        for idx in range(2, 8):
            kind = _cell_kind(row[idx])
            if kind == "yes":
                if not _extract_citations(row[idx]) and idx != 6:
                    errors.append(
                        f"{row_label}: column {idx+1} ({header[idx]}) is 'yes' but missing file:line citation (REQ-GRA-012)"
                    )
                for file, line in _extract_citations(row[idx]):
                    if not _check_citation_exists(worktree, file, line):
                        errors.append(
                            f"{row_label}: column {idx+1} citation {file}:{line} does not resolve at worktree"
                        )
            elif kind == "unknown":
                errors.append(f"{row_label}: column {idx+1} unknown value: {row[idx]!r}")

        if vuln_id:
            # Always run the column-7 caller-coverage check. When no
            # sidecars-dir is available the sidecar is None, and
            # _check_column7 fails closed on any 'yes' cell it cannot
            # verify (REQ-GRA-013) — previously this whole branch was
            # gated on `sidecars_dir`, so a fabricated coverage cell
            # passed with rc=0 whenever the validator was invoked without
            # --sidecars-dir (which was every invocation). peer review
            # re-review blocker #3.
            sidecar = _load_sidecar_for_vuln(sidecars_dir, vuln_id) if sidecars_dir else None
            result = _load_result(result_path)
            _check_column7(row[6], sidecar, result, errors, row_label)

    if errors:
        for e in errors:
            print(f"{pr_body}: {e}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Validate verification table (REQ-GRA-011..014, REQ-GRA-020).")
    ap.add_argument("pr_body", type=Path)
    ap.add_argument("--worktree", type=Path, default=Path.cwd())
    ap.add_argument("--sidecars-dir", type=Path, default=None)
    ap.add_argument("--result", type=Path, default=None)
    args = ap.parse_args(argv[1:])
    return validate(args.pr_body, args.worktree, args.sidecars_dir, args.result)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
