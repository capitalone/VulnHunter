#!/usr/bin/env python3
"""Parse tier_judgment.md LLM output into schema-conformant JSON.

Reads the raw LLM output from prompts/tier_judgment.md on stdin (or
from a file argument). Validates the primary line against the
`tierJudgment` `$def` in references/result-schema.json. Extracts an
optional sidecar block (`<!-- TIER_JUDGMENT_SIDECAR: ... -->`) into
a separate JSON if the caller supplies `--sidecar-out`.

REQ-HON-013 through REQ-HON-016 mandate:
- terminal tier ∈ {FULL, MITIGATION, WORKAROUND, null}
- rationale non-empty when final_tier is a string; null when final_tier is null
- failure_reason non-empty when final_tier is null; null otherwise

Usage:
    parse-tier-judgment.py [--sidecar-out <path>] [--in <path>]

Exit codes: 0 clean, 1 validation failure, 2 IO/parse error.
"""

from __future__ import annotations

import _skill_bootstrap  # noqa: F401 — bundled venv sys.path bootstrap

import argparse
import json
import re
import sys
from pathlib import Path

from jsonschema import Draft202012Validator


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "references" / "result-schema.json"

SIDECAR_RE = re.compile(
    r"<!--\s*TIER_JUDGMENT_SIDECAR:\s*(\{.*?\})\s*-->",
    re.DOTALL,
)


def _load_tier_judgment_validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    defs = schema.get("$defs") or {}
    if "tierJudgment" not in defs:
        raise RuntimeError("result-schema.json missing tierJudgment $def")
    # Build a validator that resolves internal $refs against the full document.
    wrapper = {"$ref": "#/$defs/tierJudgment", "$defs": defs}
    Draft202012Validator.check_schema(wrapper)
    return Draft202012Validator(wrapper)


def parse(raw: str) -> tuple[dict, dict]:
    """Return (primary, sidecar) dicts. Sidecar is {} if absent."""
    lines = raw.strip().splitlines()
    if not lines:
        raise ValueError("empty input")

    # First non-empty, non-sentinel line is the primary JSON.
    primary_line = None
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("<!--"):
            continue
        primary_line = stripped
        break
    if primary_line is None:
        raise ValueError("no primary JSON line found")

    try:
        primary = json.loads(primary_line)
    except json.JSONDecodeError as exc:
        raise ValueError(f"primary line is not valid JSON: {exc}") from exc

    sidecar: dict = {}
    m = SIDECAR_RE.search(raw)
    if m:
        try:
            sidecar = json.loads(m.group(1))
        except json.JSONDecodeError as exc:
            raise ValueError(f"sidecar block is not valid JSON: {exc}") from exc
    return primary, sidecar


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--in", dest="input", type=str, default=None,
                    help="Path to LLM output file; defaults to stdin.")
    ap.add_argument("--sidecar-out", type=str, default=None,
                    help="Optional path to write the sidecar JSON.")
    args = ap.parse_args(argv[1:])

    if args.input:
        try:
            raw = Path(args.input).read_text(encoding="utf-8")
        except OSError as exc:
            print(f"error: read failed: {exc}", file=sys.stderr)
            return 2
    else:
        raw = sys.stdin.read()

    try:
        primary, sidecar = parse(raw)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    validator = _load_tier_judgment_validator()
    errors = sorted(validator.iter_errors(primary), key=lambda e: list(e.absolute_path))
    if errors:
        for e in errors:
            loc = "/".join(str(p) for p in e.absolute_path) or "<root>"
            print(f"tier_judgment: {loc}: {e.message}", file=sys.stderr)
        return 1

    if args.sidecar_out:
        try:
            Path(args.sidecar_out).write_text(
                json.dumps(sidecar, indent=2), encoding="utf-8"
            )
        except OSError as exc:
            print(f"error: sidecar write failed: {exc}", file=sys.stderr)
            return 2

    print(json.dumps(primary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
