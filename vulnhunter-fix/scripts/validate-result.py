#!/usr/bin/env python3
"""Validate a VulnHunter-Fix result.json against references/result-schema.json.

Usage:
    validate-result.py <path/to/result.json>

Exits 0 on validation pass. Exits non-zero with a single diagnostic line on
failure, per REQ-SCH-006. Diagnostic format:
    <path>: <json-path> <reason>

Consumed at every phase transition where result artifacts are handed
forward (REQ-SCH-003) and by the schema-repair loop (REQ-SCH-004).
"""

from __future__ import annotations

import _skill_bootstrap  # noqa: F401  — adds bundled .venv site-packages to sys.path

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "references" / "result-schema.json"


def _format_error(path: str, err) -> str:
    loc = "/".join(str(p) for p in err.absolute_path) or "<root>"
    return f"{path}: {loc}: {err.message}"


def validate_file(path: str) -> int:
    schema_text = SCHEMA_PATH.read_text(encoding="utf-8")
    schema = json.loads(schema_text)
    Draft202012Validator.check_schema(schema)

    try:
        payload_text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"{path}: <io>: {exc}", file=sys.stderr)
        return 2

    try:
        payload = json.loads(payload_text)
    except json.JSONDecodeError as exc:
        print(f"{path}: <parse>: line {exc.lineno} col {exc.colno}: {exc.msg}", file=sys.stderr)
        return 3

    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(payload), key=lambda e: list(e.absolute_path))
    if not errors:
        return 0

    for err in errors:
        print(_format_error(path, err), file=sys.stderr)
    return 1


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: validate-result.py <path/to/result.json>", file=sys.stderr)
        return 64
    return validate_file(argv[1])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
