#!/usr/bin/env python3
"""Validate a VulnHunter finding against references/finding-schema.json.

Usage:
    validate-finding.py <path/to/finding.json>

Accepts either a single finding object or the parser's aggregate output
({"findings": [...]}). Exits 0 on pass, non-zero with a single diagnostic on
failure, per REQ-SCH-006.
"""

from __future__ import annotations

import _skill_bootstrap  # noqa: F401  — adds bundled .venv site-packages to sys.path

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "references" / "finding-schema.json"


def _format_error(path: str, err, prefix: str = "") -> str:
    loc = prefix + "/".join(str(p) for p in err.absolute_path) if err.absolute_path else prefix or "<root>"
    return f"{path}: {loc}: {err.message}"


def validate_file(path: str) -> int:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)

    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"{path}: <io>: {exc}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"{path}: <parse>: line {exc.lineno} col {exc.colno}: {exc.msg}", file=sys.stderr)
        return 3

    validator = Draft202012Validator(schema)

    if isinstance(payload, dict) and isinstance(payload.get("findings"), list):
        rc = 0
        for idx, finding in enumerate(payload["findings"]):
            errors = sorted(validator.iter_errors(finding), key=lambda e: list(e.absolute_path))
            for err in errors:
                print(_format_error(path, err, prefix=f"findings[{idx}]/"), file=sys.stderr)
                rc = 1
        return rc

    errors = sorted(validator.iter_errors(payload), key=lambda e: list(e.absolute_path))
    if not errors:
        return 0
    for err in errors:
        print(_format_error(path, err), file=sys.stderr)
    return 1


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: validate-finding.py <path/to/finding.json>", file=sys.stderr)
        return 64
    return validate_file(argv[1])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
