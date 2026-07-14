#!/usr/bin/env python3
"""Validate a per-finding triage sidecar against references/triage-schema.json.

Usage:
    validate-triage.py <path/to/.work/<repo>/graph_context/<vuln>.json>

Exits 0 on pass, non-zero with a diagnostic on failure, per REQ-SCH-006.
Consumed by Phase 2 (Plan) before it dispatches a worker to confirm the sidecar
carries the expected shape (including crypto_trust_chain for crypto findings).
"""

from __future__ import annotations

import _skill_bootstrap  # noqa: F401  — adds bundled .venv site-packages to sys.path

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "references" / "triage-schema.json"


def _format_error(path: str, err) -> str:
    loc = "/".join(str(p) for p in err.absolute_path) or "<root>"
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

    errors = sorted(Draft202012Validator(schema).iter_errors(payload), key=lambda e: list(e.absolute_path))
    if not errors:
        return 0
    for err in errors:
        print(_format_error(path, err), file=sys.stderr)
    return 1


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: validate-triage.py <path/to/sidecar.json>", file=sys.stderr)
        return 64
    return validate_file(argv[1])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
