#!/usr/bin/env python3
"""Validate a fix_plan artifact against references/fix_plan-schema.json.

Referenced by phase-prompt Transition Contracts (REQ-SCH-003).
Exits 0 on pass, non-zero with a diagnostic on failure (REQ-SCH-006).

Usage:
    validate-fix-plan.py <path/to/fix_plan.json>
"""

from __future__ import annotations

import _skill_bootstrap  # noqa: F401  — adds bundled .venv site-packages to sys.path

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012


REPO_ROOT = Path(__file__).resolve().parent.parent
REFERENCES_DIR = REPO_ROOT / "references"
SCHEMA_PATH = REFERENCES_DIR / "fix_plan-schema.json"


def _build_registry() -> Registry:
    """Register sibling schemas so cross-file $refs resolve.

    fix_plan-schema.json references result-schema.json#/$defs/tierJudgment.
    """
    registry = Registry()
    for sibling in ("result-schema.json", "fix_plan-schema.json"):
        contents = json.loads((REFERENCES_DIR / sibling).read_text(encoding="utf-8"))
        resource = Resource.from_contents(contents, default_specification=DRAFT202012)
        registry = registry.with_resource(uri=sibling, resource=resource)
    return registry


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

    validator = Draft202012Validator(schema, registry=_build_registry())
    errors = sorted(validator.iter_errors(payload), key=lambda e: list(e.absolute_path))
    if not errors:
        return 0
    for err in errors:
        print(_format_error(path, err), file=sys.stderr)
    return 1


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: validate-fix-plan.py <path/to/fix_plan.json>", file=sys.stderr)
        return 64
    return validate_file(argv[1])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
