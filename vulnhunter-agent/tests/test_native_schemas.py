from __future__ import annotations

import json
from pathlib import Path

from jsonschema.validators import validator_for


def test_all_native_schemas_are_valid() -> None:
    schema_dir = Path(__file__).resolve().parents[1] / "vulnhunter" / "schemas"
    schemas = list(schema_dir.glob("*.schema.json"))
    assert schemas
    for path in schemas:
        schema = json.loads(path.read_text(encoding="utf-8"))
        validator_for(schema).check_schema(schema)
