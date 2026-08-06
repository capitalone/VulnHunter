import json
from pathlib import Path
import pytest
from jsonschema import validate

def test_triage_schema_accepts_lsp_high_confidence():
    schema_path = Path(__file__).parent.parent / "references" / "triage-schema.json"
    with open(schema_path) as f:
        schema = json.load(f)
    
    sample_sidecar = {
        "vuln_id": "VULN-001",
        "confidence": "high",
        "sink_symbol": "src/auth.py:login",
        "callers_of_sink": ["src/app.py:main"],
        "blast_radius": ["src/config.py"],
        "reachable_from_entry": True,
        "graph_backend": "lsp",
        "generated_at": "2026-08-05T12:00:00Z"
    }
    # Should validate without raising jsonschema.ValidationError
    validate(instance=sample_sidecar, schema=schema)
