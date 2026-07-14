"""Tests for scripts/validate_findings_draft.py."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from validate_findings_draft import ValidationError, validate_payload


def _ok_finding(**overrides) -> dict:
    """A finding with every required field present + sane defaults."""
    base = {
        "id": "VULN-001",
        "title": "SQL injection in user lookup",
        "cwe": "CWE-89",
        "primary_cwe": "CWE-89",
        "severity": "High",
        "status": "Confirmed",
        "location": "src/db.py:42",
        "root_cause": "string concat into query",
        "entry_point": "POST /users",
        "data_flow": "body.id → get_user(id)",
        "proposed_fix": {
            "strategy": "parameterized queries",
            "files_to_change": "src/db.py",
            "why": "binds prevent injection",
        },
    }
    base.update(overrides)
    return base


class TestValidatePayloadHappyPath:
    def test_minimal_valid_payload(self):
        assert validate_payload({"findings": [_ok_finding()]}) == 1

    def test_empty_findings_list_is_valid(self):
        assert validate_payload({"findings": []}) == 0

    def test_multi_cwe_string_accepted_in_cwe_field(self):
        # `cwe` (raw) can be multi-CWE; only `primary_cwe` is constrained.
        f = _ok_finding(cwe="CWE-918 / CWE-74", primary_cwe="CWE-918")
        assert validate_payload({"findings": [f]}) == 1


class TestValidatePayloadTopLevel:
    def test_non_object_rejected(self):
        with pytest.raises(ValidationError, match="top-level"):
            validate_payload([{"findings": []}])

    def test_missing_findings_key(self):
        with pytest.raises(ValidationError, match="missing required keys"):
            validate_payload({})

    def test_findings_not_a_list(self):
        with pytest.raises(ValidationError, match="must be a list"):
            validate_payload({"findings": "not a list"})


class TestValidateFinding:
    def test_missing_required_key(self):
        f = _ok_finding()
        del f["root_cause"]
        with pytest.raises(ValidationError, match="missing required keys.*root_cause"):
            validate_payload({"findings": [f]})

    def test_bad_id_format(self):
        f = _ok_finding(id="VULN-1")  # missing zero-padding
        with pytest.raises(ValidationError, match="id="):
            validate_payload({"findings": [f]})
        f = _ok_finding(id="vuln-001")  # lowercase
        with pytest.raises(ValidationError, match="id="):
            validate_payload({"findings": [f]})

    def test_bad_primary_cwe_format(self):
        f = _ok_finding(primary_cwe="89")  # missing CWE- prefix
        with pytest.raises(ValidationError, match="primary_cwe="):
            validate_payload({"findings": [f]})

    def test_empty_primary_cwe_allowed(self):
        # If the model couldn't extract a CWE, empty string is the
        # documented escape — should pass.
        f = _ok_finding(primary_cwe="")
        assert validate_payload({"findings": [f]}) == 1

    def test_rejects_high_plus_severity(self):
        """High+ must be normalized to Critical UPSTREAM in Step 5a.
        If High+ reaches here, the subagent skipped the normalization.
        """
        f = _ok_finding(severity="High+")
        with pytest.raises(ValidationError, match="severity="):
            validate_payload({"findings": [f]})

    def test_rejects_unconfirmed_status(self):
        f = _ok_finding(status="Suspected")
        with pytest.raises(ValidationError, match="status="):
            validate_payload({"findings": [f]})

    def test_proposed_fix_must_be_object(self):
        f = _ok_finding()
        f["proposed_fix"] = "just a string"
        with pytest.raises(ValidationError, match="proposed_fix must be"):
            validate_payload({"findings": [f]})

    def test_proposed_fix_missing_key(self):
        f = _ok_finding()
        del f["proposed_fix"]["why"]
        with pytest.raises(ValidationError, match="proposed_fix missing.*why"):
            validate_payload({"findings": [f]})

    def test_finding_index_in_error_message(self):
        """When the SECOND finding is bad, the error names index 1."""
        good = _ok_finding()
        bad = _ok_finding(id="not-a-vuln")
        with pytest.raises(ValidationError, match=r"findings\[1\]"):
            validate_payload({"findings": [good, bad]})


class TestCli:
    def test_ok_exit_zero(self, tmp_path, capsys):
        import subprocess
        script = Path(__file__).resolve().parents[1] / "scripts" / "validate_findings_draft.py"
        draft = tmp_path / "findings.draft.json"
        draft.write_text(json.dumps({"findings": [_ok_finding()]}))
        result = subprocess.run(
            [sys.executable, str(script), str(draft)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "ok: 1 findings" in result.stdout

    def test_bad_payload_exit_one_with_directed_error(self, tmp_path):
        import subprocess
        script = Path(__file__).resolve().parents[1] / "scripts" / "validate_findings_draft.py"
        draft = tmp_path / "findings.draft.json"
        draft.write_text(json.dumps({"findings": [_ok_finding(severity="High+")]}))
        result = subprocess.run(
            [sys.executable, str(script), str(draft)],
            capture_output=True, text=True,
        )
        assert result.returncode == 1
        assert "Re-run Step 5a" in result.stderr

    def test_missing_file_exit_one(self, tmp_path):
        import subprocess
        script = Path(__file__).resolve().parents[1] / "scripts" / "validate_findings_draft.py"
        result = subprocess.run(
            [sys.executable, str(script), str(tmp_path / "missing.json")],
            capture_output=True, text=True,
        )
        assert result.returncode == 1
        assert "not found" in result.stderr
