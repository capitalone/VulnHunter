"""Validate `scan_manifest.schema.json` (HLD Cross-LLD §9 contract).

The schema is vendored by the scan-worker at build time and authored
here. Producer (agent) validates before write; consumer (scan-worker)
validates on read. Both sides depend on this file parsing as a
well-formed Draft 2020-12 schema, so the test bar is:

  1. The file itself is a valid Draft 2020-12 schema.
  2. A representative manifest validates.
  3. The negative cases the contract calls out (wrong version,
     unknown fields, malformed VULN-id) get rejected.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, ValidationError

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "scan_manifest.schema.json"


@pytest.fixture(scope="module")
def schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text())


@pytest.fixture(scope="module")
def validator(schema: dict[str, Any]) -> Draft202012Validator:
    return Draft202012Validator(schema)


@pytest.fixture
def manifest() -> dict[str, Any]:
    """A populated, schema-conformant manifest (every field non-empty)."""
    return {
        "schema_version": "1",
        "scan_id": "example_VULNHUNT_RESULTS_opus47_2026-06-26-153000",
        "agent_exit_code": 0,
        "cost_usd": 38.71,
        "findings": [
            {
                "id": "VULN-001",
                "title": "SQL injection in /users endpoint",
                "cwe": "CWE-89",
                "cwe_name": "SQL Injection",
                "severity": "High",
                "location": "src/users.py:42",
                "root_cause": "String concatenation into raw SQL.",
                "data_flow": "request.GET['id'] -> db.execute(...)",
                "entry_point": "GET /users?id=...",
                "exploit_description": "Attacker controls id parameter.",
                "exploit_impact": "Read arbitrary tables.",
                "fix_strategy": "Use parameterised query.",
                "severity_rationale": "Reachable from unauth public endpoint.",
                "vulnfix_key": "0123456789abcdef",
                "poc_path": "poc/vuln_001.py",
                "exploit_test_path": "exploit_tests/vuln_001.py",
            }
        ],
        "posted": [
            {
                "finding_id": "VULN-001",
                "title": "SQL injection in /users endpoint",
                "url": "https://github.com/owner/repo/issues/42",
            }
        ],
        "skipped": [
            {
                "finding_id": "VULN-002",
                "matched_issue_numbers": [42],
                "via": "key",
            }
        ],
        "failed": [
            {
                "finding_id": "VULN-003",
                "title": "Open redirect",
                "error": "503 Service Unavailable",
            }
        ],
    }


def test_schema_is_valid_draft_2020_12(schema: dict[str, Any]) -> None:
    Draft202012Validator.check_schema(schema)


def test_populated_manifest_validates(
    validator: Draft202012Validator, manifest: dict[str, Any]
) -> None:
    validator.validate(manifest)


def test_empty_findings_manifest_validates(
    validator: Draft202012Validator,
) -> None:
    """Exit-code-1 (scan ran, no findings) shape per SCAN-AGENT-005."""
    validator.validate(
        {
            "schema_version": "1",
            "scan_id": "x_VULNHUNT_RESULTS_opus47_2026-06-26-153000",
            "agent_exit_code": 1,
            "cost_usd": 0.0,
            "findings": [],
            "posted": [],
            "skipped": [],
            "failed": [],
        }
    )


def test_ghec_issue_url_validates(
    validator: Draft202012Validator, manifest: dict[str, Any]
) -> None:
    """Enterprise GitHub hosts (e.g. github.example.com) must validate."""
    manifest["posted"][0]["url"] = (
        "https://github.example.com/owner/repo/issues/1"
    )
    validator.validate(manifest)


def test_via_empty_string_validates(
    validator: Draft202012Validator, manifest: dict[str, Any]
) -> None:
    """The SkippedIssue dataclass defaults `via` to ''; that must validate."""
    manifest["skipped"][0]["via"] = ""
    validator.validate(manifest)


def test_empty_severity_and_cwe_validate(
    validator: Draft202012Validator, manifest: dict[str, Any]
) -> None:
    """The extractor uses '' when a field cannot be determined."""
    manifest["findings"][0]["severity"] = ""
    manifest["findings"][0]["cwe"] = ""
    validator.validate(manifest)


def test_nullable_poc_paths_validate(
    validator: Draft202012Validator, manifest: dict[str, Any]
) -> None:
    manifest["findings"][0]["poc_path"] = None
    manifest["findings"][0]["exploit_test_path"] = None
    validator.validate(manifest)


@pytest.mark.parametrize(
    "field",
    [
        "schema_version",
        "scan_id",
        "agent_exit_code",
        "cost_usd",
        "findings",
        "posted",
        "skipped",
        "failed",
    ],
)
def test_missing_required_top_level_field_rejected(
    validator: Draft202012Validator, manifest: dict[str, Any], field: str
) -> None:
    del manifest[field]
    with pytest.raises(ValidationError):
        validator.validate(manifest)


def test_wrong_schema_version_rejected(
    validator: Draft202012Validator, manifest: dict[str, Any]
) -> None:
    """SCAN-MANIFEST-002: schema_version != '1' fails fast."""
    manifest["schema_version"] = "2"
    with pytest.raises(ValidationError):
        validator.validate(manifest)


def test_extra_top_level_field_rejected(
    validator: Draft202012Validator, manifest: dict[str, Any]
) -> None:
    """`additionalProperties: false` enforces 'schema_version bumps are
    explicit and breaking' — any new field requires a version bump."""
    manifest["unknown_field"] = "x"
    with pytest.raises(ValidationError):
        validator.validate(manifest)


def test_extra_finding_field_rejected(
    validator: Draft202012Validator, manifest: dict[str, Any]
) -> None:
    manifest["findings"][0]["new_attr"] = "x"
    with pytest.raises(ValidationError):
        validator.validate(manifest)


@pytest.mark.parametrize(
    "bad_id", ["VULN-1", "VULN-01", "vuln_001", "VULN-0001", "VULN-", ""]
)
def test_unpadded_vuln_id_rejected(
    validator: Draft202012Validator, manifest: dict[str, Any], bad_id: str
) -> None:
    """Only zero-padded 3-digit VULN-NNN is accepted (per _normalize_vuln_id)."""
    manifest["findings"][0]["id"] = bad_id
    with pytest.raises(ValidationError):
        validator.validate(manifest)


def test_malformed_cwe_rejected(
    validator: Draft202012Validator, manifest: dict[str, Any]
) -> None:
    manifest["findings"][0]["cwe"] = "89"
    with pytest.raises(ValidationError):
        validator.validate(manifest)


def test_invalid_severity_rejected(
    validator: Draft202012Validator, manifest: dict[str, Any]
) -> None:
    manifest["findings"][0]["severity"] = "Catastrophic"
    with pytest.raises(ValidationError):
        validator.validate(manifest)


def test_short_vulnfix_key_rejected(
    validator: Draft202012Validator, manifest: dict[str, Any]
) -> None:
    manifest["findings"][0]["vulnfix_key"] = "deadbeef"  # 8 chars
    with pytest.raises(ValidationError):
        validator.validate(manifest)


def test_non_hex_vulnfix_key_rejected(
    validator: Draft202012Validator, manifest: dict[str, Any]
) -> None:
    manifest["findings"][0]["vulnfix_key"] = "0123456789ABCDEF"  # uppercase
    with pytest.raises(ValidationError):
        validator.validate(manifest)


def test_malformed_issue_url_rejected(
    validator: Draft202012Validator, manifest: dict[str, Any]
) -> None:
    manifest["posted"][0]["url"] = "not-a-url"
    with pytest.raises(ValidationError):
        validator.validate(manifest)


def test_http_issue_url_rejected(
    validator: Draft202012Validator, manifest: dict[str, Any]
) -> None:
    """``github_issue_url`` is HTTPS-only by design — GitHub's REST
    ``html_url`` field is always https on both github.com and GHEC.
    A producer emitting http:// would be either misconfigured or
    something else lying about being GitHub; fail closed."""
    manifest["posted"][0]["url"] = "http://github.com/o/r/issues/1"
    with pytest.raises(ValidationError):
        validator.validate(manifest)


def test_invalid_agent_exit_code_rejected(
    validator: Draft202012Validator, manifest: dict[str, Any]
) -> None:
    manifest["agent_exit_code"] = 6
    with pytest.raises(ValidationError):
        validator.validate(manifest)


def test_negative_cost_rejected(
    validator: Draft202012Validator, manifest: dict[str, Any]
) -> None:
    manifest["cost_usd"] = -1.0
    with pytest.raises(ValidationError):
        validator.validate(manifest)


def test_empty_matched_issue_numbers_rejected(
    validator: Draft202012Validator, manifest: dict[str, Any]
) -> None:
    """`matched_issue_numbers` is the whole point of a skipped record; empty is
    a producer bug — fail loud rather than write a useless DDB pointer."""
    manifest["skipped"][0]["matched_issue_numbers"] = []
    with pytest.raises(ValidationError):
        validator.validate(manifest)


def test_finding_id_in_records_must_match_pattern(
    validator: Draft202012Validator, manifest: dict[str, Any]
) -> None:
    """`finding_id` in posted/skipped/failed is the same VULN-NNN pattern."""
    bad = copy.deepcopy(manifest)
    bad["posted"][0]["finding_id"] = "VULN-1"
    with pytest.raises(ValidationError):
        validator.validate(bad)
    bad = copy.deepcopy(manifest)
    bad["failed"][0]["finding_id"] = "nope"
    with pytest.raises(ValidationError):
        validator.validate(bad)
