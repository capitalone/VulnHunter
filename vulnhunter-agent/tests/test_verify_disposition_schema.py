"""Validate `verify_disposition.schema.json` (fix-verify contract).

This is the per-vulnerability verdict file written by the
`/vulnhunt-fix-verify` skill. The schema is the contract between the
skill (producer) and any downstream tooling that wants to act on
verify verdicts (consumers).

The test bar mirrors `test_scan_manifest_schema.py`:

  1. The file itself is a valid Draft 2020-12 schema.
  2. A representative disposition validates.
  3. The negative cases the contract calls out (wrong version,
     unknown fields, malformed VULN-id, invalid verdict/gate status)
     get rejected.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, ValidationError

SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "verify_disposition.schema.json"
)


@pytest.fixture(scope="module")
def schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text())


@pytest.fixture(scope="module")
def validator(schema: dict[str, Any]) -> Draft202012Validator:
    return Draft202012Validator(schema)


@pytest.fixture
def disposition_doc() -> dict[str, Any]:
    """A populated, schema-conformant disposition document."""
    return {
        "schema_version": "1",
        "scan_id": "widget-service_VULNHUNT_RESULTS_opus47_2026-06-26-153000",
        "target_repo": {
            "path": "/work/widget-service",
            "head_commit": "a3b9f12",
            "head_ref": "fix/sql-injection-batch",
            "additional_repos": [],
        },
        "verified_at": "2026-06-27T14:32:17Z",
        "comments_evaluation": {
            "provided": True,
            "claims": [
                {
                    "excerpt": "We now escape the search parameter in handlers/search.go:142",
                    "status": "accepted",
                    "rationale": "R5: file exists; escape call present at cited location.",
                    "cited_location": "handlers/search.go:142",
                },
                {
                    "excerpt": "All inputs are trusted because they come from the API gateway",
                    "status": "rejected_unverifiable",
                    "rationale": "R4: bare trust assertion with no code citation.",
                },
            ],
        },
        "dispositions": [
            {
                "finding_id": "VULN-001",
                "verdict": "FIXED",
                "rationale": "SQL sink at db/queries.go:88 now uses parameterized query; sweep returned no other instances.",
                "issue_comment": "**VulnHunter Fix-Verify: ✅ Confirmed Fixed**\n\nThe SQL sink at `db/queries.go:88` now uses a parameterized query (`db.QueryRow($1, id)`), eliminating the class.\n\n| sink_mitigated | reachability | class_eliminated | sweep_complete |\n|:-:|:-:|:-:|:-:|\n| ✓ | ✓ | ✓ | ✓ |\n\nVerified against `widget-service` @ `a3b9f12`.",
                "gates": {
                    "sink_mitigated": "pass",
                    "reachability": "pass",
                    "class_eliminated": "pass",
                    "sweep_complete": "pass",
                },
                "evidence": [
                    {
                        "kind": "sink_inspection",
                        "location": "db/queries.go:88",
                        "detail": "fmt.Sprintf replaced with parameterized $1 placeholder.",
                    },
                    {
                        "kind": "sweep_grep",
                        "location": "db/",
                        "detail": "Pattern `fmt.Sprintf.*SELECT` returned 0 matches.",
                    },
                ],
            }
        ],
    }


# -- schema validity & happy path ------------------------------------------


def test_schema_is_valid_draft_2020_12(schema: dict[str, Any]) -> None:
    Draft202012Validator.check_schema(schema)


def test_populated_disposition_validates(
    validator: Draft202012Validator, disposition_doc: dict[str, Any]
) -> None:
    validator.validate(disposition_doc)


def test_clone_request_shape_rejected_by_disposition_schema(
    validator: Draft202012Validator,
) -> None:
    """Defense-in-depth: a stray "clone-request"-shaped payload (left
    over from the retired CLONE_REQUEST mechanism, or hand-written by
    mistake) must NOT validate against the disposition schema. The
    schema rejects it because none of the required disposition fields
    are present, not because of any explicit anti-clone-request rule.
    Worth keeping as a regression test in case someone tries to repurpose
    ``verify_disposition.schema.json`` for both shapes again."""
    clone_request_shape = {
        "schema_version": "1",
        "status": "needs_additional_sources",
        "requested_sources": [
            {
                "claim_excerpt": "see ../other-repo/foo",
                "repo_hint": "../other-repo",
                "reason": "cross-repo",
            }
        ],
        "instructions": "...",
    }
    with pytest.raises(ValidationError):
        validator.validate(clone_request_shape)


# -- target_repo head metadata --------------------------------------------


@pytest.mark.parametrize(
    "head_commit", ["abc1234", "a3b9f12abcd5678", "0" * 40, ""]
)
def test_valid_head_commit_shapes(
    validator: Draft202012Validator,
    disposition_doc: dict[str, Any],
    head_commit: str,
) -> None:
    """Accept 7-40 lowercase hex chars OR the empty string (when .git
    isn't readable). Anything else must be rejected."""
    disposition_doc["target_repo"]["head_commit"] = head_commit
    validator.validate(disposition_doc)


@pytest.mark.parametrize(
    "bad_head_commit",
    [
        "abc",  # < 7 chars
        "0" * 41,  # > 40 chars
        "ABC1234",  # uppercase
        "ghijklmnop",  # non-hex
        "abc 123",  # space
    ],
)
def test_malformed_head_commit_rejected(
    validator: Draft202012Validator,
    disposition_doc: dict[str, Any],
    bad_head_commit: str,
) -> None:
    disposition_doc["target_repo"]["head_commit"] = bad_head_commit
    with pytest.raises(ValidationError):
        validator.validate(disposition_doc)


def test_empty_head_ref_validates(
    validator: Draft202012Validator, disposition_doc: dict[str, Any]
) -> None:
    """When .git/HEAD can't be parsed, head_ref is '' — that must
    validate so the skill doesn't fail-close on every detached
    checkout."""
    disposition_doc["target_repo"]["head_ref"] = ""
    validator.validate(disposition_doc)


def test_additional_repos_populated_validates(
    validator: Draft202012Validator, disposition_doc: dict[str, Any]
) -> None:
    """When the caller passes additional_repos at kickoff (typically
    in response to a prior clone-request), the verdict records them
    for audit. Multiple entries are allowed."""
    disposition_doc["target_repo"]["additional_repos"] = [
        "/work/platform-validators",
        "/work/shared-libs",
    ]
    validator.validate(disposition_doc)


def test_missing_additional_repos_rejected(
    validator: Draft202012Validator, disposition_doc: dict[str, Any]
) -> None:
    """additional_repos is required (with an empty array when none
    supplied) so consumers always know what the trusted-roots set
    was. Omitting it is a schema violation."""
    del disposition_doc["target_repo"]["additional_repos"]
    with pytest.raises(ValidationError):
        validator.validate(disposition_doc)


def test_non_string_additional_repos_entry_rejected(
    validator: Draft202012Validator, disposition_doc: dict[str, Any]
) -> None:
    disposition_doc["target_repo"]["additional_repos"] = ["/work/ok", 42]
    with pytest.raises(ValidationError):
        validator.validate(disposition_doc)


# -- comments_evaluation ---------------------------------------------------


def test_comments_not_provided_validates(
    validator: Draft202012Validator, disposition_doc: dict[str, Any]
) -> None:
    """When the caller omits the `comments` arg, provided=false and
    claims=[] must validate."""
    disposition_doc["comments_evaluation"] = {"provided": False, "claims": []}
    validator.validate(disposition_doc)


@pytest.mark.parametrize(
    "claim_status",
    [
        "accepted",
        "rejected_unverifiable",
        "rejected_false",
    ],
)
def test_all_claim_statuses_validate(
    validator: Draft202012Validator,
    disposition_doc: dict[str, Any],
    claim_status: str,
) -> None:
    disposition_doc["comments_evaluation"]["claims"][0]["status"] = claim_status
    validator.validate(disposition_doc)


def test_invalid_claim_status_rejected(
    validator: Draft202012Validator, disposition_doc: dict[str, Any]
) -> None:
    disposition_doc["comments_evaluation"]["claims"][0]["status"] = "maybe"
    with pytest.raises(ValidationError):
        validator.validate(disposition_doc)


def test_claim_without_cited_location_validates(
    validator: Draft202012Validator, disposition_doc: dict[str, Any]
) -> None:
    """cited_location is optional; rejected_unverifiable claims often
    don't have one because the rejection reason IS the lack of citation."""
    claim = disposition_doc["comments_evaluation"]["claims"][1]
    assert "cited_location" not in claim  # sanity-check fixture
    validator.validate(disposition_doc)


# -- dispositions ----------------------------------------------------------


def test_empty_dispositions_rejected(
    validator: Draft202012Validator, disposition_doc: dict[str, Any]
) -> None:
    """At least one finding must be verified — an empty array means
    the run did nothing and should be expressed as INVALID_INPUT on
    each requested ID, not as an empty list."""
    disposition_doc["dispositions"] = []
    with pytest.raises(ValidationError):
        validator.validate(disposition_doc)


@pytest.mark.parametrize(
    "verdict", ["FIXED", "NOT_FIXED", "PARTIAL", "INCONCLUSIVE", "INVALID_INPUT"]
)
def test_all_verdicts_validate(
    validator: Draft202012Validator,
    disposition_doc: dict[str, Any],
    verdict: str,
) -> None:
    disposition_doc["dispositions"][0]["verdict"] = verdict
    validator.validate(disposition_doc)


def test_invalid_verdict_rejected(
    validator: Draft202012Validator, disposition_doc: dict[str, Any]
) -> None:
    disposition_doc["dispositions"][0]["verdict"] = "UNKNOWN"
    with pytest.raises(ValidationError):
        validator.validate(disposition_doc)


@pytest.mark.parametrize(
    "gate_name",
    ["sink_mitigated", "reachability", "class_eliminated", "sweep_complete"],
)
@pytest.mark.parametrize("gate_status", ["pass", "fail", "skipped", "n/a"])
def test_all_gate_statuses_validate(
    validator: Draft202012Validator,
    disposition_doc: dict[str, Any],
    gate_name: str,
    gate_status: str,
) -> None:
    disposition_doc["dispositions"][0]["gates"][gate_name] = gate_status
    validator.validate(disposition_doc)


@pytest.mark.parametrize(
    "gate_name",
    ["sink_mitigated", "reachability", "class_eliminated", "sweep_complete"],
)
def test_missing_required_gate_rejected(
    validator: Draft202012Validator,
    disposition_doc: dict[str, Any],
    gate_name: str,
) -> None:
    """All four v1 gates are required; the exploit_test_replay gate is
    deferred (docs §13) but its absence from the schema means we can't
    accidentally ship without one of the four we DO have."""
    del disposition_doc["dispositions"][0]["gates"][gate_name]
    with pytest.raises(ValidationError):
        validator.validate(disposition_doc)


def test_extra_gate_rejected(
    validator: Draft202012Validator, disposition_doc: dict[str, Any]
) -> None:
    """additionalProperties: false on `gates` ensures the deferred
    exploit_test_replay gate can't be smuggled in without a schema
    bump."""
    disposition_doc["dispositions"][0]["gates"]["exploit_test_replay"] = "pass"
    with pytest.raises(ValidationError):
        validator.validate(disposition_doc)


def test_invalid_gate_status_rejected(
    validator: Draft202012Validator, disposition_doc: dict[str, Any]
) -> None:
    disposition_doc["dispositions"][0]["gates"]["sink_mitigated"] = "yes"
    with pytest.raises(ValidationError):
        validator.validate(disposition_doc)


@pytest.mark.parametrize(
    "bad_id", ["VULN-1", "VULN-01", "vuln_001", "VULN-0001", "VULN-", ""]
)
def test_unpadded_vuln_id_rejected(
    validator: Draft202012Validator,
    disposition_doc: dict[str, Any],
    bad_id: str,
) -> None:
    """Same VULN-NNN rule as scan_manifest.schema.json — zero-padded
    three digits, no exceptions."""
    disposition_doc["dispositions"][0]["finding_id"] = bad_id
    with pytest.raises(ValidationError):
        validator.validate(disposition_doc)


def test_missing_issue_comment_rejected(
    validator: Draft202012Validator, disposition_doc: dict[str, Any]
) -> None:
    """issue_comment is required — it's the GitHub-issue-ready prose
    the downstream integration posts. Omitting it would mean the
    consumer has to synthesize the markdown itself, defeating the
    contract."""
    del disposition_doc["dispositions"][0]["issue_comment"]
    with pytest.raises(ValidationError):
        validator.validate(disposition_doc)


def test_empty_issue_comment_rejected(
    validator: Draft202012Validator, disposition_doc: dict[str, Any]
) -> None:
    """minLength: 1 — an empty string isn't a comment."""
    disposition_doc["dispositions"][0]["issue_comment"] = ""
    with pytest.raises(ValidationError):
        validator.validate(disposition_doc)


def test_empty_evidence_validates(
    validator: Draft202012Validator, disposition_doc: dict[str, Any]
) -> None:
    """INVALID_INPUT verdicts may have no evidence — phase 0 emits them
    without running phase 2 gates."""
    disposition_doc["dispositions"][0]["verdict"] = "INVALID_INPUT"
    disposition_doc["dispositions"][0]["evidence"] = []
    validator.validate(disposition_doc)


@pytest.mark.parametrize(
    "evidence_kind",
    ["sink_inspection", "data_flow_trace", "sweep_grep", "rule_check"],
)
def test_all_evidence_kinds_validate(
    validator: Draft202012Validator,
    disposition_doc: dict[str, Any],
    evidence_kind: str,
) -> None:
    disposition_doc["dispositions"][0]["evidence"][0]["kind"] = evidence_kind
    validator.validate(disposition_doc)


def test_invalid_evidence_kind_rejected(
    validator: Draft202012Validator, disposition_doc: dict[str, Any]
) -> None:
    disposition_doc["dispositions"][0]["evidence"][0]["kind"] = "intuition"
    with pytest.raises(ValidationError):
        validator.validate(disposition_doc)


def test_regressions_optional(
    validator: Draft202012Validator, disposition_doc: dict[str, Any]
) -> None:
    """The regressions array is only populated when sweep_complete=fail;
    its absence must be valid."""
    assert "regressions" not in disposition_doc["dispositions"][0]
    validator.validate(disposition_doc)


def test_regressions_array_validates(
    validator: Draft202012Validator, disposition_doc: dict[str, Any]
) -> None:
    disposition_doc["dispositions"][0]["regressions"] = [
        "templates/admin/profile.html:9",
        "templates/user/profile.html:14",
    ]
    validator.validate(disposition_doc)


# -- top-level required fields & schema_version ---------------------------


@pytest.mark.parametrize(
    "field",
    [
        "schema_version",
        "scan_id",
        "target_repo",
        "verified_at",
        "comments_evaluation",
        "dispositions",
    ],
)
def test_missing_required_top_level_field_rejected(
    validator: Draft202012Validator,
    disposition_doc: dict[str, Any],
    field: str,
) -> None:
    del disposition_doc[field]
    with pytest.raises(ValidationError):
        validator.validate(disposition_doc)


def test_wrong_schema_version_rejected(
    validator: Draft202012Validator, disposition_doc: dict[str, Any]
) -> None:
    disposition_doc["schema_version"] = "2"
    with pytest.raises(ValidationError):
        validator.validate(disposition_doc)


def test_extra_top_level_field_rejected(
    validator: Draft202012Validator, disposition_doc: dict[str, Any]
) -> None:
    """additionalProperties: false at the top level — schema bumps must
    be explicit."""
    disposition_doc["unknown_field"] = "x"
    with pytest.raises(ValidationError):
        validator.validate(disposition_doc)


def test_extra_disposition_field_rejected(
    validator: Draft202012Validator, disposition_doc: dict[str, Any]
) -> None:
    disposition_doc["dispositions"][0]["new_attr"] = "x"
    with pytest.raises(ValidationError):
        validator.validate(disposition_doc)


def test_malformed_scan_id_rejected(
    validator: Draft202012Validator, disposition_doc: dict[str, Any]
) -> None:
    """scan_id must match the *_VULNHUNT_RESULTS_* shape — same as
    scan_manifest.schema.json so the two contracts stay aligned."""
    disposition_doc["scan_id"] = "not-a-scan-id"
    with pytest.raises(ValidationError):
        validator.validate(disposition_doc)
