"""TS-17 — schema repair loop routing (REQ-SCH-004).

Skeleton test. Verifies that when a worker emits a result.json that fails
validation against references/result-schema.json, the caller routes the
finding to the existing repair loop instead of crashing, and that on the
third failure the finding lands in NEEDS_MANUAL_REVIEW (per parent-spec
REQ-TDD-008 semantics).

Under TDD this test is deliberately failing until the phase-prompt wiring
for schema-repair routing lands (task-23) and the repair-loop semantics land
in `prompts/verify.md` / `prompts/implement.md`.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
VALIDATOR = REPO_ROOT / "scripts" / "validate-result.py"


def _write(tmp_path: Path, payload: dict) -> Path:
    p = tmp_path / "result.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def _run_validator(target: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(VALIDATOR), str(target)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_validator_rejects_full_with_residuals(tmp_path):
    payload = {
        "branches": [
            {
                "vuln_id": "VULN-1",
                "status": "VERIFIED",
                "cwe": "CWE-89",
                "file_path": "x.py",
                "completeness_tier": "FULL",
                "residual_vectors": ["should not exist for FULL"],
                "tier_judgment": {
                    "invoked": False,
                    "phase": None,
                    "final_tier": None,
                    "rationale": None,
                    "failure_reason": None,
                },
                "callers_routed_through_fix": [],
                "callers_not_routed": [],
            }
        ]
    }
    result = _run_validator(_write(tmp_path, payload))
    assert result.returncode != 0
    assert result.stderr, "validator must emit a diagnostic line on failure (REQ-SCH-006)"


def test_validator_accepts_valid_mitigation(tmp_path):
    payload = {
        "branches": [
            {
                "vuln_id": "VULN-2",
                "status": "VERIFIED",
                "cwe": "CWE-327",
                "file_path": "crypto.py",
                "completeness_tier": "MITIGATION",
                "residual_vectors": ["trust-chain: algorithm not on approved list"],
                "tier_judgment": {
                    "invoked": True,
                    "phase": "plan",
                    "final_tier": "MITIGATION",
                    "rationale": "algorithm_approved false",
                    "failure_reason": None,
                },
                "callers_routed_through_fix": ["src/api.py:encrypt_field"],
                "callers_not_routed": [],
            }
        ]
    }
    result = _run_validator(_write(tmp_path, payload))
    assert result.returncode == 0, f"expected pass, got: {result.stderr}"


@pytest.mark.skip(reason="harness pending task-23 (repair-loop routing lands with phase-prompt wiring)")
def test_third_failure_routes_to_needs_manual_review():
    """On the third consecutive schema-validation failure, the executor shall
    mark the finding as NEEDS_MANUAL_REVIEW rather than looping indefinitely.

    Requires: scripts/repair-loop harness or executor test double. Filled in
    when the repair-loop wiring lands in task-23.
    """


@pytest.mark.skip(reason="harness pending task-23 (repair-loop routing lands with phase-prompt wiring)")
def test_schema_mismatch_does_not_crash_executor():
    """A malformed worker output must not raise unhandled exceptions; it must
    be caught by the phase orchestrator and routed to the repair phase
    (REQ-SCH-004).
    """
