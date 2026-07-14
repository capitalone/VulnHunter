"""Coverage tests for the four schema-validator CLI scripts.

Each validator loads its schema, reads the target file, and exits with:
  0 on validation pass
  1 on schema violation
  2 on I/O error (unreadable file)
  3 on JSON parse error
  64 on usage error

Covers: scripts/validate-result.py, validate-finding.py, validate-triage.py,
validate-fix-plan.py — the four REQ-SCH-006 entry points.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"


def _load_module(script_name: str, module_name: str):
    """Load a hyphenated CLI script as a module for direct invocation."""
    spec = importlib.util.spec_from_file_location(
        module_name, SCRIPTS / script_name
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def mod_result():
    return _load_module("validate-result.py", "vr")


@pytest.fixture(scope="module")
def mod_finding():
    return _load_module("validate-finding.py", "vf")


@pytest.fixture(scope="module")
def mod_triage():
    return _load_module("validate-triage.py", "vt")


@pytest.fixture(scope="module")
def mod_fix_plan():
    return _load_module("validate-fix-plan.py", "vfp")


def _write(tmp_path: Path, name: str, payload) -> str:
    fp = tmp_path / name
    if isinstance(payload, str):
        fp.write_text(payload, encoding="utf-8")
    else:
        fp.write_text(json.dumps(payload), encoding="utf-8")
    return str(fp)


# ---- validate-result.py ----

def _valid_result():
    return {
        "vuln_id": "VULN-42",
        "status": "VERIFIED_FULL",
        "cwe": "CWE-89",
        "file_path": "src/foo.py",
        "completeness_tier": "FULL",
        "residual_vectors": [],
        "tier_judgment": {
            "invoked": False,
            "phase": None,
            "final_tier": None,
            "rationale": None,
            "failure_reason": None,
        },
        "callers_routed_through_fix": ["src/foo.py:call_it"],
        "callers_not_routed": [],
        # Required non-null for FULL tier (REQ-GRA-017) — see the allOf guard.
        "discrimination_evidence": {
            "method": "stash-and-run",
            "pre_fix_result": "fail",
            "post_fix_result": "pass",
            "assertion_target": "tests/verify_VULN_42.py::test_it",
        },
    }


def test_result_valid_full(mod_result, tmp_path):
    path = _write(tmp_path, "result.json", _valid_result())
    assert mod_result.validate_file(path) == 0


def test_result_full_without_discrimination_rejected(mod_result, tmp_path, capsys):
    """F5 (segment-review S2): a hollow FULL — completeness_tier FULL with
    null/absent discrimination_evidence — used to validate clean, defeating the
    honesty invariant that FULL means proven. The allOf guard must reject it."""
    payload = _valid_result()
    payload["discrimination_evidence"] = None
    assert mod_result.validate_file(_write(tmp_path, "r1.json", payload)) == 1
    payload2 = _valid_result()
    del payload2["discrimination_evidence"]
    assert mod_result.validate_file(_write(tmp_path, "r2.json", payload2)) == 1


def test_result_mitigation_allows_null_discrimination(mod_result, tmp_path):
    """Only FULL requires discrimination_evidence — MITIGATION may omit it."""
    payload = _valid_result()
    payload["completeness_tier"] = "MITIGATION"
    payload["status"] = "VERIFIED_MITIGATION"
    payload["residual_vectors"] = ["one vector remains open"]
    payload["discrimination_evidence"] = None
    assert mod_result.validate_file(_write(tmp_path, "result.json", payload)) == 0


def test_result_already_fixed_full_exempt_from_discrimination(mod_result, tmp_path):
    """Carve-out: an ALREADY_FIXED finding is FULL but has no fix to
    discriminate, so it is exempt from the discrimination_evidence guard
    (the guard fires only for VERIFIED/VERIFIED_FULL)."""
    payload = _valid_result()
    payload["status"] = "ALREADY_FIXED"
    payload["discrimination_evidence"] = None
    assert mod_result.validate_file(_write(tmp_path, "result.json", payload)) == 0


def test_result_valid_mitigation(mod_result, tmp_path):
    payload = _valid_result()
    payload["completeness_tier"] = "MITIGATION"
    payload["residual_vectors"] = ["one vector remains open"]
    payload["status"] = "VERIFIED_MITIGATION"
    path = _write(tmp_path, "result.json", payload)
    assert mod_result.validate_file(path) == 0


def test_result_invalid_missing_field(mod_result, tmp_path, capsys):
    payload = _valid_result()
    del payload["completeness_tier"]
    path = _write(tmp_path, "result.json", payload)
    assert mod_result.validate_file(path) == 1
    err = capsys.readouterr().err
    assert err.strip()  # at minimum, a diagnostic was printed


def test_result_invalid_wrong_enum(mod_result, tmp_path):
    payload = _valid_result()
    payload["completeness_tier"] = "BOGUS_TIER"
    path = _write(tmp_path, "result.json", payload)
    assert mod_result.validate_file(path) == 1


def test_result_full_with_residuals_rejected(mod_result, tmp_path):
    payload = _valid_result()
    payload["residual_vectors"] = ["something leftover"]  # invalid for FULL
    path = _write(tmp_path, "result.json", payload)
    # allOf constraint enforces empty residuals when tier == FULL
    assert mod_result.validate_file(path) == 1


def test_result_full_with_hollow_discrimination_rejected(mod_result, tmp_path):
    """S1 (12-seg review): a hollow `discrimination_evidence: {}` validated
    clean for FULL+VERIFIED because the guard only asserted type:object with no
    inner required fields — hollow proof accepted, honesty invariant defeated.
    The guard must require method + pre_fix_result + post_fix_result present."""
    payload = _valid_result()
    payload["discrimination_evidence"] = {}
    assert mod_result.validate_file(_write(tmp_path, "hollow.json", payload)) == 1


def test_result_full_with_pre_fix_pass_rejected(mod_result, tmp_path):
    """S1: a test whose pre_fix_result is 'pass' does not discriminate the fix
    (compute-completeness-tier.py credits FULL only on pre==fail && post==pass).
    The schema was looser than its consumer — a non-discriminating result was
    schema-valid but silently dropped. FULL must require pre=fail/post=pass."""
    payload = _valid_result()
    payload["discrimination_evidence"] = {
        "method": "stash-and-run",
        "pre_fix_result": "pass",   # non-discriminating
        "post_fix_result": "pass",
        "assertion_target": "tests/verify_VULN_42.py::test_it",
    }
    assert mod_result.validate_file(_write(tmp_path, "prepass.json", payload)) == 1


def test_result_full_with_post_fix_fail_rejected(mod_result, tmp_path):
    """S1: post_fix_result must be 'pass' for a FULL result (the fix made the
    test green). A FULL claim with post=fail is incoherent."""
    payload = _valid_result()
    payload["discrimination_evidence"] = {
        "method": "stash-and-run",
        "pre_fix_result": "fail",
        "post_fix_result": "fail",
        "assertion_target": "tests/verify_VULN_42.py::test_it",
    }
    assert mod_result.validate_file(_write(tmp_path, "postfail.json", payload)) == 1


def test_empty_aggregate_rejected(mod_result, tmp_path):
    """S1 MEDIUM: an empty aggregate {"branches": []} validated as PASS — a
    zero-finding run passed vacuously. Require at least one branch."""
    assert mod_result.validate_file(_write(tmp_path, "agg.json", {"branches": []})) == 1


def test_valid_full_discrimination_still_accepted(mod_result, tmp_path):
    """Allow-path guard: a properly-discriminating FULL result (pre=fail,
    post=pass, non-empty fields) must STILL validate after the tightening."""
    assert mod_result.validate_file(_write(tmp_path, "ok.json", _valid_result())) == 0


def test_result_sweep_revised_forbids_full(mod_result, tmp_path):
    """S4 (12-seg review): the sweep emits sweep_revised=true when an
    unmitigated sibling remains (REQ-SWP-006), but nothing enforced it on the
    result — a sibling could ship as FULL. A result carrying sweep_revised=true
    must NOT be completeness_tier FULL."""
    payload = _valid_result()
    payload["sweep_revised"] = True   # sweep found an unmitigated sibling
    # still FULL + empty residuals → must be rejected
    assert mod_result.validate_file(_write(tmp_path, "sr.json", payload)) == 1


def test_result_sweep_revised_ok_for_mitigation(mod_result, tmp_path):
    """Allow-path: sweep_revised=true is coherent with MITIGATION + residuals."""
    payload = _valid_result()
    payload["sweep_revised"] = True
    payload["completeness_tier"] = "MITIGATION"
    payload["status"] = "VERIFIED_MITIGATION"
    payload["residual_vectors"] = ["sweep: sibling defect at other.py:caller_bad remains"]
    payload["discrimination_evidence"] = None
    assert mod_result.validate_file(_write(tmp_path, "sr2.json", payload)) == 0



def test_result_missing_file(mod_result, capsys):
    rc = mod_result.validate_file("/nonexistent/path/result.json")
    assert rc == 2
    assert "<io>" in capsys.readouterr().err


def test_result_bad_json(mod_result, tmp_path, capsys):
    path = _write(tmp_path, "result.json", "{ not valid json")
    rc = mod_result.validate_file(path)
    assert rc == 3
    assert "<parse>" in capsys.readouterr().err


def test_result_usage_error(mod_result, capsys):
    assert mod_result.main(["validate-result.py"]) == 64
    assert "usage:" in capsys.readouterr().err


def test_result_main_pass(mod_result, tmp_path):
    path = _write(tmp_path, "result.json", _valid_result())
    assert mod_result.main(["validate-result.py", path]) == 0


# ---- validate-finding.py ----

def _valid_finding():
    return {
        "id": "VULN-1",
        "title": "Injection issue",
        "cwe": "CWE-89",
        "severity": "High",
        "status": "Confirmed",
    }


def test_finding_valid_single(mod_finding, tmp_path):
    path = _write(tmp_path, "f.json", _valid_finding())
    assert mod_finding.validate_file(path) == 0


def test_finding_valid_aggregate(mod_finding, tmp_path):
    path = _write(
        tmp_path,
        "f.json",
        {"findings": [_valid_finding(), _valid_finding()]},
    )
    assert mod_finding.validate_file(path) == 0


def test_finding_invalid_aggregate(mod_finding, tmp_path, capsys):
    bad = _valid_finding()
    bad["severity"] = "SuperCritical"
    path = _write(tmp_path, "f.json", {"findings": [_valid_finding(), bad]})
    assert mod_finding.validate_file(path) == 1
    err = capsys.readouterr().err
    assert "findings[1]" in err


def test_finding_invalid_single(mod_finding, tmp_path):
    payload = _valid_finding()
    payload["cwe"] = "not-a-cwe"
    path = _write(tmp_path, "f.json", payload)
    assert mod_finding.validate_file(path) == 1


def test_finding_missing_file(mod_finding):
    assert mod_finding.validate_file("/no/such.json") == 2


def test_finding_bad_json(mod_finding, tmp_path):
    path = _write(tmp_path, "f.json", "{bad")
    assert mod_finding.validate_file(path) == 3


def test_finding_usage_error(mod_finding):
    assert mod_finding.main(["validate-finding.py"]) == 64


def test_finding_main_pass(mod_finding, tmp_path):
    path = _write(tmp_path, "f.json", _valid_finding())
    assert mod_finding.main(["validate-finding.py", path]) == 0


# ---- validate-triage.py ----

def _valid_triage():
    return {
        "vuln_id": "VULN-7",
        "confidence": "high",
        "sink_symbol": "src/auth.py:login",
        "callers_of_sink": ["src/handlers.py:on_login"],
        "graph_backend": "ast",
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def test_triage_valid_high_confidence(mod_triage, tmp_path):
    path = _write(tmp_path, "t.json", _valid_triage())
    assert mod_triage.validate_file(path) == 0


def test_triage_valid_low_confidence(mod_triage, tmp_path):
    payload = _valid_triage()
    payload["confidence"] = "low"
    payload["graph_backend"] = "grep"
    path = _write(tmp_path, "t.json", payload)
    assert mod_triage.validate_file(path) == 0


def test_triage_confidence_backend_mismatch(mod_triage, tmp_path):
    payload = _valid_triage()
    payload["confidence"] = "low"
    payload["graph_backend"] = "ast"  # inconsistent
    path = _write(tmp_path, "t.json", payload)
    assert mod_triage.validate_file(path) == 1


def test_triage_missing_required(mod_triage, tmp_path):
    payload = _valid_triage()
    del payload["vuln_id"]
    path = _write(tmp_path, "t.json", payload)
    assert mod_triage.validate_file(path) == 1


def test_triage_missing_file(mod_triage):
    assert mod_triage.validate_file("/no/such.json") == 2


def test_triage_bad_json(mod_triage, tmp_path):
    path = _write(tmp_path, "t.json", "not-json")
    assert mod_triage.validate_file(path) == 3


def test_triage_usage_error(mod_triage):
    assert mod_triage.main(["validate-triage.py"]) == 64


def test_triage_main_pass(mod_triage, tmp_path):
    path = _write(tmp_path, "t.json", _valid_triage())
    assert mod_triage.main(["validate-triage.py", path]) == 0


# ---- validate-fix-plan.py ----

def _valid_fix_plan():
    return {
        "vuln_id": "VULN-3",
        "cwe": "CWE-79",
        "strategy": "Escape output at render time.",
        "files_to_change": ["src/render.py"],
        "why_this_works": "Downstream sinks are HTML-safe.",
        "projected_completeness_tier": "FULL",
        "tier_judgment": {
            "invoked": False,
            "phase": None,
            "final_tier": None,
            "rationale": None,
            "failure_reason": None,
        },
    }


def test_fix_plan_valid_full(mod_fix_plan, tmp_path):
    path = _write(tmp_path, "p.json", _valid_fix_plan())
    assert mod_fix_plan.validate_file(path) == 0


def test_fix_plan_valid_mitigation_with_residuals(mod_fix_plan, tmp_path):
    payload = _valid_fix_plan()
    payload["projected_completeness_tier"] = "MITIGATION"
    payload["projected_residual_vectors"] = ["one vector left"]
    path = _write(tmp_path, "p.json", payload)
    assert mod_fix_plan.validate_file(path) == 0


def test_fix_plan_mitigation_without_residuals_rejected(mod_fix_plan, tmp_path):
    payload = _valid_fix_plan()
    payload["projected_completeness_tier"] = "MITIGATION"
    path = _write(tmp_path, "p.json", payload)
    assert mod_fix_plan.validate_file(path) == 1


def test_fix_plan_invalid_cwe_shape(mod_fix_plan, tmp_path):
    payload = _valid_fix_plan()
    payload["cwe"] = "not-cwe"
    path = _write(tmp_path, "p.json", payload)
    assert mod_fix_plan.validate_file(path) == 1


def test_fix_plan_missing_file(mod_fix_plan):
    assert mod_fix_plan.validate_file("/no/such.json") == 2


def test_fix_plan_bad_json(mod_fix_plan, tmp_path):
    path = _write(tmp_path, "p.json", "{ trailing")
    assert mod_fix_plan.validate_file(path) == 3


def test_fix_plan_usage_error(mod_fix_plan):
    assert mod_fix_plan.main(["validate-fix-plan.py"]) == 64


def test_fix_plan_main_pass(mod_fix_plan, tmp_path):
    path = _write(tmp_path, "p.json", _valid_fix_plan())
    assert mod_fix_plan.main(["validate-fix-plan.py", path]) == 0
