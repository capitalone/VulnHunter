"""Coverage tests for scripts/pr-body-check.py (12-seg review S6 — this
script had zero tests). Exercises claim parsing + drift detection without
running the real suite (``_run_suite`` is monkeypatched)."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"


@pytest.fixture(scope="module")
def pbc():
    spec = importlib.util.spec_from_file_location("pbc", SCRIPTS / "pr-body-check.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules["pbc"] = m
    spec.loader.exec_module(m)
    return m


def test_parse_body_claims_extracts_passed_and_coverage(pbc):
    claims = pbc._parse_body_claims("Test plan: 527 passed, 7 skipped. 83.4% coverage.")
    assert claims["claimed_passed"] == 527
    assert claims["claimed_coverage"] == 83.4


def test_parse_body_claims_absent(pbc):
    claims = pbc._parse_body_claims("No numbers in this body.")
    assert claims["claimed_passed"] is None
    assert claims["claimed_coverage"] is None


def test_check_detects_passed_drift(pbc, tmp_path, monkeypatch, capsys):
    body = tmp_path / "b.md"
    body.write_text("Test plan: 999 passed.\n", encoding="utf-8")
    monkeypatch.setattr(pbc, "_run_suite",
                        lambda: {"passed": 500, "coverage_pct": None, "returncode": 0})
    rc = pbc.main(["pr-body-check.py", "check", "--body", str(body)])
    assert rc == 1
    assert "drift" in capsys.readouterr().err.lower()


def test_check_clean_when_claims_match(pbc, tmp_path, monkeypatch):
    body = tmp_path / "b.md"
    body.write_text("Test plan: 500 passed.\n", encoding="utf-8")
    monkeypatch.setattr(pbc, "_run_suite",
                        lambda: {"passed": 500, "coverage_pct": None, "returncode": 0})
    rc = pbc.main(["pr-body-check.py", "check", "--body", str(body)])
    assert rc == 0


def test_check_coverage_tolerance(pbc, tmp_path, monkeypatch):
    """A <=1-point coverage difference is within tolerance (no drift)."""
    body = tmp_path / "b.md"
    body.write_text("Coverage: 83.0% coverage.\n", encoding="utf-8")
    monkeypatch.setattr(pbc, "_run_suite",
                        lambda: {"passed": None, "coverage_pct": 83.5, "returncode": 0})
    assert pbc.main(["pr-body-check.py", "check", "--body", str(body)]) == 0


def test_check_usage_error_without_body(pbc, capsys):
    assert pbc.main(["pr-body-check.py", "check"]) == 2
    assert "--body" in capsys.readouterr().err


def test_check_reports_suite_error(pbc, tmp_path, monkeypatch):
    body = tmp_path / "b.md"
    body.write_text("500 passed\n", encoding="utf-8")
    monkeypatch.setattr(pbc, "_run_suite", lambda: {"error": "pytest not found"})
    assert pbc.main(["pr-body-check.py", "check", "--body", str(body)]) == 2
