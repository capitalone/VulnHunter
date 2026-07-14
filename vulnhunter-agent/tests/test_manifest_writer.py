"""Tests for `agent.manifest` — the scan_manifest.json writer.

Producer-side contract for the agent-to-scan-worker manifest. One test
(or parametrized group) per behavior. When the writer module
`agent.manifest` doesn't exist yet, this whole file fails at import —
tests-before-code discipline.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

# Module-under-test — doesn't exist until Phase 6 (implementation) lands.
# All tests in this file fail with ImportError until then. Deliberate.
from agent.manifest import MANIFEST_VALIDATION_FAILURE_PREFIX, write_manifest

from agent._stream_events import SessionTotals
from agent.issues import FailedIssue, PostedIssue, PostSummary, SkippedIssue
from agent.issues_extract import Finding


# ── fixtures / helpers ──────────────────────────────────────────────────────


def _finding(idx: int = 1) -> Finding:
    """One valid Finding matching the schema's `finding` sub-type."""
    return Finding(
        id=f"VULN-{idx:03d}",
        title=f"Test finding {idx}",
        cwe="CWE-89",
        cwe_name="SQL Injection",
        severity="High",
        location=f"src/vuln{idx}.py:42",
        root_cause="unparameterized query",
        data_flow="request.args → db.execute",
        entry_point="POST /api/search",
        exploit_description="union-based",
        exploit_impact="data exfil",
        fix_strategy="parameterize",
        severity_rationale="direct auth boundary",
        vulnfix_key=f"{idx:016x}",
        poc_path="pocs/test.md",
        exploit_test_path="tests/test.py",
    )


def _post_summary(
    posted: list[PostedIssue] | None = None,
    skipped: list[SkippedIssue] | None = None,
    failed: list[FailedIssue] | None = None,
) -> PostSummary:
    return PostSummary(
        posted=posted or [],
        skipped=skipped or [],
        failed=failed or [],
    )


def _totals(cost_usd: float = 1.23) -> SessionTotals:
    t = SessionTotals()
    t.cost_usd = cost_usd
    return t


@pytest.fixture
def results_dir(tmp_path: Path) -> Path:
    """A results directory following the naming convention runner.py enforces."""
    d = tmp_path / "repo_VULNHUNT_RESULTS_opus47_1m_2026-07-04-120000"
    d.mkdir()
    return d


# ── AGENT-MANIFEST-001 ──────────────────────────────────────────────────────


@pytest.mark.parametrize("exit_code", [0, 1, 3, 4])
def test_manifest_written_on_exit_codes_that_produce_results(exit_code: int, results_dir: Path):
    """@spec AGENT-MANIFEST-001: manifest written on exit 0/1/3/4."""
    write_manifest(
        results_dir=results_dir,
        scan_id=results_dir.name,
        agent_exit_code=exit_code,
        totals=_totals(),
        findings=[_finding()],
        post_summary=_post_summary(),
    )
    assert (results_dir / "scan_manifest.json").is_file()


def test_manifest_not_written_when_results_dir_missing(tmp_path: Path):
    """@spec AGENT-MANIFEST-001: predicate requires results_dir to exist."""
    missing = tmp_path / "nonexistent_VULNHUNT_RESULTS_x_y"
    # Writer either raises or short-circuits without writing; either is spec-
    # compliant as long as no manifest ends up on disk under `missing`.
    with pytest.raises((FileNotFoundError, OSError, NotADirectoryError)):
        write_manifest(
            results_dir=missing,
            scan_id=missing.name,
            agent_exit_code=0,
            totals=_totals(),
            findings=[],
            post_summary=_post_summary(),
        )
    assert not missing.exists()


# ── AGENT-MANIFEST-002 ──────────────────────────────────────────────────────


def test_manifest_not_written_on_exit_2(results_dir: Path):
    """@spec AGENT-MANIFEST-002: exit code 2 (publish_failed) never writes."""
    write_manifest(
        results_dir=results_dir,
        scan_id=results_dir.name,
        agent_exit_code=2,
        totals=_totals(),
        findings=[_finding()],
        post_summary=_post_summary(),
    )
    assert not (results_dir / "scan_manifest.json").exists()
    assert not (results_dir / "scan_manifest.json.tmp").exists()


# ── AGENT-MANIFEST-003 ──────────────────────────────────────────────────────


def test_validation_failure_raises_with_stderr_prefix(results_dir: Path, capsys: pytest.CaptureFixture):
    """@spec AGENT-MANIFEST-003: schema-invalid data → raise + stderr prefix + no file."""
    bad = Finding(
        id="VULN-001",
        title="Test",
        cwe="CWE-89",
        cwe_name="SQL Injection",
        # `severity` enum in schema is Critical|High|Medium|Low. This is not.
        severity="Extremely Dangerous",
        location="src/x.py:1",
        root_cause="",
        data_flow="",
        entry_point="",
        exploit_description="",
        exploit_impact="",
        fix_strategy="",
        severity_rationale="",
        vulnfix_key="0" * 16,
    )
    with pytest.raises(Exception) as excinfo:
        write_manifest(
            results_dir=results_dir,
            scan_id=results_dir.name,
            agent_exit_code=0,
            totals=_totals(),
            findings=[bad],
            post_summary=_post_summary(),
        )
    # jsonschema raises ValidationError — accept anything that mentions validation.
    assert "valid" in str(excinfo.value).lower() or "schema" in str(excinfo.value).lower()
    # No partial or final file left on disk.
    assert not (results_dir / "scan_manifest.json").exists()
    assert not (results_dir / "scan_manifest.json.tmp").exists()
    # Stderr carries the metric-filter prefix so CloudWatch can distinguish
    # this from other agent crashes.
    err = capsys.readouterr().err
    assert MANIFEST_VALIDATION_FAILURE_PREFIX in err


# ── AGENT-MANIFEST-004 ──────────────────────────────────────────────────────


def test_scan_id_equals_results_dir_basename(results_dir: Path):
    """@spec AGENT-MANIFEST-004: manifest.scan_id == basename(<results_dir>)."""
    write_manifest(
        results_dir=results_dir,
        scan_id=results_dir.name,
        agent_exit_code=0,
        totals=_totals(),
        findings=[],
        post_summary=_post_summary(),
    )
    m = json.loads((results_dir / "scan_manifest.json").read_text())
    assert m["scan_id"] == results_dir.name


# ── AGENT-MANIFEST-005 ──────────────────────────────────────────────────────


@pytest.mark.parametrize("exit_code", [0, 1, 3, 4])
def test_agent_exit_code_field_matches(exit_code: int, results_dir: Path):
    """@spec AGENT-MANIFEST-005: manifest.agent_exit_code == returned code."""
    write_manifest(
        results_dir=results_dir,
        scan_id=results_dir.name,
        agent_exit_code=exit_code,
        totals=_totals(),
        findings=[],
        post_summary=_post_summary(),
    )
    m = json.loads((results_dir / "scan_manifest.json").read_text())
    assert m["agent_exit_code"] == exit_code


# ── AGENT-MANIFEST-006 ──────────────────────────────────────────────────────


def test_cost_usd_sourced_from_totals(results_dir: Path):
    """@spec AGENT-MANIFEST-006: cost_usd comes from SessionTotals.cost_usd."""
    write_manifest(
        results_dir=results_dir,
        scan_id=results_dir.name,
        agent_exit_code=0,
        totals=_totals(cost_usd=42.99),
        findings=[],
        post_summary=_post_summary(),
    )
    m = json.loads((results_dir / "scan_manifest.json").read_text())
    assert m["cost_usd"] == pytest.approx(42.99)


def test_cost_usd_zero_when_no_result_message(results_dir: Path):
    """@spec AGENT-MANIFEST-006: 0.0 fallback when no ResultMessage was ever seen."""
    write_manifest(
        results_dir=results_dir,
        scan_id=results_dir.name,
        agent_exit_code=4,
        totals=SessionTotals(),  # never updated — running-max stays 0.0
        findings=[],
        post_summary=_post_summary(),
    )
    m = json.loads((results_dir / "scan_manifest.json").read_text())
    assert m["cost_usd"] == 0.0


# ── AGENT-MANIFEST-007 ──────────────────────────────────────────────────────


def test_findings_populated_from_extracted_report(results_dir: Path):
    """@spec AGENT-MANIFEST-007: manifest.findings[] mirrors Finding dataclasses."""
    write_manifest(
        results_dir=results_dir,
        scan_id=results_dir.name,
        agent_exit_code=0,
        totals=_totals(),
        findings=[_finding(1), _finding(2)],
        post_summary=_post_summary(),
    )
    m = json.loads((results_dir / "scan_manifest.json").read_text())
    assert len(m["findings"]) == 2
    assert m["findings"][0]["id"] == "VULN-001"
    assert m["findings"][1]["id"] == "VULN-002"
    assert m["findings"][0]["cwe"] == "CWE-89"


def test_findings_empty_is_valid(results_dir: Path):
    """@spec AGENT-MANIFEST-007: empty findings[] is valid (exit code 1 clean scan)."""
    write_manifest(
        results_dir=results_dir,
        scan_id=results_dir.name,
        agent_exit_code=1,
        totals=_totals(),
        findings=[],
        post_summary=_post_summary(),
    )
    m = json.loads((results_dir / "scan_manifest.json").read_text())
    assert m["findings"] == []


# ── AGENT-MANIFEST-008 ──────────────────────────────────────────────────────


def test_post_summary_arrays_populated(results_dir: Path):
    """@spec AGENT-MANIFEST-008: posted/skipped/failed arrays match PostSummary."""
    posted = [PostedIssue(finding_id="VULN-001", title="t", url="https://github.com/x/y/issues/1")]
    skipped = [SkippedIssue(finding_id="VULN-002", matched_issue_numbers=[42], via="key")]
    failed = [FailedIssue(finding_id="VULN-003", title="t", error="rate limit")]
    write_manifest(
        results_dir=results_dir,
        scan_id=results_dir.name,
        agent_exit_code=0,
        totals=_totals(),
        findings=[_finding()],
        post_summary=_post_summary(posted=posted, skipped=skipped, failed=failed),
    )
    m = json.loads((results_dir / "scan_manifest.json").read_text())
    assert len(m["posted"]) == 1
    assert m["posted"][0]["finding_id"] == "VULN-001"
    assert m["posted"][0]["url"].endswith("/issues/1")
    assert len(m["skipped"]) == 1
    assert m["skipped"][0]["via"] == "key"
    assert len(m["failed"]) == 1
    assert m["failed"][0]["error"] == "rate limit"


# ── AGENT-MANIFEST-010 ──────────────────────────────────────────────────────


def test_atomic_write_uses_os_replace(results_dir: Path, monkeypatch: pytest.MonkeyPatch):
    """@spec AGENT-MANIFEST-010: manifest committed via os.replace, not raw write."""
    replace_calls: list[tuple[str, str]] = []
    original_replace = os.replace

    def spy(src, dst):
        replace_calls.append((str(src), str(dst)))
        return original_replace(src, dst)

    monkeypatch.setattr("os.replace", spy)
    write_manifest(
        results_dir=results_dir,
        scan_id=results_dir.name,
        agent_exit_code=0,
        totals=_totals(),
        findings=[],
        post_summary=_post_summary(),
    )
    assert len(replace_calls) == 1
    src, dst = replace_calls[0]
    assert src.endswith(".tmp")
    assert dst.endswith("scan_manifest.json")


def test_no_final_file_when_replace_fails(results_dir: Path, monkeypatch: pytest.MonkeyPatch):
    """@spec AGENT-MANIFEST-010: mid-write crash leaves no valid scan_manifest.json."""

    def failing(src, dst):
        raise OSError("simulated crash mid-rename")

    monkeypatch.setattr("os.replace", failing)
    with pytest.raises(OSError):
        write_manifest(
            results_dir=results_dir,
            scan_id=results_dir.name,
            agent_exit_code=0,
            totals=_totals(),
            findings=[],
            post_summary=_post_summary(),
        )
    assert not (results_dir / "scan_manifest.json").exists()


# ── AGENT-MANIFEST-011 ──────────────────────────────────────────────────────
# The write-before-publish ordering invariant is enforced at the caller
# (runner.py) — the writer itself just needs to make the file fully readable
# on disk before it returns. Runner-level integration test lives in
# test_runner.py after wiring; here we assert the primitive.


def test_manifest_readable_when_write_returns(results_dir: Path):
    """@spec AGENT-MANIFEST-011: file is complete + readable on return."""
    write_manifest(
        results_dir=results_dir,
        scan_id=results_dir.name,
        agent_exit_code=0,
        totals=_totals(),
        findings=[],
        post_summary=_post_summary(),
    )
    # If the caller invokes publish.py after this returns, the file must be
    # fully committed and parseable.
    text = (results_dir / "scan_manifest.json").read_text()
    parsed = json.loads(text)
    assert parsed["schema_version"] == "1"
