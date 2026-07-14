"""Tests for issues_extract: Haiku response parsing, file discovery, key computation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from agent import _llm
from agent import issues_extract as extract_mod
from agent.issues_extract import (
    _compute_vulnfix_key,
    _discover_finding_files,
    _scan_date_from_dir,
    extract_findings,
)
from tests._helpers import FakeTokenManager as _TM


@pytest.fixture
def fake_results_dir(tmp_path: Path) -> Path:
    """Build a results directory with README + poc + exploit_tests."""
    results = tmp_path / "myrepo_VULNHUNT_RESULTS_opus47_2026-06-23-141824"
    results.mkdir()
    (results / "README.md").write_text(
        "# Report\n\nFindings: see summary table.\n"
    )
    poc = results / "poc"
    poc.mkdir()
    (poc / "VULN-001_demo.py").write_text("# poc")
    tests = results / "exploit_tests"
    tests.mkdir()
    (tests / "test_vuln_001.py").write_text("# test")
    return results


def _stub_llm(monkeypatch: pytest.MonkeyPatch, response: dict | Exception) -> None:
    async def fake(**kwargs: Any) -> Any:
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(extract_mod._llm, "call_json_with_fallback", fake)


class TestComputeVulnfixKey:
    def test_stable(self) -> None:
        a = _compute_vulnfix_key("src/x.py:1", "CWE-89", "rc")
        b = _compute_vulnfix_key("src/x.py:1", "CWE-89", "rc")
        assert a == b
        assert len(a) == 16

    def test_changes_with_input(self) -> None:
        a = _compute_vulnfix_key("src/x.py:1", "CWE-89", "rc")
        b = _compute_vulnfix_key("src/x.py:2", "CWE-89", "rc")
        assert a != b


class TestScanDateFromDir:
    def test_extracts_date(self) -> None:
        assert (
            _scan_date_from_dir("repo_VULNHUNT_RESULTS_opus47_2026-06-23-141824")
            == "2026-06-23"
        )

    def test_falls_back_to_today(self) -> None:
        out = _scan_date_from_dir("no-timestamp")
        assert len(out) == 10  # YYYY-MM-DD


class TestDiscoverFiles:
    def test_finds_poc_and_test(self, fake_results_dir: Path) -> None:
        files = _discover_finding_files(fake_results_dir)
        # Files are normalized to the canonical zero-padded VULN-NNN form
        # regardless of the source filename (VULN-1 vs VULN-001 vs vuln_1).
        assert "VULN-001" in files
        sample = files["VULN-001"]
        assert "poc" in sample
        assert "exploit_test" in sample


class TestExtractFindings:
    async def test_happy_path(
        self,
        fake_results_dir: Path,
        populated_agent_config: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _stub_llm(
            monkeypatch,
            {
                "findings": [
                    {
                        "id": "VULN-001",
                        "title": "SQL injection",
                        "cwe": "CWE-89",
                        "cwe_name": "SQLi",
                        "severity": "High",
                        "location": "src/db.py:42",
                        "root_cause": "unparameterized",
                        "data_flow": "body→query",
                        "entry_point": "POST /users",
                        "exploit_description": "read all rows",
                        "exploit_impact": "data disclosure",
                        "fix_strategy": "parameterize",
                        "severity_rationale": "PII disclosure",
                    }
                ]
            },
        )


        report = await extract_findings(
            fake_results_dir, populated_agent_config, _TM()
        )
        assert len(report.findings) == 1
        f = report.findings[0]
        assert f.id == "VULN-001"
        assert f.cwe == "CWE-89"
        assert f.poc_path is not None  # discovered from filesystem
        assert f.exploit_test_path is not None
        assert len(f.vulnfix_key) == 16

    async def test_skips_findings_without_id(
        self,
        fake_results_dir: Path,
        populated_agent_config: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _stub_llm(
            monkeypatch,
            {"findings": [{"id": "", "title": "no id", "cwe": "CWE-1"}]},
        )


        report = await extract_findings(
            fake_results_dir, populated_agent_config, _TM()
        )
        assert report.findings == []

    async def test_missing_findings_list_raises(
        self,
        fake_results_dir: Path,
        populated_agent_config: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _stub_llm(monkeypatch, {"not_findings": []})


        with pytest.raises(_llm.LLMError, match="findings"):
            await extract_findings(
                fake_results_dir, populated_agent_config, _TM()
            )

    async def test_missing_readme_raises(
        self,
        tmp_path: Path,
        populated_agent_config: Any,
    ) -> None:
        empty = tmp_path / "no_readme_dir"
        empty.mkdir()


        with pytest.raises(FileNotFoundError):
            await extract_findings(empty, populated_agent_config, _TM())


class _FakeAudit:
    """Captures emit_audit records for assertions."""

    def __init__(self) -> None:
        self.records: list[dict] = []

    def emit_audit(self, record: dict) -> None:
        self.records.append(record)

    def emit_finding(self, record: dict) -> None:  # pragma: no cover
        pass


class TestModelFallbackAudit:
    async def test_scan_model_hop_emits_model_fallback(
        self,
        fake_results_dir: Path,
        populated_agent_config: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # haiku+sonnet exhausted -> escalate to scan-session model, which succeeds.
        async def fb(**_k: Any) -> Any:
            raise _llm.LLMError("haiku+sonnet down")

        async def cj(**_k: Any) -> Any:
            return {"findings": []}

        monkeypatch.setattr(extract_mod._llm, "call_json_with_fallback", fb)
        monkeypatch.setattr(extract_mod._llm, "call_json", cj)
        aw = _FakeAudit()
        await extract_findings(
            fake_results_dir, populated_agent_config, _TM(), audit_writer=aw
        )
        fbk = [r for r in aw.records if r["event_type"] == "model_fallback"]
        assert len(fbk) == 1
        assert fbk[0]["from_model"] == populated_agent_config.issues.sonnet_model
        assert fbk[0]["to_model"] == populated_agent_config.anthropic.model
        assert fbk[0]["stage"] == "extract"

    async def test_all_tiers_exhausted_emits_model_unavailable_and_raises(
        self,
        fake_results_dir: Path,
        populated_agent_config: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Every tier fails -> emit model_unavailable, then propagate the error.
        async def fb(**_k: Any) -> Any:
            raise _llm.LLMError("haiku+sonnet down")

        async def cj(**_k: Any) -> Any:
            raise _llm.LLMError("scan-model down")

        monkeypatch.setattr(extract_mod._llm, "call_json_with_fallback", fb)
        monkeypatch.setattr(extract_mod._llm, "call_json", cj)
        aw = _FakeAudit()
        with pytest.raises(_llm.LLMError):
            await extract_findings(
                fake_results_dir, populated_agent_config, _TM(), audit_writer=aw
            )
        un = [r for r in aw.records if r["event_type"] == "model_unavailable"]
        assert len(un) == 1
        assert un[0]["from_model"] == populated_agent_config.anthropic.model

    async def test_no_event_when_primary_succeeds(
        self,
        fake_results_dir: Path,
        populated_agent_config: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def ok(**_k: Any) -> Any:
            return {"findings": []}

        monkeypatch.setattr(extract_mod._llm, "call_json_with_fallback", ok)
        aw = _FakeAudit()
        await extract_findings(
            fake_results_dir, populated_agent_config, _TM(), audit_writer=aw
        )
        assert aw.records == []
