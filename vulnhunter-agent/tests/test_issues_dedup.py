"""Tests for issues_dedup: key fast-path, semantic compare, chunking, fallback."""

from __future__ import annotations

from typing import Any

import pytest

from agent import issues_dedup as dedup_mod
from agent.issues_dedup import dedup
from agent.issues_extract import Finding
from agent.issues_fetch import OpenIssue
from tests._helpers import FakeTokenManager as _FakeTokenManager


def _finding(fid: str, *, key: str = "", **overrides: object) -> Finding:
    base = dict(
        id=fid,
        title=f"finding {fid}",
        cwe="CWE-89",
        cwe_name="SQLi",
        severity="High",
        location=f"src/{fid}.py:1",
        root_cause="rc",
        data_flow="df",
        entry_point="ep",
        exploit_description="ed",
        exploit_impact="ei",
        fix_strategy="fs",
        severity_rationale="sr",
        poc_path=None,
        exploit_test_path=None,
        vulnfix_key=key or f"key_{fid}",
    )
    base.update(overrides)  # type: ignore[arg-type]
    return Finding(**base)  # type: ignore[arg-type]


def _issue(n: int, body: str = "") -> OpenIssue:
    return OpenIssue(
        number=n, title=f"issue {n}", body=body, html_url=f"u/{n}", labels=[]
    )


def _populated_config(populated_agent_config: Any) -> Any:
    """Convenience: tests don't care about scan-stage settings here."""
    return populated_agent_config


class TestKeyFastPath:
    async def test_key_marker_match(
        self, populated_agent_config: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def _empty(**kw: Any) -> Any:
            return {"duplicates": []}

        monkeypatch.setattr(
            dedup_mod._llm, "call_json_with_fallback", _empty
        )
        f1 = _finding("VULN-001", key="aaa")
        f2 = _finding("VULN-002", key="bbb")
        issues = [_issue(42, body="text\n<!-- vulnfix-key: aaa -->\n")]

        decisions = await dedup(
            [f1, f2],
            issues,
            populated_agent_config,
            _FakeTokenManager(),
        )
        by_id = {d.finding_id: d for d in decisions}
        assert by_id["VULN-001"].matched_issues == [42]
        assert by_id["VULN-001"].via == "key"
        assert by_id["VULN-002"].matched_issues == []

    async def test_no_match(
        self, populated_agent_config: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = populated_agent_config
        from dataclasses import replace

        cfg2 = replace(cfg, issues=replace(cfg.issues, semantic_dedup=False))
        decisions = await dedup(
            [_finding("VULN-001", key="zzz")],
            [_issue(1, body="no key here")],
            cfg2,
            _FakeTokenManager(),
        )
        assert decisions[0].matched_issues == []
        assert decisions[0].via == ""


class TestSemanticPass:
    async def test_semantic_match_when_no_key(
        self, populated_agent_config: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: list[tuple[str, str]] = []

        async def fake_call(
            *,
            primary_model: str,
            fallback_model: str,
            system: str,
            user: str,
            **kwargs: Any,
        ) -> Any:
            captured.append((primary_model, user))
            return {
                "duplicates": [
                    {"finding_id": "VULN-001", "issue_numbers": [7]},
                    {"finding_id": "VULN-002", "issue_numbers": []},
                ]
            }

        monkeypatch.setattr(dedup_mod._llm, "call_json_with_fallback", fake_call)

        f1 = _finding("VULN-001", key="aaa")
        f2 = _finding("VULN-002", key="bbb")
        issues = [_issue(7, body="some other body"), _issue(8, body="unrelated")]

        decisions = await dedup(
            [f1, f2],
            issues,
            populated_agent_config,
            _FakeTokenManager(),
        )
        by_id = {d.finding_id: d for d in decisions}
        assert by_id["VULN-001"].matched_issues == [7]
        assert by_id["VULN-001"].via == "semantic"
        assert by_id["VULN-002"].matched_issues == []
        assert len(captured) == 1

    async def test_semantic_skipped_when_disabled(
        self, populated_agent_config: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from dataclasses import replace

        cfg = replace(
            populated_agent_config,
            issues=replace(populated_agent_config.issues, semantic_dedup=False),
        )

        async def boom(**kwargs: Any) -> Any:
            raise AssertionError("semantic compare should not be invoked")

        monkeypatch.setattr(dedup_mod._llm, "call_json_with_fallback", boom)

        decisions = await dedup(
            [_finding("VULN-001", key="zzz")],
            [_issue(1)],
            cfg,
            _FakeTokenManager(),
        )
        assert decisions[0].matched_issues == []

    async def test_invented_issue_numbers_are_dropped(
        self, populated_agent_config: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Model returned an issue number that wasn't in the chunk → drop."""

        async def fake_call(**kwargs: Any) -> Any:
            return {"duplicates": [{"finding_id": "VULN-001", "issue_numbers": [999]}]}

        monkeypatch.setattr(dedup_mod._llm, "call_json_with_fallback", fake_call)

        decisions = await dedup(
            [_finding("VULN-001", key="aaa")],
            [_issue(7), _issue(8)],
            populated_agent_config,
            _FakeTokenManager(),
        )
        assert decisions[0].matched_issues == []


class TestChunking:
    async def test_chunks_when_budget_exceeded(
        self, populated_agent_config: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from dataclasses import replace

        cfg = replace(
            populated_agent_config,
            issues=replace(
                populated_agent_config.issues,
                model_context_tokens=2_000,
                token_budget_fraction=0.5,
            ),
        )

        chunk_sizes: list[int] = []

        async def fake_call(*, user: str, **kwargs: Any) -> Any:
            chunk_sizes.append(user.count('"number"'))
            return {"duplicates": []}

        monkeypatch.setattr(dedup_mod._llm, "call_json_with_fallback", fake_call)

        big = "x" * 8_000
        issues = [_issue(n, body=big) for n in range(1, 6)]

        await dedup(
            [_finding("VULN-001", key="aaa")],
            issues,
            cfg,
            _FakeTokenManager(),
        )
        assert len(chunk_sizes) > 1, f"expected >1 chunk, got {chunk_sizes}"
        assert sum(chunk_sizes) == len(issues)


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
        self, populated_agent_config: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # haiku+sonnet exhausted -> escalate to scan-session model, which succeeds.
        async def fb(**_k: Any) -> Any:
            raise dedup_mod._llm.LLMError("haiku+sonnet down")

        async def cj(**_k: Any) -> Any:
            return {"duplicates": []}

        monkeypatch.setattr(dedup_mod._llm, "call_json_with_fallback", fb)
        monkeypatch.setattr(dedup_mod._llm, "call_json", cj)
        aw = _FakeAudit()
        await dedup(
            [_finding("VULN-001", key="aaa")],
            [_issue(1)],
            populated_agent_config,
            _FakeTokenManager(),
            audit_writer=aw,
        )
        fbk = [r for r in aw.records if r["event_type"] == "model_fallback"]
        assert len(fbk) == 1
        assert fbk[0]["from_model"] == populated_agent_config.issues.sonnet_model
        assert fbk[0]["to_model"] == populated_agent_config.anthropic.model

    async def test_all_tiers_exhausted_emits_model_unavailable_and_raises(
        self, populated_agent_config: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Every tier fails -> emit model_unavailable, then propagate the error.
        async def fb(**_k: Any) -> Any:
            raise dedup_mod._llm.LLMError("haiku+sonnet down")

        async def cj(**_k: Any) -> Any:
            raise dedup_mod._llm.LLMError("scan-model down")

        monkeypatch.setattr(dedup_mod._llm, "call_json_with_fallback", fb)
        monkeypatch.setattr(dedup_mod._llm, "call_json", cj)
        aw = _FakeAudit()
        with pytest.raises(dedup_mod._llm.LLMError):
            await dedup(
                [_finding("VULN-001", key="aaa")],
                [_issue(1)],
                populated_agent_config,
                _FakeTokenManager(),
                audit_writer=aw,
            )
        un = [r for r in aw.records if r["event_type"] == "model_unavailable"]
        assert len(un) == 1
        assert un[0]["from_model"] == populated_agent_config.anthropic.model
