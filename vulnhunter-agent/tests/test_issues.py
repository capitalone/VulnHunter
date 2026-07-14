"""Tests for the issues stage orchestrator: ensure_label, _create_issue, post_issues, summary."""

from __future__ import annotations

import json
import logging
from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from agent import issues as issues_mod
from agent import issues_dedup as dedup_mod
from agent import issues_extract as extract_mod
from agent import issues_fetch as fetch_mod
from agent.audit import AuditPaths, AuditWriter
from agent.issues import (
    FailedIssue,
    IssuePostError,
    IssuesStageError,
    PostedIssue,
    PostSummary,
    SkippedIssue,
    _create_issue,
    _ensure_all_labels,
    _ensure_label,
    _github_default_headers,
    build_report_url_for_local_scan,
    build_report_url_for_remote_report,
    post_issues,
    print_summary,
)
from agent.issues_dedup import DedupDecision
from agent.issues_extract import ExtractedReport, Finding
from agent.issues_fetch import OpenIssue
from tests._helpers import FakeTokenManager as _TM


def _finding(fid: str = "VULN-001", *, key: str = "abc12300000def00") -> Finding:
    return Finding(
        id=fid,
        title=f"title {fid}",
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
        vulnfix_key=key,
    )


@pytest.fixture(autouse=True)
def _stub_resolve_verify(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force verify=True to avoid a str-verify deprecation in respx tests."""
    monkeypatch.setattr(issues_mod, "resolve_verify", lambda tls: True)
    monkeypatch.setattr(fetch_mod, "resolve_verify", lambda tls: True)


# ---------------------------------------------------------------------------
# _ensure_label
# ---------------------------------------------------------------------------


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        verify=True, timeout=10, headers=_github_default_headers()
    )


class TestEnsureLabel:
    @respx.mock
    async def test_existing_label_no_create(self) -> None:
        get_route = respx.get(
            "https://api.github.com/repos/o/r/labels/security"
        ).mock(return_value=httpx.Response(200, json={"name": "security"}))
        post_route = respx.post(
            "https://api.github.com/repos/o/r/labels"
        ).mock(return_value=httpx.Response(201, json={}))
        async with _client() as client:
            await _ensure_label(
                client,
                api="https://api.github.com",
                owner="o",
                name="r",
                label="security",
            )
        assert get_route.called
        assert not post_route.called

    @respx.mock
    async def test_missing_label_creates(self) -> None:
        respx.get("https://api.github.com/repos/o/r/labels/security").mock(
            return_value=httpx.Response(404, text="not found")
        )
        post_route = respx.post(
            "https://api.github.com/repos/o/r/labels"
        ).mock(return_value=httpx.Response(201, json={}))
        async with _client() as client:
            await _ensure_label(
                client,
                api="https://api.github.com",
                owner="o",
                name="r",
                label="security",
            )
        assert post_route.called

    @respx.mock
    async def test_unexpected_status_raises(self) -> None:
        respx.get("https://api.github.com/repos/o/r/labels/security").mock(
            return_value=httpx.Response(500, text="server error")
        )
        with pytest.raises(IssuesStageError, match="checking label"):
            async with _client() as client:
                await _ensure_label(
                    client,
                    api="https://api.github.com",
                    owner="o",
                    name="r",
                    label="security",
                )

    @respx.mock
    async def test_create_failure_raises(self) -> None:
        respx.get("https://api.github.com/repos/o/r/labels/security").mock(
            return_value=httpx.Response(404)
        )
        respx.post("https://api.github.com/repos/o/r/labels").mock(
            return_value=httpx.Response(403, text="forbidden")
        )
        with pytest.raises(IssuesStageError, match="creating label"):
            async with _client() as client:
                await _ensure_label(
                    client,
                    api="https://api.github.com",
                    owner="o",
                    name="r",
                    label="security",
                )

    @respx.mock
    async def test_uses_default_color_for_unknown_label(self) -> None:
        respx.get("https://api.github.com/repos/o/r/labels/custom-x").mock(
            return_value=httpx.Response(404)
        )
        post_route = respx.post(
            "https://api.github.com/repos/o/r/labels"
        ).mock(return_value=httpx.Response(201, json={}))
        async with _client() as client:
            await _ensure_label(
                client,
                api="https://api.github.com",
                owner="o",
                name="r",
                label="custom-x",
            )
        body = post_route.calls.last.request.read().decode()
        assert "ededed" in body  # _DEFAULT_LABEL_COLOR

    @respx.mock
    async def test_url_encodes_label_with_special_chars(self) -> None:
        # Labels can contain spaces; the GET path must URL-encode the
        # label so the request hits the right endpoint.
        respx.get(
            "https://api.github.com/repos/o/r/labels/needs%20triage"
        ).mock(return_value=httpx.Response(200, json={"name": "needs triage"}))
        async with _client() as client:
            await _ensure_label(
                client,
                api="https://api.github.com",
                owner="o",
                name="r",
                label="needs triage",
            )

    @respx.mock
    async def test_concurrent_create_422_returns_ok(self) -> None:
        # Race: another run created the label between our GET (404) and
        # our POST (422 already_exists). Re-GET sees it and we proceed.
        respx.get("https://api.github.com/repos/o/r/labels/security").mock(
            side_effect=[
                httpx.Response(404),
                httpx.Response(200, json={"name": "security"}),
            ]
        )
        respx.post("https://api.github.com/repos/o/r/labels").mock(
            return_value=httpx.Response(
                422,
                json={
                    "message": "Validation Failed",
                    "errors": [
                        {
                            "resource": "Label",
                            "code": "already_exists",
                            "field": "name",
                        }
                    ],
                },
            )
        )
        async with _client() as client:
            await _ensure_label(
                client,
                api="https://api.github.com",
                owner="o",
                name="r",
                label="security",
            )

    @respx.mock
    async def test_422_without_label_existing_still_raises(self) -> None:
        # 422 from POST + re-GET 404 means it's a real validation
        # failure (not a race), so we must still surface it.
        respx.get("https://api.github.com/repos/o/r/labels/security").mock(
            return_value=httpx.Response(404)
        )
        respx.post("https://api.github.com/repos/o/r/labels").mock(
            return_value=httpx.Response(422, text="bad color")
        )
        with pytest.raises(IssuesStageError, match="creating label"):
            async with _client() as client:
                await _ensure_label(
                    client,
                    api="https://api.github.com",
                    owner="o",
                    name="r",
                    label="security",
                )


# ---------------------------------------------------------------------------
# _ensure_all_labels
# ---------------------------------------------------------------------------


class TestEnsureAllLabels:
    async def test_no_token_raises(self, populated_agent_config: Any) -> None:
        cfg = replace(
            populated_agent_config,
            github=replace(populated_agent_config.github, scan_token=""),
        )
        with pytest.raises(IssuesStageError, match="scan_token"):
            await _ensure_all_labels(
                target_repo_url="https://github.com/o/r",
                config=cfg,
                verify=True,
            )

    @respx.mock
    async def test_creates_each_missing_label(
        self, populated_agent_config: Any
    ) -> None:
        cfg = replace(
            populated_agent_config,
            github=replace(populated_agent_config.github, scan_token="t"),
        )
        respx.get("https://api.github.com/repos/o/r/labels/security").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://api.github.com/repos/o/r/labels/vulnhunter").mock(
            return_value=httpx.Response(404)
        )
        post = respx.post("https://api.github.com/repos/o/r/labels").mock(
            return_value=httpx.Response(201, json={})
        )
        await _ensure_all_labels(
            target_repo_url="https://github.com/o/r",
            config=cfg,
            verify=True,
        )
        assert post.call_count == 2


# ---------------------------------------------------------------------------
# _create_issue
# ---------------------------------------------------------------------------


class TestCreateIssue:
    @respx.mock
    async def test_201_returns_url(self) -> None:
        respx.post("https://api.github.com/repos/o/r/issues").mock(
            return_value=httpx.Response(
                201, json={"html_url": "https://github.com/o/r/issues/42"}
            )
        )
        async with _client() as client:
            url = await _create_issue(
                client,
                api="https://api.github.com",
                owner="o",
                name="r",
                title="t",
                body="b",
                labels=["security"],
            )
        assert url == "https://github.com/o/r/issues/42"

    @respx.mock
    async def test_201_without_html_url_raises(self) -> None:
        # Defensive: if GitHub ever returns 201 without html_url, we'd
        # rather fail loud than store an empty URL in the summary.
        respx.post("https://api.github.com/repos/o/r/issues").mock(
            return_value=httpx.Response(201, json={})
        )
        with pytest.raises(IssuePostError, match="no html_url"):
            async with _client() as client:
                await _create_issue(
                    client,
                    api="https://api.github.com",
                    owner="o",
                    name="r",
                    title="t",
                    body="b",
                    labels=["security"],
                )

    @respx.mock
    async def test_5xx_retries_then_succeeds(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def _no_sleep(_seconds: float) -> None:
            return None

        monkeypatch.setattr(issues_mod.asyncio, "sleep", _no_sleep)
        route = respx.post(
            "https://api.github.com/repos/o/r/issues"
        ).mock(
            side_effect=[
                httpx.Response(503, text="busy"),
                httpx.Response(
                    201, json={"html_url": "https://github.com/o/r/issues/9"}
                ),
            ]
        )
        async with _client() as client:
            url = await _create_issue(
                client,
                api="https://api.github.com",
                owner="o",
                name="r",
                title="t",
                body="b",
                labels=["security"],
            )
        assert url == "https://github.com/o/r/issues/9"
        assert route.call_count == 2

    @respx.mock
    async def test_429_retries(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _no_sleep(_seconds: float) -> None:
            return None

        monkeypatch.setattr(issues_mod.asyncio, "sleep", _no_sleep)
        route = respx.post(
            "https://api.github.com/repos/o/r/issues"
        ).mock(
            side_effect=[
                httpx.Response(429, text="rate"),
                httpx.Response(201, json={"html_url": "u"}),
            ]
        )
        async with _client() as client:
            out = await _create_issue(
                client,
                api="https://api.github.com",
                owner="o",
                name="r",
                title="t",
                body="b",
                labels=["security"],
            )
        assert out == "u"
        assert route.call_count == 2

    @respx.mock
    async def test_retry_log_emitted_when_log_retries_true(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        # Verifies the optional config.logging.retries path: when set to
        # True the runtime emits an INFO trace before the backoff sleep.
        import logging as _logging

        async def _no_sleep(_seconds: float) -> None:
            return None

        monkeypatch.setattr(issues_mod.asyncio, "sleep", _no_sleep)
        respx.post("https://api.github.com/repos/o/r/issues").mock(
            side_effect=[
                httpx.Response(429, text="rate"),
                httpx.Response(201, json={"html_url": "u"}),
            ]
        )
        with caplog.at_level(_logging.INFO, logger="agent.issues"):
            async with _client() as client:
                await _create_issue(
                    client,
                    api="https://api.github.com",
                    owner="o",
                    name="r",
                    title="finding-XYZ",
                    body="b",
                    labels=["security"],
                    log_retries=True,
                )
        msgs = "\n".join(r.getMessage() for r in caplog.records)
        assert "retrying once" in msgs
        assert "429" in msgs
        assert "finding-XYZ" in msgs

    @respx.mock
    async def test_retry_log_silent_when_log_retries_false(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        # The default (log_retries=False) must not emit the retry trace —
        # users who haven't opted in see only the existing terminal logs.
        import logging as _logging

        async def _no_sleep(_seconds: float) -> None:
            return None

        monkeypatch.setattr(issues_mod.asyncio, "sleep", _no_sleep)
        respx.post("https://api.github.com/repos/o/r/issues").mock(
            side_effect=[
                httpx.Response(429, text="rate"),
                httpx.Response(201, json={"html_url": "u"}),
            ]
        )
        with caplog.at_level(_logging.INFO, logger="agent.issues"):
            async with _client() as client:
                await _create_issue(
                    client,
                    api="https://api.github.com",
                    owner="o",
                    name="r",
                    title="t",
                    body="b",
                    labels=["security"],
                    # log_retries left at default False
                )
        msgs = "\n".join(r.getMessage() for r in caplog.records)
        assert "retrying once" not in msgs

    @respx.mock
    async def test_4xx_no_retry_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def _no_sleep(_seconds: float) -> None:
            return None

        monkeypatch.setattr(issues_mod.asyncio, "sleep", _no_sleep)
        route = respx.post(
            "https://api.github.com/repos/o/r/issues"
        ).mock(return_value=httpx.Response(422, text="bad"))
        with pytest.raises(IssuePostError, match="422"):
            async with _client() as client:
                await _create_issue(
                    client,
                    api="https://api.github.com",
                    owner="o",
                    name="r",
                    title="t",
                    body="b",
                    labels=["security"],
                )
        assert route.call_count == 1  # no retry on 4xx

    @respx.mock
    async def test_5xx_persistent_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def _no_sleep(_seconds: float) -> None:
            return None

        monkeypatch.setattr(issues_mod.asyncio, "sleep", _no_sleep)
        respx.post("https://api.github.com/repos/o/r/issues").mock(
            return_value=httpx.Response(500, text="down")
        )
        with pytest.raises(IssuePostError, match="500"):
            async with _client() as client:
                await _create_issue(
                    client,
                    api="https://api.github.com",
                    owner="o",
                    name="r",
                    title="t",
                    body="b",
                    labels=["security"],
                )


# ---------------------------------------------------------------------------
# build_report_url helpers
# ---------------------------------------------------------------------------


class TestBuildReportUrl:
    def test_local_scan(self, tmp_path: Path) -> None:
        results = tmp_path / "myrepo_VULNHUNT_RESULTS_opus47_2026-06-23-141824"
        results.mkdir()
        url = build_report_url_for_local_scan(
            publish_destination_repo="https://github.com/o/dest",
            publish_branch="main",
            source_repo_url="https://github.com/x/y",
            source_commit_hash="abc",
            results_dir=results,
        )
        assert "/blob/main/x/y/2026-06-23-141824/abc/" in url
        assert url.endswith("/README.md")

    def test_remote_report(self) -> None:
        url = build_report_url_for_remote_report(
            publish_destination_repo="https://github.com/o/dest",
            publish_branch="main",
            rel_path_in_dest="x/y/abc1234/myrepo_VULNHUNT_RESULTS_opus47_2026-06-23-141824",
        )
        assert url == (
            "https://github.com/o/dest/blob/main/"
            "x/y/abc1234/myrepo_VULNHUNT_RESULTS_opus47_2026-06-23-141824/README.md"
        )

    def test_remote_report_strips_dot_git(self) -> None:
        url = build_report_url_for_remote_report(
            publish_destination_repo="https://github.com/o/dest.git",
            publish_branch="main",
            rel_path_in_dest="x/y/results",
        )
        assert ".git/blob" not in url
        assert url.startswith("https://github.com/o/dest/blob/main/x/y/")


# ---------------------------------------------------------------------------
# print_summary
# ---------------------------------------------------------------------------


class TestPrintSummary:
    def test_full_summary_lines(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        s = PostSummary(
            posted=[PostedIssue(finding_id="V1", title="t", url="u1")],
            skipped=[
                SkippedIssue(
                    finding_id="V2", matched_issue_numbers=[1, 2], via="key"
                )
            ],
            failed=[FailedIssue(finding_id="V3", title="t3", error="boom")],
        )
        print_summary(s)
        out = capsys.readouterr().out
        assert "Posted:  1" in out
        assert "u1" in out
        assert "Skipped: 1" in out
        assert "duplicates: V2" in out
        assert "Failed:  1" in out
        assert "V3: boom" in out

    def test_empty_with_note(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        s = PostSummary(note="no findings")
        print_summary(s)
        out = capsys.readouterr().out
        assert "Note:    no findings" in out
        assert "Posted:  0" in out
        assert "Skipped: 0" in out
        assert "Failed:  0" in out

    def test_any_failed_property(self) -> None:
        assert not PostSummary().any_failed
        assert PostSummary(
            failed=[FailedIssue("x", "y", "z")]
        ).any_failed

    def test_cost_line_when_calls_made(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from agent._llm import CostStats

        s = PostSummary(
            cost=CostStats(
                cost_usd=0.0234,
                num_turns=4,
                duration_api_ms=1500,
                calls=2,
            )
        )
        print_summary(s)
        out = capsys.readouterr().out
        assert "Cost:    $0.0234" in out
        assert "2 call(s)" in out
        assert "4 turn(s)" in out
        assert "API duration=1500ms" in out

    def test_cost_line_omitted_when_no_calls(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Default CostStats has calls=0 → no cost line.
        s = PostSummary()
        print_summary(s)
        out = capsys.readouterr().out
        assert "Cost:" not in out


# ---------------------------------------------------------------------------
# post_issues — orchestrator
# ---------------------------------------------------------------------------


class TestPostIssues:
    """Stub extract/fetch/dedup; exercise the orchestrator's branching."""

    def _stub_pipeline(
        self,
        monkeypatch: pytest.MonkeyPatch,
        *,
        findings: list[Finding],
        open_issues: list[OpenIssue],
        decisions: list[DedupDecision],
    ) -> None:
        report = ExtractedReport(
            findings=findings,
            scan_date="2026-06-23",
            results_dir_name="myrepo_VULNHUNT_RESULTS_opus47_2026-06-23-141824",
        )

        async def _fake_extract(*a: Any, **k: Any) -> ExtractedReport:
            return report

        async def _fake_dedup(*a: Any, **k: Any) -> list[DedupDecision]:
            return decisions

        monkeypatch.setattr(extract_mod, "extract_findings", _fake_extract)
        monkeypatch.setattr(
            fetch_mod, "fetch_open_issues_with_label", lambda *a, **k: open_issues
        )
        monkeypatch.setattr(dedup_mod, "dedup", _fake_dedup)

    def _cfg_with_token(self, populated_agent_config: Any) -> Any:
        return replace(
            populated_agent_config,
            github=replace(populated_agent_config.github, scan_token="t"),
        )

    def _cfg_no_clean_scan(self, populated_agent_config: Any) -> Any:
        base = self._cfg_with_token(populated_agent_config)
        return replace(
            base,
            issues=replace(base.issues, notify_clean_scan=False),
        )

    @respx.mock
    async def test_no_findings_short_circuits(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
        tmp_path: Path,
    ) -> None:
        self._stub_pipeline(
            monkeypatch, findings=[], open_issues=[], decisions=[]
        )
        out = await post_issues(
            results_dir=tmp_path,
            report_url="u",
            target_repo_url="https://github.com/o/r",
            config=self._cfg_no_clean_scan(populated_agent_config),
            token_manager=_TM(),
        )
        assert out.note == "no confirmed findings in report"
        assert not out.posted
        assert not out.skipped
        assert not out.failed
        assert out.clean_scan is None

    def _stub_labels_existing(self) -> None:
        respx.get("https://api.github.com/repos/o/r/labels/security").mock(
            return_value=httpx.Response(200, json={"name": "security"})
        )
        respx.get(
            "https://api.github.com/repos/o/r/labels/vulnhunter"
        ).mock(
            return_value=httpx.Response(200, json={"name": "vulnhunter"})
        )

    @respx.mock
    async def test_skips_duplicates(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
        tmp_path: Path,
    ) -> None:
        self._stub_labels_existing()
        f = _finding("VULN-001")
        self._stub_pipeline(
            monkeypatch,
            findings=[f],
            open_issues=[],
            decisions=[
                DedupDecision(
                    finding_id="VULN-001", matched_issues=[42], via="key"
                )
            ],
        )
        out = await post_issues(
            results_dir=tmp_path,
            report_url="u",
            target_repo_url="https://github.com/o/r",
            config=self._cfg_with_token(populated_agent_config),
            token_manager=_TM(),
        )
        assert len(out.skipped) == 1
        assert out.skipped[0].finding_id == "VULN-001"
        assert out.skipped[0].matched_issue_numbers == [42]
        assert out.skipped[0].via == "key"
        assert not out.posted

    @respx.mock
    async def test_posts_non_duplicate(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
        tmp_path: Path,
    ) -> None:
        self._stub_labels_existing()
        respx.post("https://api.github.com/repos/o/r/issues").mock(
            return_value=httpx.Response(
                201, json={"html_url": "https://github.com/o/r/issues/9"}
            )
        )
        f = _finding("VULN-001")
        self._stub_pipeline(
            monkeypatch,
            findings=[f],
            open_issues=[],
            decisions=[
                DedupDecision(
                    finding_id="VULN-001", matched_issues=[], via=""
                )
            ],
        )
        out = await post_issues(
            results_dir=tmp_path,
            report_url="https://example.com/blob/main/o/n/2026-06-23-141824/abc/d/README.md",
            target_repo_url="https://github.com/o/r",
            config=self._cfg_with_token(populated_agent_config),
            token_manager=_TM(),
        )
        assert len(out.posted) == 1
        assert out.posted[0].url == "https://github.com/o/r/issues/9"
        assert not out.failed
        assert not out.any_failed

    @respx.mock
    async def test_post_failure_continues_to_next_finding(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
        tmp_path: Path,
    ) -> None:
        self._stub_labels_existing()
        # First POST fails (422, no retry); second succeeds (201).
        respx.post(
            "https://api.github.com/repos/o/r/issues"
        ).mock(
            side_effect=[
                httpx.Response(422, text="bad"),
                httpx.Response(201, json={"html_url": "u2"}),
            ]
        )
        f1 = _finding("VULN-001", key="k1")
        f2 = _finding("VULN-002", key="k2")
        self._stub_pipeline(
            monkeypatch,
            findings=[f1, f2],
            open_issues=[],
            decisions=[
                DedupDecision(
                    finding_id="VULN-001", matched_issues=[], via=""
                ),
                DedupDecision(
                    finding_id="VULN-002", matched_issues=[], via=""
                ),
            ],
        )
        out = await post_issues(
            results_dir=tmp_path,
            report_url="u",
            target_repo_url="https://github.com/o/r",
            config=self._cfg_with_token(populated_agent_config),
            token_manager=_TM(),
        )
        assert len(out.posted) == 1
        assert out.posted[0].finding_id == "VULN-002"
        assert len(out.failed) == 1
        assert out.failed[0].finding_id == "VULN-001"
        assert out.any_failed


# ---------------------------------------------------------------------------
# Clean-scan notice path
# ---------------------------------------------------------------------------


class TestCleanScanNotice:
    """post_issues() zero-findings branch → _post_clean_scan_notice.

    Covers docs/clean-scan-notifications-design.md §2 (create+close,
    append, close-back failure), §5 (>1 open receipts tiebreak), §6
    (notify_clean_scan=false toggle), and §8 (audit event emission).
    Every skipped sub-case is asserted so a regression in the
    failure-containment guarantee (HIGH review finding #1) surfaces.
    """

    _CLEAN_LABEL_ENC = "VulnHunter%3A%20clean-scan"
    _RESULTS_DIR = "myrepo_VULNHUNT_RESULTS_opus47_2026-06-23-141824"
    _REPORT_ID = _RESULTS_DIR

    def _cfg(self, populated_agent_config: Any) -> Any:
        return replace(
            populated_agent_config,
            github=replace(populated_agent_config.github, scan_token="t"),
        )

    def _cfg_no_token(self, populated_agent_config: Any) -> Any:
        return replace(
            populated_agent_config,
            github=replace(populated_agent_config.github, scan_token=""),
        )

    def _cfg_no_clean_scan(self, populated_agent_config: Any) -> Any:
        base = self._cfg(populated_agent_config)
        return replace(
            base,
            issues=replace(base.issues, notify_clean_scan=False),
        )

    def _stub_zero_findings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        report = ExtractedReport(
            findings=[],
            scan_date="2026-06-23",
            results_dir_name=self._RESULTS_DIR,
        )

        async def _fake_extract(*a: Any, **k: Any) -> ExtractedReport:
            return report

        monkeypatch.setattr(extract_mod, "extract_findings", _fake_extract)

    def _stub_label_exists(self) -> None:
        respx.get(
            f"https://api.github.com/repos/o/r/labels/{self._CLEAN_LABEL_ENC}"
        ).mock(
            return_value=httpx.Response(
                200, json={"name": "VulnHunter: clean-scan"}
            )
        )

    def _results_dir(self, tmp_path: Path) -> Path:
        # Callers thread ``results_dir.name`` through ``report_id`` and
        # timestamp parsing; give it a real, uniquely-named path.
        d = tmp_path / self._RESULTS_DIR
        d.mkdir()
        return d

    def _audit_writer(self, tmp_path: Path) -> AuditWriter:
        return AuditWriter(
            paths=AuditPaths(
                events=tmp_path / "audit.jsonl",
                findings=tmp_path / "findings.jsonl",
            ),
            stdout=False,
            strict=False,
        )

    def _read_clean_scan_event(self, tmp_path: Path) -> dict[str, Any]:
        """Read + parse the single expected clean_scan_notified line."""
        path = tmp_path / "audit.jsonl"
        assert path.is_file(), "audit writer did not create the events file"
        lines = path.read_text().splitlines()
        events = [json.loads(l) for l in lines]
        clean = [e for e in events if e.get("event_type") == "clean_scan_notified"]
        assert len(clean) == 1, (
            f"expected exactly one clean_scan_notified event; got {len(clean)}"
        )
        return clean[0]

    # ---- happy paths -----------------------------------------------------

    @respx.mock
    async def test_creates_and_closes_receipt_when_no_open_exists(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
        tmp_path: Path,
    ) -> None:
        self._stub_zero_findings(monkeypatch)
        self._stub_label_exists()
        monkeypatch.setattr(
            fetch_mod, "fetch_open_issues_with_label", lambda *a, **k: []
        )
        post_route = respx.post(
            "https://api.github.com/repos/o/r/issues"
        ).mock(
            return_value=httpx.Response(
                201, json={"html_url": "https://github.com/o/r/issues/42"}
            )
        )
        patch_route = respx.patch(
            "https://api.github.com/repos/o/r/issues/42"
        ).mock(return_value=httpx.Response(200, json={"state": "closed"}))
        writer = self._audit_writer(tmp_path)

        out = await post_issues(
            results_dir=self._results_dir(tmp_path),
            report_url="https://example.com/report",
            target_repo_url="https://github.com/o/r",
            config=self._cfg(populated_agent_config),
            token_manager=_TM(),
            audit_writer=writer,
            audit_report_id=self._REPORT_ID,
            audit_repo_slug="o/r",
            commit_sha="deadbee",
        )
        writer.close()

        assert out.clean_scan is not None
        assert out.clean_scan.mode == "created"
        assert out.clean_scan.state == "CLOSED"
        assert out.clean_scan.url == "https://github.com/o/r/issues/42"
        assert post_route.called
        assert patch_route.called
        patch_body = patch_route.calls.last.request.content
        assert b'"state":"closed"' in patch_body
        assert b'"state_reason":"completed"' in patch_body
        post_body = post_route.calls.last.request.content
        assert b"VulnHunter: clean-scan" in post_body
        assert b"security" not in post_body
        # Audit event carries the design §8 field shape for happy path.
        event = self._read_clean_scan_event(tmp_path)
        assert event["to_status"] == "CLOSED"
        assert event["github_issue_url"] == "https://github.com/o/r/issues/42"
        assert event["target_sha"] == "deadbee"
        assert event["report_id"] == self._REPORT_ID
        # notes is dropped by _clean when empty; None on happy path.
        assert event.get("notes") is None

    @respx.mock
    async def test_appends_comment_when_open_receipt_exists(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
        tmp_path: Path,
    ) -> None:
        self._stub_zero_findings(monkeypatch)
        self._stub_label_exists()
        existing = OpenIssue(
            number=7,
            title="[VulnHunter] Clean scan — no findings detected",
            body="",
            html_url="https://github.com/o/r/issues/7",
            labels=["VulnHunter: clean-scan"],
        )
        monkeypatch.setattr(
            fetch_mod,
            "fetch_open_issues_with_label",
            lambda *a, **k: [existing],
        )
        comment_route = respx.post(
            "https://api.github.com/repos/o/r/issues/7/comments"
        ).mock(
            return_value=httpx.Response(
                201,
                json={
                    "html_url": "https://github.com/o/r/issues/7#issuecomment-1"
                },
            )
        )
        issue_post_route = respx.post(
            "https://api.github.com/repos/o/r/issues"
        )
        writer = self._audit_writer(tmp_path)

        out = await post_issues(
            results_dir=self._results_dir(tmp_path),
            report_url="",
            target_repo_url="https://github.com/o/r",
            config=self._cfg(populated_agent_config),
            token_manager=_TM(),
            audit_writer=writer,
            audit_report_id=self._REPORT_ID,
            audit_repo_slug="o/r",
            commit_sha="deadbee",
        )
        writer.close()

        assert out.clean_scan is not None
        assert out.clean_scan.mode == "appended"
        assert out.clean_scan.url == "https://github.com/o/r/issues/7"
        assert comment_route.called
        # Critical invariant: we do NOT create a duplicate issue when
        # an existing open receipt was found.
        assert not issue_post_route.called
        # Audit event: append semantic — to_status stays CLOSED since we
        # didn't touch the existing issue's state, and notes carries the
        # target URL for downstream correlation.
        event = self._read_clean_scan_event(tmp_path)
        assert event["to_status"] == "CLOSED"
        assert event["github_issue_url"] == "https://github.com/o/r/issues/7"
        assert event["notes"] == "append: https://github.com/o/r/issues/7"

    @respx.mock
    async def test_appends_to_lowest_numbered_when_multiple_opens(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """>1 open receipts is state-drift. Deterministic tiebreak =
        lowest number; operator gets a WARN listing the strays."""
        self._stub_zero_findings(monkeypatch)
        self._stub_label_exists()
        strays = [
            OpenIssue(
                number=n,
                title="[VulnHunter] Clean scan — no findings detected",
                body="",
                html_url=f"https://github.com/o/r/issues/{n}",
                labels=["VulnHunter: clean-scan"],
            )
            for n in (17, 3, 42)  # deliberately out of order
        ]
        monkeypatch.setattr(
            fetch_mod, "fetch_open_issues_with_label", lambda *a, **k: strays
        )
        comment_route = respx.post(
            "https://api.github.com/repos/o/r/issues/3/comments"
        ).mock(
            return_value=httpx.Response(
                201, json={"html_url": "https://github.com/o/r/issues/3#c"}
            )
        )
        # If the tiebreak regressed to max/first-in-list, these would
        # get hit; leave them unmocked so respx would blow up.
        writer = self._audit_writer(tmp_path)

        with caplog.at_level(logging.WARNING, logger="agent.issues"):
            out = await post_issues(
                results_dir=self._results_dir(tmp_path),
                report_url="",
                target_repo_url="https://github.com/o/r",
                config=self._cfg(populated_agent_config),
                token_manager=_TM(),
                audit_writer=writer,
                audit_report_id=self._REPORT_ID,
                audit_repo_slug="o/r",
                commit_sha="deadbee",
            )
        writer.close()

        assert out.clean_scan is not None
        assert out.clean_scan.mode == "appended"
        assert out.clean_scan.url == "https://github.com/o/r/issues/3"
        assert comment_route.called
        # WARN message names the target (#3) and lists the strays.
        drift_warnings = [
            r for r in caplog.records
            if r.levelname == "WARNING" and "3 open clean-scan issues" in r.getMessage()
        ]
        assert len(drift_warnings) == 1
        msg = drift_warnings[0].getMessage()
        assert "#3" in msg
        assert "[17, 42]" in msg

    @respx.mock
    async def test_close_back_failure_leaves_issue_open(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
        tmp_path: Path,
    ) -> None:
        self._stub_zero_findings(monkeypatch)
        self._stub_label_exists()
        monkeypatch.setattr(
            fetch_mod, "fetch_open_issues_with_label", lambda *a, **k: []
        )
        respx.post("https://api.github.com/repos/o/r/issues").mock(
            return_value=httpx.Response(
                201, json={"html_url": "https://github.com/o/r/issues/99"}
            )
        )
        # PATCH fails twice (retry + final). 500 is retryable so
        # _close_issue burns its one retry, then raises. Assert the
        # retry actually happened — a regression that skips the retry
        # would silently pass otherwise.
        patch_route = respx.patch(
            "https://api.github.com/repos/o/r/issues/99"
        ).mock(
            side_effect=[
                httpx.Response(500, text="boom"),
                httpx.Response(500, text="boom"),
            ]
        )
        # Silence the 30s retry sleep so the test runs in milliseconds.
        monkeypatch.setattr(issues_mod.asyncio, "sleep", _no_sleep)
        writer = self._audit_writer(tmp_path)

        out = await post_issues(
            results_dir=self._results_dir(tmp_path),
            report_url="",
            target_repo_url="https://github.com/o/r",
            config=self._cfg(populated_agent_config),
            token_manager=_TM(),
            audit_writer=writer,
            audit_report_id=self._REPORT_ID,
            audit_repo_slug="o/r",
            commit_sha="deadbee",
        )
        writer.close()

        assert out.clean_scan is not None
        assert out.clean_scan.mode == "close_back_failed"
        assert out.clean_scan.state == "OPEN"
        assert out.clean_scan.url == "https://github.com/o/r/issues/99"
        # PATCH was invoked twice (initial + one retry) — this locks in
        # the retry semantics documented in _close_issue's docstring.
        assert patch_route.call_count == 2
        # Audit event reflects the anomaly: to_status=OPEN, notes says
        # close-back failed. Downstream consumers can distinguish this
        # from the happy-path CLOSED state.
        event = self._read_clean_scan_event(tmp_path)
        assert event["to_status"] == "OPEN"
        assert event["github_issue_url"] == "https://github.com/o/r/issues/99"
        assert "close-back failed" in event["notes"]

    # ---- toggle ---------------------------------------------------------

    async def test_notify_clean_scan_disabled_skips_receipt_entirely(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
        tmp_path: Path,
    ) -> None:
        """notify_clean_scan=False → no HTTP, no audit event, clean_scan=None.

        respx is deliberately NOT enabled: any HTTP attempt would raise
        because httpx has no mock backing.
        """
        self._stub_zero_findings(monkeypatch)
        writer = self._audit_writer(tmp_path)

        out = await post_issues(
            results_dir=self._results_dir(tmp_path),
            report_url="",
            target_repo_url="https://github.com/o/r",
            config=self._cfg_no_clean_scan(populated_agent_config),
            token_manager=_TM(),
            audit_writer=writer,
            audit_report_id=self._REPORT_ID,
            audit_repo_slug="o/r",
        )
        writer.close()

        assert out.clean_scan is None
        assert out.note == "no confirmed findings in report"
        # No clean_scan_notified event on the audit stream.
        audit_path = tmp_path / "audit.jsonl"
        if audit_path.is_file():
            events = [json.loads(l) for l in audit_path.read_text().splitlines()]
            assert not any(
                e.get("event_type") == "clean_scan_notified" for e in events
            )

    # ---- skipped sub-cases ---------------------------------------------

    async def test_missing_scan_token_skips_receipt(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
        tmp_path: Path,
    ) -> None:
        """No scan_token → skipped outcome, no HTTP attempted, no audit event."""
        self._stub_zero_findings(monkeypatch)
        writer = self._audit_writer(tmp_path)

        out = await post_issues(
            results_dir=self._results_dir(tmp_path),
            report_url="",
            target_repo_url="https://github.com/o/r",
            config=self._cfg_no_token(populated_agent_config),
            token_manager=_TM(),
            audit_writer=writer,
            audit_report_id=self._REPORT_ID,
            audit_repo_slug="o/r",
        )
        writer.close()

        assert out.clean_scan is not None
        assert out.clean_scan.mode == "skipped"
        assert out.clean_scan.url == ""
        assert "scan_token missing" in out.clean_scan.note
        # No audit event emitted on the token-missing early exit.
        audit_path = tmp_path / "audit.jsonl"
        if audit_path.is_file():
            content = audit_path.read_text()
            assert "clean_scan_notified" not in content

    @respx.mock
    async def test_label_ensure_transport_failure_downgrades_to_skipped(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
        tmp_path: Path,
    ) -> None:
        """Transport failure on label ensure → skipped, not stage failure.

        Guards HIGH review finding #1: httpx.RequestError used to
        escape the try/except and fail the whole issues stage.
        """
        self._stub_zero_findings(monkeypatch)
        respx.get(
            f"https://api.github.com/repos/o/r/labels/{self._CLEAN_LABEL_ENC}"
        ).mock(side_effect=httpx.ConnectError("dns down"))
        # If containment regressed, this call would raise and
        # post_issues would abort with an unhandled exception.
        writer = self._audit_writer(tmp_path)

        out = await post_issues(
            results_dir=self._results_dir(tmp_path),
            report_url="",
            target_repo_url="https://github.com/o/r",
            config=self._cfg(populated_agent_config),
            token_manager=_TM(),
            audit_writer=writer,
            audit_report_id=self._REPORT_ID,
            audit_repo_slug="o/r",
        )
        writer.close()

        assert out.clean_scan is not None
        assert out.clean_scan.mode == "skipped"
        assert "label-ensure failed" in out.clean_scan.note
        # No audit event on skipped paths that didn't reach an issue.
        audit_path = tmp_path / "audit.jsonl"
        if audit_path.is_file():
            content = audit_path.read_text()
            assert "clean_scan_notified" not in content

    @respx.mock
    async def test_open_issue_lookup_failure_downgrades_to_skipped(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
        tmp_path: Path,
    ) -> None:
        """issues_fetch failure → skipped, not stage failure."""
        self._stub_zero_findings(monkeypatch)
        self._stub_label_exists()

        def _boom(*a: Any, **k: Any) -> list[OpenIssue]:
            raise fetch_mod.IssuesFetchError("upstream 502")

        monkeypatch.setattr(fetch_mod, "fetch_open_issues_with_label", _boom)

        out = await post_issues(
            results_dir=self._results_dir(tmp_path),
            report_url="",
            target_repo_url="https://github.com/o/r",
            config=self._cfg(populated_agent_config),
            token_manager=_TM(),
            audit_report_id=self._REPORT_ID,
            audit_repo_slug="o/r",
        )

        assert out.clean_scan is not None
        assert out.clean_scan.mode == "skipped"
        assert "open-issue lookup failed" in out.clean_scan.note

    @respx.mock
    async def test_comment_post_failure_preserves_existing_url(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
        tmp_path: Path,
    ) -> None:
        """Comment POST fail on append path → skipped with existing url.

        Locks in the subtle semantic that on this skipped branch the
        outcome.url points at the *pre-existing* open receipt, not
        empty — downstream consumers still know which issue was the
        intended target.
        """
        self._stub_zero_findings(monkeypatch)
        self._stub_label_exists()
        existing = OpenIssue(
            number=7,
            title="[VulnHunter] Clean scan — no findings detected",
            body="",
            html_url="https://github.com/o/r/issues/7",
            labels=["VulnHunter: clean-scan"],
        )
        monkeypatch.setattr(
            fetch_mod,
            "fetch_open_issues_with_label",
            lambda *a, **k: [existing],
        )
        # POST fails twice (retry + final).
        respx.post(
            "https://api.github.com/repos/o/r/issues/7/comments"
        ).mock(
            side_effect=[
                httpx.Response(500, text="boom"),
                httpx.Response(500, text="boom"),
            ]
        )
        monkeypatch.setattr(issues_mod.asyncio, "sleep", _no_sleep)

        out = await post_issues(
            results_dir=self._results_dir(tmp_path),
            report_url="",
            target_repo_url="https://github.com/o/r",
            config=self._cfg(populated_agent_config),
            token_manager=_TM(),
            audit_report_id=self._REPORT_ID,
            audit_repo_slug="o/r",
        )

        assert out.clean_scan is not None
        assert out.clean_scan.mode == "skipped"
        assert out.clean_scan.url == "https://github.com/o/r/issues/7"
        assert "comment POST failed" in out.clean_scan.note

    @respx.mock
    async def test_issue_post_failure_downgrades_to_skipped(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
        tmp_path: Path,
    ) -> None:
        """POST /issues fail (no existing receipt) → skipped, no PATCH attempted."""
        self._stub_zero_findings(monkeypatch)
        self._stub_label_exists()
        monkeypatch.setattr(
            fetch_mod, "fetch_open_issues_with_label", lambda *a, **k: []
        )
        respx.post("https://api.github.com/repos/o/r/issues").mock(
            side_effect=[
                httpx.Response(500, text="boom"),
                httpx.Response(500, text="boom"),
            ]
        )
        # PATCH route: register but leave unmocked-side-effect so a
        # regression that PATCHes issue-0 would blow up loudly.
        monkeypatch.setattr(issues_mod.asyncio, "sleep", _no_sleep)

        out = await post_issues(
            results_dir=self._results_dir(tmp_path),
            report_url="",
            target_repo_url="https://github.com/o/r",
            config=self._cfg(populated_agent_config),
            token_manager=_TM(),
            audit_report_id=self._REPORT_ID,
            audit_repo_slug="o/r",
        )

        assert out.clean_scan is not None
        assert out.clean_scan.mode == "skipped"
        assert out.clean_scan.url == ""
        assert "issue POST failed" in out.clean_scan.note

    @respx.mock
    async def test_empty_commit_sha_still_produces_receipt(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
        tmp_path: Path,
    ) -> None:
        """--no-scan / download path threads commit_sha="" — receipt still posts.

        Guards the interaction where the caller has no local clone to
        compute a commit SHA against. The renderer must fold the empty
        SHA into a dash rather than blow up.
        """
        self._stub_zero_findings(monkeypatch)
        self._stub_label_exists()
        monkeypatch.setattr(
            fetch_mod, "fetch_open_issues_with_label", lambda *a, **k: []
        )
        post_route = respx.post(
            "https://api.github.com/repos/o/r/issues"
        ).mock(
            return_value=httpx.Response(
                201, json={"html_url": "https://github.com/o/r/issues/1"}
            )
        )
        respx.patch("https://api.github.com/repos/o/r/issues/1").mock(
            return_value=httpx.Response(200, json={"state": "closed"})
        )

        out = await post_issues(
            results_dir=self._results_dir(tmp_path),
            report_url="",
            target_repo_url="https://github.com/o/r",
            config=self._cfg(populated_agent_config),
            token_manager=_TM(),
            audit_report_id=self._REPORT_ID,
            audit_repo_slug="o/r",
            # commit_sha= omitted → defaults to empty string
        )

        assert out.clean_scan is not None
        assert out.clean_scan.mode == "created"
        # The rendered body used a dash in the Commit-scanned cell.
        post_body = post_route.calls.last.request.content.decode()
        assert "`—`" in post_body  # short SHA cell was backticked with a dash
        # Sanity: it did not accidentally render "None" or similar.
        assert "None" not in post_body

    @respx.mock
    async def test_malformed_issue_url_treated_as_close_back_failure(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
        tmp_path: Path,
    ) -> None:
        """POST returns an html_url whose tail isn't an integer.

        Real GitHub never does this, but if the response ever ships a
        malformed URL we don't want to PATCH /issues/0 and blame the
        404 on GitHub. Instead the parse failure surfaces as the same
        close_back_failed outcome — the issue was created but we
        couldn't close it, and self-heal will pick it up next scan.
        """
        self._stub_zero_findings(monkeypatch)
        self._stub_label_exists()
        monkeypatch.setattr(
            fetch_mod, "fetch_open_issues_with_label", lambda *a, **k: []
        )
        respx.post("https://api.github.com/repos/o/r/issues").mock(
            return_value=httpx.Response(
                201, json={"html_url": "https://github.com/o/r/issues/oops"}
            )
        )
        # If the parse failure regressed to a fallback issue_number=0,
        # PATCH would hit /issues/0 — leave that route unmocked so respx
        # blows up rather than silently masking the regression.

        out = await post_issues(
            results_dir=self._results_dir(tmp_path),
            report_url="",
            target_repo_url="https://github.com/o/r",
            config=self._cfg(populated_agent_config),
            token_manager=_TM(),
            audit_report_id=self._REPORT_ID,
            audit_repo_slug="o/r",
            commit_sha="deadbee",
        )

        assert out.clean_scan is not None
        assert out.clean_scan.mode == "close_back_failed"
        assert out.clean_scan.state == "OPEN"
        assert "cannot parse issue number" in out.clean_scan.note


async def _no_sleep(*_a: Any, **_k: Any) -> None:
    """Fast-forward through issues.py's per-retry backoff sleeps."""
    return None
