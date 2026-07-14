"""Unit tests for ``agent/verify_runner.py``.

The pure-function parts are covered directly. The SDK driver
``run_verify_session`` is tested with a mocked ``ClaudeSDKClient``
to confirm the kickoff prompt is sent, events are logged, and the
output classifier sees what's on disk afterwards.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
from claude_agent_sdk import (
    AssistantMessage,
    ResultMessage,
    TaskStartedMessage,
    TextBlock,
)

from agent import verify_runner
from agent.verify_runner import (
    OutputKind,
    VerifySessionResult,
    build_kickoff_prompt,
    classify_output,
)


# ---------- build_kickoff_prompt --------------------------------------------


def test_build_kickoff_prompt_minimum() -> None:
    prompt = build_kickoff_prompt(
        repo=Path("/r"),
        report=Path("/rep"),
        fixed_ids=["VULN-001"],
        out=Path("/out"),
        comments=Path("/c.md"),
    )
    assert prompt.startswith("/vulnhunt-fix-verify")
    assert "  repo:     /r" in prompt
    assert "  report:   /rep" in prompt
    assert "  fixed:    VULN-001" in prompt
    assert "  out:      /out" in prompt
    assert "  comments: /c.md" in prompt
    # No additional_repos line when not provided.
    assert "additional_repos" not in prompt


def test_build_kickoff_prompt_multiple_vulns_comma_joined() -> None:
    prompt = build_kickoff_prompt(
        repo=Path("/r"),
        report=Path("/rep"),
        fixed_ids=["VULN-001", "VULN-003", "VULN-007"],
        out=Path("/out"),
        comments=Path("/c.md"),
    )
    assert "  fixed:    VULN-001,VULN-003,VULN-007" in prompt


def test_build_kickoff_prompt_with_additional_repos() -> None:
    prompt = build_kickoff_prompt(
        repo=Path("/r"),
        report=Path("/rep"),
        fixed_ids=["VULN-001"],
        out=Path("/out"),
        comments=Path("/c.md"),
        additional_repos=[Path("/extra/one"), Path("/extra/two")],
    )
    assert "  additional_repos: /extra/one,/extra/two" in prompt


def test_build_kickoff_prompt_empty_additional_repos_is_omitted() -> None:
    """Empty list != None — both must result in the field being absent
    from the prompt so the skill's phase-0 sees ADDITIONAL_REPOS as
    unset rather than as an empty/zero-length list."""
    prompt = build_kickoff_prompt(
        repo=Path("/r"),
        report=Path("/rep"),
        fixed_ids=["VULN-001"],
        out=Path("/out"),
        comments=Path("/c.md"),
        additional_repos=[],
    )
    assert "additional_repos" not in prompt


def test_build_kickoff_prompt_rejects_empty_fixed_ids() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        build_kickoff_prompt(
            repo=Path("/r"),
            report=Path("/rep"),
            fixed_ids=[],
            out=Path("/out"),
            comments=Path("/c.md"),
        )


# ---------- classify_output -------------------------------------------------


def _valid_disposition_doc() -> dict:
    """Minimum disposition payload that passes the schema."""
    return {
        "schema_version": "1",
        "scan_id": "widget_VULNHUNT_RESULTS_opus47_2026-06-26",
        "target_repo": {
            "path": "/work/widget",
            "head_commit": "abc1234",
            "head_ref": "main",
            "additional_repos": [],
        },
        "verified_at": "2026-06-27T14:32:17Z",
        "comments_evaluation": {"provided": False, "claims": []},
        "dispositions": [
            {
                "finding_id": "VULN-001",
                "verdict": "FIXED",
                "rationale": "all four gates pass at db/queries.go:88",
                "issue_comment": "**VulnHunter Fix-Verify: Confirmed Fixed**",
                "gates": {
                    "sink_mitigated": "pass",
                    "reachability": "pass",
                    "class_eliminated": "pass",
                    "sweep_complete": "pass",
                },
                "evidence": [],
            }
        ],
    }


def test_classify_output_disposition(tmp_path: Path) -> None:
    (tmp_path / "verify_disposition.json").write_text(
        json.dumps(_valid_disposition_doc()), encoding="utf-8"
    )
    result = classify_output(tmp_path)
    assert result.kind is OutputKind.DISPOSITION
    assert result.output_path == tmp_path / "verify_disposition.json"
    assert result.parsed is not None
    assert result.parsed["dispositions"][0]["finding_id"] == "VULN-001"
    assert result.error_detail == ""


def test_classify_output_empty_returns_empty_kind(tmp_path: Path) -> None:
    result = classify_output(tmp_path)
    assert result.kind is OutputKind.EMPTY
    assert result.output_path is None
    assert result.parsed is None
    assert "verify_disposition.json did not appear" in result.error_detail


def test_classify_output_schema_invalid_disposition(tmp_path: Path) -> None:
    bad = _valid_disposition_doc()
    bad["dispositions"][0]["verdict"] = "DEFINITELY_NOT_A_VALID_VERDICT"
    (tmp_path / "verify_disposition.json").write_text(
        json.dumps(bad), encoding="utf-8"
    )
    result = classify_output(tmp_path)
    assert result.kind is OutputKind.SCHEMA_INVALID
    assert "validation" in result.error_detail.lower()


def test_classify_output_malformed_json(tmp_path: Path) -> None:
    (tmp_path / "verify_disposition.json").write_text(
        "{ not valid json", encoding="utf-8"
    )
    result = classify_output(tmp_path)
    assert result.kind is OutputKind.SCHEMA_INVALID
    assert "Could not parse" in result.error_detail


def test_classify_output_missing_issue_comment_rejected(tmp_path: Path) -> None:
    """The schema requires non-empty issue_comment on every disposition
    entry. Smoke-test that the validator catches its absence."""
    bad = _valid_disposition_doc()
    del bad["dispositions"][0]["issue_comment"]
    (tmp_path / "verify_disposition.json").write_text(
        json.dumps(bad), encoding="utf-8"
    )
    result = classify_output(tmp_path)
    assert result.kind is OutputKind.SCHEMA_INVALID


# ---------- run_verify_session (SDK-mocked) ---------------------------------


class _FakeSDKClient:
    """Minimal stand-in for ``ClaudeSDKClient`` used by the
    run_verify_session tests.

    Implements the async-context-manager + ``query`` + ``receive_response``
    surface the runner depends on. The test passes in a list of events
    to yield from ``receive_response``; the SDK options are recorded
    on the class so the test can assert what the runner constructed.
    """

    _recorded_options = None
    _events: list[object] = []
    _query_calls: list[str] = []
    _writes_after_query: list[tuple[Path, str]] = []

    def __init__(self, options):
        type(self)._recorded_options = options

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def query(self, prompt: str) -> None:
        type(self)._query_calls.append(prompt)
        # Allow the test to plant a file in out_dir as a side effect
        # of "running the skill" — the runner calls classify_output
        # after the session and expects the file to exist.
        for path, content in type(self)._writes_after_query:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

    async def receive_response(self):
        for event in type(self)._events:
            yield event


def _stub_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """build_claude_settings has its own deep config dependencies;
    stub it so run_verify_session tests don't drag those in."""
    from agent import verify_runner as vr
    monkeypatch.setattr(
        vr, "build_claude_settings", lambda *a, **k: "{}"
    )


def _fresh_fake_client():
    """Reset class-level state on _FakeSDKClient so each test starts clean."""
    _FakeSDKClient._recorded_options = None
    _FakeSDKClient._events = []
    _FakeSDKClient._query_calls = []
    _FakeSDKClient._writes_after_query = []


@pytest.mark.asyncio
async def test_run_verify_session_disposition_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    populated_agent_config,
) -> None:
    """Skill produces a valid disposition.json; the session driver
    classifies it as DISPOSITION."""
    _fresh_fake_client()
    out_dir = tmp_path / "out" / "iter-1"
    out_dir.mkdir(parents=True)
    _FakeSDKClient._writes_after_query = [
        (out_dir / "verify_disposition.json", json.dumps(_valid_disposition_doc()))
    ]
    _stub_settings(monkeypatch)
    from agent import verify_runner as vr
    monkeypatch.setattr(vr, "ClaudeSDKClient", _FakeSDKClient)

    result = await vr.run_verify_session(
        config=populated_agent_config,
        auth_token="tok",
        cwd=tmp_path,
        out_dir=out_dir,
        prompt="/vulnhunt-fix-verify\nfoo",
        log_path=tmp_path / "agent.log",
    )
    assert result.kind is OutputKind.DISPOSITION
    assert result.output_path == out_dir / "verify_disposition.json"
    assert (tmp_path / "agent.log").read_text(encoding="utf-8").startswith(
        "\n--- verify session begin"
    )
    # Tool allow-list is locked.
    assert sorted(_FakeSDKClient._recorded_options.allowed_tools) == [
        "Agent", "Edit", "Glob", "Grep", "Read", "Write",
    ]
    assert _FakeSDKClient._query_calls == ["/vulnhunt-fix-verify\nfoo"]


@pytest.mark.asyncio
async def test_run_verify_session_empty_when_no_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    populated_agent_config,
) -> None:
    """The skill completed but wrote no output file. The session
    driver classifies as EMPTY so the orchestrator exits 1."""
    _fresh_fake_client()
    out_dir = tmp_path / "out" / "iter-1"
    out_dir.mkdir(parents=True)
    _stub_settings(monkeypatch)
    from agent import verify_runner as vr
    monkeypatch.setattr(vr, "ClaudeSDKClient", _FakeSDKClient)

    result = await vr.run_verify_session(
        config=populated_agent_config,
        auth_token="tok",
        cwd=tmp_path,
        out_dir=out_dir,
        prompt="/vulnhunt-fix-verify\nfoo",
        log_path=tmp_path / "agent.log",
    )
    assert result.kind is OutputKind.EMPTY


@pytest.mark.asyncio
async def test_run_verify_session_sdk_exception_returns_empty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    populated_agent_config,
) -> None:
    """SDK throws during query → log it and return EMPTY (so the
    orchestrator treats it as an infra failure with no GitHub side
    effects)."""

    class _ExplodingClient(_FakeSDKClient):
        async def query(self, prompt: str) -> None:
            raise RuntimeError("simulated SDK boom")

    _fresh_fake_client()
    out_dir = tmp_path / "out" / "iter-1"
    out_dir.mkdir(parents=True)
    _stub_settings(monkeypatch)
    from agent import verify_runner as vr
    monkeypatch.setattr(vr, "ClaudeSDKClient", _ExplodingClient)

    result = await vr.run_verify_session(
        config=populated_agent_config,
        auth_token="tok",
        cwd=tmp_path,
        out_dir=out_dir,
        prompt="/vulnhunt-fix-verify\nfoo",
        log_path=tmp_path / "agent.log",
    )
    assert result.kind is OutputKind.EMPTY
    assert "SDK session raised" in result.error_detail
    # The log file should record the exception for forensics.
    log_content = (tmp_path / "agent.log").read_text(encoding="utf-8")
    assert "!!! SDK exception" in log_content


@pytest.mark.asyncio
async def test_run_verify_session_uses_model_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    populated_agent_config,
) -> None:
    """``model_override`` takes precedence over ``config.anthropic.model``
    in the SDK options."""
    _fresh_fake_client()
    out_dir = tmp_path / "out" / "iter-1"
    out_dir.mkdir(parents=True)
    _FakeSDKClient._writes_after_query = [
        (out_dir / "verify_disposition.json", json.dumps(_valid_disposition_doc()))
    ]
    _stub_settings(monkeypatch)
    from agent import verify_runner as vr
    monkeypatch.setattr(vr, "ClaudeSDKClient", _FakeSDKClient)

    await vr.run_verify_session(
        config=populated_agent_config,
        auth_token="tok",
        cwd=tmp_path,
        out_dir=out_dir,
        prompt="x",
        log_path=tmp_path / "agent.log",
        model_override="claude-sonnet-5",
    )
    assert _FakeSDKClient._recorded_options.model == "claude-sonnet-5"


def _verify_result_message(cost: float, num_turns: int, duration_api_ms: int) -> ResultMessage:
    """Build a minimal ResultMessage matching the scan-runner test factory."""
    return ResultMessage(
        subtype="success",
        duration_ms=10,
        duration_api_ms=duration_api_ms,
        is_error=False,
        num_turns=num_turns,
        session_id="s",
        total_cost_usd=cost,
    )


@pytest.mark.asyncio
async def test_run_verify_session_emits_totals_rollup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    populated_agent_config,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verify mode should mirror scan mode's end-of-session cost
    rollup. Two ResultMessages with distinct per-cycle durations
    confirm the sum-vs-max accounting matches the shared
    accumulator: cost is running-max (cumulative-within-session),
    duration sums, turns sum."""
    _fresh_fake_client()
    out_dir = tmp_path / "out" / "iter-1"
    out_dir.mkdir(parents=True)
    _FakeSDKClient._writes_after_query = [
        (out_dir / "verify_disposition.json", json.dumps(_valid_disposition_doc()))
    ]
    _FakeSDKClient._events = [
        _verify_result_message(cost=0.10, num_turns=2, duration_api_ms=1500),
        _verify_result_message(cost=0.25, num_turns=3, duration_api_ms=900),
    ]
    _stub_settings(monkeypatch)
    from agent import verify_runner as vr
    monkeypatch.setattr(vr, "ClaudeSDKClient", _FakeSDKClient)

    with caplog.at_level(logging.INFO, logger="agent.runner"):
        await vr.run_verify_session(
            config=populated_agent_config,
            auth_token="tok",
            cwd=tmp_path,
            out_dir=out_dir,
            prompt="x",
            log_path=tmp_path / "agent.log",
        )
    joined = "\n".join(r.getMessage() for r in caplog.records)
    # Check the rollup specifically — earlier per-RM logs legitimately
    # show each cycle's value.
    assert "Verify totals" in joined
    _, _, rollup = joined.partition("Verify totals")
    # 1500 + 900 = 2400 ms (per-cycle sum, not max-of-cumulative).
    assert "API duration=2400ms" in rollup
    # max(0.10, 0.25) = 0.25 (running max for cumulative cost).
    assert "cost_usd=$0.2500" in rollup
    # 2 + 3 = 5 turns total (per-cycle sum).
    assert "5 turn(s) across 2 ResultMessage(s)" in rollup


@pytest.mark.asyncio
async def test_run_verify_session_routes_assistant_prose_through_shared_logger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    populated_agent_config,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Assistant TextBlock prose must reach the shared ``agent.runner``
    logger so verify-mode users see the same per-event stream as scan
    mode. Without the shared dispatcher, this prose only landed in the
    on-disk ``agent.log`` file."""
    _fresh_fake_client()
    out_dir = tmp_path / "out" / "iter-1"
    out_dir.mkdir(parents=True)
    _FakeSDKClient._writes_after_query = [
        (out_dir / "verify_disposition.json", json.dumps(_valid_disposition_doc()))
    ]
    _FakeSDKClient._events = [
        AssistantMessage(
            content=[TextBlock(text="Phase 1: reading the report")],
            model="opus-4-7",
            parent_tool_use_id=None,
        ),
        _verify_result_message(cost=0.05, num_turns=1, duration_api_ms=500),
    ]
    _stub_settings(monkeypatch)
    from agent import verify_runner as vr
    monkeypatch.setattr(vr, "ClaudeSDKClient", _FakeSDKClient)

    with caplog.at_level(logging.INFO, logger="agent.runner"):
        await vr.run_verify_session(
            config=populated_agent_config,
            auth_token="tok",
            cwd=tmp_path,
            out_dir=out_dir,
            prompt="x",
            log_path=tmp_path / "agent.log",
        )
    joined = "\n".join(r.getMessage() for r in caplog.records)
    assert "Phase 1: reading the report" in joined
