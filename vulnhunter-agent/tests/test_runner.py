"""Tests for agent.runner: model tag, prompts, skill lookup, async loop."""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

import pytest
from claude_agent_sdk import (
    AssistantMessage,
    ResultMessage,
    SystemMessage,
    TaskNotificationMessage,
    TaskStartedMessage,
    TextBlock,
    ThinkingBlock,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
)

from agent import runner as runner_mod
from agent.runner import (
    AuthRejectedError,
    RateLimitError,
    _agent_name_from_started,
    _build_vulnhunt_prompt,
    _find_results_dir,
    _is_auth_failure,
    _is_rate_limit_result,
    _is_rate_limit_system_message,
    _log_assistant_message,
    _log_per_turn_usage,
    _log_system_message,
    _log_task_started,
    _log_task_status,
    _log_user_message,
    _model_tag,
    _vulnhunt_skill_path,
    run_vulnhunt,
    set_verbosity,
)


# ---------------------------------------------------------------------------
# _model_tag
# ---------------------------------------------------------------------------


class TestModelTag:
    @pytest.mark.parametrize(
        "model,expected",
        [
            ("claude-opus-4-8", "opus48"),
            ("claude-opus-4-8[1m]", "opus48_1m"),
            ("claude-opus-4-6_1m", "opus46_1m"),
            ("claude-4.6-opus", "opus46"),
            ("claude-4.6-opus[1M]", "opus46_1m"),
            ("claude-sonnet-5", "sonnet5"),
            ("claude-haiku-4-5", "haiku45"),
            ("claude-3-5-sonnet-20240620", "sonnet35"),
            ("gpt-4o", "gpt4"),
        ],
    )
    def test_matrix(self, model: str, expected: str) -> None:
        assert _model_tag(model) == expected


# ---------------------------------------------------------------------------
# _build_vulnhunt_prompt
# ---------------------------------------------------------------------------


class TestBuildVulnhuntPrompt:
    def test_includes_absolute_path(self, tmp_path: Path) -> None:
        clone = tmp_path / "myrepo"
        clone.mkdir()
        prompt = _build_vulnhunt_prompt(clone, "claude-opus-4-8")
        assert str(clone) in prompt

    def test_includes_model_tag_instruction(self, tmp_path: Path) -> None:
        prompt = _build_vulnhunt_prompt(tmp_path, "claude-opus-4-8")
        assert "opus48" in prompt
        assert "Use the model tag" in prompt

    def test_handles_braces_in_path(self, tmp_path: Path) -> None:
        weird = tmp_path / "repo{with}braces"
        weird.mkdir()
        # Should not raise even though { } would break str.format.
        prompt = _build_vulnhunt_prompt(weird, "claude-opus-4-8")
        assert "repo{with}braces" in prompt

    def test_read_only_default_appends_suffix(self, tmp_path: Path) -> None:
        prompt = _build_vulnhunt_prompt(tmp_path, "claude-opus-4-8")
        assert "read-only scan" in prompt
        assert "skip instructions related to getting dependencies" in prompt

    def test_read_only_false_omits_suffix(self, tmp_path: Path) -> None:
        prompt = _build_vulnhunt_prompt(
            tmp_path, "claude-opus-4-8", read_only=False
        )
        assert "read-only scan" not in prompt


# ---------------------------------------------------------------------------
# _vulnhunt_skill_path
# ---------------------------------------------------------------------------


def _patch_skill_candidates(
    monkeypatch: pytest.MonkeyPatch,
    *,
    container: Path,
    home: Path,
) -> None:
    """Redirect _vulnhunt_skill_path's two candidate roots to the given paths."""
    real_path_cls = runner_mod.Path

    class _PathWrapper:
        # Behaves like Path: passthrough construction except for the special
        # container literal, plus a home() classmethod returning ``home``.
        def __new__(cls, *args: object, **kwargs: object) -> Path:  # type: ignore[misc]
            if len(args) == 1 and str(args[0]) == "/home/appuser/.claude/skills/vulnhunt":
                return container
            return real_path_cls(*args, **kwargs)  # type: ignore[arg-type]

        @classmethod
        def home(cls) -> Path:
            return home

    monkeypatch.setattr(runner_mod, "Path", _PathWrapper)


class TestVulnhuntSkillPath:
    def test_container_path_takes_priority(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        container = tmp_path / "container" / ".claude" / "skills" / "vulnhunt"
        container.mkdir(parents=True)
        (container / "SKILL.md").write_text("ok")

        home = tmp_path / "home"
        home_skill = home / ".claude" / "skills" / "vulnhunt"
        home_skill.mkdir(parents=True)
        (home_skill / "SKILL.md").write_text("home wins by default")

        _patch_skill_candidates(monkeypatch, container=container, home=home)
        assert _vulnhunt_skill_path() == container

    def test_home_path_when_container_missing(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        container = tmp_path / "no-container"  # never created
        home = tmp_path / "home"
        home_skill = home / ".claude" / "skills" / "vulnhunt"
        home_skill.mkdir(parents=True)
        (home_skill / "SKILL.md").write_text("ok")
        _patch_skill_candidates(monkeypatch, container=container, home=home)
        assert _vulnhunt_skill_path() == home_skill

    def test_neither_returns_none(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _patch_skill_candidates(
            monkeypatch,
            container=tmp_path / "no-container",
            home=tmp_path / "no-home",
        )
        assert _vulnhunt_skill_path() is None

    def test_lowercase_skill_md_not_found(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        home = tmp_path / "home"
        skill_dir = home / ".claude" / "skills" / "vulnhunt"
        skill_dir.mkdir(parents=True)
        (skill_dir / "skill.md").write_text("lowercase only")
        _patch_skill_candidates(
            monkeypatch,
            container=tmp_path / "no-container",
            home=home,
        )
        # On a case-sensitive FS this returns None; on a case-insensitive FS
        # the lookup may succeed against 'skill.md' — skip in that case.
        result = _vulnhunt_skill_path()
        if (skill_dir / "SKILL.md").is_file():
            pytest.skip("filesystem is case-insensitive; cannot regress")
        assert result is None


# ---------------------------------------------------------------------------
# _find_results_dir
# ---------------------------------------------------------------------------


class TestFindResultsDir:
    def test_no_clone_dir_returns_none(self, tmp_path: Path) -> None:
        assert _find_results_dir(tmp_path / "missing") is None

    def test_no_matching_subdir_returns_none(self, tmp_path: Path) -> None:
        (tmp_path / "src").mkdir()
        (tmp_path / "scripts").mkdir()
        assert _find_results_dir(tmp_path) is None

    def test_one_matching_returned(self, tmp_path: Path) -> None:
        target = tmp_path / "x_VULNHUNT_RESULTS_y"
        target.mkdir()
        assert _find_results_dir(tmp_path) == target

    def test_multiple_matching_returns_newest(self, tmp_path: Path) -> None:
        older = tmp_path / "vulnhunter_VULNHUNT_RESULTS_old"
        newer = tmp_path / "vulnhunter_VULNHUNT_RESULTS_new"
        older.mkdir()
        newer.mkdir()
        os.utime(older, (1000, 1000))
        os.utime(newer, (5000, 5000))
        assert _find_results_dir(tmp_path) == newer


# ---------------------------------------------------------------------------
# Verbosity-gated logging
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_verbosity():
    set_verbosity(0)
    yield
    set_verbosity(0)


class TestLogAssistantMessage:
    def test_text_block_always_shown(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(0)
        msg = AssistantMessage(content=[TextBlock(text="hello world")], model="m")
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_assistant_message(msg)
        assert any("hello world" in r.getMessage() for r in caplog.records)

    def test_tool_use_format_v0(self, caplog: pytest.LogCaptureFixture) -> None:
        set_verbosity(0)
        msg = AssistantMessage(
            content=[ToolUseBlock(id="x", name="Read", input={"file_path": "/etc/hosts"})],
            model="m",
        )
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_assistant_message(msg)
        joined = "\n".join(r.getMessage() for r in caplog.records)
        assert "Read(/etc/hosts)" in joined
        # At v=0 the full repr of input is NOT shown.
        assert "{'file_path'" not in joined

    def test_tool_use_format_v1_includes_full_input(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(1)
        msg = AssistantMessage(
            content=[ToolUseBlock(id="x", name="Read", input={"file_path": "/p"})],
            model="m",
        )
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_assistant_message(msg)
        joined = "\n".join(r.getMessage() for r in caplog.records)
        assert "file_path" in joined and "/p" in joined

    def test_thinking_block_only_at_v2(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        msg = AssistantMessage(
            content=[ThinkingBlock(thinking="deep thoughts", signature="sig")],
            model="m",
        )
        # v=0: silent.
        set_verbosity(0)
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_assistant_message(msg)
        joined = "\n".join(r.getMessage() for r in caplog.records)
        assert "deep thoughts" not in joined
        caplog.clear()
        # v=2: shown.
        set_verbosity(2)
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_assistant_message(msg)
        joined = "\n".join(r.getMessage() for r in caplog.records)
        assert "deep thoughts" in joined


class TestLogUserMessage:
    def test_tool_result_terse_at_v0(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(0)
        msg = UserMessage(
            content=[
                ToolResultBlock(
                    tool_use_id="abc",
                    content="line1\nline2\nline3",
                )
            ],
        )
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_user_message(msg)
        joined = "\n".join(r.getMessage() for r in caplog.records)
        # Terse format uses the ↳ marker.
        assert "↳" in joined
        # Only the first line is shown plus a "(+N more)" suffix.
        assert "line1" in joined
        assert "line2" not in joined

    def test_tool_result_full_at_v1(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(1)
        msg = UserMessage(
            content=[
                ToolResultBlock(
                    tool_use_id="abc", content="line1\nline2\nline3"
                )
            ],
        )
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_user_message(msg)
        joined = "\n".join(r.getMessage() for r in caplog.records)
        # Full content rendered (with newlines escaped to \\n).
        assert "line1" in joined
        assert "line2" in joined


class TestLogTaskStarted:
    def test_short_at_v0(self, caplog: pytest.LogCaptureFixture) -> None:
        set_verbosity(0)
        msg = TaskStartedMessage(
            subtype="task_started",
            data={},
            task_id="task-123",
            description="dispatch security audit",
            uuid="u",
            session_id="s",
            task_type="audit",
        )
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_task_started(msg)
        joined = "\n".join(r.getMessage() for r in caplog.records)
        assert "dispatch security audit" in joined
        assert "task-123" not in joined

    def test_includes_id_at_v1(self, caplog: pytest.LogCaptureFixture) -> None:
        set_verbosity(1)
        msg = TaskStartedMessage(
            subtype="task_started",
            data={},
            task_id="task-123",
            description="d",
            uuid="u",
            session_id="s",
            task_type="audit",
        )
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_task_started(msg)
        joined = "\n".join(r.getMessage() for r in caplog.records)
        assert "task-123" in joined


class TestLogTaskStatus:
    def test_terminal_only_at_v0(self, caplog: pytest.LogCaptureFixture) -> None:
        set_verbosity(0)
        running = TaskNotificationMessage(
            subtype="task_notification",
            data={},
            task_id="t",
            status="running",
            output_file=None,
            summary=None,
            uuid="u",
            session_id="s",
        )
        completed = TaskNotificationMessage(
            subtype="task_notification",
            data={},
            task_id="t",
            status="completed",
            output_file=None,
            summary="all done",
            uuid="u",
            session_id="s",
        )
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_task_status(running)
            _log_task_status(completed)
        joined = "\n".join(r.getMessage() for r in caplog.records)
        # 'running' suppressed.
        assert "running" not in joined
        # 'completed' surfaces.
        assert "completed" in joined

    def test_all_statuses_at_v1(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(1)
        running = TaskNotificationMessage(
            subtype="task_notification",
            data={},
            task_id="t",
            status="running",
            output_file=None,
            summary=None,
            uuid="u",
            session_id="s",
        )
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_task_status(running)
        joined = "\n".join(r.getMessage() for r in caplog.records)
        assert "running" in joined

    def test_agent_name_rendered_at_v0(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        # Friendly subagent name is surfaced in the [name] bracket on
        # terminal status logs so multi-agent fan-outs are readable.
        set_verbosity(0)
        completed = TaskNotificationMessage(
            subtype="task_notification",
            data={},
            task_id="t",
            status="completed",
            output_file=None,
            summary="done",
            uuid="u",
            session_id="s",
        )
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_task_status(completed, agent_name="INJ partition 1")
        joined = "\n".join(r.getMessage() for r in caplog.records)
        assert "[INJ partition 1]" in joined

    def test_no_brackets_when_agent_name_absent(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(0)
        completed = TaskNotificationMessage(
            subtype="task_notification",
            data={},
            task_id="t",
            status="completed",
            output_file=None,
            summary="done",
            uuid="u",
            session_id="s",
        )
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_task_status(completed)  # no agent_name
        joined = "\n".join(r.getMessage() for r in caplog.records)
        assert "[" not in joined  # no stray empty bracket


# ---------------------------------------------------------------------------
# _agent_name_from_started
# ---------------------------------------------------------------------------


class TestAgentNameFromStarted:
    def _msg(
        self, *, description: str = "", task_type: str = "general-purpose"
    ) -> TaskStartedMessage:
        return TaskStartedMessage(
            subtype="task_started",
            data={},
            task_id="t",
            description=description,
            uuid="u",
            session_id="s",
            task_type=task_type,
        )

    def test_prefers_description_first_line(self) -> None:
        # The orchestrator's prompt first line is the most informative
        # label ("INJ partition 1" vs the SDK-generic "general-purpose").
        msg = self._msg(
            description="INJ partition 1\n\nDetailed task body...",
        )
        assert _agent_name_from_started(msg) == "INJ partition 1"

    def test_falls_back_to_task_type(self) -> None:
        msg = self._msg(description="", task_type="general-purpose")
        assert _agent_name_from_started(msg) == "general-purpose"

    def test_empty_when_both_missing(self) -> None:
        msg = self._msg(description="", task_type="")
        assert _agent_name_from_started(msg) == ""

    def test_long_description_truncated(self) -> None:
        # 200 chars of `x` — the helper caps at 60.
        msg = self._msg(description="x" * 200)
        out = _agent_name_from_started(msg)
        # _truncate uses 60 limit + "...<truncated>" suffix.
        assert out.startswith("x" * 60)
        assert len(out) < 200


# ---------------------------------------------------------------------------
# _log_per_turn_usage
# ---------------------------------------------------------------------------


class TestLogPerTurnUsage:
    def test_root_orchestrator_labelled_root(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        msg = AssistantMessage(
            content=[TextBlock(text="x")],
            model="opus-4-7",
            parent_tool_use_id=None,
            usage={
                "input_tokens": 100,
                "output_tokens": 50,
                "cache_read_input_tokens": 1000,
                "cache_creation_input_tokens": 0,
            },
        )
        last_ts: dict[str | None, float] = {None: 0.0}
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_per_turn_usage(msg, last_ts, run_start=0.0, agent_names={})
        line = "\n".join(r.getMessage() for r in caplog.records)
        assert "agent=root" in line
        assert "in=100" in line
        assert "out=50" in line
        assert "cache_read=1000" in line

    def test_subagent_uses_registry_label(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        msg = AssistantMessage(
            content=[TextBlock(text="x")],
            model="opus-4-7",
            parent_tool_use_id="toolu_abc",
            usage={"input_tokens": 1, "output_tokens": 1},
        )
        names = {"toolu_abc": "INJ partition 1"}
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_per_turn_usage(msg, {}, run_start=0.0, agent_names=names)
        line = "\n".join(r.getMessage() for r in caplog.records)
        assert "agent=INJ partition 1" in line

    def test_subagent_unknown_falls_back_to_id_prefix(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        # Registry empty — the event ordering let the AssistantMessage
        # arrive before we logged the TaskStartedMessage. Still readable.
        msg = AssistantMessage(
            content=[TextBlock(text="x")],
            model="m",
            parent_tool_use_id="toolu_abcdefgh_xyz",
            usage={"input_tokens": 1, "output_tokens": 1},
        )
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_per_turn_usage(msg, {}, run_start=0.0, agent_names={})
        line = "\n".join(r.getMessage() for r in caplog.records)
        assert "agent=agent[toolu_ab]" in line  # 8-char prefix

    def test_delta_updates_per_agent(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        # Two sequential turns from the same subagent: second Δ should be
        # measured against the first turn's timestamp, not run_start.
        msg = AssistantMessage(
            content=[TextBlock(text="x")],
            model="m",
            parent_tool_use_id="toolu_a",
            usage={"input_tokens": 1, "output_tokens": 1},
        )
        last_ts: dict[str | None, float] = {"toolu_a": 100.0}
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_per_turn_usage(msg, last_ts, run_start=0.0, agent_names={})
        # After the call, last_ts["toolu_a"] should be ~now, not 100.0.
        assert last_ts["toolu_a"] > 100.0


# ---------------------------------------------------------------------------
# end of new tests
# ---------------------------------------------------------------------------


class TestLogSystemMessage:
    def test_init_with_vulnhunt_emits_check(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(0)
        msg = SystemMessage(subtype="init", data={"slash_commands": ["vulnhunt", "help"]})
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_system_message(msg)
        joined = "\n".join(r.getMessage() for r in caplog.records)
        assert "/vulnhunt is loaded" in joined

    def test_init_with_vulnhunt_fix_verify_emits_check(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """R3-#6: verify's loaded command must also be recognized."""
        set_verbosity(0)
        msg = SystemMessage(
            subtype="init", data={"slash_commands": ["vulnhunt-fix-verify", "help"]}
        )
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_system_message(msg)
        joined = "\n".join(r.getMessage() for r in caplog.records)
        assert "/vulnhunt-fix-verify is loaded" in joined
        # And no spurious warning about it being absent.
        warns = [r for r in caplog.records if r.levelname == "WARNING"]
        assert not warns

    def test_init_without_vulnhunt_warns(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(0)
        msg = SystemMessage(subtype="init", data={"slash_commands": ["help"]})
        with caplog.at_level(logging.WARNING, logger="agent.runner"):
            _log_system_message(msg)
        joined = "\n".join(r.getMessage() for r in caplog.records)
        assert "No vulnhunt* slash command loaded" in joined

    def test_task_progress_silent_at_v0(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(0)
        msg = SystemMessage(subtype="task_progress", data={"step": "x"})
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_system_message(msg)
        # Nothing logged.
        joined = "\n".join(r.getMessage() for r in caplog.records)
        assert "task_progress" not in joined and "step" not in joined

    def test_full_data_dump_at_v2(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(2)
        msg = SystemMessage(subtype="custom", data={"key": "value-marker"})
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_system_message(msg)
        joined = "\n".join(r.getMessage() for r in caplog.records)
        assert "value-marker" in joined


# ---------------------------------------------------------------------------
# _is_auth_failure
# ---------------------------------------------------------------------------


class TestIsAuthFailure:
    def test_error_status_401(self) -> None:
        msg = SystemMessage(subtype="error", data={"error_status": 401})
        assert _is_auth_failure(msg) is True

    def test_error_authentication_failed(self) -> None:
        msg = SystemMessage(subtype="error", data={"error": "authentication_failed"})
        assert _is_auth_failure(msg) is True

    def test_benign_payload_returns_false(self) -> None:
        msg = SystemMessage(subtype="info", data={"hello": "world"})
        assert _is_auth_failure(msg) is False

    def test_non_dict_data_returns_false(self) -> None:
        msg = SystemMessage(subtype="info", data="not a dict")
        assert _is_auth_failure(msg) is False


# ---------------------------------------------------------------------------
# run_vulnhunt (async)
# ---------------------------------------------------------------------------


class _FakeAsyncClient:
    """Stand-in for ClaudeSDKClient used as an async context manager."""

    def __init__(self, scripts: list[list[Any]]) -> None:
        # Each script is the message list yielded for one query() call.
        self._scripts = list(scripts)
        self.queries: list[str] = []

    async def __aenter__(self) -> "_FakeAsyncClient":
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    async def query(self, prompt: str) -> None:
        self.queries.append(prompt)

    def receive_response(self):
        # Pop the next scripted batch each time receive_response() is called.
        if not self._scripts:
            messages: list[Any] = []
        else:
            messages = self._scripts.pop(0)

        async def _gen():
            for m in messages:
                yield m

        return _gen()


def _result_message(
    cost: float = 0.0, num_turns: int = 1, duration_api_ms: int = 5
) -> ResultMessage:
    return ResultMessage(
        subtype="success",
        duration_ms=10,
        duration_api_ms=duration_api_ms,
        is_error=False,
        num_turns=num_turns,
        session_id="s",
        total_cost_usd=cost,
    )


def _patch_run_vulnhunt_environment(
    monkeypatch: pytest.MonkeyPatch,
    *,
    scripts: list[list[Any]],
    skill_path: Path | None,
) -> _FakeAsyncClient:
    """Wire up runner.run_vulnhunt's external collaborators."""
    fake_client = _FakeAsyncClient(scripts)

    class FakeMgr:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        def get_valid_token(self) -> str:
            return "fake-token"

    monkeypatch.setattr(runner_mod, "make_token_manager", lambda *a, **k: FakeMgr())
    monkeypatch.setattr(
        runner_mod, "build_claude_settings", lambda *a, **k: '{"env":{}}'
    )
    monkeypatch.setattr(
        runner_mod, "ClaudeSDKClient", lambda *a, **k: fake_client
    )
    monkeypatch.setattr(runner_mod, "_vulnhunt_skill_path", lambda: skill_path)
    return fake_client


@pytest.mark.asyncio
async def test_run_vulnhunt_happy_path_returns_results_dir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config,
) -> None:
    clone = tmp_path / "clone"
    clone.mkdir()
    # Python now pre-creates the results dir inside run_vulnhunt; no test setup needed.

    _patch_run_vulnhunt_environment(
        monkeypatch,
        scripts=[[_result_message()]],
        skill_path=tmp_path / "skill",
    )
    out = await run_vulnhunt(clone, populated_agent_config)
    # Python pre-created the results dir; assert run_vulnhunt returned it.
    assert out is not None
    assert out.parent == clone
    assert "_VULNHUNT_RESULTS_" in out.name
    assert out.is_dir()


@pytest.mark.asyncio
async def test_run_vulnhunt_skill_missing_raises(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config,
) -> None:
    _patch_run_vulnhunt_environment(monkeypatch, scripts=[[]], skill_path=None)
    with pytest.raises(RuntimeError, match="vulnhunt skill not found"):
        await run_vulnhunt(tmp_path, populated_agent_config)


@pytest.mark.asyncio
async def test_run_vulnhunt_three_auth_failures_raise(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config,
) -> None:
    clone = tmp_path / "clone"
    clone.mkdir()
    auth_msg = SystemMessage(subtype="error", data={"error_status": 401})
    _patch_run_vulnhunt_environment(
        monkeypatch,
        scripts=[[auth_msg, auth_msg, auth_msg, _result_message()]],
        skill_path=tmp_path / "skill",
    )
    with pytest.raises(AuthRejectedError):
        await run_vulnhunt(clone, populated_agent_config)


@pytest.mark.asyncio
async def test_run_vulnhunt_continuation_loop(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config,
) -> None:
    clone = tmp_path / "clone"
    clone.mkdir()
    # Python now pre-creates the results dir inside run_vulnhunt; no test setup needed.

    started = TaskStartedMessage(
        subtype="task_started",
        data={},
        task_id="t1",
        description="d",
        uuid="u",
        session_id="s",
        task_type="audit",
    )
    completed = TaskNotificationMessage(
        subtype="task_notification",
        data={},
        task_id="t1",
        status="completed",
        output_file=None,
        summary="done",
        uuid="u",
        session_id="s",
    )
    fake = _patch_run_vulnhunt_environment(
        monkeypatch,
        scripts=[
            [started, _result_message()],     # first turn: pending task remains
            [completed, _result_message()],   # second turn: drains pending
        ],
        skill_path=tmp_path / "skill",
    )
    out = await run_vulnhunt(clone, populated_agent_config)
    # Python pre-created the results dir; assert run_vulnhunt returned it.
    assert out is not None
    assert out.parent == clone
    assert "_VULNHUNT_RESULTS_" in out.name
    assert out.is_dir()
    # Two queries: original + one continuation.
    assert len(fake.queries) == 2


@pytest.mark.asyncio
async def test_run_vulnhunt_stall_cap_logs_warning_when_no_tasks_complete(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Stall detector fires when NO task lifecycle events (start or
    terminal) arrive across N consecutive continuations. With
    ``_MAX_STALLED_CONTINUATIONS=2`` and an initial cycle that dispatches
    one task followed by continuation cycles emitting only ResultMessages
    (no task activity), the warning fires after 2 stalled cycles.
    """
    clone = tmp_path / "clone"
    clone.mkdir()
    monkeypatch.setattr(runner_mod, "_MAX_STALLED_CONTINUATIONS", 2)
    started = TaskStartedMessage(
        subtype="task_started",
        data={},
        task_id="orphaned",
        description="d",
        uuid="u",
        session_id="s",
        task_type="audit",
    )
    scripts = [
        # Cycle 0: dispatch one task. Lifecycle event count = 1 → stall=0.
        [started, _result_message()],
        # Cycle 1: silence. No lifecycle events → stall=1.
        [_result_message()],
        # Cycle 2: still silent. stall=2 → trip.
        [_result_message()],
        # Cycle 3 onward: should never run; defensive script just in case.
        [_result_message()],
        [_result_message()],
    ]
    _patch_run_vulnhunt_environment(
        monkeypatch, scripts=scripts, skill_path=tmp_path / "skill"
    )
    with caplog.at_level(logging.WARNING, logger="agent.runner"):
        await run_vulnhunt(clone, populated_agent_config)
    joined = "\n".join(r.getMessage() for r in caplog.records)
    assert "No task completed for" in joined
    assert "orphaned" in joined


@pytest.mark.asyncio
async def test_run_vulnhunt_terminal_event_resets_stall_counter(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A terminal TaskNotificationMessage resets the stall counter.

    With ``_MAX_STALLED_CONTINUATIONS=2`` and a 4-script sequence
    (initial + 3 continuations), trace:

      script[0] (initial): 2 starts → lifecycle=2, stall=0, pending={t1,t2}
      script[1] (cont 1):  silent   → lifecycle=0, stall=1, pending={t1,t2}
      script[2] (cont 2):  t1 done  → lifecycle=1, stall=0 (reset), pending={t2}
      script[3] (cont 3):  t2 done  → drains pending, loop exits cleanly

    Without the reset on script[2], a third silent cycle would have
    tripped the stall warning. We assert the warning does NOT fire.
    """
    clone = tmp_path / "clone"
    clone.mkdir()
    # Python now pre-creates the results dir inside run_vulnhunt; no test setup needed.

    monkeypatch.setattr(runner_mod, "_MAX_STALLED_CONTINUATIONS", 2)
    started = TaskStartedMessage(
        subtype="task_started",
        data={},
        task_id="t1",
        description="d",
        uuid="u",
        session_id="s",
        task_type="audit",
    )
    started2 = TaskStartedMessage(
        subtype="task_started",
        data={},
        task_id="t2",
        description="d",
        uuid="u",
        session_id="s",
        task_type="audit",
    )
    completed_t1 = TaskNotificationMessage(
        subtype="task_notification",
        data={},
        task_id="t1",
        status="completed",
        output_file=None,
        summary="done",
        uuid="u",
        session_id="s",
    )
    completed_t2 = TaskNotificationMessage(
        subtype="task_notification",
        data={},
        task_id="t2",
        status="completed",
        output_file=None,
        summary="done",
        uuid="u",
        session_id="s",
    )
    scripts = [
        # Cycle 0: start t1 and t2. Pending={t1,t2}.
        [started, started2, _result_message()],
        # Cycle 1: no progress (stall=1).
        [_result_message()],
        # Cycle 2: t1 completes (resets stall to 0). Pending={t2}.
        [completed_t1, _result_message()],
        # Cycle 3: t2 completes — pending now empty so loop exits cleanly.
        [completed_t2, _result_message()],
    ]
    _patch_run_vulnhunt_environment(
        monkeypatch, scripts=scripts, skill_path=tmp_path / "skill"
    )
    with caplog.at_level(logging.WARNING, logger="agent.runner"):
        await run_vulnhunt(clone, populated_agent_config)
    joined = "\n".join(r.getMessage() for r in caplog.records)
    assert "No task completed for" not in joined


@pytest.mark.asyncio
async def test_run_vulnhunt_cost_accumulator(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config,
    caplog: pytest.LogCaptureFixture,
) -> None:
    clone = tmp_path / "clone"
    clone.mkdir()
    started = TaskStartedMessage(
        subtype="task_started",
        data={},
        task_id="t1",
        description="d",
        uuid="u",
        session_id="s",
        task_type="audit",
    )
    completed = TaskNotificationMessage(
        subtype="task_notification",
        data={},
        task_id="t1",
        status="completed",
        output_file=None,
        summary="done",
        uuid="u",
        session_id="s",
    )
    # Three ResultMessages emitting CUMULATIVE costs $1, $2, $3 — that's
    # how the upstream Claude Code stream-json result event reports
    # total_cost_usd (running sum since session start, not a per-turn
    # delta). The runner now takes the running max, so the reported
    # total is $3 (the highest cumulative seen), not $6.
    _patch_run_vulnhunt_environment(
        monkeypatch,
        scripts=[
            [started, _result_message(cost=1.0)],
            [_result_message(cost=2.0)],  # still has pending
            [completed, _result_message(cost=3.0)],
        ],
        skill_path=tmp_path / "skill",
    )
    with caplog.at_level(logging.INFO, logger="agent.runner"):
        await run_vulnhunt(clone, populated_agent_config)
    joined = "\n".join(r.getMessage() for r in caplog.records)
    assert "Scan totals" in joined
    assert "cost_usd=$3.0000" in joined
    assert "cost_usd=$6.0000" not in joined


@pytest.mark.asyncio
async def test_run_vulnhunt_cost_uses_max_not_last(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Guards against "last value wins" semantics on cost_usd. A final
    ResultMessage that arrives with total_cost_usd=0 (e.g. an error
    ResultMessage with no usage data) must NOT zero out the cumulative
    total — taking the running max is robust against that pattern.
    """
    clone = tmp_path / "clone"
    clone.mkdir()
    started = TaskStartedMessage(
        subtype="task_started",
        data={},
        task_id="t1",
        description="d",
        uuid="u",
        session_id="s",
        task_type="audit",
    )
    completed = TaskNotificationMessage(
        subtype="task_notification",
        data={},
        task_id="t1",
        status="completed",
        output_file=None,
        summary="done",
        uuid="u",
        session_id="s",
    )
    _patch_run_vulnhunt_environment(
        monkeypatch,
        scripts=[
            [started, _result_message(cost=5.0)],
            # Final ResultMessage with cost=0 (error / no usage). The
            # running-max policy keeps $5.00, not $0.00.
            [completed, _result_message(cost=0.0)],
        ],
        skill_path=tmp_path / "skill",
    )
    with caplog.at_level(logging.INFO, logger="agent.runner"):
        await run_vulnhunt(clone, populated_agent_config)
    joined = "\n".join(r.getMessage() for r in caplog.records)
    assert "Scan totals" in joined
    # Check only the segment AFTER "Scan totals" — earlier per-RM logs
    # legitimately show the $0 ResultMessage; the rollup must not.
    _, _, rollup = joined.partition("Scan totals")
    assert "cost_usd=$5.0000" in rollup
    assert "cost_usd=$0.0000" not in rollup


@pytest.mark.asyncio
async def test_run_vulnhunt_num_turns_sums_per_cycle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """num_turns is per-cycle (no ``total_`` prefix; empirically
    non-monotonic across ResultMessages in real scans), so it sums
    across cycles. Only ``total_cost_usd`` (which IS prefixed
    cumulative) uses running-max.
    """
    clone = tmp_path / "clone"
    clone.mkdir()
    started = TaskStartedMessage(
        subtype="task_started",
        data={},
        task_id="t1",
        description="d",
        uuid="u",
        session_id="s",
        task_type="audit",
    )
    completed = TaskNotificationMessage(
        subtype="task_notification",
        data={},
        task_id="t1",
        status="completed",
        output_file=None,
        summary="done",
        uuid="u",
        session_id="s",
    )
    _patch_run_vulnhunt_environment(
        monkeypatch,
        scripts=[
            [started, _result_message(num_turns=35)],
            [_result_message(num_turns=2)],
            [completed, _result_message(num_turns=7)],
        ],
        skill_path=tmp_path / "skill",
    )
    with caplog.at_level(logging.INFO, logger="agent.runner"):
        await run_vulnhunt(clone, populated_agent_config)
    joined = "\n".join(r.getMessage() for r in caplog.records)
    # 35 + 2 + 7 = 44 — per-cycle sum, not max-of-cumulative.
    assert "44 turn(s)" in joined


@pytest.mark.asyncio
async def test_run_vulnhunt_duration_api_ms_sums_per_cycle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``duration_api_ms`` is per-cycle (no ``total_`` prefix on the
    SDK field name — the SDK uses ``total_`` as the marker for
    cumulative-within-session values; ``duration_api_ms`` lacks it).
    The field's semantic purpose is detecting API slowness on THIS
    cycle, which a cumulative-since-session value couldn't serve. So
    sum across cycles like ``num_turns``; only ``total_cost_usd``
    uses running-max. Empirical confirmation lives in the per-RM
    ``api_duration=...`` line in ``_log_result``.
    """
    clone = tmp_path / "clone"
    clone.mkdir()
    started = TaskStartedMessage(
        subtype="task_started",
        data={},
        task_id="t1",
        description="d",
        uuid="u",
        session_id="s",
        task_type="audit",
    )
    completed = TaskNotificationMessage(
        subtype="task_notification",
        data={},
        task_id="t1",
        status="completed",
        output_file=None,
        summary="done",
        uuid="u",
        session_id="s",
    )
    _patch_run_vulnhunt_environment(
        monkeypatch,
        scripts=[
            [started, _result_message(duration_api_ms=1200)],
            [_result_message(duration_api_ms=800)],
            [completed, _result_message(duration_api_ms=600)],
        ],
        skill_path=tmp_path / "skill",
    )
    with caplog.at_level(logging.INFO, logger="agent.runner"):
        await run_vulnhunt(clone, populated_agent_config)
    joined = "\n".join(r.getMessage() for r in caplog.records)
    # 1200 + 800 + 600 = 2600 ms — per-cycle sum, not max-of-cumulative.
    # Check the rollup specifically — earlier per-RM logs legitimately
    # show each cycle's value.
    assert "Scan totals" in joined
    _, _, rollup = joined.partition("Scan totals")
    assert "API duration=2600ms" in rollup


@pytest.mark.asyncio
async def test_run_vulnhunt_pending_set_drains_on_terminal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config,
) -> None:
    clone = tmp_path / "clone"
    clone.mkdir()
    started = TaskStartedMessage(
        subtype="task_started",
        data={},
        task_id="t1",
        description="d",
        uuid="u",
        session_id="s",
        task_type="audit",
    )
    completed = TaskNotificationMessage(
        subtype="task_notification",
        data={},
        task_id="t1",
        status="completed",
        output_file=None,
        summary="done",
        uuid="u",
        session_id="s",
    )
    fake = _patch_run_vulnhunt_environment(
        monkeypatch,
        scripts=[[started, completed, _result_message()]],
        skill_path=tmp_path / "skill",
    )
    await run_vulnhunt(clone, populated_agent_config)
    # Single query: terminal status drained pending in the same batch.
    assert len(fake.queries) == 1


@pytest.mark.asyncio
async def test_run_vulnhunt_non_terminal_status_keeps_pending(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config,
) -> None:
    clone = tmp_path / "clone"
    clone.mkdir()
    started = TaskStartedMessage(
        subtype="task_started",
        data={},
        task_id="t1",
        description="d",
        uuid="u",
        session_id="s",
        task_type="audit",
    )
    running = TaskNotificationMessage(
        subtype="task_notification",
        data={},
        task_id="t1",
        status="running",
        output_file=None,
        summary=None,
        uuid="u",
        session_id="s",
    )
    completed = TaskNotificationMessage(
        subtype="task_notification",
        data={},
        task_id="t1",
        status="completed",
        output_file=None,
        summary=None,
        uuid="u",
        session_id="s",
    )
    fake = _patch_run_vulnhunt_environment(
        monkeypatch,
        scripts=[
            [started, running, _result_message()],
            [completed, _result_message()],
        ],
        skill_path=tmp_path / "skill",
    )
    await run_vulnhunt(clone, populated_agent_config)
    # 'running' did NOT drain the pending set, so a continuation was needed.
    assert len(fake.queries) == 2


# ---------------------------------------------------------------------------
# Cold-start rate-limit detection and retry (RateLimitError path)
# ---------------------------------------------------------------------------


def _rate_limit_result(status: int = 429) -> ResultMessage:
    """A terminal ResultMessage that signals a transient API failure.

    Sets both ``api_error_status`` (the typed signal _is_rate_limit_result
    looks at first) and ``errors`` (the fallback path) so the helper
    keeps working if the SDK ever drops the typed field.
    """
    return ResultMessage(
        subtype="error",
        duration_ms=10,
        duration_api_ms=5,
        is_error=True,
        num_turns=0,
        session_id="s",
        total_cost_usd=0.0,
        api_error_status=status,
        errors=[f"HTTP {status} from upstream"],
    )


def _rate_limit_system() -> SystemMessage:
    return SystemMessage(subtype="error", data={"error_status": 429})


class TestRateLimitDetectors:
    def test_system_message_429_status_detected(self) -> None:
        assert _is_rate_limit_system_message(
            SystemMessage(subtype="error", data={"error_status": 429})
        )

    def test_system_message_503_status_detected(self) -> None:
        assert _is_rate_limit_system_message(
            SystemMessage(subtype="error", data={"error_status": 503})
        )

    def test_system_message_api_error_status_field(self) -> None:
        assert _is_rate_limit_system_message(
            SystemMessage(subtype="error", data={"api_error_status": 429})
        )

    def test_system_message_error_text_rate_limit(self) -> None:
        assert _is_rate_limit_system_message(
            SystemMessage(subtype="error", data={"error": "rate_limit_exceeded"})
        )

    def test_system_message_overloaded(self) -> None:
        assert _is_rate_limit_system_message(
            SystemMessage(subtype="error", data={"error": "Model is overloaded"})
        )

    def test_system_message_non_transient_status_ignored(self) -> None:
        assert not _is_rate_limit_system_message(
            SystemMessage(subtype="error", data={"error_status": 404})
        )

    def test_system_message_no_data_ignored(self) -> None:
        assert not _is_rate_limit_system_message(
            SystemMessage(subtype="init", data=None)
        )

    def test_result_message_is_error_false_not_rate_limit(self) -> None:
        assert not _is_rate_limit_result(_result_message())

    def test_result_message_api_error_status_429(self) -> None:
        msg = _rate_limit_result(status=429)
        assert _is_rate_limit_result(msg)

    def test_result_message_errors_payload_contains_429(self) -> None:
        # Errors-payload-only path: api_error_status is left unset so
        # the helper has to fall through to the errors substring scan.
        msg = ResultMessage(
            subtype="error",
            duration_ms=1,
            duration_api_ms=1,
            is_error=True,
            num_turns=0,
            session_id="s",
            total_cost_usd=0.0,
            errors=["HTTP 429 throttled by bedrock"],
        )
        assert _is_rate_limit_result(msg)

    # Bug 2 lock-down (PR #11 review): bare numeric substring matching
    # used to false-positive when an error payload contained a token
    # count. Word-boundary regex rejects each.
    def test_result_message_token_count_5000_not_rate_limit(self) -> None:
        msg = ResultMessage(
            subtype="error",
            duration_ms=1,
            duration_api_ms=1,
            is_error=True,
            num_turns=0,
            session_id="s",
            total_cost_usd=0.0,
            errors=["prompt exceeded 5000 tokens; max 4096"],
        )
        assert not _is_rate_limit_result(msg)

    def test_result_message_token_count_4290_not_rate_limit(self) -> None:
        msg = ResultMessage(
            subtype="error",
            duration_ms=1,
            duration_api_ms=1,
            is_error=True,
            num_turns=0,
            session_id="s",
            total_cost_usd=0.0,
            errors=["4290 tokens used of 4096 budget"],
        )
        assert not _is_rate_limit_result(msg)

    def test_result_message_errors_payload_overloaded_still_matches(self) -> None:
        # Phrase indicators still classify via the shared regex.
        msg = ResultMessage(
            subtype="error",
            duration_ms=1,
            duration_api_ms=1,
            is_error=True,
            num_turns=0,
            session_id="s",
            total_cost_usd=0.0,
            errors=["upstream returned: model is overloaded"],
        )
        assert _is_rate_limit_result(msg)

    # Bug-1-shape closure (PR #11 follow-up review). Before the
    # ``classify`` helper landed, these detectors fell through to a
    # text scan whenever the typed status was non-None-but-non-
    # transient, so a ResultMessage with ``api_error_status=400`` and
    # ``errors=["rate_limit_exceeded"]`` would have classified as
    # rate-limit and triggered a cold-start retry.
    def test_result_message_typed_400_short_circuits_transient_text(
        self,
    ) -> None:
        msg = ResultMessage(
            subtype="error",
            duration_ms=1,
            duration_api_ms=1,
            is_error=True,
            num_turns=0,
            session_id="s",
            total_cost_usd=0.0,
            api_error_status=400,
            errors=["rate_limit_exceeded"],
        )
        assert not _is_rate_limit_result(msg)

    def test_result_message_typed_404_short_circuits_overloaded_text(
        self,
    ) -> None:
        msg = ResultMessage(
            subtype="error",
            duration_ms=1,
            duration_api_ms=1,
            is_error=True,
            num_turns=0,
            session_id="s",
            total_cost_usd=0.0,
            api_error_status=404,
            errors=["model is overloaded"],
        )
        assert not _is_rate_limit_result(msg)

    def test_system_message_typed_400_short_circuits_transient_text(
        self,
    ) -> None:
        """Same closure for SystemMessage. ``error_status=400`` +
        ``error="rate_limit_exceeded"`` must be permanent."""
        assert not _is_rate_limit_system_message(
            SystemMessage(
                subtype="error",
                data={"error_status": 400, "error": "rate_limit_exceeded"},
            )
        )

    def test_system_message_typed_403_short_circuits_overloaded_text(
        self,
    ) -> None:
        assert not _is_rate_limit_system_message(
            SystemMessage(
                subtype="error",
                data={"api_error_status": 403, "error": "model is overloaded"},
            )
        )


def _patch_run_vulnhunt_environment_multi_attempt(
    monkeypatch: pytest.MonkeyPatch,
    *,
    per_attempt_scripts: list[list[list[Any]]],
    skill_path: Path | None,
) -> list[_FakeAsyncClient]:
    """Like ``_patch_run_vulnhunt_environment`` but returns a *new* fake
    client for each ClaudeSDKClient(...) call.

    ``per_attempt_scripts[i]`` is the script list for the i-th attempt.
    The patch records all instantiated clients so tests can assert on
    how many attempts ran and what each one received.

    Backoff sleeps are skipped at the test layer by passing
    ``backoffs=(0.0, 0.0, ...)`` to ``run_vulnhunt`` — the helper does
    NOT need to patch any sleep function, since tenacity respects
    whatever ``backoffs`` resolves to.
    """
    pending = list(per_attempt_scripts)
    created: list[_FakeAsyncClient] = []

    class FakeMgr:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        def get_valid_token(self) -> str:
            return "fake-token"

    def make_client(*_a: object, **_k: object) -> _FakeAsyncClient:
        if not pending:
            # If the runner asks for another attempt past what the test
            # scripted, return a closed-stream client so the test fails
            # informatively instead of hanging.
            return _FakeAsyncClient([])
        client = _FakeAsyncClient(pending.pop(0))
        created.append(client)
        return client

    monkeypatch.setattr(runner_mod, "make_token_manager", lambda *a, **k: FakeMgr())
    monkeypatch.setattr(
        runner_mod, "build_claude_settings", lambda *a, **k: '{"env":{}}'
    )
    monkeypatch.setattr(runner_mod, "ClaudeSDKClient", make_client)
    monkeypatch.setattr(runner_mod, "_vulnhunt_skill_path", lambda: skill_path)
    return created


# Zero-delay backoff schedule used by retry tests so they finish instantly
# while still exercising the full attempt count of _SCAN_RETRY_BACKOFFS.
_TEST_NO_DELAY_BACKOFFS = (0.0,) * len(runner_mod._SCAN_RETRY_BACKOFFS)


@pytest.mark.asyncio
async def test_run_vulnhunt_cold_start_rate_limit_retries(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config,
) -> None:
    """Three consecutive rate-limit SystemMessages with no AssistantMessage =
    cold-start failure. The outer loop should retry; second attempt succeeds.
    """
    clone = tmp_path / "clone"
    clone.mkdir()
    # Python now pre-creates the results dir inside run_vulnhunt; no test setup needed.

    rl = _rate_limit_system()
    created = _patch_run_vulnhunt_environment_multi_attempt(
        monkeypatch,
        per_attempt_scripts=[
            # Attempt 1: 3 consecutive rate-limit SystemMessages → RateLimitError.
            [[rl, rl, rl, _result_message()]],
            # Attempt 2: clean success.
            [[_result_message()]],
        ],
        skill_path=tmp_path / "skill",
    )
    out = await run_vulnhunt(
        clone, populated_agent_config, backoffs=_TEST_NO_DELAY_BACKOFFS
    )
    # Python pre-created the results dir; assert run_vulnhunt returned it.
    assert out is not None
    assert out.parent == clone
    assert "_VULNHUNT_RESULTS_" in out.name
    assert out.is_dir()
    # Two SDK client instances created — one per attempt.
    assert len(created) == 2


@pytest.mark.asyncio
async def test_run_vulnhunt_mid_stream_rate_limit_does_not_retry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config,
) -> None:
    """An AssistantMessage flips saw_assistant=True; subsequent rate-limits
    log a warning but DON'T raise RateLimitError, so no retry happens.
    """
    clone = tmp_path / "clone"
    clone.mkdir()
    # Python now pre-creates the results dir inside run_vulnhunt; no test setup needed.

    rl = _rate_limit_system()
    # AssistantMessage with empty content list — exercises the saw_assistant
    # flag without needing real content blocks.
    assistant = AssistantMessage(content=[], model="m", parent_tool_use_id=None)
    created = _patch_run_vulnhunt_environment_multi_attempt(
        monkeypatch,
        per_attempt_scripts=[
            [[assistant, rl, rl, rl, rl, _result_message()]],
        ],
        skill_path=tmp_path / "skill",
    )
    out = await run_vulnhunt(
        clone, populated_agent_config, backoffs=_TEST_NO_DELAY_BACKOFFS
    )
    # Python pre-created the results dir; assert run_vulnhunt returned it.
    assert out is not None
    assert out.parent == clone
    assert "_VULNHUNT_RESULTS_" in out.name
    assert out.is_dir()
    # Only ONE attempt — mid-stream transients do not restart the session.
    assert len(created) == 1


@pytest.mark.asyncio
async def test_run_vulnhunt_rate_limit_result_message_retries(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config,
) -> None:
    """A terminal ResultMessage with is_error=True + 429 indicator, with NO
    AssistantMessage seen, also triggers a cold-start retry.
    """
    clone = tmp_path / "clone"
    clone.mkdir()
    # Python now pre-creates the results dir inside run_vulnhunt; no test setup needed.

    created = _patch_run_vulnhunt_environment_multi_attempt(
        monkeypatch,
        per_attempt_scripts=[
            [[_rate_limit_result()]],
            [[_result_message()]],
        ],
        skill_path=tmp_path / "skill",
    )
    out = await run_vulnhunt(
        clone, populated_agent_config, backoffs=_TEST_NO_DELAY_BACKOFFS
    )
    # Python pre-created the results dir; assert run_vulnhunt returned it.
    assert out is not None
    assert out.parent == clone
    assert "_VULNHUNT_RESULTS_" in out.name
    assert out.is_dir()
    assert len(created) == 2


@pytest.mark.asyncio
async def test_run_vulnhunt_rate_limit_exhausts_retries(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """When every attempt hits a cold-start rate-limit, the function should
    raise RateLimitError after exhausting the backoff schedule AND log an
    operator-facing ERROR line surfacing the retry count.
    """
    clone = tmp_path / "clone"
    clone.mkdir()

    # _SCAN_RETRY_BACKOFFS has 3 entries → 4 total attempts.
    rl_script = [[_rate_limit_result()]]
    per_attempt_scripts = [rl_script] * (1 + len(runner_mod._SCAN_RETRY_BACKOFFS))

    created = _patch_run_vulnhunt_environment_multi_attempt(
        monkeypatch,
        per_attempt_scripts=per_attempt_scripts,
        skill_path=tmp_path / "skill",
    )
    with caplog.at_level(logging.ERROR, logger="agent.runner"):
        with pytest.raises(RateLimitError):
            await run_vulnhunt(
                clone, populated_agent_config, backoffs=_TEST_NO_DELAY_BACKOFFS
            )
    # All scripted attempts were consumed.
    assert len(created) == len(per_attempt_scripts)
    msgs = "\n".join(r.getMessage() for r in caplog.records)
    assert "exhausted" in msgs
    assert str(len(_TEST_NO_DELAY_BACKOFFS)) in msgs


@pytest.mark.asyncio
async def test_run_vulnhunt_assistant_resets_rate_limit_counter(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config,
) -> None:
    """A single rate-limit SystemMessage that's followed by an AssistantMessage
    must not push the consecutive counter to the threshold — saw_assistant
    flips and the counter resets, so the session continues.
    """
    clone = tmp_path / "clone"
    clone.mkdir()
    # Python now pre-creates the results dir inside run_vulnhunt; no test setup needed.

    rl = _rate_limit_system()
    assistant = AssistantMessage(content=[], model="m", parent_tool_use_id=None)
    created = _patch_run_vulnhunt_environment_multi_attempt(
        monkeypatch,
        per_attempt_scripts=[
            # rl, rl, then assistant → counter resets → another rl, rl, rl
            # would normally be 3 in a row, but the assistant interruption
            # earlier already reset the counter, so this second cluster
            # also has to reach 3 from scratch. Here we only emit 2.
            [[rl, rl, assistant, rl, rl, _result_message()]],
        ],
        skill_path=tmp_path / "skill",
    )
    out = await run_vulnhunt(
        clone, populated_agent_config, backoffs=_TEST_NO_DELAY_BACKOFFS
    )
    # Python pre-created the results dir; assert run_vulnhunt returned it.
    assert out is not None
    assert out.parent == clone
    assert "_VULNHUNT_RESULTS_" in out.name
    assert out.is_dir()
    assert len(created) == 1


# ---------------------------------------------------------------------------
# _git_context — pre-staging the values the skill used to gather via Bash
# ---------------------------------------------------------------------------


def _stub_git_runner(
    monkeypatch: pytest.MonkeyPatch,
    *,
    branch: str | None = "main",
    sha: str | None = "abc1234",
    origin: str | None = "https://github.com/example-org/example.git",
) -> None:
    """Patch ``runner_mod._run_git`` to return scripted values without
    spawning ``git``. Pass ``None`` for any field to simulate a non-zero
    git exit (the helper returns ``""`` in that case, matching real
    behavior).
    """

    def fake(_clone: Path, *args: str) -> str:
        joined = " ".join(args)
        if joined.startswith("rev-parse --abbrev-ref HEAD"):
            return branch or ""
        if joined.startswith("rev-parse --short HEAD"):
            return sha or ""
        if joined.startswith("remote get-url origin"):
            return origin or ""
        return ""

    monkeypatch.setattr(runner_mod, "_run_git", fake)


class TestGitContext:
    def test_happy_path_branch_label_and_repo_url(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _stub_git_runner(monkeypatch)
        ctx = runner_mod._git_context(tmp_path)
        assert ctx["branch_label"] == "main [abc1234]"
        assert ctx["repo_url"] == "https://github.com/example-org/example"

    def test_not_a_git_repo_falls_back_to_unknown_and_basename(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _stub_git_runner(monkeypatch, branch=None, sha=None, origin=None)
        clone = tmp_path / "myrepo"
        clone.mkdir()
        ctx = runner_mod._git_context(clone)
        assert ctx["branch_label"] == "unknown"
        assert ctx["repo_url"] == "myrepo"

    def test_ssh_origin_rewritten_to_https(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _stub_git_runner(monkeypatch, origin="git@github.com:example-org/example.git")
        ctx = runner_mod._git_context(tmp_path)
        assert ctx["repo_url"] == "https://github.com/example-org/example"

    def test_git_suffix_stripped(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _stub_git_runner(monkeypatch, origin="https://github.com/example-org/example.git")
        ctx = runner_mod._git_context(tmp_path)
        assert ctx["repo_url"] == "https://github.com/example-org/example"

    def test_basic_auth_userinfo_stripped(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _stub_git_runner(
            monkeypatch,
            origin="https://alice:ghp_realtoken@github.com/example-org/example.git",
        )
        ctx = runner_mod._git_context(tmp_path)
        # Token must not survive into the normalized URL — this value lands
        # in the prompt and the README header, both user-facing.
        assert "ghp_realtoken" not in ctx["repo_url"]
        assert "alice" not in ctx["repo_url"]
        assert ctx["repo_url"] == "https://github.com/example-org/example"

    def test_partial_failure_branch_only_falls_back_to_unknown(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Branch succeeded, SHA failed → label is "unknown" (we don't
        # report a half-resolved label).
        _stub_git_runner(monkeypatch, branch="main", sha=None)
        ctx = runner_mod._git_context(tmp_path)
        assert ctx["branch_label"] == "unknown"

    def test_run_git_oserror_returns_empty(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Simulate `git` binary missing — subprocess.run raises FileNotFoundError.
        def fake_run(*a: object, **kw: object) -> object:
            raise FileNotFoundError("no git on PATH")

        monkeypatch.setattr(runner_mod.subprocess, "run", fake_run)
        out = runner_mod._run_git(tmp_path, "rev-parse", "HEAD")
        assert out == ""

    def test_run_git_short_circuits_when_executable_missing(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """When ``_GIT_EXECUTABLE`` is None at module load (git not on
        PATH at import time), ``_run_git`` must return "" without calling
        ``subprocess.run`` — no surprise OSError, no PATH-time resolution
        at call sites (Bandit B607 hardening)."""
        called: list[object] = []

        def fake_run(*a: object, **kw: object) -> object:
            called.append((a, kw))
            raise AssertionError("subprocess.run must not be called")

        monkeypatch.setattr(runner_mod, "_GIT_EXECUTABLE", None)
        monkeypatch.setattr(runner_mod.subprocess, "run", fake_run)
        out = runner_mod._run_git(tmp_path, "rev-parse", "HEAD")
        assert out == ""
        assert called == []

    def test_run_git_uses_absolute_executable_path(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The argv list passed to subprocess.run must start with the
        absolute path resolved by ``shutil.which`` at module load — not
        the bare string "git" (Bandit B607)."""
        captured: dict[str, object] = {}

        def fake_run(argv: list[str], **kw: object) -> object:
            captured["argv"] = argv

            class _Result:
                returncode = 0
                stdout = "main\n"
                stderr = ""

            return _Result()

        monkeypatch.setattr(runner_mod, "_GIT_EXECUTABLE", "/usr/bin/git")
        monkeypatch.setattr(runner_mod.subprocess, "run", fake_run)
        out = runner_mod._run_git(tmp_path, "rev-parse", "--abbrev-ref", "HEAD")
        assert out == "main"
        assert captured["argv"] == [
            "/usr/bin/git",
            "rev-parse",
            "--abbrev-ref",
            "HEAD",
        ]


# ---------------------------------------------------------------------------
# _compute_results_dir / _check_no_prior_results
# ---------------------------------------------------------------------------


class TestComputeResultsDir:
    def test_includes_tag_and_timestamp(self, tmp_path: Path) -> None:
        clone = tmp_path / "myrepo"
        clone.mkdir()
        out = runner_mod._compute_results_dir(clone, "claude-opus-4-8")
        assert out.parent == clone
        assert out.name.startswith("myrepo_VULNHUNT_RESULTS_opus48_")
        # Timestamp tail looks like YYYY-MM-DD-HHMMSS.
        assert re.match(
            r".*_VULNHUNT_RESULTS_opus48_\d{4}-\d{2}-\d{2}-\d{6}$", out.name
        )

    def test_unique_per_call(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # Two calls in the same second should still differ because
        # _compute_results_dir uses %H%M%S precision; force a second tick.
        import time as _time

        clone = tmp_path / "myrepo"
        clone.mkdir()
        a = runner_mod._compute_results_dir(clone, "claude-opus-4-8")
        _time.sleep(1.01)
        b = runner_mod._compute_results_dir(clone, "claude-opus-4-8")
        assert a != b


class TestCheckNoPriorResults:
    def test_empty_clone_passes(self, tmp_path: Path) -> None:
        clone = tmp_path / "clone"
        clone.mkdir()
        runner_mod._check_no_prior_results(clone)  # should not raise

    def test_unrelated_dirs_pass(self, tmp_path: Path) -> None:
        clone = tmp_path / "clone"
        clone.mkdir()
        (clone / "src").mkdir()
        (clone / ".git").mkdir()
        runner_mod._check_no_prior_results(clone)  # should not raise

    def test_existing_results_dir_raises(self, tmp_path: Path) -> None:
        clone = tmp_path / "clone"
        clone.mkdir()
        (clone / "myrepo_VULNHUNT_RESULTS_opus48_2026-01-01-000000").mkdir()
        with pytest.raises(runner_mod.PriorResultsError, match="VULNHUNT_RESULTS"):
            runner_mod._check_no_prior_results(clone)

    def test_missing_dir_treated_as_empty(self, tmp_path: Path) -> None:
        # Clone hasn't been created yet — shouldn't crash.
        runner_mod._check_no_prior_results(tmp_path / "nonexistent")


# ---------------------------------------------------------------------------
# _build_vulnhunt_prompt — pre-staged metadata block
# ---------------------------------------------------------------------------


class TestBuildVulnhuntPromptPreStaged:
    def test_includes_pre_resolved_metadata_block(self, tmp_path: Path) -> None:
        results = tmp_path / "x_VULNHUNT_RESULTS_y"
        prompt = _build_vulnhunt_prompt(
            tmp_path,
            "claude-opus-4-8",
            results_dir=results,
            branch_label="main [abc1234]",
            repo_url="https://github.com/example-org/example",
        )
        assert "Pre-resolved scan metadata" in prompt
        assert f"VULNHUNT_DIR: {results}" in prompt
        assert "VULNHUNT_BRANCH: main [abc1234]" in prompt
        assert "Repository URL: https://github.com/example-org/example" in prompt

    def test_bash_line_reflects_enable_bash_false(self, tmp_path: Path) -> None:
        results = tmp_path / "x_VULNHUNT_RESULTS_y"
        prompt = _build_vulnhunt_prompt(
            tmp_path,
            "claude-opus-4-8",
            results_dir=results,
            branch_label="unknown",
            repo_url=tmp_path.name,
            enable_bash=False,
        )
        assert "Bash is NOT available" in prompt
        assert "Bash is AVAILABLE" not in prompt

    def test_bash_line_reflects_enable_bash_true(self, tmp_path: Path) -> None:
        results = tmp_path / "x_VULNHUNT_RESULTS_y"
        prompt = _build_vulnhunt_prompt(
            tmp_path,
            "claude-opus-4-8",
            results_dir=results,
            branch_label="unknown",
            repo_url=tmp_path.name,
            enable_bash=True,
        )
        assert "Bash is AVAILABLE" in prompt

    def test_defaults_omit_metadata_block_for_backcompat(self, tmp_path: Path) -> None:
        # When no pre-staged values are supplied (test default path),
        # the prompt retains its historical shape — no metadata block.
        prompt = _build_vulnhunt_prompt(tmp_path, "claude-opus-4-8")
        assert "Pre-resolved scan metadata" not in prompt

    def test_bash_line_renders_effective_tools_when_present(
        self, tmp_path: Path
    ) -> None:
        """Bug-fix (PR #20 review): the read-only bash_line used to hard-
        code "Read/Grep/Glob/Write/Edit only", which lied to the model
        when the TOML allow-list didn't include Grep / Edit. Now the
        line is generated from ``effective_tools`` (Bash + Agent
        stripped)."""
        prompt = _build_vulnhunt_prompt(
            tmp_path,
            "claude-opus-4-8",
            results_dir=tmp_path / "x_VULNHUNT_RESULTS_y",
            branch_label="main [abc]",
            repo_url="https://github.com/example-org/example",
            enable_bash=False,
            effective_tools=["Agent", "Glob", "Read", "Write"],
        )
        # Tools actually in the allow-list show up; Bash + Agent are
        # filtered out (Bash is unavailable here; Agent is the
        # subagent dispatcher, not a content-access tool).
        assert "Bash is NOT available — use Glob/Read/Write only." in prompt
        assert "Grep" not in prompt
        assert "Edit" not in prompt

    def test_bash_line_with_grep_and_edit_in_allow_list(
        self, tmp_path: Path
    ) -> None:
        prompt = _build_vulnhunt_prompt(
            tmp_path,
            "claude-opus-4-8",
            results_dir=tmp_path / "x_VULNHUNT_RESULTS_y",
            branch_label="main [abc]",
            repo_url="https://github.com/example-org/example",
            enable_bash=False,
            effective_tools=["Agent", "Glob", "Read", "Write", "Grep", "Edit"],
        )
        # When the TOML adds Grep / Edit, they show up in the rendered line.
        assert "Grep" in prompt
        assert "Edit" in prompt

    def test_bash_line_falls_back_when_no_effective_tools_supplied(
        self, tmp_path: Path
    ) -> None:
        """``effective_tools=None`` is the legacy path (test callers that
        bypass ``run_vulnhunt``). Falls back to a vague-but-honest
        phrasing rather than hard-coding a list that may not match."""
        prompt = _build_vulnhunt_prompt(
            tmp_path,
            "claude-opus-4-8",
            results_dir=tmp_path / "x_VULNHUNT_RESULTS_y",
            branch_label="main [abc]",
            repo_url="https://github.com/example-org/example",
            enable_bash=False,
            effective_tools=None,
        )
        assert (
            "Bash is NOT available — use the non-Bash tools in your "
            "allow-list only." in prompt
        )

    def test_bash_line_enable_bash_ignores_effective_tools(
        self, tmp_path: Path
    ) -> None:
        """When Bash IS available, the bash_line doesn't enumerate other
        tools — just states Bash is available."""
        prompt = _build_vulnhunt_prompt(
            tmp_path,
            "claude-opus-4-8",
            results_dir=tmp_path / "x_VULNHUNT_RESULTS_y",
            branch_label="main [abc]",
            repo_url="https://github.com/example-org/example",
            enable_bash=True,
            effective_tools=["Agent", "Glob", "Read", "Write", "Bash"],
        )
        assert "Bash is AVAILABLE" in prompt
        # No tool-list enumeration in the AVAILABLE branch.
        assert "Glob/Read/Write" not in prompt


# ---------------------------------------------------------------------------
# run_vulnhunt — effective tool list / metadata plumbing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_vulnhunt_strips_bash_from_allowed_tools(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    agent_config: Any,
) -> None:
    """Even if a hand-edited config includes Bash, run_vulnhunt strips it
    when ``enable_bash=False`` (the default). The CLI flag is the only
    way to authorize Bash for a scan.
    """
    clone = tmp_path / "clone"
    clone.mkdir()

    # Config that mistakenly includes Bash in allowed_tools.
    from agent.config import ScanConfig

    cfg = agent_config(
        scan=ScanConfig(
            clone_base_dir="./clones",
            clone_timeout_seconds=300,
            allowed_tools=["Read", "Grep", "Bash"],
            permission_mode="acceptEdits",
            autocompact_pct_override=85,
            async_agent_stall_timeout_ms=1_200_000,
        )
    )

    captured_options: list[Any] = []

    class _CapturingClient:
        def __init__(self, opts: Any) -> None:
            captured_options.append(opts)

        async def __aenter__(self) -> "_CapturingClient":
            return self

        async def __aexit__(self, *a: object) -> bool:
            return False

        async def query(self, _prompt: str) -> None:
            pass

        def receive_response(self):
            async def _gen():
                yield _result_message()
            return _gen()

    class _FakeMgr:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        def get_valid_token(self) -> str:
            return "fake"

    monkeypatch.setattr(runner_mod, "make_token_manager", lambda *a, **k: _FakeMgr())
    monkeypatch.setattr(runner_mod, "build_claude_settings", lambda *a, **k: "{}")
    monkeypatch.setattr(runner_mod, "ClaudeSDKClient", _CapturingClient)
    monkeypatch.setattr(runner_mod, "_vulnhunt_skill_path", lambda: tmp_path / "skill")
    _stub_git_runner(monkeypatch)

    await run_vulnhunt(clone, cfg, enable_bash=False)
    assert "Bash" not in captured_options[0].allowed_tools
    assert "Bash" not in captured_options[0].tools


@pytest.mark.asyncio
async def test_run_vulnhunt_appends_bash_when_enable_bash_true(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config,
) -> None:
    """enable_bash=True re-adds Bash even when the config omits it."""
    clone = tmp_path / "clone"
    clone.mkdir()

    captured_options: list[Any] = []

    class _CapturingClient:
        def __init__(self, opts: Any) -> None:
            captured_options.append(opts)

        async def __aenter__(self) -> "_CapturingClient":
            return self

        async def __aexit__(self, *a: object) -> bool:
            return False

        async def query(self, _prompt: str) -> None:
            pass

        def receive_response(self):
            async def _gen():
                yield _result_message()
            return _gen()

    class _FakeMgr:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        def get_valid_token(self) -> str:
            return "fake"

    monkeypatch.setattr(runner_mod, "make_token_manager", lambda *a, **k: _FakeMgr())
    monkeypatch.setattr(runner_mod, "build_claude_settings", lambda *a, **k: "{}")
    monkeypatch.setattr(runner_mod, "ClaudeSDKClient", _CapturingClient)
    monkeypatch.setattr(runner_mod, "_vulnhunt_skill_path", lambda: tmp_path / "skill")
    _stub_git_runner(monkeypatch)

    await run_vulnhunt(clone, populated_agent_config, enable_bash=True, read_only=False)
    assert "Bash" in captured_options[0].allowed_tools
    assert "Bash" in captured_options[0].tools


@pytest.mark.asyncio
async def test_run_vulnhunt_warns_on_enable_bash_with_read_only(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Programmatic callers can pass enable_bash=True with read_only=True
    (the CLI rejects this at parse time, but the runner is an importable
    API). run_vulnhunt logs a WARN flagging the misconfig so the symptom
    is visible — Bash ends up in the allow-list but the prompt tells the
    model not to execute code, an almost-certainly-unintended combination.
    """
    clone = tmp_path / "clone"
    clone.mkdir()

    class _Client:
        def __init__(self, _opts: object) -> None:
            pass

        async def __aenter__(self) -> "_Client":
            return self

        async def __aexit__(self, *a: object) -> bool:
            return False

        async def query(self, _prompt: str) -> None:
            pass

        def receive_response(self):
            async def _gen():
                yield _result_message()
            return _gen()

    class _FakeMgr:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        def get_valid_token(self) -> str:
            return "fake"

    monkeypatch.setattr(runner_mod, "make_token_manager", lambda *a, **k: _FakeMgr())
    monkeypatch.setattr(runner_mod, "build_claude_settings", lambda *a, **k: "{}")
    monkeypatch.setattr(runner_mod, "ClaudeSDKClient", _Client)
    monkeypatch.setattr(runner_mod, "_vulnhunt_skill_path", lambda: tmp_path / "skill")
    _stub_git_runner(monkeypatch)

    with caplog.at_level(logging.WARNING, logger="agent.runner"):
        await run_vulnhunt(
            clone, populated_agent_config, enable_bash=True, read_only=True
        )
    joined = "\n".join(r.getMessage() for r in caplog.records)
    assert "enable_bash=True with read_only=True" in joined
    assert "misconfiguration" in joined

@pytest.mark.asyncio
async def test_run_vulnhunt_refuses_when_prior_results_exist(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config,
) -> None:
    clone = tmp_path / "clone"
    clone.mkdir()
    (clone / "myrepo_VULNHUNT_RESULTS_opus48_2026-01-01-000000").mkdir()
    monkeypatch.setattr(runner_mod, "_vulnhunt_skill_path", lambda: tmp_path / "skill")

    class _FakeMgr:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        def get_valid_token(self) -> str:
            return "fake"

    monkeypatch.setattr(runner_mod, "make_token_manager", lambda *a, **k: _FakeMgr())
    with pytest.raises(runner_mod.PriorResultsError):
        await run_vulnhunt(clone, populated_agent_config)


@pytest.mark.asyncio
async def test_run_vulnhunt_injects_pre_staged_values_into_prompt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config,
) -> None:
    """The /vulnhunt kickoff prompt must carry the pre-resolved metadata
    block — that's how the skill receives the values it used to gather
    via Bash.
    """
    clone = tmp_path / "clone"
    clone.mkdir()

    seen_prompts: list[str] = []

    class _Client:
        def __init__(self, _opts: Any) -> None:
            pass

        async def __aenter__(self) -> "_Client":
            return self

        async def __aexit__(self, *a: object) -> bool:
            return False

        async def query(self, prompt: str) -> None:
            seen_prompts.append(prompt)

        def receive_response(self):
            async def _gen():
                yield _result_message()
            return _gen()

    class _FakeMgr:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        def get_valid_token(self) -> str:
            return "fake"

    monkeypatch.setattr(runner_mod, "make_token_manager", lambda *a, **k: _FakeMgr())
    monkeypatch.setattr(runner_mod, "build_claude_settings", lambda *a, **k: "{}")
    monkeypatch.setattr(runner_mod, "ClaudeSDKClient", _Client)
    monkeypatch.setattr(runner_mod, "_vulnhunt_skill_path", lambda: tmp_path / "skill")
    _stub_git_runner(
        monkeypatch,
        branch="feat/x",
        sha="deadbee",
        origin="https://github.com/example-org/example.git",
    )

    await run_vulnhunt(clone, populated_agent_config)
    assert seen_prompts, "no prompt was sent"
    p = seen_prompts[0]
    assert "Pre-resolved scan metadata" in p
    assert "VULNHUNT_BRANCH: feat/x [deadbee]" in p
    assert "Repository URL: https://github.com/example-org/example" in p
    assert "VULNHUNT_DIR: " in p
    assert "Bash is NOT available" in p
