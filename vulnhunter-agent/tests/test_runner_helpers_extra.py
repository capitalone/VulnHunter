"""Coverage fill-in for runner.py's verbosity-tiered helpers.

Targets the branches the main test_runner.py only exercises at verbosity
0: every `_tool_brief` tool name, `_result_brief`/`_render_block` shapes,
verbosity 1/2 paths in `_log_assistant_message` / `_log_user_message`,
non-terminal task status, error system messages, etc.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest

from agent import runner
from agent.runner import (
    _log_assistant_message,
    _log_result,
    _log_system_message,
    _log_task_started,
    _log_task_status,
    _log_user_message,
    _render_block,
    _result_brief,
    _tool_brief,
    set_verbosity,
)


# ---------------------------------------------------------------------------
# Lightweight stand-ins for SDK content blocks. Real SDK blocks are
# dataclasses, but the helpers only do duck-typed `getattr` access, so
# small namespace-style shims are enough.
# ---------------------------------------------------------------------------


class _Block:
    """Minimal content-block stub. Attributes set via kwargs."""

    def __init__(self, **kwargs: Any) -> None:
        self.__dict__.update(kwargs)


def _msg(**kwargs: Any) -> Any:
    """Build a SystemMessage-like / Result-like / Assistant-like object."""
    return _Block(**kwargs)


@pytest.fixture(autouse=True)
def reset_verbosity() -> None:
    """Each test starts at verbosity 0 and we restore after."""
    set_verbosity(0)
    yield
    set_verbosity(0)


# ---------------------------------------------------------------------------
# _tool_brief — covers every named branch
# ---------------------------------------------------------------------------


class TestToolBrief:
    def test_non_dict_input_renders_repr(self) -> None:
        assert _tool_brief("Bash", ["ls"]).startswith("[")

    def test_description_short_circuits(self) -> None:
        # Any tool name; if 'description' is set we use it.
        out = _tool_brief("Read", {"description": "scan the file"})
        assert out == "scan the file"

    def test_read_uses_file_path(self) -> None:
        assert _tool_brief("Read", {"file_path": "/tmp/x"}) == "/tmp/x"

    def test_read_missing_file_path_falls_back_to_question_mark(self) -> None:
        assert _tool_brief("Read", {}) == "?"

    def test_bash_truncates_command(self) -> None:
        cmd = "echo " + ("x" * 200)
        out = _tool_brief("Bash", {"command": cmd})
        assert out.startswith("echo ")
        assert "<truncated>" in out

    def test_grep_with_path(self) -> None:
        out = _tool_brief("Grep", {"pattern": "TODO", "path": "src/"})
        assert out == "TODO in src/"

    def test_grep_without_path(self) -> None:
        out = _tool_brief("Grep", {"pattern": "TODO"})
        assert out == "TODO"

    def test_glob(self) -> None:
        out = _tool_brief("Glob", {"pattern": "**/*.py"})
        assert out == "**/*.py"

    def test_agent_with_subagent_and_description(self) -> None:
        # `description` short-circuits in _tool_brief regardless of tool
        # name — that's the v=0 contract: prefer the model's own
        # one-line description when it gave us one.
        out = _tool_brief(
            "Agent", {"subagent_type": "general-purpose", "description": "scan stuff"}
        )
        assert out == "scan stuff"

    def test_agent_with_prompt_when_no_description(self) -> None:
        out = _tool_brief(
            "Agent", {"subagent_type": "general-purpose", "prompt": "do thing"}
        )
        assert out == "general-purpose: do thing"

    def test_agent_without_prompt_or_description(self) -> None:
        out = _tool_brief("Agent", {"subagent_type": "general-purpose"})
        assert out == "general-purpose"

    def test_task_alias(self) -> None:
        out = _tool_brief("Task", {"subagent_type": "summarizer"})
        assert out == "summarizer"

    def test_webfetch(self) -> None:
        out = _tool_brief("WebFetch", {"url": "https://example.com"})
        assert out == "https://example.com"

    def test_webfetch_missing_url(self) -> None:
        assert _tool_brief("WebFetch", {}) == "?"

    def test_todowrite_with_list(self) -> None:
        out = _tool_brief("TodoWrite", {"todos": [{"content": "a"}, {"content": "b"}]})
        assert out == "2 item(s)"

    def test_todowrite_with_non_list(self) -> None:
        out = _tool_brief("TodoWrite", {"todos": "not-a-list"})
        assert out == "?"

    def test_unknown_tool_falls_back_to_repr(self) -> None:
        out = _tool_brief("MysteryTool", {"foo": "bar"})
        assert "foo" in out and "bar" in out


# ---------------------------------------------------------------------------
# _result_brief — covers str/list/empty/repr branches
# ---------------------------------------------------------------------------


class TestResultBrief:
    def test_empty_string(self) -> None:
        assert _result_brief("") == "<empty>"

    def test_whitespace_only(self) -> None:
        assert _result_brief("   \n  ") == "<empty>"

    def test_single_line(self) -> None:
        assert _result_brief("hello") == "hello"

    def test_multi_line_appends_count_suffix(self) -> None:
        out = _result_brief("first\nsecond\nthird")
        assert out.startswith("first")
        assert "(+2 more line(s))" in out

    def test_list_input(self) -> None:
        out = _result_brief([1, 2, 3])
        assert out == "<3 block(s)>"

    def test_other_input_falls_back_to_repr(self) -> None:
        out = _result_brief({"a": 1})
        assert "'a'" in out


# ---------------------------------------------------------------------------
# _render_block — every branch
# ---------------------------------------------------------------------------


class TestRenderBlock:
    def test_text_block(self) -> None:
        b = _Block(text="hello world")
        assert _render_block(b).startswith("_Block: hello world")

    def test_tool_use_block_uses_repr_of_input(self) -> None:
        b = _Block(name="Read", input={"file_path": "/tmp/x"})
        out = _render_block(b)
        assert "Read" in out and "/tmp/x" in out

    def test_tool_result_str_content(self) -> None:
        b = _Block(content="some output")
        out = _render_block(b)
        assert "some output" in out

    def test_tool_result_list_content(self) -> None:
        inner = _Block(text="line one")
        b = _Block(content=[inner])
        out = _render_block(b)
        assert "line one" in out

    def test_unknown_block_falls_back_to_repr(self) -> None:
        b = _Block(unknown_attr=42)
        out = _render_block(b)
        assert "_Block" in out


# ---------------------------------------------------------------------------
# _log_assistant_message — verbosity tiers
# ---------------------------------------------------------------------------


class TestLogAssistantMessageExtra:
    def test_empty_content_silent_at_v0(self, caplog: pytest.LogCaptureFixture) -> None:
        set_verbosity(0)
        msg = _msg(model="m", content=None)
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_assistant_message(msg)
        assert not [r for r in caplog.records if "<empty>" in r.message]

    def test_empty_content_logs_at_v1(self, caplog: pytest.LogCaptureFixture) -> None:
        set_verbosity(1)
        msg = _msg(model="claude", content=[])
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_assistant_message(msg)
        assert any("<empty>" in r.message for r in caplog.records)

    def test_text_block_with_empty_text_skipped(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(0)
        # Block has type-name TextBlock-ish: the helper checks str(type(block).__name__)
        block = _Block(text="")
        block.__class__.__name__ = "TextBlock"
        msg = _msg(model="m", content=[block])
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_assistant_message(msg)
        assert not [r for r in caplog.records if r.message.startswith("  assistant:")]

    def test_tool_use_block_v0_brief_only(self, caplog: pytest.LogCaptureFixture) -> None:
        set_verbosity(0)
        block = _Block(name="Read", input={"file_path": "/x"})
        block.__class__.__name__ = "ToolUseBlock"
        msg = _msg(model="m", content=[block])
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_assistant_message(msg)
        assert any("Read(/x)" in r.message for r in caplog.records)
        # No full repr at v=0
        assert not any("file_path" in r.message for r in caplog.records)

    def test_tool_use_block_v1_includes_full_input(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(1)
        block = _Block(name="Read", input={"file_path": "/x"})
        block.__class__.__name__ = "ToolUseBlock"
        msg = _msg(model="m", content=[block])
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_assistant_message(msg)
        assert any("file_path" in r.message for r in caplog.records)

    def test_thinking_block_silent_under_v2(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(1)
        block = _Block(text="hidden thoughts")
        block.__class__.__name__ = "ThinkingBlock"
        msg = _msg(model="m", content=[block])
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_assistant_message(msg)
        assert not any("hidden thoughts" in r.message for r in caplog.records)

    def test_thinking_block_visible_at_v2(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(2)
        block = _Block(text="hidden thoughts")
        block.__class__.__name__ = "ThinkingBlock"
        msg = _msg(model="m", content=[block])
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_assistant_message(msg)
        assert any("hidden thoughts" in r.message for r in caplog.records)

    def test_other_block_type_at_v0_silent(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(0)
        block = _Block(content="some result")
        block.__class__.__name__ = "ToolResultBlock"
        msg = _msg(model="m", content=[block])
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_assistant_message(msg)
        # ToolResultBlock at v=0 in assistant content is silent.
        assert not any("some result" in r.message for r in caplog.records)

    def test_other_block_type_at_v1_visible(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(1)
        block = _Block(content="some result")
        block.__class__.__name__ = "ToolResultBlock"
        msg = _msg(model="m", content=[block])
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_assistant_message(msg)
        assert any("some result" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# _log_user_message — every shape
# ---------------------------------------------------------------------------


class TestLogUserMessageExtra:
    def test_none_content_silent_at_v0(self, caplog: pytest.LogCaptureFixture) -> None:
        set_verbosity(0)
        msg = _msg(content=None)
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_user_message(msg)
        assert not [r for r in caplog.records if r.message]

    def test_none_content_emits_at_v1(self, caplog: pytest.LogCaptureFixture) -> None:
        set_verbosity(1)
        msg = _msg(content=None)
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_user_message(msg)
        assert any("<empty>" in r.message for r in caplog.records)

    def test_string_content_terse_at_v0(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(0)
        msg = _msg(content="hello")
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_user_message(msg)
        assert any("↳" in r.message and "hello" in r.message for r in caplog.records)

    def test_string_content_full_at_v1(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(1)
        msg = _msg(content="hello")
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_user_message(msg)
        assert any(r.message.startswith("  user: hello") for r in caplog.records)

    def test_empty_list_silent_at_v0(self, caplog: pytest.LogCaptureFixture) -> None:
        set_verbosity(0)
        msg = _msg(content=[])
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_user_message(msg)
        assert not [r for r in caplog.records if r.message]

    def test_empty_list_emits_at_v1(self, caplog: pytest.LogCaptureFixture) -> None:
        set_verbosity(1)
        msg = _msg(content=[])
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_user_message(msg)
        assert any("<empty list>" in r.message for r in caplog.records)

    def test_tool_result_block_at_v1_uses_render_block(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(1)
        block = _Block(content="output here")
        block.__class__.__name__ = "ToolResultBlock"
        msg = _msg(content=[block])
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_user_message(msg)
        assert any("output here" in r.message for r in caplog.records)

    def test_non_tool_result_block_in_list_v0_silent(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(0)
        block = _Block(text="something")
        block.__class__.__name__ = "TextBlock"
        msg = _msg(content=[block])
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_user_message(msg)
        assert not any("something" in r.message for r in caplog.records)

    def test_non_tool_result_block_in_list_v1_visible(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(1)
        block = _Block(text="something")
        block.__class__.__name__ = "TextBlock"
        msg = _msg(content=[block])
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_user_message(msg)
        assert any("something" in r.message for r in caplog.records)

    def test_dict_content_at_v1(self, caplog: pytest.LogCaptureFixture) -> None:
        set_verbosity(1)
        msg = _msg(content={"weird": "shape"})
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_user_message(msg)
        assert any("weird" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# _log_task_started — id branch at v>=1
# ---------------------------------------------------------------------------


class TestLogTaskStartedExtra:
    def test_id_line_emitted_at_v1(self, caplog: pytest.LogCaptureFixture) -> None:
        set_verbosity(1)
        msg = _msg(task_id="abc123", description="trace SG-1", task_type="general-purpose")
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_task_started(msg)
        assert any("task_id=abc123" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# _log_task_status — non-terminal branches and extras
# ---------------------------------------------------------------------------


class TestLogTaskStatusExtra:
    def test_non_terminal_status_silent_at_v0(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(0)
        msg = _msg(task_id="t1", status="running", summary=None, output_file=None)
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_task_status(msg)
        assert not any(r.message for r in caplog.records)

    def test_non_terminal_status_visible_at_v1(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(1)
        msg = _msg(
            task_id="t1",
            status="running",
            summary="thinking",
            output_file=None,
        )
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_task_status(msg)
        assert any("running" in r.message and "summary=" in r.message for r in caplog.records)

    def test_with_output_file_at_v1(self, caplog: pytest.LogCaptureFixture) -> None:
        set_verbosity(1)
        msg = _msg(
            task_id="t1",
            status="completed",
            summary=None,
            output_file="/tmp/out.md",
        )
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_task_status(msg)
        assert any("/tmp/out.md" in r.message for r in caplog.records)

    def test_failed_logged_as_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        set_verbosity(0)
        msg = _msg(task_id="t1", status="failed", summary="oops", output_file=None)
        with caplog.at_level(logging.WARNING, logger="agent.runner"):
            _log_task_status(msg)
        assert any(r.levelno == logging.WARNING for r in caplog.records)


# ---------------------------------------------------------------------------
# _log_system_message — error / task_progress / data=None branches
# ---------------------------------------------------------------------------


class TestLogSystemMessageExtra:
    def test_init_with_data_at_v2_dumps_blob(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(2)
        msg = _msg(subtype="init", data={"slash_commands": ["vulnhunt"], "extra": 1})
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_system_message(msg)
        assert any("system [init]" in r.message for r in caplog.records)

    def test_task_progress_silent_at_v0(self, caplog: pytest.LogCaptureFixture) -> None:
        set_verbosity(0)
        msg = _msg(subtype="task_progress", data={"task_id": "x"})
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_system_message(msg)
        assert not any("task_progress" in r.message for r in caplog.records)

    def test_task_progress_visible_at_v1(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(1)
        msg = _msg(subtype="task_progress", data={"task_id": "x"})
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_system_message(msg)
        assert any("task_progress" in r.message for r in caplog.records)

    def test_error_subtype_logged_at_error_level(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(0)
        msg = _msg(subtype="error", data={"is_error": True, "msg": "boom"})
        with caplog.at_level(logging.DEBUG, logger="agent.runner"):
            _log_system_message(msg)
        assert any(r.levelno == logging.ERROR for r in caplog.records)

    def test_data_none_at_v1(self, caplog: pytest.LogCaptureFixture) -> None:
        set_verbosity(1)
        msg = _msg(subtype="random", data=None)
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_system_message(msg)
        assert any("<no data>" in r.message for r in caplog.records)

    def test_data_none_with_error_subtype_emits_even_at_v0(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(0)
        msg = _msg(subtype="error", data=None)
        with caplog.at_level(logging.DEBUG, logger="agent.runner"):
            _log_system_message(msg)
        assert any(r.levelno == logging.ERROR for r in caplog.records)

    def test_other_subtype_at_v2_includes_data(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(2)
        msg = _msg(subtype="ping", data={"hello": "world"})
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_system_message(msg)
        assert any("hello" in r.message and "ping" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# _log_result — is_error branch
# ---------------------------------------------------------------------------


class TestLogResultExtra:
    def test_is_error_logs_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        msg = _msg(
            is_error=True,
            errors=["thing failed"],
            total_cost_usd=0.0,
            duration_ms=100,
            num_turns=2,
        )
        with caplog.at_level(logging.WARNING, logger="agent.runner"):
            _log_result(msg)
        assert any(r.levelno == logging.WARNING for r in caplog.records)
        assert any("thing failed" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Credential redaction in log paths — the security-critical leak guard.
# ---------------------------------------------------------------------------


_LEAKED_URL = (
    "https://x-access-token:ghp_supersecret@github.com/owner/repo.git"
)
_REDACTED_FRAGMENT = "https://***@github.com/owner/repo.git"


class TestRedactionInLogs:
    def test_user_string_content_at_v0_is_redacted(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(0)
        msg = _msg(content=f"origin url: {_LEAKED_URL}")
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_user_message(msg)
        joined = "\n".join(r.message for r in caplog.records)
        assert "ghp_supersecret" not in joined
        assert _REDACTED_FRAGMENT in joined

    def test_user_string_content_at_v1_is_redacted(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(1)
        msg = _msg(content=f"origin url: {_LEAKED_URL}")
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_user_message(msg)
        joined = "\n".join(r.message for r in caplog.records)
        assert "ghp_supersecret" not in joined

    def test_tool_result_block_content_redacted(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        set_verbosity(0)
        block = _Block(content=f"remote.origin.url={_LEAKED_URL}")
        block.__class__.__name__ = "ToolResultBlock"
        msg = _msg(content=[block])
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_user_message(msg)
        joined = "\n".join(r.message for r in caplog.records)
        assert "ghp_supersecret" not in joined

    def test_assistant_text_block_redacted(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The model can echo back URLs it saw in tool output. TextBlock
        prose is logged verbatim (no truncation) so it has its own
        redact() call, not just the _truncate-mediated one."""
        set_verbosity(0)
        block = _Block(text=f"I'll clone {_LEAKED_URL} now.")
        block.__class__.__name__ = "TextBlock"
        msg = _msg(model="claude-opus-4-8", content=[block])
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_assistant_message(msg)
        joined = "\n".join(r.message for r in caplog.records)
        assert "ghp_supersecret" not in joined

    def test_tool_use_block_input_redacted_at_v1(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """An input dict whose repr contains a token-bearing URL is
        scrubbed when v=1 logs it via _truncate(repr(...))."""
        set_verbosity(1)
        block = _Block(
            name="Bash",
            input={"command": f"git remote get-url; echo {_LEAKED_URL}"},
        )
        block.__class__.__name__ = "ToolUseBlock"
        msg = _msg(model="m", content=[block])
        with caplog.at_level(logging.INFO, logger="agent.runner"):
            _log_assistant_message(msg)
        joined = "\n".join(r.message for r in caplog.records)
        assert "ghp_supersecret" not in joined
