"""Tests for agent._llm: response extraction, fallback chain, JSON parsing.

We mock at ``_send_prompt`` (our thin wrapper around the SDK) so tests
don't spawn a real ``claude`` CLI subprocess. The wrapper itself is
exercised end-to-end during real runs; for unit tests we trust the
SDK and verify our domain logic (JSON extraction, fallback,
error mapping).
"""

from __future__ import annotations

from typing import Any

import pytest

from agent import _llm
from agent._llm import (
    LLMError,
    TransientLLMError,
    _classify_boundary_error,
    _extract_json_block,
    _is_transient,
    _looks_transient_at_boundary,
    call_json,
    call_json_with_fallback,
    estimate_tokens,
)
from tests._helpers import FakeTokenManager as _TM


def _stub_send(
    monkeypatch: pytest.MonkeyPatch,
    *,
    text: str | None = None,
    side_effect: Exception | list[Any] | None = None,
) -> list[dict[str, Any]]:
    """Patch _send_prompt, recording each call's kwargs."""
    calls: list[dict[str, Any]] = []
    seq: list[Any] | None = None
    if isinstance(side_effect, list):
        seq = list(side_effect)

    async def fake(**kwargs: Any) -> str:
        calls.append(kwargs)
        if seq is not None:
            item = seq.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        if isinstance(side_effect, Exception):
            raise side_effect
        assert text is not None
        return text

    monkeypatch.setattr(_llm, "_send_prompt", fake)
    return calls


# ---------------------------------------------------------------------------
# _extract_json_block
# ---------------------------------------------------------------------------


class TestExtractJsonBlock:
    def test_plain_object(self) -> None:
        assert _extract_json_block('{"a": 1}') == '{"a": 1}'

    def test_object_with_prose_prefix(self) -> None:
        assert _extract_json_block('Here you go: {"a": 1} done.') == '{"a": 1}'

    def test_object_inside_code_fence(self) -> None:
        assert _extract_json_block('```json\n{"a": 1}\n```') == '{"a": 1}'

    def test_object_inside_unlabeled_fence(self) -> None:
        assert _extract_json_block('```\n{"a": 1}\n```') == '{"a": 1}'

    def test_array_extraction(self) -> None:
        assert _extract_json_block("[1, 2, 3]") == "[1, 2, 3]"

    def test_nested_object(self) -> None:
        text = 'noise {"a": {"b": 1}} tail'
        assert _extract_json_block(text) == '{"a": {"b": 1}}'

    def test_no_json_returns_input(self) -> None:
        assert _extract_json_block("no json at all") == "no json at all"


# ---------------------------------------------------------------------------
# estimate_tokens
# ---------------------------------------------------------------------------


class TestEstimateTokens:
    def test_short_text(self) -> None:
        assert estimate_tokens("a") == 1

    def test_longer_text(self) -> None:
        assert estimate_tokens("abcdefgh") == 2  # 8 / 4

    def test_empty_returns_at_least_one(self) -> None:
        assert estimate_tokens("") == 1


# ---------------------------------------------------------------------------
# CostStats — direct accumulation
# ---------------------------------------------------------------------------


class TestCostStats:
    def test_add_result_sums_fields(self) -> None:
        stats = _llm.CostStats()

        class _FakeResult:
            total_cost_usd = 0.005
            num_turns = 2
            duration_api_ms = 800

        stats.add_result(_FakeResult())
        stats.add_result(_FakeResult())
        assert stats.cost_usd == pytest.approx(0.010)
        assert stats.num_turns == 4
        assert stats.duration_api_ms == 1600
        assert stats.calls == 2

    def test_add_result_handles_missing_attrs(self) -> None:
        stats = _llm.CostStats()

        class _Bare:
            pass

        stats.add_result(_Bare())
        assert stats.cost_usd == 0.0
        assert stats.num_turns == 0
        assert stats.duration_api_ms == 0
        assert stats.calls == 1

    def test_add_result_handles_string_with_none_values(self) -> None:
        stats = _llm.CostStats()

        class _Nulls:
            total_cost_usd = None
            num_turns = None
            duration_api_ms = None

        stats.add_result(_Nulls())
        assert stats.cost_usd == 0.0
        assert stats.num_turns == 0
        assert stats.duration_api_ms == 0


# ---------------------------------------------------------------------------
# _extract_json_block — handles JSON strings containing braces
# ---------------------------------------------------------------------------


class TestExtractJsonBlockEdgeCases:
    def test_brace_inside_string_does_not_close_object(self) -> None:
        # Without proper string-tracking the counter would close at the
        # first `}` and lose the rest of the JSON.
        text = '{"description": "missing }", "ok": 1}'
        out = _extract_json_block(text)
        import json as _json

        assert _json.loads(out) == {"description": "missing }", "ok": 1}

    def test_escaped_quote_inside_string(self) -> None:
        text = r'{"a": "she said \"hi\"", "b": 2}'
        out = _extract_json_block(text)
        import json as _json

        assert _json.loads(out)["b"] == 2

    def test_strips_fence_then_walks_braces(self) -> None:
        # Fenced JSON with a brace in a string — fence is removed, then
        # the brace walker handles the inner string correctly.
        text = '```json\n{"path": "a/}/b", "n": 7}\n```'
        out = _extract_json_block(text)
        import json as _json

        assert _json.loads(out) == {"path": "a/}/b", "n": 7}


# ---------------------------------------------------------------------------
# call_json
# ---------------------------------------------------------------------------


class TestCallJson:
    async def test_parses_json_response(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        _stub_send(monkeypatch, text='{"k": "v"}')
        out = await call_json(
            model="m",
            system="s",
            user="u",
            config=populated_agent_config,
            token_manager=_TM(),
        )
        assert out == {"k": "v"}

    async def test_extracts_json_from_prose(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        _stub_send(monkeypatch, text='Sure! {"answer": 42} done.')
        out = await call_json(
            model="m",
            system="s",
            user="u",
            config=populated_agent_config,
            token_manager=_TM(),
        )
        assert out == {"answer": 42}

    async def test_malformed_json_raises_llmerror(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        _stub_send(monkeypatch, text="not json")
        with pytest.raises(LLMError, match="non-JSON"):
            await call_json(
                model="m",
                system="s",
                user="u",
                config=populated_agent_config,
                token_manager=_TM(),
            )

    async def test_empty_response_raises(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        _stub_send(monkeypatch, text="   \n  ")
        with pytest.raises(LLMError, match="empty response"):
            await call_json(
                model="m",
                system="s",
                user="u",
                config=populated_agent_config,
                token_manager=_TM(),
            )

    async def test_sdk_exception_wraps_to_llmerror(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        _stub_send(monkeypatch, side_effect=RuntimeError("SDK boom"))
        with pytest.raises(LLMError, match="SDK boom"):
            await call_json(
                model="m",
                system="s",
                user="u",
                config=populated_agent_config,
                token_manager=_TM(),
            )

    async def test_passes_token_and_model_to_send(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        calls = _stub_send(monkeypatch, text='{"ok": 1}')
        await call_json(
            model="claude-x",
            system="my-system",
            user="my-user",
            config=populated_agent_config,
            token_manager=_TM("my-token"),
        )
        assert len(calls) == 1
        assert calls[0]["model"] == "claude-x"
        assert calls[0]["system"] == "my-system"
        assert calls[0]["user"] == "my-user"
        assert calls[0]["auth_token"] == "my-token"


# ---------------------------------------------------------------------------
# call_json_with_fallback
# ---------------------------------------------------------------------------


class TestCallJsonWithFallback:
    async def test_primary_success_no_fallback(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        calls = _stub_send(monkeypatch, text='{"ok": 1}')
        out = await call_json_with_fallback(
            primary_model="haiku",
            fallback_model="sonnet",
            system="s",
            user="u",
            config=populated_agent_config,
            token_manager=_TM(),
        )
        assert out == {"ok": 1}
        assert len(calls) == 1
        assert calls[0]["model"] == "haiku"

    async def test_primary_fail_fallback_success(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        calls = _stub_send(
            monkeypatch,
            side_effect=[RuntimeError("primary down"), '{"ok": 1}'],
        )
        out = await call_json_with_fallback(
            primary_model="haiku",
            fallback_model="sonnet",
            system="s",
            user="u",
            config=populated_agent_config,
            token_manager=_TM(),
        )
        assert out == {"ok": 1}
        assert [c["model"] for c in calls] == ["haiku", "sonnet"]

    async def test_both_fail_raises_llmerror(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        _stub_send(
            monkeypatch,
            side_effect=[RuntimeError("primary"), RuntimeError("fallback")],
        )
        with pytest.raises(LLMError):
            await call_json_with_fallback(
                primary_model="haiku",
                fallback_model="sonnet",
                system="s",
                user="u",
                config=populated_agent_config,
                token_manager=_TM(),
            )

    async def test_fallback_emits_model_fallback_audit_event(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        # Primary fails, fallback succeeds -> one model_fallback audit event.
        _stub_send(
            monkeypatch,
            side_effect=[RuntimeError("primary down"), '{"ok": 1}'],
        )

        class _FakeAudit:
            def __init__(self) -> None:
                self.records: list[dict] = []

            def emit_audit(self, record: dict) -> None:
                self.records.append(record)

        aw = _FakeAudit()
        out = await call_json_with_fallback(
            primary_model="haiku",
            fallback_model="sonnet",
            system="s",
            user="u",
            config=populated_agent_config,
            token_manager=_TM(),
            stage="extract",
            audit_writer=aw,
        )
        assert out == {"ok": 1}
        fb = [r for r in aw.records if r["event_type"] == "model_fallback"]
        assert len(fb) == 1
        assert fb[0]["from_model"] == "haiku"
        assert fb[0]["to_model"] == "sonnet"
        assert fb[0]["stage"] == "extract"

    async def test_no_audit_event_when_primary_succeeds(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        _stub_send(monkeypatch, text='{"ok": 1}')

        class _FakeAudit:
            def __init__(self) -> None:
                self.records: list[dict] = []

            def emit_audit(self, record: dict) -> None:
                self.records.append(record)

        aw = _FakeAudit()
        await call_json_with_fallback(
            primary_model="haiku",
            fallback_model="sonnet",
            system="s",
            user="u",
            config=populated_agent_config,
            token_manager=_TM(),
            audit_writer=aw,
        )
        assert aw.records == []

    async def test_primary_parse_error_falls_back(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        # Primary returns garbage → JSONDecodeError → LLMError; fallback succeeds.
        calls = _stub_send(
            monkeypatch,
            side_effect=["garbage", '{"v": 2}'],
        )
        out = await call_json_with_fallback(
            primary_model="haiku",
            fallback_model="sonnet",
            system="s",
            user="u",
            config=populated_agent_config,
            token_manager=_TM(),
        )
        assert out == {"v": 2}
        assert [c["model"] for c in calls] == ["haiku", "sonnet"]

    async def test_stage_label_appears_in_fallback_warning(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        # When `stage=` is passed, the warning prefix should include it so
        # multi-stage runs (extract + dedup) are distinguishable in logs.
        import logging as _logging

        _stub_send(
            monkeypatch,
            side_effect=[RuntimeError("primary down"), '{"ok": 1}'],
        )
        with caplog.at_level(_logging.WARNING, logger="agent._llm"):
            await call_json_with_fallback(
                primary_model="haiku",
                fallback_model="sonnet",
                system="s",
                user="u",
                config=populated_agent_config,
                token_manager=_TM(),
                stage="extract",
            )
        msgs = "\n".join(r.getMessage() for r in caplog.records)
        assert "[extract]" in msgs
        assert "haiku" in msgs

    async def test_stage_omitted_no_bracket_prefix(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        # Default `stage=""` → no stray "[] " prefix on the warning.
        import logging as _logging

        _stub_send(
            monkeypatch,
            side_effect=[RuntimeError("primary down"), '{"ok": 1}'],
        )
        with caplog.at_level(_logging.WARNING, logger="agent._llm"):
            await call_json_with_fallback(
                primary_model="haiku",
                fallback_model="sonnet",
                system="s",
                user="u",
                config=populated_agent_config,
                token_manager=_TM(),
            )
        msgs = "\n".join(r.getMessage() for r in caplog.records)
        # The warning starts with "Primary model" — no leading bracket.
        assert "[" not in msgs.split("Primary")[0]


# ---------------------------------------------------------------------------
# _send_prompt — unit test with a mocked ClaudeSDKClient
# ---------------------------------------------------------------------------


class _FakeTextBlock:
    """Mimics the SDK's text-content block (has .type and .text)."""

    type = "text"

    def __init__(self, text: str) -> None:
        self.text = text


class _FakeAssistantMessage:
    def __init__(self, content: list[Any]) -> None:
        self.content = content


class _FakeNonTextBlock:
    """A non-text block (e.g. tool_use) the collector should ignore."""

    type = "tool_use"


class TestSendPrompt:
    """Drives _send_prompt with a fake ClaudeSDKClient — no subprocess spawned."""

    async def test_collects_text_from_assistant_messages(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        captured: dict[str, Any] = {}

        class _FakeClient:
            def __init__(self, options: Any) -> None:
                captured["options"] = options

            async def __aenter__(self) -> "_FakeClient":
                return self

            async def __aexit__(self, *a: Any) -> None:
                pass

            async def query(self, prompt: str) -> None:
                captured["prompt"] = prompt

            async def receive_response(self):  # noqa: ANN201
                yield _FakeAssistantMessage(
                    [_FakeNonTextBlock(), _FakeTextBlock("hello "), _FakeTextBlock("world")]
                )

        # AssistantMessage isinstance check needs the fake to be the SDK's class.
        monkeypatch.setattr(_llm, "AssistantMessage", _FakeAssistantMessage)
        monkeypatch.setattr(_llm, "ClaudeSDKClient", _FakeClient)
        monkeypatch.setattr(
            _llm,
            "build_claude_settings",
            lambda cfg, token, model=None, scan_id="": "{}",
        )

        out = await _llm._send_prompt(
            model="claude-x",
            system="my-system",
            user="my-user",
            config=populated_agent_config,
            auth_token="my-token",
        )
        assert out == "hello world"
        # Verify the SDK options were configured with our values.
        opts = captured["options"]
        assert opts.model == "claude-x"
        assert opts.system_prompt == "my-system"
        assert opts.tools == []
        assert opts.allowed_tools == []
        # The user prompt must reach the client via query().
        assert captured["prompt"] == "my-user"

    async def test_empty_response_returns_empty_string(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        class _FakeClient:
            def __init__(self, options: Any) -> None:
                pass

            async def __aenter__(self) -> "_FakeClient":
                return self

            async def __aexit__(self, *a: Any) -> None:
                pass

            async def query(self, prompt: str) -> None:
                pass

            async def receive_response(self):  # noqa: ANN201
                # No assistant messages emitted.
                if False:
                    yield None

        monkeypatch.setattr(_llm, "AssistantMessage", _FakeAssistantMessage)
        monkeypatch.setattr(_llm, "ClaudeSDKClient", _FakeClient)
        monkeypatch.setattr(
            _llm,
            "build_claude_settings",
            lambda cfg, token, model=None, scan_id="": "{}",
        )

        out = await _llm._send_prompt(
            model="m",
            system="s",
            user="u",
            config=populated_agent_config,
            auth_token="t",
        )
        assert out == ""

    async def test_transient_result_message_raises_transient_llm_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        """A ResultMessage with is_error=True + api_error_status in {429, 5xx}
        must raise ``TransientLLMError`` via the typed-signal path — no
        string matching involved. Previously the SDK would yield this
        message and _send_prompt would happily return empty text, leaving
        retries unreachable."""

        class _FakeResultMessage:
            def __init__(self, *, is_error: bool, api_error_status: int) -> None:
                self.is_error = is_error
                self.api_error_status = api_error_status
                self.total_cost_usd = 0.0
                self.num_turns = 0
                self.duration_api_ms = 0

        class _FakeClient:
            def __init__(self, options: Any) -> None:
                pass

            async def __aenter__(self) -> "_FakeClient":
                return self

            async def __aexit__(self, *a: Any) -> None:
                pass

            async def query(self, prompt: str) -> None:
                pass

            async def receive_response(self):  # noqa: ANN201
                yield _FakeResultMessage(is_error=True, api_error_status=429)

        monkeypatch.setattr(_llm, "AssistantMessage", _FakeAssistantMessage)
        monkeypatch.setattr(_llm, "ResultMessage", _FakeResultMessage)
        monkeypatch.setattr(_llm, "ClaudeSDKClient", _FakeClient)
        monkeypatch.setattr(
            _llm,
            "build_claude_settings",
            lambda cfg, token, model=None, scan_id="": "{}",
        )

        with pytest.raises(TransientLLMError, match="429"):
            await _llm._send_prompt(
                model="m",
                system="s",
                user="u",
                config=populated_agent_config,
                auth_token="t",
            )

    async def test_non_transient_result_message_does_not_raise(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        """is_error=True with a non-transient status (e.g. 400) must NOT
        raise — that's a permanent failure and surfaces as empty text
        which call_json then turns into a plain ``LLMError`` ("empty
        response"). No retry."""

        class _FakeResultMessage:
            def __init__(self, *, is_error: bool, api_error_status: int) -> None:
                self.is_error = is_error
                self.api_error_status = api_error_status
                self.total_cost_usd = 0.0
                self.num_turns = 0
                self.duration_api_ms = 0

        class _FakeClient:
            def __init__(self, options: Any) -> None:
                pass

            async def __aenter__(self) -> "_FakeClient":
                return self

            async def __aexit__(self, *a: Any) -> None:
                pass

            async def query(self, prompt: str) -> None:
                pass

            async def receive_response(self):  # noqa: ANN201
                yield _FakeResultMessage(is_error=True, api_error_status=400)

        monkeypatch.setattr(_llm, "AssistantMessage", _FakeAssistantMessage)
        monkeypatch.setattr(_llm, "ResultMessage", _FakeResultMessage)
        monkeypatch.setattr(_llm, "ClaudeSDKClient", _FakeClient)
        monkeypatch.setattr(
            _llm,
            "build_claude_settings",
            lambda cfg, token, model=None, scan_id="": "{}",
        )

        out = await _llm._send_prompt(
            model="m",
            system="s",
            user="u",
            config=populated_agent_config,
            auth_token="t",
        )
        assert out == ""


# ---------------------------------------------------------------------------
# Transient classification — split across two test classes:
#
#   TestLooksTransientAtBoundary covers the boundary classifier that
#   inspects raw SDK exceptions (typed status attrs + shared regex
#   fallback). This is where string matching lives.
#
#   TestIsTransient covers the retry predicate, which is a pure
#   ``isinstance`` walk of the cause chain looking for
#   ``TransientLLMError``. No string matching at the retry decision.
#
#   TestClassifyBoundaryError covers the wrapper that converts a raw
#   SDK exception into the right typed LLMError subclass.
# ---------------------------------------------------------------------------


class _HasStatus(Exception):
    def __init__(self, status_code: int, message: str = "") -> None:
        super().__init__(message)
        self.status_code = status_code


class _HasResponse(Exception):
    def __init__(self, status_code: int, message: str = "") -> None:
        super().__init__(message)

        class _R:
            pass

        self.response = _R()
        self.response.status_code = status_code  # type: ignore[attr-defined]


class TestLooksTransientAtBoundary:
    """Typed-attr + text-fallback classifier — the single string-matching site."""

    def test_status_429_attribute(self) -> None:
        assert _looks_transient_at_boundary(_HasStatus(429))

    def test_status_503_attribute(self) -> None:
        assert _looks_transient_at_boundary(_HasStatus(503))

    def test_status_500_attribute(self) -> None:
        assert _looks_transient_at_boundary(_HasStatus(500))

    def test_response_status_429(self) -> None:
        assert _looks_transient_at_boundary(_HasResponse(429))

    def test_status_400_is_not_transient(self) -> None:
        assert not _looks_transient_at_boundary(_HasStatus(400))

    def test_status_404_is_not_transient(self) -> None:
        assert not _looks_transient_at_boundary(_HasStatus(404))

    def test_message_contains_429(self) -> None:
        assert _looks_transient_at_boundary(RuntimeError("got HTTP 429 from bedrock"))

    def test_message_contains_rate_limit(self) -> None:
        assert _looks_transient_at_boundary(RuntimeError("rate_limit_exceeded"))

    def test_message_contains_overloaded(self) -> None:
        assert _looks_transient_at_boundary(
            RuntimeError("model is overloaded, try again")
        )

    def test_walks_cause_chain(self) -> None:
        inner = _HasStatus(429)
        outer = RuntimeError("call failed")
        try:
            raise outer from inner
        except RuntimeError as e:
            assert _looks_transient_at_boundary(e)

    def test_plain_runtime_error_not_transient(self) -> None:
        assert not _looks_transient_at_boundary(RuntimeError("something else went wrong"))

    def test_empty_message_not_transient(self) -> None:
        assert not _looks_transient_at_boundary(RuntimeError())

    # Bug 1 lock-down (PR #11 review): when a typed status is present
    # and non-transient, the message text on the same frame must NOT
    # override it.
    def test_status_401_with_rate_limit_in_message_not_transient(self) -> None:
        exc = _HasStatus(
            401,
            "token expired; rate_limit headers were: x-ratelimit-remaining=5",
        )
        assert not _looks_transient_at_boundary(exc)

    def test_status_400_with_overloaded_in_message_not_transient(self) -> None:
        exc = _HasResponse(400, "model says it is overloaded")
        assert not _looks_transient_at_boundary(exc)

    def test_non_transient_wrapper_with_transient_cause_still_transient(
        self,
    ) -> None:
        # A 400 wrapper with a 429 cause underneath is still transient.
        inner = _HasStatus(429)
        outer = _HasStatus(400, "wrapped")
        try:
            raise outer from inner
        except _HasStatus as e:
            assert _looks_transient_at_boundary(e)

    # Bug 2 lock-down (PR #11 review): word-boundary regex rejects bare
    # numerics inside longer digit sequences.
    def test_token_count_5000_not_transient(self) -> None:
        assert not _looks_transient_at_boundary(
            RuntimeError("prompt exceeded 5000 tokens; max 4096")
        )

    def test_token_count_4290_not_transient(self) -> None:
        assert not _looks_transient_at_boundary(
            RuntimeError("4290 tokens used of 4096 budget")
        )

    def test_token_count_5031_not_transient(self) -> None:
        assert not _looks_transient_at_boundary(
            RuntimeError("5031 tokens, max 4096")
        )


class TestClassifyBoundaryError:
    """Wrapper that produces the right typed ``LLMError`` subclass."""

    def test_transient_exc_produces_transient_llm_error(self) -> None:
        wrapped = _classify_boundary_error("m", _HasStatus(429))
        assert isinstance(wrapped, TransientLLMError)
        assert isinstance(wrapped, LLMError)  # subclass relationship

    def test_non_transient_exc_produces_plain_llm_error(self) -> None:
        wrapped = _classify_boundary_error("m", _HasStatus(400))
        assert isinstance(wrapped, LLMError)
        assert not isinstance(wrapped, TransientLLMError)

    def test_text_only_transient_produces_transient_llm_error(self) -> None:
        # SDKs like claude_agent_sdk's ProcessError surface the upstream
        # 429 only in stderr text — text fallback in the classifier
        # must still produce a typed signal.
        wrapped = _classify_boundary_error(
            "m", RuntimeError("ProcessError: stderr: rate_limit_exceeded")
        )
        assert isinstance(wrapped, TransientLLMError)


class TestIsTransient:
    """Retry predicate — pure ``isinstance`` walk, no string matching."""

    def test_transient_llm_error_is_transient(self) -> None:
        assert _is_transient(TransientLLMError("transient"))

    def test_plain_llm_error_is_not_transient(self) -> None:
        assert not _is_transient(LLMError("permanent"))

    def test_walks_cause_chain_for_transient_llm_error(self) -> None:
        inner = TransientLLMError("inner")
        outer = LLMError("outer")
        try:
            raise outer from inner
        except LLMError as e:
            assert _is_transient(e)

    def test_walks_context_chain_for_transient_llm_error(self) -> None:
        # ``__context__`` set automatically by Python when a raise
        # happens during exception handling (no explicit `from`).
        try:
            try:
                raise TransientLLMError("inner")
            except TransientLLMError:
                raise LLMError("outer")
        except LLMError as e:
            assert _is_transient(e)

    def test_runtime_error_without_transient_cause_is_not_transient(self) -> None:
        # The predicate is type-based — a raw status_code attribute on
        # the exception is NOT enough. Classification has to have
        # happened at the boundary first.
        assert not _is_transient(_HasStatus(429))

    def test_runtime_error_with_transient_message_is_not_transient(self) -> None:
        # Same — text matching does NOT happen at the retry predicate.
        assert not _is_transient(RuntimeError("got HTTP 429"))

    def test_empty_exception_is_not_transient(self) -> None:
        assert not _is_transient(RuntimeError())


# ---------------------------------------------------------------------------
# call_json — transient retry path (uses backoffs=(0.0,) to keep tests fast)
# ---------------------------------------------------------------------------


class TestCallJsonRetry:
    async def test_transient_then_success_returns_payload(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        # First call raises a 429-shaped error, second call succeeds.
        calls = _stub_send(
            monkeypatch,
            side_effect=[_HasStatus(429, "rate limit"), '{"v": 1}'],
        )
        out = await call_json(
            model="m",
            system="s",
            user="u",
            config=populated_agent_config,
            token_manager=_TM(),
            backoffs=(0.0,),
        )
        assert out == {"v": 1}
        assert len(calls) == 2

    async def test_transient_exhausted_raises_llmerror(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        # Two transient errors with backoffs=(0.0,) → only 1 retry allowed → raise.
        calls = _stub_send(
            monkeypatch,
            side_effect=[_HasStatus(503, "service unavailable"), _HasStatus(503)],
        )
        with pytest.raises(LLMError):
            await call_json(
                model="m",
                system="s",
                user="u",
                config=populated_agent_config,
                token_manager=_TM(),
                backoffs=(0.0,),
            )
        assert len(calls) == 2

    async def test_non_transient_raises_immediately_no_retry(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        # ValueError isn't transient — must not consume a retry slot.
        calls = _stub_send(
            monkeypatch,
            side_effect=[ValueError("bad input"), '{"v": 1}'],
        )
        with pytest.raises(LLMError, match="bad input"):
            await call_json(
                model="m",
                system="s",
                user="u",
                config=populated_agent_config,
                token_manager=_TM(),
                backoffs=(0.0,),
            )
        # Second value never consumed — only one call was made.
        assert len(calls) == 1

    async def test_backoffs_empty_disables_retry(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        calls = _stub_send(
            monkeypatch,
            side_effect=[_HasStatus(429), '{"v": 1}'],
        )
        with pytest.raises(LLMError):
            await call_json(
                model="m",
                system="s",
                user="u",
                config=populated_agent_config,
                token_manager=_TM(),
                backoffs=(),
            )
        assert len(calls) == 1

    async def test_log_retries_emits_info_line(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        import logging as _logging

        _stub_send(
            monkeypatch,
            side_effect=[_HasStatus(429, "throttled"), '{"v": 1}'],
        )
        with caplog.at_level(_logging.INFO, logger="agent._llm"):
            await call_json(
                model="haiku",
                system="s",
                user="u",
                config=populated_agent_config,
                token_manager=_TM(),
                backoffs=(0.0,),
                log_retries=True,
                stage="extract",
            )
        msgs = "\n".join(r.getMessage() for r in caplog.records)
        assert "[extract]" in msgs
        assert "haiku" in msgs
        assert "transient" in msgs
        # Bug 3 lock-down (PR #11 review): the denominator must read as
        # "K of N total attempts", matching runner.py::_log_scan_retry.
        # backoffs=(0.0,) → max_attempt_number=2 → first failure logs
        # "attempt 1/2". The previous form (denom = max_attempt - 1)
        # logged "attempt 1/1" on a first failure with a retry queued,
        # which read to operators as "exhausted" — exactly wrong.
        assert "attempt 1/2" in msgs

    async def test_log_retries_off_suppresses_info_line(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        import logging as _logging

        _stub_send(
            monkeypatch,
            side_effect=[_HasStatus(429), '{"v": 1}'],
        )
        with caplog.at_level(_logging.INFO, logger="agent._llm"):
            await call_json(
                model="haiku",
                system="s",
                user="u",
                config=populated_agent_config,
                token_manager=_TM(),
                backoffs=(0.0,),
                log_retries=False,
            )
        msgs = "\n".join(r.getMessage() for r in caplog.records)
        assert "transient" not in msgs

    async def test_transient_exhausted_logs_warning_with_retry_count(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        # When transient retries are exhausted, the operator-facing
        # WARNING surfacing "exhausted N retries" fires regardless of
        # log_retries — the framing is load-bearing for diagnosis.
        import logging as _logging

        _stub_send(
            monkeypatch,
            side_effect=[
                _HasStatus(429, "throttle 1"),
                _HasStatus(429, "throttle 2"),
            ],
        )
        with caplog.at_level(_logging.WARNING, logger="agent._llm"):
            with pytest.raises(LLMError):
                await call_json(
                    model="haiku",
                    system="s",
                    user="u",
                    config=populated_agent_config,
                    token_manager=_TM(),
                    backoffs=(0.0,),
                    log_retries=False,
                    stage="extract",
                )
        msgs = "\n".join(r.getMessage() for r in caplog.records)
        assert "exhausted 1 transient" in msgs
        assert "[extract]" in msgs

    async def test_non_transient_exhaustion_does_not_log_retry_count(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        # A non-transient failure raises on the first attempt without
        # consuming retries; the "exhausted N retries" log should NOT
        # fire (no retries actually happened).
        import logging as _logging

        _stub_send(monkeypatch, side_effect=ValueError("bad prompt"))
        with caplog.at_level(_logging.WARNING, logger="agent._llm"):
            with pytest.raises(LLMError):
                await call_json(
                    model="haiku",
                    system="s",
                    user="u",
                    config=populated_agent_config,
                    token_manager=_TM(),
                    backoffs=(0.0,),
                )
        msgs = "\n".join(r.getMessage() for r in caplog.records)
        assert "exhausted" not in msgs

    async def test_empty_backoffs_does_not_log_retry_count(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        # backoffs=() means "no retries"; even if the single attempt is
        # transient, we never "exhausted retries" — there were none to
        # exhaust. The log gate (`if backoffs and ...`) protects this.
        import logging as _logging

        _stub_send(monkeypatch, side_effect=_HasStatus(429))
        with caplog.at_level(_logging.WARNING, logger="agent._llm"):
            with pytest.raises(LLMError):
                await call_json(
                    model="haiku",
                    system="s",
                    user="u",
                    config=populated_agent_config,
                    token_manager=_TM(),
                    backoffs=(),
                )
        msgs = "\n".join(r.getMessage() for r in caplog.records)
        assert "exhausted" not in msgs


# ---------------------------------------------------------------------------
# call_json_with_fallback — interaction between transient retry and model fallback
# ---------------------------------------------------------------------------


class TestCallJsonWithFallbackRetry:
    async def test_primary_transient_recovers_no_fallback(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        # Primary 429s once, then succeeds. Fallback never invoked.
        calls = _stub_send(
            monkeypatch,
            side_effect=[_HasStatus(429), '{"v": 1}'],
        )
        out = await call_json_with_fallback(
            primary_model="haiku",
            fallback_model="sonnet",
            system="s",
            user="u",
            config=populated_agent_config,
            token_manager=_TM(),
            backoffs=(0.0,),
        )
        assert out == {"v": 1}
        assert [c["model"] for c in calls] == ["haiku", "haiku"]

    async def test_primary_transient_exhausted_falls_to_secondary(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        # Primary 429s twice (1 try + 1 retry), then secondary succeeds.
        calls = _stub_send(
            monkeypatch,
            side_effect=[_HasStatus(429), _HasStatus(429), '{"v": 1}'],
        )
        out = await call_json_with_fallback(
            primary_model="haiku",
            fallback_model="sonnet",
            system="s",
            user="u",
            config=populated_agent_config,
            token_manager=_TM(),
            backoffs=(0.0,),
        )
        assert out == {"v": 1}
        assert [c["model"] for c in calls] == ["haiku", "haiku", "sonnet"]

    async def test_both_transient_exhausted_raises(
        self,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        # 2 primary failures + 2 secondary failures = LLMError.
        _stub_send(
            monkeypatch,
            side_effect=[
                _HasStatus(429), _HasStatus(429),
                _HasStatus(503), _HasStatus(503),
            ],
        )
        with pytest.raises(LLMError):
            await call_json_with_fallback(
                primary_model="haiku",
                fallback_model="sonnet",
                system="s",
                user="u",
                config=populated_agent_config,
                token_manager=_TM(),
                backoffs=(0.0,),
            )

    async def test_logging_retries_flag_propagates_from_config(
        self,
        monkeypatch: pytest.MonkeyPatch,
        agent_config: Any,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        # When config.logging.retries=True, the INFO retry trace should fire
        # without the test having to set log_retries explicitly.
        import dataclasses
        import logging as _logging

        from agent.config import LoggingConfig

        base = agent_config()
        cfg = dataclasses.replace(
            base, logging=LoggingConfig(per_turn_usage=False, retries=True)
        )
        _stub_send(
            monkeypatch,
            side_effect=[_HasStatus(429), '{"v": 1}'],
        )
        with caplog.at_level(_logging.INFO, logger="agent._llm"):
            await call_json_with_fallback(
                primary_model="haiku",
                fallback_model="sonnet",
                system="s",
                user="u",
                config=cfg,
                token_manager=_TM(),
                backoffs=(0.0,),
                stage="dedup",
            )
        msgs = "\n".join(r.getMessage() for r in caplog.records)
        assert "[dedup]" in msgs
        assert "transient" in msgs
