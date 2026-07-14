"""Unit tests for ``agent/_transient.py``.

Kept separate from ``test_llm.py`` / ``test_runner.py`` so the shared
classifier can be tested without pulling in tenacity, the SDK, or any
other heavy dependency. The same logic is exercised end-to-end via the
``_is_transient`` and ``_is_rate_limit_result`` tests in those files.
"""

from __future__ import annotations

import pytest

from agent._transient import classify, is_transient_status, is_transient_text


class TestIsTransientStatus:
    @pytest.mark.parametrize("status", [429, 500, 502, 503, 504, 599])
    def test_transient_status_codes_match(self, status: int) -> None:
        assert is_transient_status(status)

    @pytest.mark.parametrize("status", [200, 301, 400, 401, 403, 404])
    def test_non_transient_status_codes_do_not_match(self, status: int) -> None:
        assert not is_transient_status(status)

    @pytest.mark.parametrize("value", [None, "429", 429.0, object()])
    def test_non_int_inputs_do_not_match(self, value: object) -> None:
        # Accepts arbitrary objects so callers can pass getattr() output
        # without an isinstance check at every call site.
        assert not is_transient_status(value)


class TestIsTransientText:
    @pytest.mark.parametrize(
        "msg",
        [
            "HTTP 429 from bedrock",
            "got 503 too many tries",
            "upstream returned 502",
            "anthropic 500 internal",
            "edge 504 gateway timeout",
        ],
    )
    def test_http_codes_with_word_boundary_match(self, msg: str) -> None:
        assert is_transient_text(msg)

    @pytest.mark.parametrize(
        "msg",
        [
            "rate limit exceeded",
            "rate_limit_exceeded",
            "Rate Limit hit",
            "RATE_LIMIT_ERROR",
            "model is overloaded, try again",
            "service unavailable",
            "service_unavailable",
            "bad gateway",
            "gateway timeout",
        ],
    )
    def test_phrases_match(self, msg: str) -> None:
        assert is_transient_text(msg)

    @pytest.mark.parametrize(
        "msg",
        [
            # Bug 2 (PR #11 review): bare numerics used to false-match
            # against token counts.
            "prompt exceeded 5000 tokens; max 4096",
            "4290 tokens used of 4096 budget",
            "5031 tokens, max 4096",
            "consumed 50244 tokens",
            "max 4096 tokens, you sent 5040",
        ],
    )
    def test_token_counts_do_not_match(self, msg: str) -> None:
        assert not is_transient_text(msg)

    @pytest.mark.parametrize(
        "msg",
        [
            "authentication failed",
            "permission denied",
            "the model returned no content",
            "json parse error at byte 17",
            "",
        ],
    )
    def test_non_transient_messages_do_not_match(self, msg: str) -> None:
        assert not is_transient_text(msg)

    def test_substring_in_word_does_not_match(self) -> None:
        # Word boundary must hold on BOTH sides for a numeric arm.
        # ``xyz500abc`` should not match \b500\b.
        assert not is_transient_text("xyz500abc")

    def test_prefix_word_does_not_match_phrase(self) -> None:
        # Leading \b on phrase arms prevents ``xyzrate_limit`` from matching.
        assert not is_transient_text("xyzrate_limit")

    def test_suffix_on_phrase_still_matches(self) -> None:
        # The phrase arms intentionally omit a trailing \b so the very
        # common ``rate_limit_exceeded`` pattern continues to match.
        assert is_transient_text("rate_limit_exceeded_at_node_3")


class TestClassify:
    """Typed-first composite — short-circuits on authoritative status."""

    @pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
    def test_transient_status_returns_true_regardless_of_text(
        self, status: int
    ) -> None:
        assert classify(status, "")
        assert classify(status, "unrelated message")

    @pytest.mark.parametrize("status", [400, 401, 403, 404])
    def test_non_transient_status_short_circuits_even_with_transient_text(
        self, status: int
    ) -> None:
        """Bug-1-shape closure (PR #11 review follow-up): a typed
        non-transient status returns False even if ``text`` contains
        ``rate_limit_exceeded`` or similar. The SDK shouldn't surface a
        400 with rate-limit-y text in practice — but the asymmetry with
        ``_looks_transient_at_boundary`` (which already short-circuits)
        is what makes this a bug-shape worth fixing across all sites."""
        assert not classify(status, "rate_limit_exceeded")
        assert not classify(status, "model is overloaded")
        assert not classify(status, "HTTP 429 throttled")

    def test_no_status_falls_back_to_text_match(self) -> None:
        assert classify(None, "rate_limit_exceeded")
        assert classify(None, "HTTP 503 upstream")
        assert classify("not an int", "model is overloaded")

    def test_no_status_no_transient_text_returns_false(self) -> None:
        assert not classify(None, "")
        assert not classify(None, "authentication failed")
        assert not classify(None, "prompt exceeded 5000 tokens")

    def test_aligns_with_looks_transient_at_boundary_single_frame_shape(
        self,
    ) -> None:
        """Document the alignment invariant: any single (status, text)
        pair classified here must match what
        ``_llm.py::_looks_transient_at_boundary`` does on a single
        frame (it walks the cause chain calling this helper per
        frame)."""
        # Typed transient wins
        assert classify(429, "anything")
        # Typed non-transient suppresses text on this frame
        assert not classify(401, "rate_limit")
        # Text fallback when no typed status
        assert classify(None, "rate_limit")
