"""Tests for ``agent/verify_refs.py``.

The pre-flight is mocked via an ``_llm.call_json`` stub (verify uses the
scan-session model, no fallback). We focus on the
shape-coercion path (``_coerce_sources``) and on the public
``extract_cross_repo_references`` contract: returns a list of
``requested_sources``-shaped dicts on success; returns ``[]`` (never
raises) on any LLM failure or malformed response.
"""

from __future__ import annotations

from typing import Any

import pytest

from agent import _llm
from agent import verify_refs as refs_mod
from agent.verify_refs import _coerce_sources, extract_cross_repo_references
from tests._helpers import FakeTokenManager as _TM


def _stub_llm(monkeypatch: pytest.MonkeyPatch, response: dict | Exception) -> None:
    async def fake(**kwargs: Any) -> Any:
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(refs_mod._llm, "call_json", fake)


# ---------- _coerce_sources (pure) -----------------------------------------


class TestCoerceSources:
    def test_well_formed_response_passes_through(self) -> None:
        parsed = {
            "requested_sources": [
                {
                    "claim_excerpt": "see github.com/org/svc",
                    "repo_hint": "https://github.com/org/svc",
                    "reason": "developer cited a WAF in that repo",
                }
            ]
        }
        out = _coerce_sources(parsed)
        assert out == parsed["requested_sources"]

    def test_truncates_claim_excerpt(self) -> None:
        parsed = {
            "requested_sources": [
                {
                    "claim_excerpt": "x" * 500,
                    "repo_hint": "https://github.com/org/svc",
                    "reason": "y",
                }
            ]
        }
        out = _coerce_sources(parsed)
        assert len(out[0]["claim_excerpt"]) == 200

    def test_missing_reason_gets_default(self) -> None:
        """``reason`` is required downstream (the skill template references
        it). When the model omits it, fill a generic explanation rather
        than letting an empty string downstream confuse the developer."""
        parsed = {
            "requested_sources": [
                {
                    "claim_excerpt": "x",
                    "repo_hint": "https://github.com/org/svc",
                }
            ]
        }
        out = _coerce_sources(parsed)
        assert out[0]["reason"]
        assert "Pre-flight" in out[0]["reason"]

    def test_missing_repo_hint_drops_entry(self) -> None:
        """``repo_hint`` is the only field that's load-bearing for
        downstream resolution. An entry without it can't be cloned
        and there's nothing meaningful to ignore — drop it."""
        parsed = {
            "requested_sources": [
                {"claim_excerpt": "x", "reason": "y"},  # no repo_hint
                {
                    "claim_excerpt": "x",
                    "repo_hint": "https://github.com/org/svc",
                    "reason": "y",
                },
            ]
        }
        out = _coerce_sources(parsed)
        assert len(out) == 1
        assert out[0]["repo_hint"] == "https://github.com/org/svc"

    def test_blank_repo_hint_drops_entry(self) -> None:
        parsed = {
            "requested_sources": [
                {"claim_excerpt": "x", "repo_hint": "   ", "reason": "y"}
            ]
        }
        assert _coerce_sources(parsed) == []

    @pytest.mark.parametrize(
        "bad",
        [
            None,
            "not a dict",
            42,
            {"requested_sources": None},
            {"requested_sources": "not a list"},
            {"requested_sources": [None, "string", 42]},
        ],
    )
    def test_malformed_response_returns_empty(self, bad: Any) -> None:
        assert _coerce_sources(bad) == []

    def test_empty_list_returns_empty(self) -> None:
        assert _coerce_sources({"requested_sources": []}) == []


# ---------- extract_cross_repo_references ---------------------------------


@pytest.mark.asyncio
async def test_extract_empty_comments_skips_llm(
    monkeypatch: pytest.MonkeyPatch, populated_agent_config
) -> None:
    """Whitespace-only comments → return [] without calling the LLM at
    all. Saves a request when the issue has no developer narrative."""
    called = False

    async def fake(**kwargs: Any) -> Any:
        nonlocal called
        called = True
        return {"requested_sources": []}

    monkeypatch.setattr(refs_mod._llm, "call_json", fake)
    result = await extract_cross_repo_references(
        "   \n\n   ",
        config=populated_agent_config,
        token_manager=_TM(),
    )
    assert result == []
    assert called is False


@pytest.mark.asyncio
async def test_extract_passes_response_through(
    monkeypatch: pytest.MonkeyPatch, populated_agent_config
) -> None:
    payload = {
        "requested_sources": [
            {
                "claim_excerpt": "see https://github.com/your-org/example-shared-repo",
                "repo_hint": "https://github.com/your-org/example-shared-repo",
                "reason": "developer cited a WAF in that repo as the fix",
            }
        ]
    }
    _stub_llm(monkeypatch, payload)
    result = await extract_cross_repo_references(
        "Please also take a look at https://github.com/your-org/example-shared-repo",
        config=populated_agent_config,
        token_manager=_TM(),
    )
    assert result == payload["requested_sources"]


@pytest.mark.asyncio
async def test_extract_llm_failure_returns_empty(
    monkeypatch: pytest.MonkeyPatch, populated_agent_config
) -> None:
    """LLM transport failure → log a warning and return []. The skill's
    R2 still runs over the same comments, so this is best-effort."""
    _stub_llm(monkeypatch, _llm.LLMError("transport blew up"))
    result = await extract_cross_repo_references(
        "Please also take a look at https://github.com/your-org/example-shared-repo",
        config=populated_agent_config,
        token_manager=_TM(),
    )
    assert result == []


@pytest.mark.asyncio
async def test_extract_malformed_response_returns_empty(
    monkeypatch: pytest.MonkeyPatch, populated_agent_config
) -> None:
    """LLM returned valid JSON but with the wrong shape — same outcome
    as a transport failure."""
    _stub_llm(monkeypatch, {"some_other_key": [1, 2, 3]})
    result = await extract_cross_repo_references(
        "some text",
        config=populated_agent_config,
        token_manager=_TM(),
    )
    assert result == []
