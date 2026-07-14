"""Unit tests for ``agent/_stream_events.py``.

The verbosity-tiered ``_log_*`` helpers and the rendering utilities
(``_truncate``, ``_tool_brief``, ``_result_brief``, ``_render_block``,
``_agent_name_from_started``) are covered by the broader
``test_runner.py`` and ``test_runner_helpers_extra.py`` suites — they
test these via the ``agent.runner`` re-exports, which point at the
same module-level functions here. This file covers the genuinely-new
surface introduced by the extraction: the ``SessionTotals`` dataclass,
``accumulate_result``, and ``log_session_totals``.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest

from agent._stream_events import (
    SessionTotals,
    accumulate_result,
    get_verbosity,
    log_session_totals,
    set_verbosity,
)


# ---------- SessionTotals + accumulate_result -------------------------------


def test_session_totals_defaults_zero() -> None:
    t = SessionTotals()
    assert t.cost_usd == 0.0
    assert t.num_turns == 0
    assert t.duration_api_ms == 0
    assert t.result_messages == 0


def test_accumulate_result_cost_running_max() -> None:
    """``total_cost_usd`` is cumulative-within-session — the SDK
    re-emits the running total each cycle. Running-max captures the
    highest seen so a terminal ResultMessage with cost=None doesn't
    zero the value."""
    t = SessionTotals()
    accumulate_result(t, SimpleNamespace(total_cost_usd=0.10, duration_api_ms=0, num_turns=0))
    accumulate_result(t, SimpleNamespace(total_cost_usd=0.50, duration_api_ms=0, num_turns=0))
    accumulate_result(t, SimpleNamespace(total_cost_usd=0.30, duration_api_ms=0, num_turns=0))
    assert t.cost_usd == 0.50


def test_accumulate_result_cost_handles_none() -> None:
    """An error ResultMessage can carry ``total_cost_usd=None``; the
    accumulator must not crash or zero the prior max."""
    t = SessionTotals()
    accumulate_result(t, SimpleNamespace(total_cost_usd=0.25, duration_api_ms=0, num_turns=0))
    accumulate_result(t, SimpleNamespace(total_cost_usd=None, duration_api_ms=0, num_turns=0))
    assert t.cost_usd == 0.25


def test_accumulate_result_duration_and_turns_sum() -> None:
    """``duration_api_ms`` and ``num_turns`` are per-cycle (no ``total_``
    prefix), so summing across cycles gives the session total."""
    t = SessionTotals()
    accumulate_result(t, SimpleNamespace(total_cost_usd=0.0, duration_api_ms=1200, num_turns=3))
    accumulate_result(t, SimpleNamespace(total_cost_usd=0.0, duration_api_ms=800, num_turns=2))
    accumulate_result(t, SimpleNamespace(total_cost_usd=0.0, duration_api_ms=600, num_turns=5))
    assert t.duration_api_ms == 2600
    assert t.num_turns == 10


def test_accumulate_result_counts_messages() -> None:
    t = SessionTotals()
    for _ in range(4):
        accumulate_result(t, SimpleNamespace(total_cost_usd=0.0, duration_api_ms=0, num_turns=0))
    assert t.result_messages == 4


# ---------- log_session_totals ----------------------------------------------


def test_log_session_totals_emits_rollup_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    t = SessionTotals(
        cost_usd=1.2345, num_turns=7, duration_api_ms=4200, result_messages=3
    )
    with caplog.at_level(logging.INFO, logger="agent.runner"):
        log_session_totals(t, "Scan")
    joined = "\n".join(r.getMessage() for r in caplog.records)
    assert "Scan totals: 7 turn(s) across 3 ResultMessage(s)" in joined
    assert "API duration=4200ms" in joined
    assert "cost_usd=$1.2345" in joined


def test_log_session_totals_label_appears_verbatim(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``label`` is the leading word — verifies both ``Scan`` and
    ``Verify`` produce the matching prefix."""
    t = SessionTotals(cost_usd=0.0, num_turns=1, duration_api_ms=10, result_messages=1)
    with caplog.at_level(logging.INFO, logger="agent.runner"):
        log_session_totals(t, "Verify")
    joined = "\n".join(r.getMessage() for r in caplog.records)
    assert "Verify totals:" in joined
    assert "Scan totals:" not in joined


# ---------- set_verbosity / get_verbosity -----------------------------------


def test_set_verbosity_clamps_negative() -> None:
    """Negative levels collapse to 0 so callers can't accidentally
    silence everything via a bad CLI integer."""
    set_verbosity(-5)
    assert get_verbosity() == 0
    set_verbosity(0)  # restore for sibling tests


def test_set_verbosity_round_trip() -> None:
    set_verbosity(2)
    assert get_verbosity() == 2
    set_verbosity(1)
    assert get_verbosity() == 1
    set_verbosity(0)
    assert get_verbosity() == 0
