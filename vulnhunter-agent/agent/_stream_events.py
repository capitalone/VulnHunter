"""Shared SDK-event rendering and cumulative-totals logging.

Both ``runner.py`` (scan) and ``verify_runner.py`` (verify) drive
``ClaudeSDKClient`` and need to surface the same kinds of events
(assistant prose, tool calls, task lifecycle, system messages,
ResultMessage rollups) in the same verbosity-tiered way. This
module owns the rendering primitives + per-turn-usage + totals
logging; the runners own their own control flow (retry on
cold-start rate-limit, continuation prompts, etc.).

The shared logger name is ``agent.runner`` rather than this
module's own ``agent._stream_events``. Two reasons: (1) keeps
existing ``caplog.at_level(..., logger="agent.runner")`` test
fixtures capturing every emitted event, and (2) gives both
scan and verify modes a single, predictable logger users can
filter on in production.

The runners stream events through ``stream_event`` — one call
per SDK message — which dispatches to the right verbosity-tiered
``_log_*`` helper and accumulates per-cycle totals in the
mutable ``Totals`` dataclass the runner owns.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ._url import redact as _redact

if TYPE_CHECKING:
    from claude_agent_sdk import (
        AssistantMessage,
        ResultMessage,
        SystemMessage,
        TaskNotificationMessage,
        TaskStartedMessage,
        TaskUpdatedMessage,
        UserMessage,
    )


# Shared with runner.py so tests filtering on ``logger="agent.runner"``
# capture verify-mode events too. See module docstring.
logger = logging.getLogger("agent.runner")


_PREVIEW_MAX = 300


# Verbosity tiers, set via set_verbosity() before driving an SDK session:
#   0 (default) — Claude Code interactive parity: assistant prose, tool
#                 calls with brief descriptions, terse result summaries,
#                 task lifecycle, run/clone/results banner, errors.
#   1 (-v)     — also: full tool inputs, truncated tool result content,
#                 task progress events, the "[t] message #N: Type" header.
#   2 (-vv)    — also: thinking blocks, full system-message data dumps,
#                 deeper truncation. Effectively the previous default.
_verbosity = 0


def set_verbosity(level: int) -> None:
    """Set module-level verbosity. Call before driving the SDK session."""
    global _verbosity
    _verbosity = max(0, level)


def get_verbosity() -> int:
    """Return the current verbosity tier (for callers that branch on it)."""
    return _verbosity


def _truncate(text: str, limit: int = _PREVIEW_MAX) -> str:
    # Always scrub embedded basic-auth credentials before truncating —
    # the cloned repo's .git/config (and any tool output that reads it)
    # can contain a tokenized URL, and we don't want to leak the token
    # into agent logs even as a fragment.
    text = _redact(text)
    text = text.replace("\n", "\\n")
    if len(text) <= limit:
        return text
    return text[:limit] + "...<truncated>"


# What to surface for a ToolUseBlock at default verbosity. Maps tool name
# to a callable that pulls a short, human-readable label from the input.
def _tool_brief(name: str, tool_input: object) -> str:
    if not isinstance(tool_input, dict):
        return _truncate(repr(tool_input), 80)
    desc = tool_input.get("description")
    if desc:
        return _truncate(str(desc), 100)
    if name in ("Read", "Edit", "Write"):
        return str(tool_input.get("file_path", "?"))
    if name == "Bash":
        cmd = tool_input.get("command", "")
        return _truncate(str(cmd), 100)
    if name == "Grep":
        pat = tool_input.get("pattern", "?")
        path = tool_input.get("path", "")
        return f"{pat}{(' in ' + path) if path else ''}"
    if name == "Glob":
        return str(tool_input.get("pattern", "?"))
    if name in ("Agent", "Task"):
        sub = tool_input.get("subagent_type", "")
        d = tool_input.get("description") or tool_input.get("prompt", "")
        return f"{sub}{(': ' + _truncate(str(d), 80)) if d else ''}"
    if name == "WebFetch":
        return str(tool_input.get("url", "?"))
    if name == "TodoWrite":
        todos = tool_input.get("todos", [])
        return f"{len(todos)} item(s)" if isinstance(todos, list) else "?"
    return _truncate(repr(tool_input), 100)


def _result_brief(content: object) -> str:
    """One-line summary for a ToolResultBlock's content at default verbosity."""
    if isinstance(content, str):
        text = content.strip()
        if not text:
            return "<empty>"
        first = text.splitlines()[0]
        suffix = ""
        line_count = text.count("\n") + 1
        if line_count > 1:
            suffix = f" (+{line_count - 1} more line(s))"
        return _truncate(first, 120) + suffix
    if isinstance(content, list):
        return f"<{len(content)} block(s)>"
    return _truncate(repr(content), 120)


def _render_block(block: object) -> str:
    """One-line summary of a content block, used at -v / -vv verbosity."""
    block_type = type(block).__name__
    if hasattr(block, "text") and isinstance(getattr(block, "text"), str):
        return f"{block_type}: {_truncate(block.text)}"
    if hasattr(block, "name") and hasattr(block, "input"):
        # ToolUseBlock / ServerToolUseBlock
        name = getattr(block, "name", "?")
        tool_input = getattr(block, "input", None)
        return f"{block_type}({name}): {_truncate(repr(tool_input))}"
    if hasattr(block, "content"):
        # ToolResultBlock — content can be a str or list of blocks.
        content = getattr(block, "content")
        if isinstance(content, str):
            return f"{block_type}: {_truncate(content)}"
        if isinstance(content, list):
            inner = " | ".join(_render_block(b) for b in content)
            return f"{block_type}: {_truncate(inner)}"
    return f"{block_type}: {_truncate(repr(block))}"


def _agent_name_from_started(message: "TaskStartedMessage") -> str:
    """Derive a short label for a subagent from a TaskStartedMessage.

    Prefers the orchestrator-supplied ``description`` (the prompt's first
    line, e.g. "Recon subagent" or "INJ partition 1"); falls back to the
    SDK-supplied ``task_type`` (e.g. "general-purpose", "Explore"). Empty
    string if neither is available.

    The resulting label is what gets attached to per-turn usage logs and
    task-lifecycle status logs so multi-agent runs are readable without
    cross-referencing opaque tool_use_ids.
    """
    desc = (getattr(message, "description", "") or "").strip()
    if desc:
        first = desc.splitlines()[0].strip()
        if first:
            return _truncate(first, 60)
    task_type = (getattr(message, "task_type", "") or "").strip()
    return task_type


def _log_per_turn_usage(
    message: "AssistantMessage",
    last_turn_ts: dict[str | None, float],
    run_start: float,
    agent_names: dict[str, str],
) -> None:
    """Print per-agent token use and wall-clock duration for one turn.

    Gated on ``config.logging.per_turn_usage`` at the runner. The "agent"
    identifier is ``parent_tool_use_id`` — None for the root orchestrator,
    otherwise the Task tool's tool_use_id that spawned the subagent.
    ``agent_names`` is consulted to render the friendly label populated
    from TaskStartedMessage; falls back to a short prefix of the
    tool_use_id if the registry has no entry yet (can happen if the SDK
    reorders the started/assistant events).

    Δ is wall-clock between sequential events for the same agent: for the
    root orchestrator, since run start (first turn) or since its previous
    AssistantMessage; for a subagent, since its TaskStartedMessage (first
    turn) or since its previous AssistantMessage. It approximates "time
    spent on this turn" but is wall-clock — under parallel fan-out a
    subagent can sit blocked behind another's work, which inflates Δ
    above the model's real compute time. Useful for spotting slow agents,
    not for cost attribution.
    """
    now = time.time()
    agent_id = getattr(message, "parent_tool_use_id", None)
    prev = last_turn_ts.get(agent_id, run_start)
    last_turn_ts[agent_id] = now
    delta = now - prev
    usage = getattr(message, "usage", None) or {}
    in_tokens = int(usage.get("input_tokens", 0) or 0)
    out_tokens = int(usage.get("output_tokens", 0) or 0)
    cache_read = int(usage.get("cache_read_input_tokens", 0) or 0)
    cache_create = int(usage.get("cache_creation_input_tokens", 0) or 0)
    model = getattr(message, "model", "?") or "?"
    if agent_id is None:
        agent_label = "root"
    else:
        agent_label = agent_names.get(agent_id) or f"agent[{agent_id[:8]}]"
    logger.info(
        "  turn-usage agent=%s model=%s Δ=%.1fs in=%d out=%d cache_read=%d cache_create=%d",
        agent_label,
        model,
        delta,
        in_tokens,
        out_tokens,
        cache_read,
        cache_create,
    )


def _log_assistant_message(message: "AssistantMessage") -> None:
    """Verbosity-tiered assistant logging.

    v=0: print TextBlock prose verbatim, ToolUse as ``Tool(name): brief``,
         skip thinking and tool results.
    v>=1: also print full tool inputs.
    v>=2: also print thinking-block previews.
    """
    model = getattr(message, "model", None) or "?"
    content = getattr(message, "content", None) or []
    if not content:
        if _verbosity >= 1:
            logger.info("  assistant [model=%s]: <empty>", model)
        return
    for block in content:
        block_type = type(block).__name__
        # Plain assistant prose — always show.
        if block_type == "TextBlock":
            text = getattr(block, "text", "")
            if not text:
                continue
            for line in text.rstrip().splitlines() or [""]:
                # Scrub any embedded basic-auth tokens — the model can
                # echo back URLs it saw in tool output. _truncate would
                # do this for us, but TextBlock prose is logged verbatim
                # so we apply redact directly.
                logger.info("  assistant: %s", _redact(line))
            continue
        # Tool use — brief at v=0, full input at v>=1.
        if block_type in ("ToolUseBlock", "ServerToolUseBlock"):
            name = getattr(block, "name", "?")
            tool_input = getattr(block, "input", None)
            if _verbosity == 0:
                logger.info("  ● %s(%s)", name, _tool_brief(name, tool_input))
            else:
                logger.info(
                    "  ● %s(%s): %s",
                    name,
                    _tool_brief(name, tool_input),
                    _truncate(repr(tool_input)),
                )
            continue
        # Thinking — only at -vv.
        if block_type == "ThinkingBlock":
            if _verbosity >= 2:
                logger.info("  assistant %s", _render_block(block))
            continue
        # Tool result blocks shouldn't normally appear in assistant content;
        # if they do, only render at -v+.
        if _verbosity >= 1:
            logger.info("  assistant [model=%s] %s", model, _render_block(block))


def _log_user_message(message: "UserMessage") -> None:
    """Tool-result feedback ('user' role). Brief at v=0, fuller at v>=1."""
    content = getattr(message, "content", None)
    if content is None:
        if _verbosity >= 1:
            logger.info("  user: <empty>")
        return
    if isinstance(content, str):
        if _verbosity == 0:
            logger.info("  ↳ %s", _result_brief(content))
        else:
            logger.info("  user: %s", _truncate(content))
        return
    if isinstance(content, list):
        if not content:
            if _verbosity >= 1:
                logger.info("  user: <empty list>")
            return
        for block in content:
            block_type = type(block).__name__
            if block_type in ("ToolResultBlock",):
                inner = getattr(block, "content", None)
                if _verbosity == 0:
                    logger.info("  ↳ %s", _result_brief(inner))
                else:
                    logger.info("  user %s", _render_block(block))
                continue
            if _verbosity >= 1:
                logger.info("  user %s", _render_block(block))
        return
    if _verbosity >= 1:
        logger.info("  user: %s", _truncate(repr(content)))


def _log_task_started(message: "TaskStartedMessage") -> None:
    desc = getattr(message, "description", "") or ""
    task_type = getattr(message, "task_type", "") or "?"
    # Show task starts at v=0 — they're load-bearing for understanding the
    # workflow — but keep them short.
    short = _truncate(desc, 100 if _verbosity == 0 else 200)
    logger.info("  ▶ task started: %s (type=%s)", short, task_type)
    if _verbosity >= 1:
        logger.info("        task_id=%s", message.task_id)


def _log_task_status(
    message: "TaskUpdatedMessage | TaskNotificationMessage",
    *,
    agent_name: str | None = None,
) -> None:
    # Lazy import to avoid a hard top-level dep on TERMINAL_TASK_STATUSES.
    from claude_agent_sdk import TERMINAL_TASK_STATUSES

    status = getattr(message, "status", None) or "?"
    summary = getattr(message, "summary", None)
    output_file = getattr(message, "output_file", None)
    log = logger.warning if status in ("failed", "killed") else logger.info
    icon = "✓" if status == "completed" else "✗" if status in ("failed", "killed") else "·"
    name_suffix = f" [{agent_name}]" if agent_name else ""
    if _verbosity == 0:
        # Only surface terminal statuses at v=0; updates ('running', 'paused')
        # are noisy and the orchestrator's text already conveys progress.
        if status not in TERMINAL_TASK_STATUSES:
            return
        head = _truncate(summary or "", 100) if summary else ""
        log("  %s task %s%s%s", icon, status, name_suffix, f": {head}" if head else "")
        return
    extras = []
    if summary:
        extras.append(f"summary={_truncate(summary, 120)}")
    if output_file:
        extras.append(f"output_file={output_file}")
    suffix = (" " + " ".join(extras)) if extras else ""
    log("  %s task %s%s: id=%s%s", icon, status, name_suffix, message.task_id, suffix)


def _log_system_message(message: "SystemMessage") -> None:
    """Log SystemMessage contents.

    At v=0 we only surface the things a user genuinely needs to see:
    the init confirmation that /vulnhunt is loaded, and any error events.
    At v=1 we add other subtypes' data (truncated). At v=2 we add task
    progress and dump the full data blob.
    """
    subtype = getattr(message, "subtype", "") or "<none>"
    data = getattr(message, "data", None)

    is_error = subtype.lower() == "error" or (
        isinstance(data, dict) and bool(data.get("is_error") or data.get("error"))
    )

    # Auth-failure surfaces are critical and stay visible at every level.
    if subtype == "init":
        if isinstance(data, dict):
            commands = data.get("slash_commands") or []
            # Match either `vulnhunt` (scan path) or `vulnhunt-fix-verify`
            # (verify path). This helper is shared across both runners;
            # using ``"vulnhunt" in commands`` would raise a false-
            # positive warning on every verify run because the loaded
            # command is the ``-fix-verify`` variant.
            loaded = [c for c in commands if isinstance(c, str) and c.startswith("vulnhunt")]
            if loaded:
                logger.info("/%s is loaded ✓", loaded[0])
            else:
                logger.warning(
                    "No vulnhunt* slash command loaded (loaded %d commands: %s)",
                    len(commands),
                    sorted(commands),
                )
        if _verbosity >= 2:
            logger.info("  system [init]: %s", _truncate(repr(data), 800))
        return

    # task_progress is a constant fire-hose during subagent work — silence
    # it unless the user opted into -v.
    if subtype == "task_progress" and _verbosity < 1:
        return

    log = logger.error if is_error else logger.info
    if data is None:
        if is_error or _verbosity >= 1:
            log("  system [%s]: <no data>", subtype)
        return

    if is_error:
        log("  system [%s]: %s", subtype, _truncate(repr(data), 800))
    elif _verbosity >= 2:
        log("  system [%s]: %s", subtype, _truncate(repr(data), 800))
    elif _verbosity >= 1:
        log("  system [%s]: %s", subtype, _truncate(repr(data), 200))


def _log_result(message: "ResultMessage") -> None:
    is_error = getattr(message, "is_error", False)
    if is_error:
        errors = getattr(message, "errors", None)
        logger.warning("ResultMessage is_error=True: %s", errors)
    cost = getattr(message, "total_cost_usd", 0.0) or 0.0
    duration_ms = getattr(message, "duration_ms", 0) or 0
    duration_api_ms = getattr(message, "duration_api_ms", 0) or 0
    num_turns = getattr(message, "num_turns", 0) or 0
    logger.info(
        "ResultMessage: duration=%dms api_duration=%dms turns=%d cost_usd=$%.4f",
        duration_ms,
        duration_api_ms,
        num_turns,
        cost,
    )


# ---- Per-session totals --------------------------------------------------


@dataclass
class SessionTotals:
    """Cumulative SDK-session counters, accumulated per ResultMessage.

    Semantics vary by field — see ``accumulate_result`` below:

    - ``cost_usd``: running max. ``total_cost_usd`` is cumulative-within-
      session (the SDK re-emits the running total each cycle), so max-of-
      seen captures the final figure even if the last ResultMessage has
      ``total_cost_usd=None`` (an error ResultMessage can come through
      that way and would zero the value under "last wins").
    - ``duration_api_ms``: sum. Per-cycle API time — no ``total_`` prefix
      means it's THIS cycle's value, not cumulative.
    - ``num_turns``: sum. Per-cycle too; empirically non-monotonic across
      cycles, so summing is the only way to get the session total.
    - ``result_messages``: count of ResultMessage events seen.
    """

    cost_usd: float = 0.0
    num_turns: int = 0
    duration_api_ms: int = 0
    result_messages: int = 0


def accumulate_result(totals: SessionTotals, message: "ResultMessage") -> None:
    """Fold one ResultMessage's stats into ``totals``."""
    cost_now = float(getattr(message, "total_cost_usd", 0.0) or 0.0)
    if cost_now > totals.cost_usd:
        totals.cost_usd = cost_now
    totals.duration_api_ms += int(getattr(message, "duration_api_ms", 0) or 0)
    totals.num_turns += int(getattr(message, "num_turns", 0) or 0)
    totals.result_messages += 1


def log_session_totals(totals: SessionTotals, label: str) -> None:
    """Emit the cumulative rollup line at the end of an SDK session.

    ``label`` is the leading word (e.g. ``"Scan"`` → ``"Scan totals:"``,
    ``"Verify"`` → ``"Verify totals:"``).
    """
    logger.info(
        "%s totals: %d turn(s) across %d ResultMessage(s), "
        "API duration=%dms, cost_usd=$%.4f",
        label,
        totals.num_turns,
        totals.result_messages,
        totals.duration_api_ms,
        totals.cost_usd,
    )
