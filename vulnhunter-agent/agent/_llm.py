"""LLM calls routed through the Claude Agent SDK.

The scan stage already runs the SDK with bearer auth via env vars
(``ANTHROPIC_AUTH_TOKEN`` + ``CLAUDE_CODE_USE_BEDROCK=1``). Rather
than duplicate that machinery for the issues stage, we spin up a
short-lived ``ClaudeSDKClient`` per call: same auth, same transport,
same FM-Gateway / Bedrock path, just with no skill loaded and no
tools available so the model just answers our prompt.

Two entry points (both async):
- ``call_json``: one model call with same-model retry on transient
  (HTTP 429 / 5xx / overload) errors; parsed JSON returned.
- ``call_json_with_fallback``: same as ``call_json`` for the primary
  model, then — on any ``LLMError`` (transient retries exhausted, or
  non-transient transport / parse failure) — re-runs with the
  secondary model under the same retry policy.

**Transient-error architecture.** Classification is type-based at the
retry decision point. Detection happens once per call, at the
SDK→``call_json`` boundary:

1. ``_send_prompt`` raises ``TransientLLMError`` directly when a
   ``ResultMessage`` arrives with ``is_error=True`` and a transient
   ``api_error_status`` (429 / 5xx). This is the typed primary path
   — no string matching anywhere.
2. SDK exceptions (``claude_agent_sdk.ProcessError`` etc.) bubble
   into ``call_json``'s exception handler, which calls
   ``_classify_boundary_error``. That walks the exception chain,
   uses typed ``status_code`` / ``response.status_code`` attrs
   first, and only falls back to the shared
   ``_transient`` word-boundary regex for SDKs that surface
   the upstream HTTP code in stderr text alone.

After classification, tenacity's ``retry_if_exception(_is_transient)``
is a pure ``isinstance`` walk of the cause chain — the retry decision
point itself does no string matching.
"""

from __future__ import annotations

import json
import logging
import re
import tempfile
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    ResultMessage,
)
from tenacity import (
    AsyncRetrying,
    RetryCallState,
    retry_if_exception,
    stop_after_attempt,
    wait_chain,
    wait_fixed,
    wait_none,
)

from .auth import OAuthTokenManager
from .build_settings import build_claude_settings
from .config import AgentConfig
from ._transient import classify as _classify_transient, is_transient_status

if TYPE_CHECKING:
    from .audit import AuditWriter

logger = logging.getLogger(__name__)


class LLMError(RuntimeError):
    """Raised when an LLM call cannot return valid JSON content."""


class TransientLLMError(LLMError):
    """An inference call failed transiently — same-model retry is warranted.

    Raised at the SDK→``call_json`` boundary in two situations:

    1. A ``ResultMessage`` arrives with ``is_error=True`` and an
       ``api_error_status`` in {429, 500-599}. This is the typed
       primary signal — the SDK has already parsed the upstream HTTP
       status, no string matching involved.
    2. The SDK raises an exception whose chain carries a typed status
       attribute, or whose ``str()`` matches the shared
       ``_transient`` regex. The latter is the fallback for
       ``claude_agent_sdk``'s ``ProcessError``, which surfaces the
       upstream HTTP code only via stderr text — string matching is
       confined to the single boundary call inside
       ``_classify_boundary_error``.

    Once raised, the retry predicate ``_is_transient`` is a pure
    ``isinstance`` walk of the cause chain — no string matching at the
    retry decision point.
    """


# Same-model retry schedule on HTTP 429 / 5xx / overload. One retry at
# 60s matches the typical gateway throttle window — long enough for the
# bucket to refill, short enough that latency-sensitive callers don't
# stall. Worst-case latency added before falling through to the
# secondary model: ~60s + one extra call.
_TRANSIENT_BACKOFFS: tuple[float, ...] = (60.0,)


def _looks_transient_at_boundary(exc: BaseException) -> bool:
    """Boundary classifier — typed first, then text fallback.

    Used exactly once per ``call_json`` invocation, at the
    SDK→``call_json`` exception handler, to decide whether a raw SDK
    exception should be promoted to ``TransientLLMError`` or wrapped
    as plain ``LLMError``. Walks the cause chain:

    - **Typed signal first.** If a frame carries ``status_code`` or
      ``response.status_code``, that's authoritative for that frame:
      transient if 429/5xx; if it's non-transient, the message text
      on the same frame is ignored (a 401 with "rate_limit" in its
      message body is still a permanent auth failure) and we keep
      walking — a wrapper's 400 may have a transient cause beneath.
    - **Text fallback.** Only when no typed status is present on a
      frame, the shared ``_transient`` word-boundary regex
      classifies the message text. Word boundaries on the numeric
      arms prevent "500" from matching inside "5000 tokens".

    This is the only site in the module where string matching
    classifies an SDK error. The retry predicate elsewhere
    (``_is_transient``) is a pure ``isinstance`` check.
    """
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        status = getattr(cur, "status_code", None)
        if not isinstance(status, int):
            resp = getattr(cur, "response", None)
            if resp is not None:
                status = getattr(resp, "status_code", None)
        # Shared typed-first classifier: a non-transient typed status
        # short-circuits this frame (text scan is suppressed); when
        # there's no typed status, text matches via the shared regex.
        if _classify_transient(status, str(cur)):
            return True
        cur = getattr(cur, "__cause__", None) or getattr(cur, "__context__", None)
    return False


def _classify_boundary_error(model: str, exc: BaseException) -> LLMError:
    """Wrap an SDK exception as ``TransientLLMError`` or plain ``LLMError``.

    Single conversion point so the retry predicate downstream is a
    type check. The wrapped exception is attached as ``__cause__`` so
    the original traceback is preserved.
    """
    if _looks_transient_at_boundary(exc):
        return TransientLLMError(f"{model} call via SDK failed transiently: {exc}")
    return LLMError(f"{model} call via SDK failed: {exc}")


def _is_transient(exc: BaseException) -> bool:
    """Retry predicate — walks the cause chain for ``TransientLLMError``.

    Pure ``isinstance`` check. Classification of HTTP status / SDK text
    happens once at the ``_classify_boundary_error`` boundary; this
    predicate just sees the resulting typed signal.
    """
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, TransientLLMError):
            return True
        cur = getattr(cur, "__cause__", None) or getattr(cur, "__context__", None)
    return False


@dataclass
class CostStats:
    """Running totals across every LLM call in a stage.

    Mirrors the fields the SDK emits on each ``ResultMessage``: cost in
    USD, turn count, API-side duration. ``calls`` tracks how many
    individual model calls produced the totals (one per ``call_json``).
    Mutable so callers can pass a single instance through the full call
    chain and accumulate.
    """

    cost_usd: float = 0.0
    num_turns: int = 0
    duration_api_ms: int = 0
    calls: int = 0

    def add_result(self, msg: ResultMessage) -> None:
        self.cost_usd += float(getattr(msg, "total_cost_usd", 0.0) or 0.0)
        self.num_turns += int(getattr(msg, "num_turns", 0) or 0)
        self.duration_api_ms += int(getattr(msg, "duration_api_ms", 0) or 0)
        self.calls += 1


def _extract_json_block(text: str) -> str:
    """Pull the first {...} or [...] JSON value out of an LLM response.

    Strips an optional ```json``` (or plain ```) code fence, then walks
    the remaining text counting brace/bracket depth — but skips over
    JSON string literals so a ``"}"`` inside a string doesn't fool the
    counter. Without that, a finding description containing a literal
    ``}`` would prematurely close the object and the rest of the JSON
    would be lost.

    Returns the input unchanged if no balanced object/array is found;
    the caller's ``json.loads`` will then raise.
    """
    # Strip surrounding fence if present so the brace walker has a
    # clean substring to scan.
    fence = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
    body = fence.group(1) if fence else text

    for opener, closer in [("{", "}"), ("[", "]")]:
        start = body.find(opener)
        if start == -1:
            continue
        depth = 0
        in_string = False
        escape = False
        for i in range(start, len(body)):
            ch = body[i]
            if in_string:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_string = False
                continue
            if ch == '"':
                in_string = True
            elif ch == opener:
                depth += 1
            elif ch == closer:
                depth -= 1
                if depth == 0:
                    return body[start : i + 1]
    return body  # let the json parser raise


async def _send_prompt(
    *,
    model: str,
    system: str,
    user: str,
    config: AgentConfig,
    auth_token: str,
    cost_tracker: CostStats | None = None,
) -> str:
    """One-shot prompt → assistant text. No tools, no skills, no extras.

    If ``cost_tracker`` is provided, the SDK's ``ResultMessage`` (cost,
    turns, duration) is added to it. If a ``ResultMessage`` arrives with
    ``is_error=True`` and a transient ``api_error_status`` (429 / 5xx),
    a ``TransientLLMError`` is raised — typed primary signal, no string
    matching. This is the only path that lets a same-model retry fire
    when the upstream 429 surfaces via ResultMessage rather than as an
    SDK exception.
    """
    settings_json = build_claude_settings(config, auth_token, model=model)
    with tempfile.TemporaryDirectory(prefix="vulnhunt-llm-") as cwd:
        options = ClaudeAgentOptions(
            model=model,
            settings=settings_json,
            tools=[],
            allowed_tools=[],
            permission_mode="bypassPermissions",
            setting_sources=[],
            skills=[],
            system_prompt=system,
            cwd=cwd,
        )
        text_parts: list[str] = []
        async with ClaudeSDKClient(options) as client:
            await client.query(user)
            async for msg in client.receive_response():
                if isinstance(msg, AssistantMessage):
                    for block in getattr(msg, "content", []) or []:
                        if getattr(block, "type", None) == "text" or (
                            type(block).__name__ == "TextBlock"
                        ):
                            piece = getattr(block, "text", "")
                            if piece:
                                text_parts.append(piece)
                elif isinstance(msg, ResultMessage):
                    if cost_tracker is not None:
                        cost_tracker.add_result(msg)
                    # Typed transient signal — the SDK has already
                    # parsed the upstream HTTP status. Raise so the
                    # tenacity retry fires (predicate is type-based).
                    if getattr(msg, "is_error", False) and is_transient_status(
                        getattr(msg, "api_error_status", None)
                    ):
                        raise TransientLLMError(
                            f"{model} upstream returned HTTP "
                            f"{msg.api_error_status} via ResultMessage"
                        )
        return "".join(text_parts)


def _build_async_retrying(
    *,
    backoffs: tuple[float, ...],
    before_sleep: Callable[[RetryCallState], None] | None,
) -> AsyncRetrying:
    """Build an ``AsyncRetrying`` configured for our transient-retry policy.

    ``backoffs`` is the sequence of per-retry delays in seconds — an empty
    tuple disables retries entirely. The retry predicate is
    ``_is_transient``, which is a pure ``isinstance`` walk of the cause
    chain for ``TransientLLMError`` — classification happens once at the
    SDK→``call_json`` boundary in ``_classify_boundary_error``.
    ``reraise=True`` makes tenacity raise the original exception once
    retries are exhausted instead of wrapping it in ``RetryError``.
    """
    if backoffs:
        wait = wait_chain(*[wait_fixed(b) for b in backoffs])
    else:
        wait = wait_none()
    return AsyncRetrying(
        retry=retry_if_exception(_is_transient),
        wait=wait,
        stop=stop_after_attempt(1 + len(backoffs)),
        before_sleep=before_sleep,
        reraise=True,
    )


def _make_retry_logger(
    *, model: str, stage: str, log_retries: bool
) -> Callable[[RetryCallState], None] | None:
    """Build a tenacity ``before_sleep`` callable gated on ``log_retries``.

    Returns ``None`` when ``log_retries`` is False so tenacity does not
    invoke any hook at all — keeps the "no retry chatter unless asked"
    contract exactly matching the previous manual loop.
    """
    if not log_retries:
        return None
    stage_tag = f"[{stage}] " if stage else ""

    def _hook(retry_state: RetryCallState) -> None:
        delay = (
            retry_state.next_action.sleep
            if retry_state.next_action is not None
            else 0.0
        )
        exc = (
            retry_state.outcome.exception()
            if retry_state.outcome is not None
            else None
        )
        # `stop_after_attempt(N)` exposes the cap as `max_attempt_number`.
        # Use it directly so the log reads "attempt K of N total" — same
        # framing as runner.py::_log_scan_retry. The previous form
        # (`max_attempts - 1`, "K of N retries") rendered as "1/1" on a
        # first failure with one retry queued, which read as "exhausted"
        # to operators.
        max_attempts = getattr(
            retry_state.retry_object.stop, "max_attempt_number", None
        )
        logger.info(
            "%s%s transient error (%s); retrying in %.0fs (attempt %d/%s)",
            stage_tag,
            model,
            exc,
            delay,
            retry_state.attempt_number,
            max_attempts if max_attempts else "?",
        )

    return _hook


async def call_json(
    *,
    model: str,
    system: str,
    user: str,
    config: AgentConfig,
    token_manager: OAuthTokenManager,
    cost_tracker: CostStats | None = None,
    backoffs: tuple[float, ...] = _TRANSIENT_BACKOFFS,
    log_retries: bool = False,
    stage: str = "",
) -> Any:
    """Single LLM call via the SDK; parse the response as JSON.

    Transient errors (HTTP 429 / 5xx / overload) trigger same-model
    retries with the delays in ``backoffs``. Each entry is the wait (in
    seconds) before the corresponding retry — pass ``backoffs=()`` to
    disable. Non-transient transport errors and JSON-parse failures
    raise ``LLMError`` immediately (no retry — we don't want to mask a
    bad prompt as a flaky network).

    Retry orchestration is delegated to ``tenacity.AsyncRetrying`` — the
    predicate ``_is_transient`` walks the ``__cause__`` chain so it sees
    the underlying 429 even after we wrap the SDK error in ``LLMError``.

    ``log_retries`` gates the INFO retry trace; ``call_json_with_fallback``
    forwards it from ``config.logging.retries``. ``stage`` (e.g.
    ``"extract"``) is included in retry logs so multi-stage runs are
    distinguishable.

    Raises ``LLMError`` on transport / SDK error (after retries exhausted)
    or JSON-parse failure.
    """
    retrying = _build_async_retrying(
        backoffs=backoffs,
        before_sleep=_make_retry_logger(
            model=model, stage=stage, log_retries=log_retries
        ),
    )
    try:
        async for attempt in retrying:
            with attempt:
                token = token_manager.get_valid_token()
                try:
                    text = await _send_prompt(
                        model=model,
                        system=system,
                        user=user,
                        config=config,
                        auth_token=token,
                        cost_tracker=cost_tracker,
                    )
                except LLMError:
                    # ``_send_prompt`` already raised a classified
                    # ``LLMError`` / ``TransientLLMError`` (the typed
                    # ResultMessage path). Don't double-wrap.
                    raise
                except Exception as exc:  # noqa: BLE001 — boundary site
                    # The single string-matching boundary: walk the SDK
                    # exception chain via ``_classify_boundary_error``,
                    # which decides typed vs. transient. Everywhere
                    # downstream uses an ``isinstance`` check.
                    raise _classify_boundary_error(model, exc) from exc
                if not text.strip():
                    raise LLMError(f"{model} returned an empty response")
                block = _extract_json_block(text)
                try:
                    return json.loads(block)
                except json.JSONDecodeError as exc:
                    raise LLMError(
                        f"{model} returned non-JSON (or malformed JSON): {exc}; "
                        f"first 200 chars: {text[:200]!r}"
                    ) from exc
    except LLMError as exc:
        # Tenacity raised the final transient failure (reraise=True). Add
        # a WARNING trace so operators see "exhausted N retries" even when
        # log_retries is off — the exception alone doesn't make the
        # retry-count visible. Non-transient errors short-circuit on the
        # first attempt and skip this branch.
        if backoffs and _is_transient(exc):
            stage_tag = f"[{stage}] " if stage else ""
            logger.warning(
                "%s%s exhausted %d transient retry/retries; surfacing: %s",
                stage_tag,
                model,
                len(backoffs),
                exc,
            )
        raise
    # Defensive: AsyncRetrying must either yield-then-return or raise.
    raise LLMError(f"{model} call via SDK: retrying loop exited without resolution")


async def call_json_with_fallback(
    *,
    primary_model: str,
    fallback_model: str,
    system: str,
    user: str,
    config: AgentConfig,
    token_manager: OAuthTokenManager,
    cost_tracker: CostStats | None = None,
    stage: str = "",
    backoffs: tuple[float, ...] = _TRANSIENT_BACKOFFS,
    audit_writer: "AuditWriter | None" = None,
) -> Any:
    """Try primary_model with transient retries; on any LLMError, try
    fallback_model (also with transient retries).

    Each model gets the full ``backoffs`` schedule. Worst case before
    raising: ``(1 + len(backoffs)) * 2`` SDK calls plus the cumulative
    backoff wait twice.

    ``stage`` is a short label (e.g. ``"extract"``, ``"dedup"``) included
    in fallback and retry logs so multi-stage runs are distinguishable.

    The "primary failed, retrying with fallback" warning is logged
    unconditionally and is intentionally NOT gated on
    ``config.logging.retries``. A model fallback signals a real model
    failure (transport gave up or JSON was unparseable); we always want
    it surfaced. The same-model transient-retry INFO traces ARE gated on
    ``config.logging.retries`` — those are noisier and lower-signal.
    """
    log_retries = config.logging.retries
    try:
        return await call_json(
            model=primary_model,
            system=system,
            user=user,
            config=config,
            token_manager=token_manager,
            cost_tracker=cost_tracker,
            backoffs=backoffs,
            log_retries=log_retries,
            stage=stage,
        )
    except LLMError as exc:
        stage_tag = f"[{stage}] " if stage else ""
        logger.warning(
            "%sPrimary model %s failed (%s); retrying with %s",
            stage_tag,
            primary_model,
            exc,
            fallback_model,
        )
        if audit_writer is not None:
            from .audit import build_model_fallback

            audit_writer.emit_audit(
                build_model_fallback(
                    app_id=config.audit.app_id,
                    actor=config.audit.actor,
                    from_model=primary_model,
                    to_model=fallback_model,
                    stage=stage,
                    reason=str(exc),
                )
            )
        return await call_json(
            model=fallback_model,
            system=system,
            user=user,
            config=config,
            token_manager=token_manager,
            cost_tracker=cost_tracker,
            backoffs=backoffs,
            log_retries=log_retries,
            stage=stage,
        )


def estimate_tokens(text: str) -> int:
    """Rough char-to-token estimate. Anthropic averages ~4 chars/token."""
    return max(1, len(text) // 4)
