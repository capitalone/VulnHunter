"""Shared transient-error indicator regex + typed-first classifier.

Four call sites need to decide whether an exception or message text
represents a transient API failure worth retrying (HTTP 429 / 5xx /
overload / similar):

- ``_llm.py::_looks_transient_at_boundary`` — issues-stage SDK
  exception-chain walker.
- ``_llm.py::_send_prompt`` — typed ``ResultMessage`` check
  (uses ``is_transient_status`` directly; pure typed signal, no text).
- ``runner.py::_is_rate_limit_system_message`` — mid-stream
  ``SystemMessage`` classifier.
- ``runner.py::_is_rate_limit_result`` — terminal ``ResultMessage``
  classifier.

They used to maintain near-duplicate substring lists that drifted (the
``_is_rate_limit_system_message`` list dropped the numeric codes; the
others kept bare ``"500"`` / ``"502"`` etc. that false-matched against
``"5000 tokens"`` and stack-trace line numbers).

Two helpers solve different needs:

- ``is_transient_status`` / ``is_transient_text`` are the primitives
  for the rare site that wants only one signal in isolation.
- ``classify(status, text)`` is the typed-first composite — a typed
  non-transient status short-circuits, suppressing the text scan on
  the same frame. Use this anywhere a single (status, text) pair
  needs to be classified; it keeps the four sites aligned and
  prevents the Bug-1-shape asymmetry (a ``ResultMessage`` with
  ``api_error_status=400`` and ``errors=["rate_limit_exceeded"]``
  is permanent, not retryable).
"""

from __future__ import annotations

import re

# Word boundaries on the HTTP-code arms only — they prevent "500" from
# matching inside "5000 tokens" or "4290 tokens" (the underlying char
# being a digit means there's no \b mid-token). The phrase arms don't
# use trailing \b because suffixes like ``rate_limit_exceeded`` contain
# only word chars after ``limit`` (no boundary present), and we still
# want those to match. The leading \b on phrase arms prevents
# ``xyzrate_limit`` from matching.
#
# Known residual: ``stack trace at runner.py:504`` will match \b504\b
# (``:`` is a non-word boundary and end-of-string is a \b). This is
# accepted noise — an unnecessary retry on a code-internal log is
# preferable to missing a real upstream 504, and stack traces rarely
# end up in the SDK-error string anyway.
_TRANSIENT_INDICATOR_RE = re.compile(
    r"\b(?:429|500|502|503|504)\b"
    r"|\brate[ _]?limit"
    r"|\boverloaded"
    r"|\bservice[ _]?unavailable"
    r"|\bgateway timeout"
    r"|\bbad gateway",
    re.IGNORECASE,
)


def is_transient_text(text: str) -> bool:
    """True if ``text`` mentions a transient HTTP code or phrase.

    Used as the message-text fallback when no typed status is available
    on an exception or SDK message.
    """
    return bool(_TRANSIENT_INDICATOR_RE.search(text))


def is_transient_status(status: object) -> bool:
    """True if a typed HTTP status indicates a transient failure.

    Accepts ``object`` so callers can pass through ``getattr(..., None)``
    results without a separate isinstance check at every call site.
    """
    return isinstance(status, int) and (status == 429 or status >= 500)


def classify(status: object, text: str) -> bool:
    """Typed-first transient classifier for a single (status, text) pair.

    Rule: when ``status`` is a known HTTP integer, that's authoritative
    — a non-transient typed status (400/401/404/etc.) returns False
    even if ``text`` happens to contain ``"rate_limit"`` or similar.
    Text matching is only consulted when ``status`` isn't an int (the
    SDK omitted the typed field). Mirrors the short-circuit semantics
    of ``_llm.py::_looks_transient_at_boundary`` so all four call
    sites stay aligned:

    - ``_llm.py::_looks_transient_at_boundary`` (walks an exception
      cause chain, calls this per frame).
    - ``runner.py::_is_rate_limit_system_message`` (one frame —
      ``data.error_status`` or ``data.api_error_status``, plus
      ``data.error`` text).
    - ``runner.py::_is_rate_limit_result`` (one frame —
      ``api_error_status`` plus ``errors`` payload).
    """
    if isinstance(status, int):
        return is_transient_status(status)
    return is_transient_text(text)
