"""Pre-flight extraction of cross-repo references from developer comments.

Cross-repo references in developer comments (URLs, ``../`` paths,
named repo identifiers) point at source code that lives outside the
target checkout. To verify a fix that's spread across two repos, the
verifier needs access to both — so the orchestrator runs this Haiku
pre-flight before invoking the skill, scans every comment for
cross-repo references, resolves each via ``resolve_repo_hint``, and
pre-clones whatever it can.

This is the *only* path the agent uses to acquire additional repos.
The skill used to emit a ``verify_clone_request.json`` stop-signal
when it spotted a cross-repo reference during phase 0, but that
mechanism was retired once the pre-flight existed — the skill now
classifies any unresolved cross-repo reference as
``rejected_unverifiable`` (R2) and continues.

This module calls the scan-session model (``config.anthropic.model``) —
the same model the scan stage runs — to extract cross-repo references.
Unlike the issues stage it does NOT use the haiku->sonnet fallback tiers
and does not escalate on failure; a failed pre-flight degrades to
skill-side R2 detection. We feed the model
the assembled per-comment text and ask for a strict-JSON list of
cross-repo references — same shape ``_process_clone_request`` already
consumes. The orchestrator then resolves each (via the existing
``resolve_repo_hint`` + alias logic), clones what it can, and
records the rest as ignored hints — all before the skill is
invoked. The skill sees a fully-resolved checkout on its single
pass; R2 stays in place as a defense-in-depth net for anything
Haiku misses.

The prompt is deliberately narrow: only **unambiguous** cross-repo
references count (explicit URLs, ``../<name>`` paths, quoted "see
the X repo" phrasings with a hyphenated identifier ≥4 chars).
Fuzzy hints ("our shared library", "the framework") are left for
the skill's R2 to decide on. This minimizes false positives without
losing the common case the design was built around.
"""

from __future__ import annotations

import logging
from typing import Any

from . import _llm
from .auth import TokenProvider
from .config import AgentConfig

logger = logging.getLogger(__name__)

# Upper bound on cross-repo references coerced from a single pre-flight
# extraction. The response is derived by an LLM from attacker-authored
# issue/comment text and is otherwise unbounded; capping here keeps the
# reference list feeding the downstream clone loop bounded even before the
# clone-attempt cap in ``verify._process_clone_request`` applies.
MAX_EXTRACTED_SOURCES = 10


_EXTRACTOR_SYSTEM = """You extract cross-repository references from a \
developer-comments markdown file into strict JSON. You return ONLY a JSON \
object — no prose, no code fences, no commentary.

CONTEXT: A verifier is about to check whether a security finding was \
correctly fixed. The comments file (below in the user message) contains \
developer prose justifying the fix. If a comment references code that lives \
OUTSIDE the target repository the verifier was given, that external source \
must be cloned before verification can proceed.

YOUR JOB: Identify every UNAMBIGUOUS cross-repository reference in the \
comments. Be conservative — false positives slow the run, but false \
negatives are caught by a downstream safety net.

FLAG these patterns:

1. Explicit git repository URLs:
   - https://github.com/<owner>/<repo>[...]
   - https://<host>/<owner>/<repo>[.git]
   - git@<host>:<owner>/<repo>[.git]
   - ssh://...
2. Relative paths that clearly point outside the target repo:
   - ../<repo-name>/...
   - ../<repo-name> (bare)
3. Named references with a hyphenated or underscore-separated identifier ≥4 \
characters:
   - "see the platform-validators repo"
   - "implemented in our shared-libs project"
   - "in our other repo: foo/bar-service"

DO NOT FLAG:

- Plain file paths inside the current repo (anything without `../` is local).
- Package or library names (e.g. "react", "boto3", "httpx") — those are \
dependencies, not source repositories the verifier needs to read.
- Generic mentions without a specific identifier ("the framework", "our \
microservice", "the upstream service").
- The comments file's own structural markers (`<!-- ... -->` HTML comments).

Schema (always emit `requested_sources` even when empty):

{
  "requested_sources": [
    {
      "claim_excerpt": "verbatim snippet of the comment line, ≤200 chars",
      "repo_hint": "URL or identifier from the patterns above, copied verbatim",
      "reason": "one-sentence reason this source needs to be cloned"
    }
  ]
}

Return {"requested_sources": []} when no qualifying references appear.
Do not deduplicate — each distinct mention is one entry. The downstream \
deduplicates by ``repo_hint``.
"""


async def extract_cross_repo_references(
    comments_text: str,
    *,
    config: AgentConfig,
    token_manager: TokenProvider,
    cost_tracker: "_llm.CostStats | None" = None,
) -> list[dict[str, str]]:
    """Run Haiku (Sonnet fallback) over ``comments_text`` and return the
    list of cross-repo references.

    Each entry of the returned list matches the
    ``requested_sources[]`` shape (``claim_excerpt``,
    ``repo_hint``, ``reason``) so the caller can hand it straight to
    ``_process_clone_request`` without any further shape massaging.

    On any LLM failure (transport, JSON parse, schema-shape mismatch)
    the function logs a warning and returns ``[]``. That makes the
    pre-flight a *best-effort* optimization — the skill's R2 still
    catches anything we missed in its single pass, and we never abort
    a verify run just because the pre-flight model was unavailable.
    """
    if not comments_text.strip():
        return []
    user_msg = (
        "Extract every UNAMBIGUOUS cross-repository reference from the "
        "developer comments below. Return strict JSON matching the schema "
        "in the system prompt. Comments begin after the marker.\n\n"
        "----- BEGIN COMMENTS -----\n"
        f"{comments_text}\n"
        "----- END COMMENTS -----\n"
    )
    try:
        # Verify uses the same model as the scan (config.anthropic.model), not
        # the issues-stage haiku->sonnet tiers, and does NOT fall back: this is
        # a pre-flight optimization, so on any LLM failure we degrade to
        # skill-side R2 detection rather than escalating to another model.
        parsed = await _llm.call_json(
            model=config.anthropic.model,
            system=_EXTRACTOR_SYSTEM,
            user=user_msg,
            config=config,
            token_manager=token_manager,
            cost_tracker=cost_tracker,
            stage="verify-refs",
        )
    except _llm.LLMError as exc:
        logger.warning(
            "Pre-flight cross-repo extraction failed (%s); falling back "
            "to skill-side R2 detection.",
            exc,
        )
        return []
    return _coerce_sources(parsed)


def _coerce_sources(parsed: Any) -> list[dict[str, str]]:
    """Validate the model's response and coerce it to the wire shape.

    Permissive on shape mismatches — drop bad entries silently and
    return whatever is salvageable. The skill's R2 still runs over
    the same comments file, so a malformed pre-flight result just
    means we miss some entries here and the skill catches them in
    iteration 1 instead of zero.
    """
    if not isinstance(parsed, dict):
        return []
    raw = parsed.get("requested_sources")
    if not isinstance(raw, list):
        return []
    out: list[dict[str, str]] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        hint = str(entry.get("repo_hint") or "").strip()
        if not hint:
            continue
        excerpt = str(entry.get("claim_excerpt") or "")[:200]
        reason = str(entry.get("reason") or "").strip()
        if not reason:
            reason = (
                "Pre-flight extractor flagged a cross-repo reference; "
                "verifier cannot evaluate the claim without local access."
            )
        out.append(
            {
                "claim_excerpt": excerpt,
                "repo_hint": hint,
                "reason": reason,
            }
        )
    if len(out) > MAX_EXTRACTED_SOURCES:
        logger.warning(
            "Pre-flight extractor returned %d cross-repo reference(s); "
            "truncating to %d to bound downstream clone work.",
            len(out),
            MAX_EXTRACTED_SOURCES,
        )
        out = out[:MAX_EXTRACTED_SOURCES]
    return out
