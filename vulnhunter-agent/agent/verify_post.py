"""Post verify outcomes back to the source GitHub issues.

Two responsibilities, owned by this module so the orchestrator's
top-level flow stays linear:

1. **Per-verdict state machine** (design §12). For each disposition
   entry, post the verifier's ``issue_comment`` verbatim and reopen
   the issue when the verdict is ``NOT_FIXED`` / ``PARTIAL`` /
   ``INCONCLUSIVE``. ``FIXED`` and ``INVALID_INPUT`` leave the issue
   in its current (closed) state.

2. **Body-tampering archival comment** (design §12.1). When the
   agent detected that the issue body had been edited since
   /vulnhunt originally posted, it reconstructed the original via
   ``_body_reconstruct``. After the verdict comment is posted, this
   module appends a second comment archiving the original body
   under a clarifying header, so audit readers can see exactly
   which body the verifier worked from.

The module deliberately does **not** apply labels — design §12
removed the label palette. The comment is the audit trail; the
issue state is the gross outcome.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

from ._github_verify import GitHubVerifyError, IssueRef, post_comment, reopen_issue

logger = logging.getLogger(__name__)


# Verdicts that trigger a reopen. Order matches design §12; FIXED
# and INVALID_INPUT are intentionally absent.
_REOPEN_VERDICTS: frozenset[str] = frozenset(
    {"NOT_FIXED", "PARTIAL", "INCONCLUSIVE"}
)


_ARCHIVAL_HEADER = (
    "## VulnHunter Fix-Verify — original issue context\n\n"
    "The issue body has been edited since `/vulnhunt` originally posted "
    "this finding. The verification above was performed against the "
    "**original** body (reconstructed from GitHub's edit history), not "
    "the current text. The original is reproduced below for reference "
    "and audit.\n\n"
    "---\n\n"
)


def _render_verdict_comment(
    *, finding_id: str, verdict: str, issue_comment_md: str
) -> str:
    """Wrap the verifier's narrative with a server-owned attribution banner
    (VULN-008, CWE-290).

    The verdict comment is posted under the agent's GitHub identity. The
    narrative below the banner is derived from a developer-supplied fix story
    (user-influenceable input), so the banner marks it as such and states the
    verdict is evidence-based — a reader (or a downstream skill) must not treat
    the prose as an authoritative agent assertion. The banner fields
    (``finding_id``, ``verdict``) are server-owned and bounded; the narrative
    is preserved verbatim below it, clearly demarcated.
    """
    # Residual risk (VULN-008, CWE-290): the banner attributes and frames the
    # narrative, but an attacker can still steer the LLM verdict enum itself
    # (and thus a reopen). Independent evidence verification lives in the
    # /vulnhunt-fix-verify skill, not here.
    banner = (
        f"> **VulnHunter Fix-Verify — automated result for {finding_id}: "
        f"{verdict}.** The section below is derived from the "
        f"**developer-supplied** fix narrative and is evaluated as user "
        f"input, not an authoritative agent assertion; the verdict rests on "
        f"evidence verified against the code, not on the narrative's claims."
    )
    return f"{banner}\n\n{issue_comment_md}"


@dataclass(frozen=True)
class PostResult:
    """What got posted to one issue for one disposition.

    A ``PostResult`` is returned even when the comment posted but a
    subsequent step (archival comment, reopen) failed. The
    ``reopen_failed`` and ``archival_failed`` flags distinguish those
    partial-success states so the orchestrator's summary can label
    them accurately rather than calling the whole finding
    ``POST_FAILED``. A run with any of these flags set still exits 1
    — the issue is in an inconsistent state — but the comment did
    land and is visible to the developer.
    """

    finding_id: str
    issue_number: int
    verdict: str
    verdict_comment_url: str
    archival_comment_url: str = ""  # populated when body was tampered
    reopened: bool = False
    reopen_failed: bool = False
    archival_failed: bool = False


async def post_disposition(
    client: httpx.AsyncClient,
    host: str,
    ref: IssueRef,
    *,
    finding_id: str,
    verdict: str,
    issue_comment_md: str,
    body_tampered: bool,
    original_body: str,
    allow_reopen: bool = True,
) -> PostResult:
    """Post one disposition's outcome to its GitHub issue.

    The sequence is fixed: verdict comment first, then (if
    ``body_tampered``) the archival comment, then (if applicable) the
    reopen. The verdict-comment post is the only step that raises on
    failure — without that comment landing there's no audit trail to
    distinguish a partial success from a total failure, so the
    orchestrator needs to know the verdict didn't land at all.

    Failures of the archival comment or the reopen step are caught
    here and surfaced via ``archival_failed`` / ``reopen_failed``
    flags on the returned ``PostResult``. The orchestrator treats
    those flags as partial-success indicators: the verdict comment
    is on the issue, but the issue's state or audit trail is
    incomplete, so the run still exits 1.

    ``allow_reopen=False`` suppresses the reopen step (``--no-reopen``
    on the CLI). The comment is still posted in both cases, and
    ``reopen_failed`` stays False.
    """
    if not issue_comment_md.strip():
        raise ValueError(
            f"issue_comment for {finding_id} is empty — refusing to post"
        )

    # The verdict comment is the audit trail. If it doesn't land,
    # subsequent steps would have no useful state to attach to —
    # propagate the error and let the orchestrator mark the whole
    # finding POST_FAILED. The narrative is wrapped with a server-owned
    # attribution banner (VULN-008) so it isn't read as an authoritative
    # agent assertion.
    verdict_url = await post_comment(
        client,
        host,
        ref,
        _render_verdict_comment(
            finding_id=finding_id, verdict=verdict, issue_comment_md=issue_comment_md
        ),
    )
    logger.info(
        "Posted verdict comment for %s on issue #%d (%s)",
        finding_id,
        ref.number,
        verdict,
    )

    archival_url = ""
    archival_failed = False
    if body_tampered:
        archival_body = _ARCHIVAL_HEADER + original_body
        try:
            archival_url = await post_comment(client, host, ref, archival_body)
            logger.info(
                "Posted body-tampering archival comment for %s on issue #%d",
                finding_id,
                ref.number,
            )
        except GitHubVerifyError as exc:
            archival_failed = True
            logger.error(
                "Verdict comment for %s landed on issue #%d but the "
                "body-tampering archival comment failed: %s. The "
                "reconstructed original body is still recorded in "
                "the run's scratch dir.",
                finding_id,
                ref.number,
                exc,
            )

    reopened = False
    reopen_failed = False
    if allow_reopen and verdict in _REOPEN_VERDICTS:
        try:
            await reopen_issue(client, host, ref)
            reopened = True
            logger.info(
                "Reopened issue #%d after %s verdict for %s",
                ref.number,
                verdict,
                finding_id,
            )
        except GitHubVerifyError as exc:
            reopen_failed = True
            logger.error(
                "Verdict comment for %s landed on issue #%d (%s) but "
                "reopen failed: %s. The issue remains in its prior "
                "state; the comment is the audit trail.",
                finding_id,
                ref.number,
                verdict,
                exc,
            )

    return PostResult(
        finding_id=finding_id,
        issue_number=ref.number,
        verdict=verdict,
        verdict_comment_url=verdict_url,
        archival_comment_url=archival_url,
        reopened=reopened,
        reopen_failed=reopen_failed,
        archival_failed=archival_failed,
    )


def should_reopen(verdict: str) -> bool:
    """True iff ``verdict`` triggers an issue reopen per design §12.

    Exposed so the orchestrator can compute its summary line without
    re-implementing the rule.
    """
    return verdict in _REOPEN_VERDICTS
