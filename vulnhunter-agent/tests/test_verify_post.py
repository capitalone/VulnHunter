"""Unit tests for ``agent/verify_post.py``.

The state machine and HTTP behavior is exercised end-to-end against
a respx mock — no live GitHub. Tests cover the four verdict
trajectories (FIXED, NOT_FIXED, PARTIAL, INCONCLUSIVE) plus
INVALID_INPUT, body-tampering archival posting, the ``--no-reopen``
override, and the clone-request give-up path.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from agent._github_verify import GitHubVerifyError, IssueRef, make_client
from agent.verify_post import (
    PostResult,
    post_disposition,
    should_reopen,
)


# ---------- should_reopen (pure) --------------------------------------------


@pytest.mark.parametrize("verdict", ["NOT_FIXED", "PARTIAL", "INCONCLUSIVE"])
def test_should_reopen_for_non_fixed(verdict: str) -> None:
    assert should_reopen(verdict) is True


@pytest.mark.parametrize("verdict", ["FIXED", "INVALID_INPUT"])
def test_should_not_reopen_for_terminal(verdict: str) -> None:
    assert should_reopen(verdict) is False


def test_should_reopen_unknown_verdict() -> None:
    """Defensive: an unexpected verdict string is treated as "don't
    reopen." Avoids accidentally reopening on a schema-version drift."""
    assert should_reopen("SOMETHING_NEW") is False


# ---------- respx scaffolding ------------------------------------------------


HOST = "github.com"
OWNER = "org"
REPO = "repo"


def _comments_url(number: int) -> str:
    return f"https://api.github.com/repos/{OWNER}/{REPO}/issues/{number}/comments"


def _issue_url(number: int) -> str:
    return f"https://api.github.com/repos/{OWNER}/{REPO}/issues/{number}"


def _comment_response(comment_id: int = 1) -> dict:
    return {
        "id": comment_id,
        "html_url": f"https://github.com/{OWNER}/{REPO}/issues/42#issuecomment-{comment_id}",
        "body": "ignored",
    }


# ---------- post_disposition: FIXED ----------------------------------------


@pytest.mark.asyncio
async def test_post_disposition_fixed_posts_only_comment(
    respx_mock: respx.MockRouter,
) -> None:
    respx_mock.post(_comments_url(42)).mock(
        return_value=httpx.Response(201, json=_comment_response(101))
    )
    async with make_client("tok") as client:
        result = await post_disposition(
            client,
            HOST,
            IssueRef(owner=OWNER, repo=REPO, number=42),
            finding_id="VULN-001",
            verdict="FIXED",
            issue_comment_md="confirmed fixed",
            body_tampered=False,
            original_body="",
        )
    assert isinstance(result, PostResult)
    assert result.verdict == "FIXED"
    assert result.reopened is False
    assert result.archival_comment_url == ""
    # Exactly one POST to /comments (the verdict comment); no PATCH.
    assert len(respx_mock.calls) == 1


# ---------- post_disposition: NOT_FIXED → reopen ---------------------------


@pytest.mark.asyncio
async def test_post_disposition_not_fixed_reopens(
    respx_mock: respx.MockRouter,
) -> None:
    respx_mock.post(_comments_url(42)).mock(
        return_value=httpx.Response(201, json=_comment_response(102))
    )
    respx_mock.patch(_issue_url(42)).mock(
        return_value=httpx.Response(200, json={"state": "open"})
    )
    async with make_client("tok") as client:
        result = await post_disposition(
            client,
            HOST,
            IssueRef(owner=OWNER, repo=REPO, number=42),
            finding_id="VULN-001",
            verdict="NOT_FIXED",
            issue_comment_md="still vulnerable",
            body_tampered=False,
            original_body="",
        )
    assert result.verdict == "NOT_FIXED"
    assert result.reopened is True
    # 1 comment + 1 reopen patch.
    assert len(respx_mock.calls) == 2


# ---------- post_disposition: PARTIAL / INCONCLUSIVE → reopen --------------


@pytest.mark.asyncio
@pytest.mark.parametrize("verdict", ["PARTIAL", "INCONCLUSIVE"])
async def test_post_disposition_partial_and_inconclusive_reopen(
    respx_mock: respx.MockRouter, verdict: str
) -> None:
    respx_mock.post(_comments_url(42)).mock(
        return_value=httpx.Response(201, json=_comment_response())
    )
    respx_mock.patch(_issue_url(42)).mock(
        return_value=httpx.Response(200, json={"state": "open"})
    )
    async with make_client("tok") as client:
        result = await post_disposition(
            client,
            HOST,
            IssueRef(owner=OWNER, repo=REPO, number=42),
            finding_id="VULN-007",
            verdict=verdict,
            issue_comment_md="see above",
            body_tampered=False,
            original_body="",
        )
    assert result.reopened is True


# ---------- post_disposition: INVALID_INPUT leaves closed ------------------


@pytest.mark.asyncio
async def test_post_disposition_invalid_input_leaves_closed(
    respx_mock: respx.MockRouter,
) -> None:
    respx_mock.post(_comments_url(42)).mock(
        return_value=httpx.Response(201, json=_comment_response())
    )
    async with make_client("tok") as client:
        result = await post_disposition(
            client,
            HOST,
            IssueRef(owner=OWNER, repo=REPO, number=42),
            finding_id="VULN-999",
            verdict="INVALID_INPUT",
            issue_comment_md="ID not in report",
            body_tampered=False,
            original_body="",
        )
    assert result.reopened is False
    assert len(respx_mock.calls) == 1  # comment only, no PATCH


# ---------- body-tampering archival comment --------------------------------


@pytest.mark.asyncio
async def test_post_disposition_with_body_tampered_posts_archival(
    respx_mock: respx.MockRouter,
) -> None:
    captured_bodies: list[str] = []

    def capture(request: httpx.Request) -> httpx.Response:
        import json

        payload = json.loads(request.content)
        captured_bodies.append(payload["body"])
        return httpx.Response(201, json=_comment_response(len(captured_bodies)))

    respx_mock.post(_comments_url(42)).mock(side_effect=capture)
    async with make_client("tok") as client:
        result = await post_disposition(
            client,
            HOST,
            IssueRef(owner=OWNER, repo=REPO, number=42),
            finding_id="VULN-001",
            verdict="FIXED",
            issue_comment_md="confirmed",
            body_tampered=True,
            original_body=(
                "## Original SQL Injection finding\n\n"
                "Body content as it was originally posted by /vulnhunt."
            ),
        )
    # Two POSTs to /comments: the verdict, then the archival.
    assert len(captured_bodies) == 2
    # Updated for VULN-008: the verdict comment now carries a server-owned
    # attribution banner marking the narrative as developer-supplied; the
    # narrative itself is still included below it.
    assert "developer-supplied" in captured_bodies[0]
    assert "confirmed" in captured_bodies[0]
    assert "VulnHunter Fix-Verify — original issue context" in captured_bodies[1]
    assert "Original SQL Injection finding" in captured_bodies[1]
    assert result.archival_comment_url != ""


@pytest.mark.asyncio
async def test_post_disposition_no_archival_when_body_not_tampered(
    respx_mock: respx.MockRouter,
) -> None:
    respx_mock.post(_comments_url(42)).mock(
        return_value=httpx.Response(201, json=_comment_response())
    )
    async with make_client("tok") as client:
        result = await post_disposition(
            client,
            HOST,
            IssueRef(owner=OWNER, repo=REPO, number=42),
            finding_id="VULN-001",
            verdict="FIXED",
            issue_comment_md="confirmed",
            body_tampered=False,
            original_body="(would not be posted)",
        )
    assert result.archival_comment_url == ""
    assert len(respx_mock.calls) == 1


# ---------- --no-reopen override -------------------------------------------


@pytest.mark.asyncio
async def test_post_disposition_no_reopen_suppresses_reopen(
    respx_mock: respx.MockRouter,
) -> None:
    respx_mock.post(_comments_url(42)).mock(
        return_value=httpx.Response(201, json=_comment_response())
    )
    # No PATCH route registered — if the code tried to reopen, the
    # respx mock would raise ALL_MOCKED_ASSERTION.
    async with make_client("tok") as client:
        result = await post_disposition(
            client,
            HOST,
            IssueRef(owner=OWNER, repo=REPO, number=42),
            finding_id="VULN-001",
            verdict="NOT_FIXED",
            issue_comment_md="see above",
            body_tampered=False,
            original_body="",
            allow_reopen=False,
        )
    assert result.reopened is False


# ---------- empty issue_comment is refused ---------------------------------


@pytest.mark.asyncio
async def test_post_disposition_refuses_empty_comment() -> None:
    async with make_client("tok") as client:
        with pytest.raises(ValueError, match="empty"):
            await post_disposition(
                client,
                HOST,
                IssueRef(owner=OWNER, repo=REPO, number=42),
                finding_id="VULN-001",
                verdict="FIXED",
                issue_comment_md="   ",
                body_tampered=False,
                original_body="",
            )


# ---- partial-failure flags (verdict comment landed but a later step failed) ----


def _fast_sleep_monkeypatch(monkeypatch: pytest.MonkeyPatch) -> None:
    """The httpx retry layer sleeps 30s between retries by default.
    Make it instant so a 5xx failure path completes in milliseconds."""
    import asyncio as _asyncio

    async def fast_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(_asyncio, "sleep", fast_sleep)


@pytest.mark.asyncio
async def test_post_disposition_reopen_failure_sets_flag(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the verdict comment lands but the reopen PATCH fails,
    the returned PostResult has ``reopen_failed=True`` and the
    verdict_comment_url is still populated. The function does NOT
    raise — the orchestrator distinguishes this from a hard
    comment-post failure via the flag."""
    _fast_sleep_monkeypatch(monkeypatch)
    respx_mock.post(_comments_url(42)).mock(
        return_value=httpx.Response(201, json=_comment_response(7))
    )
    respx_mock.patch(_issue_url(42)).mock(
        return_value=httpx.Response(500, json={"message": "reopen boom"})
    )
    async with make_client("tok") as client:
        result = await post_disposition(
            client,
            HOST,
            IssueRef(owner=OWNER, repo=REPO, number=42),
            finding_id="VULN-001",
            verdict="NOT_FIXED",
            issue_comment_md="see above",
            body_tampered=False,
            original_body="",
        )
    assert result.verdict_comment_url != ""
    assert result.reopened is False
    assert result.reopen_failed is True
    assert result.archival_failed is False


@pytest.mark.asyncio
async def test_post_disposition_archival_failure_sets_flag(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the verdict comment lands but the archival comment fails,
    archival_failed is True and the verdict_comment_url is still
    populated. No reopen is attempted on a FIXED verdict."""
    _fast_sleep_monkeypatch(monkeypatch)

    call_count = {"n": 0}

    def post_handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        if call_count["n"] == 1:
            # Verdict comment lands.
            return httpx.Response(201, json=_comment_response(call_count["n"]))
        # Archival comment fails.
        return httpx.Response(500, json={"message": "archival boom"})

    respx_mock.post(_comments_url(42)).mock(side_effect=post_handler)
    async with make_client("tok") as client:
        result = await post_disposition(
            client,
            HOST,
            IssueRef(owner=OWNER, repo=REPO, number=42),
            finding_id="VULN-001",
            verdict="FIXED",
            issue_comment_md="confirmed",
            body_tampered=True,
            original_body="ORIGINAL CONTENT",
        )
    assert result.verdict_comment_url != ""
    assert result.archival_comment_url == ""
    assert result.archival_failed is True
    assert result.reopen_failed is False


@pytest.mark.asyncio
async def test_post_disposition_archival_and_reopen_both_fail(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    """body_tampered + non-FIXED + both downstream steps fail. The
    verdict comment still landed; both partial-failure flags are
    set; the finding should be surfaced once in the orchestrator's
    partial_failures list (not in the hard-failed list)."""
    _fast_sleep_monkeypatch(monkeypatch)

    call_count = {"n": 0}

    def post_handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        if call_count["n"] == 1:
            return httpx.Response(201, json=_comment_response(call_count["n"]))
        return httpx.Response(500, json={"message": "archival boom"})

    respx_mock.post(_comments_url(42)).mock(side_effect=post_handler)
    respx_mock.patch(_issue_url(42)).mock(
        return_value=httpx.Response(500, json={"message": "reopen boom"})
    )
    async with make_client("tok") as client:
        result = await post_disposition(
            client,
            HOST,
            IssueRef(owner=OWNER, repo=REPO, number=42),
            finding_id="VULN-001",
            verdict="NOT_FIXED",
            issue_comment_md="see above",
            body_tampered=True,
            original_body="ORIGINAL CONTENT",
        )
    assert result.verdict_comment_url != ""
    assert result.archival_failed is True
    assert result.reopen_failed is True
    assert result.reopened is False


@pytest.mark.asyncio
async def test_post_disposition_verdict_comment_failure_still_raises(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the verdict comment itself fails, post_disposition raises
    GitHubVerifyError — the orchestrator marks the finding
    POST_FAILED. This is distinct from the partial-failure flags
    above; here there's no audit trail to attach them to."""
    _fast_sleep_monkeypatch(monkeypatch)
    respx_mock.post(_comments_url(42)).mock(
        return_value=httpx.Response(500, json={"message": "comment boom"})
    )
    async with make_client("tok") as client:
        with pytest.raises(GitHubVerifyError):
            await post_disposition(
                client,
                HOST,
                IssueRef(owner=OWNER, repo=REPO, number=42),
                finding_id="VULN-001",
                verdict="FIXED",
                issue_comment_md="confirmed",
                body_tampered=False,
                original_body="",
            )
