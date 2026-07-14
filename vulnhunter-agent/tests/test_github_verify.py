"""Unit tests for ``agent/_github_verify.py``.

Pure-function parts (URL parsers, header builders) are tested
directly. The HTTP surfaces (REST + GraphQL) are tested against
respx mocks — same pattern the existing ``agent/issues.py`` tests
use.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from agent._github_verify import (
    GitHubVerifyError,
    IssueComment,
    IssueEvent,
    IssueRef,
    UserContentEdit,
    get_issue,
    issue_host,
    list_comments,
    list_events,
    list_user_content_edits,
    make_client,
    parse_issue_url,
    post_comment,
    reopen_issue,
)


# ---------- parse_issue_url -------------------------------------------------


def test_parse_issue_url_web_ui() -> None:
    ref = parse_issue_url("https://github.com/owner/repo/issues/42")
    assert ref == IssueRef(owner="owner", repo="repo", number=42)


def test_parse_issue_url_api_form() -> None:
    """The API URL form drops through the `repos` prefix-strip."""
    ref = parse_issue_url("https://api.github.com/repos/owner/repo/issues/99")
    assert ref == IssueRef(owner="owner", repo="repo", number=99)


def test_parse_issue_url_ghe_api_form() -> None:
    """GitHub Enterprise API URLs include a versioned ``/api/vN/`` prefix
    that ``parse_issue_url`` must strip before locating ``repos``."""
    ref = parse_issue_url(
        "https://ghe.example.com/api/v3/repos/org/svc/issues/7"
    )
    assert ref == IssueRef(owner="org", repo="svc", number=7)


def test_parse_issue_url_ghe_api_form_v4() -> None:
    """Future GHE API versions use ``/api/v4/`` or similar — the
    parser accepts any ``vN`` where N is digits."""
    ref = parse_issue_url(
        "https://ghe.example.com/api/v4/repos/org/svc/issues/12"
    )
    assert ref == IssueRef(owner="org", repo="svc", number=12)


def test_parse_issue_url_rejects_non_versioned_api_prefix() -> None:
    """``/api/version/repos/...`` (non-digit suffix) is not a valid
    GHE API URL and must not be silently accepted by the parser."""
    with pytest.raises(GitHubVerifyError):
        parse_issue_url(
            "https://ghe.example.com/api/version/repos/org/svc/issues/7"
        )


def test_parse_issue_url_ghec_host() -> None:
    ref = parse_issue_url(
        "https://github.cloud.example.com/org/svc/issues/7"
    )
    assert ref == IssueRef(owner="org", repo="svc", number=7)


def test_parse_issue_url_accepts_pr_web_ui_alias() -> None:
    """``/pull/<n>`` is the web-UI URL for a PR. PRs and issues share a
    number space, and the REST endpoint ``/repos/.../issues/<n>``
    returns either kind of object. ``kind`` is tagged ``"pull"`` so
    the downstream GraphQL fetch picks the right resolver
    (``repository.pullRequest`` vs ``repository.issue`` — GitHub
    doesn't fall back between them)."""
    ref = parse_issue_url("https://github.com/o/r/pull/9")
    assert ref == IssueRef(owner="o", repo="r", number=9, kind="pull")


def test_parse_issue_url_accepts_pr_api_alias() -> None:
    """``/pulls/<n>`` is the REST API segment for PRs."""
    ref = parse_issue_url("https://api.github.com/repos/o/r/pulls/9")
    assert ref == IssueRef(owner="o", repo="r", number=9, kind="pull")


def test_parse_issue_url_accepts_pr_ghe_api_alias() -> None:
    ref = parse_issue_url(
        "https://ghe.example.com/api/v3/repos/o/r/pulls/9"
    )
    assert ref == IssueRef(owner="o", repo="r", number=9, kind="pull")


def test_parse_issue_url_issue_kind_defaults() -> None:
    """The default kind is ``"issue"`` so existing call sites that
    construct IssueRef directly (notably the test fixtures) don't
    need to be updated."""
    ref = parse_issue_url("https://github.com/o/r/issues/42")
    assert ref.kind == "issue"


@pytest.mark.parametrize(
    "url",
    [
        "ftp://github.com/o/r/issues/42",          # bad scheme
        "https://github.com/o/r",                    # no /issues/
        "https://github.com/o",                       # too few segments
        "https://github.com/o/r/issues/",            # missing number
        "https://github.com/o/r/issues/abc",         # non-numeric
        "https://github.com/o/r/issues/-1",          # negative
    ],
)
def test_parse_issue_url_rejects_malformed(url: str) -> None:
    with pytest.raises(GitHubVerifyError):
        parse_issue_url(url)


def test_issue_host_extracts_bare_host() -> None:
    assert issue_host("https://github.com/o/r/issues/1") == "github.com"
    assert (
        issue_host("https://github.cloud.example.com/o/r/issues/1")
        == "github.cloud.example.com"
    )


def test_issue_host_rejects_empty() -> None:
    with pytest.raises(GitHubVerifyError):
        issue_host("not-a-url")


# ---------- REST surface (mocked) -------------------------------------------


def _issue_payload(number: int = 42, state: str = "closed", body: str = "") -> dict:
    return {
        "number": number,
        "state": state,
        "state_reason": "completed",
        "title": "title",
        "body": body,
        "closed_at": "2026-06-27T14:30:00Z",
        "html_url": f"https://github.com/o/r/issues/{number}",
    }


@pytest.mark.asyncio
async def test_get_issue_parses_response(respx_mock: respx.MockRouter) -> None:
    respx_mock.get("https://api.github.com/repos/o/r/issues/42").mock(
        return_value=httpx.Response(200, json=_issue_payload(body="hello"))
    )
    async with make_client("tok") as client:
        issue = await get_issue(
            client, "github.com", IssueRef("o", "r", 42)
        )
    assert issue.number == 42
    assert issue.state == "closed"
    assert issue.body == "hello"
    assert issue.html_url == "https://github.com/o/r/issues/42"


@pytest.mark.asyncio
async def test_get_issue_retries_on_503(
    respx_mock: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One retry on 5xx. Patch the backoff sleep so the test runs fast."""

    async def fast_sleep(_seconds: float) -> None:
        return None

    # Monkeypatch the module attribute the code reads (``asyncio.sleep``
    # via ``import asyncio``). Restoration happens automatically at
    # fixture teardown.
    import asyncio as _asyncio
    monkeypatch.setattr(_asyncio, "sleep", fast_sleep)

    route = respx_mock.get(
        "https://api.github.com/repos/o/r/issues/42"
    ).mock(
        side_effect=[
            httpx.Response(503, json={"message": "rate"}),
            httpx.Response(200, json=_issue_payload()),
        ]
    )
    async with make_client("tok") as client:
        issue = await get_issue(client, "github.com", IssueRef("o", "r", 42))
    assert issue.number == 42
    assert route.call_count == 2


@pytest.mark.asyncio
async def test_get_issue_404_does_not_retry(respx_mock: respx.MockRouter) -> None:
    """Non-retryable status raises immediately, no second attempt."""
    route = respx_mock.get("https://api.github.com/repos/o/r/issues/42").mock(
        return_value=httpx.Response(404, json={"message": "not found"})
    )
    async with make_client("tok") as client:
        with pytest.raises(GitHubVerifyError, match="404"):
            await get_issue(client, "github.com", IssueRef("o", "r", 42))
    assert route.call_count == 1


@pytest.mark.asyncio
async def test_list_comments_paginates(respx_mock: respx.MockRouter) -> None:
    """Follows the Link: rel=\"next\" header across pages."""
    page1 = [
        {
            "id": 1,
            "user": {"login": "alice"},
            "created_at": "2026-06-27T14:30:00Z",
            "body": "first",
        }
    ]
    page2 = [
        {
            "id": 2,
            "user": {"login": "bob"},
            "created_at": "2026-06-27T15:00:00Z",
            "body": "second",
        }
    ]
    next_url = "https://api.github.com/repos/o/r/issues/42/comments?page=2"
    # Use a side_effect that returns different responses on successive
    # calls. Both requests share the same base URL (the page-2 fetch
    # follows the Link header from page 1), so a single route is the
    # cleanest way to express the pagination dance.
    respx_mock.get(
        url__startswith="https://api.github.com/repos/o/r/issues/42/comments"
    ).mock(
        side_effect=[
            httpx.Response(
                200,
                json=page1,
                headers={"Link": f'<{next_url}>; rel="next"'},
            ),
            httpx.Response(200, json=page2),
        ]
    )
    async with make_client("tok") as client:
        comments = await list_comments(client, "github.com", IssueRef("o", "r", 42))
    assert [c.body for c in comments] == ["first", "second"]


@pytest.mark.asyncio
async def test_list_events_includes_close_event(respx_mock: respx.MockRouter) -> None:
    payload = [
        {
            "event": "closed",
            "actor": {"login": "alice"},
            "created_at": "2026-06-27T14:30:00Z",
            "commit_id": "abc1234",
        },
        {
            "event": "reopened",
            "actor": {"login": "bob"},
            "created_at": "2026-06-27T15:00:00Z",
            "commit_id": None,
        },
    ]
    respx_mock.get(
        "https://api.github.com/repos/o/r/issues/42/events"
    ).mock(return_value=httpx.Response(200, json=payload))
    async with make_client("tok") as client:
        events = await list_events(client, "github.com", IssueRef("o", "r", 42))
    assert len(events) == 2
    assert events[0].event == "closed"
    assert events[0].commit_id == "abc1234"
    assert events[1].commit_id == ""  # null → ""


# ---------- GraphQL: userContentEdits ---------------------------------------


@pytest.mark.asyncio
async def test_list_user_content_edits_empty(respx_mock: respx.MockRouter) -> None:
    """An issue with no edits returns an empty list."""
    respx_mock.post("https://api.github.com/graphql").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "repository": {
                        "issue": {
                            "userContentEdits": {"nodes": []}
                        }
                    }
                }
            },
        )
    )
    async with make_client("tok") as client:
        edits = await list_user_content_edits(
            client, "github.com", IssueRef("o", "r", 42)
        )
    assert edits == []


@pytest.mark.asyncio
async def test_list_user_content_edits_parses_nodes(
    respx_mock: respx.MockRouter,
) -> None:
    respx_mock.post("https://api.github.com/graphql").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "repository": {
                        "issue": {
                            "userContentEdits": {
                                "nodes": [
                                    {
                                        "editedAt": "2026-06-27T15:00:00Z",
                                        "editor": {"login": "alice"},
                                        "diff": "@@ -1 +1 @@\n-old\n+new\n",
                                    },
                                    {
                                        "editedAt": "2026-06-27T15:01:00Z",
                                        "editor": None,
                                        "diff": "@@ -1 +1 @@\n-a\n+b\n",
                                    },
                                ]
                            }
                        }
                    }
                }
            },
        )
    )
    async with make_client("tok") as client:
        edits = await list_user_content_edits(
            client, "github.com", IssueRef("o", "r", 42)
        )
    assert len(edits) == 2
    assert edits[0].editor == "alice"
    assert edits[1].editor == ""  # null actor → empty string


@pytest.mark.asyncio
async def test_list_user_content_edits_skips_null_diff(
    respx_mock: respx.MockRouter,
) -> None:
    """Metadata-only edits return ``null`` for the diff field; the
    function silently drops those (they're not body edits)."""
    respx_mock.post("https://api.github.com/graphql").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "repository": {
                        "issue": {
                            "userContentEdits": {
                                "nodes": [
                                    {
                                        "editedAt": "2026-06-27T15:00:00Z",
                                        "editor": {"login": "alice"},
                                        "diff": None,
                                    },
                                    {
                                        "editedAt": "2026-06-27T15:01:00Z",
                                        "editor": {"login": "alice"},
                                        "diff": "@@ -1 +1 @@\n-x\n+y\n",
                                    },
                                ]
                            }
                        }
                    }
                }
            },
        )
    )
    async with make_client("tok") as client:
        edits = await list_user_content_edits(
            client, "github.com", IssueRef("o", "r", 42)
        )
    assert len(edits) == 1
    assert edits[0].diff.startswith("@@ -1 +1 @@")


@pytest.mark.asyncio
async def test_list_user_content_edits_errors_response(
    respx_mock: respx.MockRouter,
) -> None:
    respx_mock.post("https://api.github.com/graphql").mock(
        return_value=httpx.Response(
            200,
            json={"errors": [{"message": "permission denied"}]},
        )
    )
    async with make_client("tok") as client:
        with pytest.raises(GitHubVerifyError, match="permission denied"):
            await list_user_content_edits(
                client, "github.com", IssueRef("o", "r", 42)
            )


@pytest.mark.asyncio
async def test_list_user_content_edits_uses_pull_request_resolver_for_pr_ref(
    respx_mock: respx.MockRouter,
) -> None:
    """When the URL was a /pull/ alias (``ref.kind == "pull"``), the
    GraphQL query must select ``repository.pullRequest`` rather than
    ``repository.issue``. The two are distinct resolvers on GitHub
    with no fallback between them, so dispatching on kind is what
    keeps PR-aliased verify runs from hitting NOT_FOUND."""
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "data": {
                    "repository": {
                        "pullRequest": {
                            "userContentEdits": {"nodes": []}
                        }
                    }
                }
            },
        )

    respx_mock.post("https://api.github.com/graphql").mock(side_effect=handler)

    async with make_client("tok") as client:
        edits = await list_user_content_edits(
            client,
            "github.com",
            IssueRef(owner="o", repo="r", number=7, kind="pull"),
        )
    assert edits == []
    # Confirm we sent the pullRequest variant of the query.
    assert "pullRequest(number:" in captured["body"]["query"]
    assert "issue(number:" not in captured["body"]["query"]


@pytest.mark.asyncio
async def test_list_user_content_edits_uses_issue_resolver_for_issue_ref(
    respx_mock: respx.MockRouter,
) -> None:
    """Default ``kind == "issue"`` continues to select
    ``repository.issue`` — verified by inspecting the outgoing query
    so a future refactor that drops the dispatch is caught."""
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "data": {
                    "repository": {
                        "issue": {
                            "userContentEdits": {"nodes": []}
                        }
                    }
                }
            },
        )

    respx_mock.post("https://api.github.com/graphql").mock(side_effect=handler)

    async with make_client("tok") as client:
        await list_user_content_edits(
            client, "github.com", IssueRef("o", "r", 42)
        )
    assert "issue(number:" in captured["body"]["query"]
    assert "pullRequest(number:" not in captured["body"]["query"]


# ---------- mutations -------------------------------------------------------


@pytest.mark.asyncio
async def test_post_comment_returns_html_url(respx_mock: respx.MockRouter) -> None:
    respx_mock.post(
        "https://api.github.com/repos/o/r/issues/42/comments"
    ).mock(
        return_value=httpx.Response(
            201,
            json={
                "id": 100,
                "html_url": "https://github.com/o/r/issues/42#issuecomment-100",
                "body": "body content",
            },
        )
    )
    async with make_client("tok") as client:
        url = await post_comment(
            client, "github.com", IssueRef("o", "r", 42), "body content"
        )
    assert "issuecomment-100" in url


@pytest.mark.asyncio
async def test_reopen_issue_patches_state(respx_mock: respx.MockRouter) -> None:
    captured: dict = {}

    def capture(request: httpx.Request) -> httpx.Response:
        import json

        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"state": "open", "state_reason": "reopened"})

    respx_mock.patch(
        "https://api.github.com/repos/o/r/issues/42"
    ).mock(side_effect=capture)
    async with make_client("tok") as client:
        await reopen_issue(client, "github.com", IssueRef("o", "r", 42))
    assert captured["body"] == {
        "state": "open",
        "state_reason": "reopened",
    }


# ---------- GHE host routing -----------------------------------------------


@pytest.mark.asyncio
async def test_get_issue_uses_ghe_api_base(respx_mock: respx.MockRouter) -> None:
    """Non-github.com hosts hit /api/v3 instead of api.github.com."""
    respx_mock.get(
        "https://ghe.example.com/api/v3/repos/o/r/issues/42"
    ).mock(return_value=httpx.Response(200, json=_issue_payload()))
    async with make_client("tok") as client:
        issue = await get_issue(
            client, "ghe.example.com", IssueRef("o", "r", 42)
        )
    assert issue.number == 42
