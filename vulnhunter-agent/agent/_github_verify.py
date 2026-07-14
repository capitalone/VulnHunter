"""GitHub REST + GraphQL surface used by ``--mode=verify``.

The existing ``agent/issues.py`` covers issue creation and label
ensure. Verify needs orthogonal operations: read one issue, read its
edit history, list comments and events, post a new comment, reopen.
This module owns those calls so ``verify_post.py`` and
``verify_extract.py`` can both depend on it.

Shared with ``issues.py``:

- ``_github_headers(token)`` builds the same Authorization /
  X-GitHub-Api-Version headers (re-implemented privately here to
  keep the modules decoupled — the function is two lines).
- The retry pattern: one retry on 429/5xx with a fixed backoff.

GraphQL endpoint convention: ``<api_base>/graphql`` for github.com,
``<api_base>/graphql`` for GHE (where api_base is the v3 root).
Same Bearer token.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from ._github import api_base

logger = logging.getLogger(__name__)

# Resource-consumption bounds for the verify path (CWE-400). An attacker who
# floods an issue with comments/events/edits must not be able to make the agent
# fetch and accumulate an unbounded amount of data. These are conservative
# defaults; callers may override from config.verify.
_MAX_COMMENT_PAGES = 20
_MAX_TIMELINE_BYTES = 5_000_000  # cumulative comment-body budget (~5 MB)
_MAX_EVENT_PAGES = 20
_MAX_EDIT_DIFF_BYTES = 200_000  # per-edit diff cap (~200 KB)
_MAX_EDIT_TOTAL_BYTES = 5_000_000  # cumulative edit-history budget (~5 MB)


# Same convention as issues.py — one retry on 429/5xx, fail fast otherwise.
_RETRY_BACKOFF_SECONDS = 30


class GitHubVerifyError(RuntimeError):
    """Raised when a GitHub call needed by the verify path fails."""


@dataclass(frozen=True)
class IssueRef:
    """Owner + repo name + issue-or-PR number, extracted from a URL.

    ``kind`` records whether the source URL used the ``/issues/`` or
    ``/pull(s)/`` path segment. The REST endpoint
    ``/repos/<owner>/<repo>/issues/<n>`` returns either kind of object
    interchangeably, so most call sites can ignore ``kind``. The
    distinction matters for the GraphQL ``userContentEdits`` fetch —
    GraphQL's ``repository.issue(number:)`` and
    ``repository.pullRequest(number:)`` are separate resolvers with no
    cross-fallback, so we have to dispatch on ``kind``.
    """

    owner: str
    repo: str
    number: int
    kind: str = "issue"  # "issue" | "pull"


@dataclass(frozen=True)
class FetchedIssue:
    """Subset of an issue's REST representation the verify path needs."""

    number: int
    state: str           # "open" | "closed"
    state_reason: str    # "completed" | "not_planned" | "reopened" | ""
    title: str
    body: str            # current body — may have been edited
    closed_at: str       # ISO-8601 or "" when still open
    html_url: str


@dataclass(frozen=True)
class IssueComment:
    """One comment from the issue's timeline."""

    id: int
    author: str
    created_at: str
    body: str


@dataclass(frozen=True)
class IssueEvent:
    """One event from the issue's timeline (e.g. closed, reopened)."""

    event: str           # "closed", "reopened", "renamed", ...
    actor: str
    created_at: str
    commit_id: str       # populated when event=="closed" via commit; else ""


@dataclass(frozen=True)
class UserContentEdit:
    """One edit-history entry from GraphQL ``userContentEdits``."""

    edited_at: str       # ISO-8601
    editor: str          # login or "" when the actor isn't surfaced
    diff: str            # unified-diff string, before -> after


def _headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def parse_issue_url(url: str) -> IssueRef:
    """Extract owner/repo/number from a GitHub issue URL.

    Accepts three URL shapes for the path segment:

    - Web UI:    ``https://<host>/<owner>/<repo>/issues/<n>``
    - GH.com API: ``https://api.github.com/repos/<owner>/<repo>/issues/<n>``
    - GHE API:   ``https://<host>/api/v3/repos/<owner>/<repo>/issues/<n>``
                 (or ``/api/v4``, ``/api/v5`` for future enterprise API
                 versions)

    Pull-request URLs (``/pull/<n>`` or ``/pulls/<n>``) are accepted as
    aliases for the corresponding issue. PRs and issues share a number
    space on GitHub — ``/pull/9`` and ``/issues/9`` refer to the same
    backend object, and the REST endpoint
    ``/repos/<owner>/<repo>/issues/<n>`` returns both. Downstream marker
    extraction will validate that the object actually carries the
    ``/vulnhunt`` markers it expects, so passing a fix PR URL when the
    user meant the corresponding /vulnhunt issue surfaces a clear
    "missing marker(s)" error rather than a hostile URL-parse failure
    here.

    Raises ``GitHubVerifyError`` on malformed input.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise GitHubVerifyError(f"Issue URL must be http(s): {url}")
    parts = [p for p in parsed.path.split("/") if p]
    # Normalize: strip the GHE-style ``/api/vN/`` prefix when present
    # (the v3/v4/v5 variants are all valid REST roots on different
    # GHE versions). Then strip the ``repos`` prefix common to both
    # github.com and GHE API URLs. After both passes both shapes land
    # at ``[owner, repo, <resource>, number]``.
    if (
        len(parts) >= 2
        and parts[0] == "api"
        and len(parts[1]) >= 2
        and parts[1].startswith("v")
        and parts[1][1:].isdigit()
    ):
        parts = parts[2:]
    if parts and parts[0] == "repos":
        parts = parts[1:]
    # Accept "issues" plus the PR aliases — the web UI uses singular
    # "pull" while the REST API exposes PRs under "pulls", so be
    # tolerant of both.
    if len(parts) < 4 or parts[2] not in ("issues", "pull", "pulls"):
        raise GitHubVerifyError(
            f"Issue URL must be of the form https://<host>/<owner>/<repo>/issues/<n> "
            f"(or .../pull/<n> for the PR-as-issue alias): {url}"
        )
    owner, repo, resource, number = parts[0], parts[1], parts[2], parts[3]
    try:
        n = int(number)
    except ValueError as exc:
        raise GitHubVerifyError(f"Issue number must be an integer: {url}") from exc
    if n <= 0:
        raise GitHubVerifyError(f"Issue number must be positive: {url}")
    kind = "pull" if resource in ("pull", "pulls") else "issue"
    return IssueRef(owner=owner, repo=repo, number=n, kind=kind)


def issue_host(url: str) -> str:
    """Return the bare host from a GitHub issue URL (no scheme, no port)."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not host:
        raise GitHubVerifyError(f"Cannot resolve host from URL: {url}")
    return host


async def _request_with_retry(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    json: dict | None = None,
    params: dict | None = None,
    expected_codes: tuple[int, ...] = (200,),
    context: str = "",
) -> httpx.Response:
    """One HTTP request with a single retry on 429/5xx."""
    attempts = 0
    while True:
        attempts += 1
        try:
            resp = await client.request(method, url, json=json, params=params)
        except httpx.HTTPError as exc:
            if attempts > 1:
                raise GitHubVerifyError(
                    f"{context} failed after retry: {exc!r}"
                ) from exc
            logger.warning(
                "%s raised %r; retrying once after %ds", context, exc, _RETRY_BACKOFF_SECONDS
            )
            await asyncio.sleep(_RETRY_BACKOFF_SECONDS)
            continue
        if resp.status_code in expected_codes:
            return resp
        retryable = resp.status_code == 429 or resp.status_code >= 500
        if retryable and attempts == 1:
            logger.warning(
                "%s got HTTP %d; retrying once after %ds",
                context,
                resp.status_code,
                _RETRY_BACKOFF_SECONDS,
            )
            await asyncio.sleep(_RETRY_BACKOFF_SECONDS)
            continue
        raise GitHubVerifyError(
            f"{context} failed: HTTP {resp.status_code} body={resp.text[:500]!r}"
        )


# ---- REST: get one issue ---------------------------------------------------


async def get_issue(
    client: httpx.AsyncClient,
    host: str,
    ref: IssueRef,
) -> FetchedIssue:
    """GET /repos/{owner}/{repo}/issues/{n}."""
    url = f"{api_base(host)}/repos/{ref.owner}/{ref.repo}/issues/{ref.number}"
    resp = await _request_with_retry(
        client,
        "GET",
        url,
        context=f"GET issue #{ref.number}",
    )
    data = resp.json()
    return FetchedIssue(
        number=int(data["number"]),
        state=str(data.get("state", "")),
        state_reason=str(data.get("state_reason") or ""),
        title=str(data.get("title", "")),
        body=str(data.get("body") or ""),
        closed_at=str(data.get("closed_at") or ""),
        html_url=str(data.get("html_url", "")),
    )


# ---- REST: list comments and events (paginated) ----------------------------


async def list_comments(
    client: httpx.AsyncClient,
    host: str,
    ref: IssueRef,
    *,
    max_pages: int = _MAX_COMMENT_PAGES,
    max_total_bytes: int = _MAX_TIMELINE_BYTES,
) -> list[IssueComment]:
    """GET /repos/{owner}/{repo}/issues/{n}/comments (paginated).

    Bounded per CWE-400: stops following ``Link: rel="next"`` after
    ``max_pages`` pages or once the cumulative comment-body size exceeds
    ``max_total_bytes``, whichever comes first, logging a warning. This keeps
    the work independent of attacker comment volume.
    """
    out: list[IssueComment] = []
    url: str | None = (
        f"{api_base(host)}/repos/{ref.owner}/{ref.repo}/issues/{ref.number}/comments"
    )
    params: dict | None = {"per_page": 100}
    pages = 0
    total_bytes = 0
    while url:
        resp = await _request_with_retry(
            client,
            "GET",
            url,
            params=params,
            context=f"GET comments for issue #{ref.number}",
        )
        for item in resp.json():
            body = str(item.get("body") or "")
            total_bytes += len(body.encode("utf-8", "replace"))
            out.append(
                IssueComment(
                    id=int(item["id"]),
                    author=str((item.get("user") or {}).get("login", "")),
                    created_at=str(item.get("created_at", "")),
                    body=body,
                )
            )
        pages += 1
        # Follow Link: rel="next" if present — unless a bound was hit.
        link_header = resp.headers.get("link", "")
        next_url = _next_link(link_header)
        if next_url and pages >= max_pages:
            logger.warning(
                "Stopping comment pagination for issue #%d at the page cap "
                "(%d pages); remaining pages ignored.",
                ref.number,
                max_pages,
            )
            break
        if next_url and total_bytes >= max_total_bytes:
            logger.warning(
                "Stopping comment pagination for issue #%d at the body budget "
                "(%d bytes); remaining pages ignored.",
                ref.number,
                max_total_bytes,
            )
            break
        url, params = next_url, None
    return out


async def list_events(
    client: httpx.AsyncClient,
    host: str,
    ref: IssueRef,
    *,
    max_pages: int = _MAX_EVENT_PAGES,
) -> list[IssueEvent]:
    """GET /repos/{owner}/{repo}/issues/{n}/events (paginated).

    Each event has ``event`` (e.g. ``closed``), ``actor.login``, and
    ``commit_id`` when the close was tied to a commit/PR. Bounded per CWE-400:
    stops following ``Link: rel="next"`` after ``max_pages`` pages.
    """
    out: list[IssueEvent] = []
    url: str | None = (
        f"{api_base(host)}/repos/{ref.owner}/{ref.repo}/issues/{ref.number}/events"
    )
    params: dict | None = {"per_page": 100}
    pages = 0
    while url:
        resp = await _request_with_retry(
            client,
            "GET",
            url,
            params=params,
            context=f"GET events for issue #{ref.number}",
        )
        for item in resp.json():
            out.append(
                IssueEvent(
                    event=str(item.get("event", "")),
                    actor=str((item.get("actor") or {}).get("login", "")),
                    created_at=str(item.get("created_at", "")),
                    commit_id=str(item.get("commit_id") or ""),
                )
            )
        pages += 1
        link_header = resp.headers.get("link", "")
        next_url = _next_link(link_header)
        if next_url and pages >= max_pages:
            logger.warning(
                "Stopping event pagination for issue #%d at the page cap "
                "(%d pages); remaining pages ignored.",
                ref.number,
                max_pages,
            )
            break
        url, params = next_url, None
    return out


def _next_link(link_header: str) -> str | None:
    """Extract the rel="next" URL from a GitHub Link header, if any."""
    if not link_header:
        return None
    for piece in link_header.split(","):
        piece = piece.strip()
        if 'rel="next"' not in piece:
            continue
        # Format: <https://api.github.com/...>; rel="next"
        if "<" in piece and ">" in piece:
            return piece[piece.index("<") + 1 : piece.index(">")]
    return None


# ---- GraphQL: edit history -------------------------------------------------


# Two near-identical queries: GraphQL's ``Issue`` and ``PullRequest``
# are separate types under ``repository`` with no fallback between
# them, so we have to ship a parameterized query and pick the
# resolver name based on ``IssueRef.kind``. Both expose
# ``userContentEdits`` with the same shape.
_USER_CONTENT_EDITS_QUERY_ISSUE = """
query IssueEdits($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    issue(number: $number) {
      userContentEdits(first: 100) {
        nodes {
          editedAt
          editor { login }
          diff
        }
      }
    }
  }
}
"""

_USER_CONTENT_EDITS_QUERY_PR = """
query PullEdits($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      userContentEdits(first: 100) {
        nodes {
          editedAt
          editor { login }
          diff
        }
      }
    }
  }
}
"""


async def list_user_content_edits(
    client: httpx.AsyncClient,
    host: str,
    ref: IssueRef,
    *,
    max_diff_bytes: int = _MAX_EDIT_DIFF_BYTES,
    max_total_bytes: int = _MAX_EDIT_TOTAL_BYTES,
) -> list[UserContentEdit]:
    """Query GraphQL for the issue's body edit history.

    Returns an empty list when the body has never been edited. Raises
    ``GitHubVerifyError`` if the GraphQL endpoint returns errors or a
    malformed response. Dispatches on ``ref.kind`` so PR-aliased URLs
    use ``repository.pullRequest`` rather than ``repository.issue`` —
    the two resolvers don't fall back to each other on GitHub.

    Bounded per CWE-400: ``userContentEdits(first:100)`` caps node count, but
    each per-node ``diff`` is unbounded, so an oversized diff is truncated to
    ``max_diff_bytes`` (with a marker) and accumulation stops once the
    cumulative edit-history size exceeds ``max_total_bytes``.
    """
    graphql_url = f"{api_base(host)}/graphql"
    if ref.kind == "pull":
        query = _USER_CONTENT_EDITS_QUERY_PR
        resolver_field = "pullRequest"
    else:
        query = _USER_CONTENT_EDITS_QUERY_ISSUE
        resolver_field = "issue"
    payload = {
        "query": query,
        "variables": {
            "owner": ref.owner,
            "name": ref.repo,
            "number": ref.number,
        },
    }
    resp = await _request_with_retry(
        client,
        "POST",
        graphql_url,
        json=payload,
        context=f"GraphQL userContentEdits for {ref.kind} #{ref.number}",
    )
    data = resp.json()
    if "errors" in data and data["errors"]:
        raise GitHubVerifyError(
            f"GraphQL userContentEdits returned errors: {data['errors']!r}"
        )
    try:
        nodes = (
            data["data"]["repository"][resolver_field]["userContentEdits"]["nodes"]
        )
    except (KeyError, TypeError) as exc:
        raise GitHubVerifyError(
            f"GraphQL userContentEdits response missing expected fields: "
            f"{data!r}"
        ) from exc

    out: list[UserContentEdit] = []
    total_bytes = 0
    for node in nodes:
        diff = node.get("diff")
        # GitHub returns null for the diff when the edit didn't touch
        # the body field (e.g. some attribute-only edits). Skip those.
        if diff is None:
            continue
        diff = str(diff)
        # CWE-400: truncate an oversized per-edit diff so a few huge diffs
        # can't inflate memory even under the first:100 node cap. Reserve room
        # for the marker so the result stays within max_diff_bytes.
        encoded = diff.encode("utf-8", "replace")
        if len(encoded) > max_diff_bytes:
            marker = "\n[...diff truncated by verify: exceeded per-edit size cap...]"
            keep = max(0, max_diff_bytes - len(marker.encode("utf-8")))
            diff = encoded[:keep].decode("utf-8", "ignore") + marker
            logger.warning(
                "Truncated an oversized userContentEdit diff for %s #%d "
                "(%d bytes > cap %d).",
                ref.kind,
                ref.number,
                len(encoded),
                max_diff_bytes,
            )
        total_bytes += len(diff.encode("utf-8", "replace"))
        if total_bytes > max_total_bytes:
            logger.warning(
                "Stopping edit-history accumulation for %s #%d at the "
                "cumulative budget (%d bytes); remaining edits ignored.",
                ref.kind,
                ref.number,
                max_total_bytes,
            )
            break
        editor = (node.get("editor") or {}).get("login") or ""
        out.append(
            UserContentEdit(
                edited_at=str(node.get("editedAt", "")),
                editor=str(editor),
                diff=diff,
            )
        )
    return out


# ---- REST mutations: post comment, reopen ----------------------------------


async def post_comment(
    client: httpx.AsyncClient,
    host: str,
    ref: IssueRef,
    body: str,
) -> str:
    """POST a comment on the issue. Returns the new comment's html_url."""
    url = (
        f"{api_base(host)}/repos/{ref.owner}/{ref.repo}/issues/{ref.number}/comments"
    )
    resp = await _request_with_retry(
        client,
        "POST",
        url,
        json={"body": body},
        expected_codes=(201,),
        context=f"POST comment on issue #{ref.number}",
    )
    data = resp.json()
    return str(data.get("html_url", ""))


async def reopen_issue(
    client: httpx.AsyncClient,
    host: str,
    ref: IssueRef,
) -> None:
    """PATCH the issue to set state=open, state_reason=reopened.

    Idempotent: if the issue is already open, this is a no-op from
    GitHub's perspective (state changes to "open" with no event).
    """
    url = f"{api_base(host)}/repos/{ref.owner}/{ref.repo}/issues/{ref.number}"
    await _request_with_retry(
        client,
        "PATCH",
        url,
        json={"state": "open", "state_reason": "reopened"},
        context=f"PATCH (reopen) issue #{ref.number}",
    )


# ---- Session helper --------------------------------------------------------


def make_client(token: str, *, verify_ssl=True, timeout: float = 30.0) -> httpx.AsyncClient:
    """Construct an httpx.AsyncClient with the verify-path headers and
    retry-friendly defaults. The caller is responsible for closing it
    (``async with`` recommended)."""
    return httpx.AsyncClient(
        verify=verify_ssl,
        timeout=timeout,
        headers=_headers(token),
    )
