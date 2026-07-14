"""Fetch open GitHub issues carrying a label, paginated.

Used by the issues-stage dedup pool. Returns plain dataclasses; the
dedup module decides what to do with them.

The /issues endpoint returns BOTH issues and pull requests by default;
we drop anything with a "pull_request" key so the dedup pool is
issues-only (the agent never produces PRs and we don't want to
double-count fix PRs from other workflows).

Each page request is retried once on 429/5xx with a 30-second backoff,
matching the issue-creation path's retry semantics.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

import httpx

from ._github import api_base, parse_owner_repo
from .auth import resolve_verify
from .config import AgentConfig
from .token_client import BrokerTokenAuth, get_github_token

logger = logging.getLogger(__name__)


# Backoff between transient-error retries on a single page fetch. One
# retry per page; if that fails, the whole stage fails (unlike issue
# creation, dedup needs the complete list to be useful).
_RETRY_BACKOFF_SECONDS = 30


def _is_retryable(status_code: int) -> bool:
    return status_code == 429 or status_code >= 500


class IssuesFetchError(RuntimeError):
    """Raised when the GitHub issues endpoint cannot be queried."""


@dataclass(frozen=True)
class OpenIssue:
    number: int
    title: str
    body: str
    html_url: str
    labels: list[str]


def fetch_open_issues_with_label(
    target_repo_url: str,
    label: str,
    *,
    config: AgentConfig,
    log_retries: bool = False,
) -> list[OpenIssue]:
    """Return all open issues on target_repo_url tagged with ``label``.

    Paginates server-side at 100/page; raises IssuesFetchError if
    ``max_open_issues`` is hit (signals a label-hygiene problem upstream).
    """
    token = get_github_token("scan", config)
    if not token:
        raise IssuesFetchError(
            "scan_token is required to list issues for dedup."
        )
    owner, name = parse_owner_repo(target_repo_url)
    api = api_base(config.github.host)
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    verify = resolve_verify(config.tls)
    issues_cfg = config.issues

    out: list[OpenIssue] = []
    page = 1
    per_page = 100

    with httpx.Client(
        verify=verify,
        timeout=issues_cfg.request_timeout_seconds,
        headers=headers,
        auth=BrokerTokenAuth("scan", config),
    ) as client:
        while True:
            url = f"{api}/repos/{owner}/{name}/issues"
            params = {
                "state": "open",
                "labels": label,
                "per_page": per_page,
                "page": page,
            }
            resp = _get_with_retry(client, url, params=params, label=label, owner=owner, name=name, page=page, log_retries=log_retries)
            batch = resp.json()
            if not isinstance(batch, list):
                raise IssuesFetchError(
                    f"unexpected non-list response: {batch!r}"
                )
            if not batch:
                break
            for raw in batch:
                if "pull_request" in raw:
                    # /issues includes PRs; skip them.
                    continue
                out.append(_coerce(raw))
                if len(out) >= issues_cfg.max_open_issues:
                    raise IssuesFetchError(
                        f"hit max_open_issues={issues_cfg.max_open_issues} for "
                        f"{owner}/{name} label={label!r} — refine the label "
                        "or raise the cap."
                    )
            if len(batch) < per_page:
                break
            page += 1

    logger.info(
        "Fetched %d open issue(s) on %s/%s with label %r",
        len(out),
        owner,
        name,
        label,
    )
    return out


def _get_with_retry(
    client: httpx.Client,
    url: str,
    *,
    params: dict[str, Any],
    label: str,
    owner: str,
    name: str,
    page: int,
    log_retries: bool = False,
) -> httpx.Response:
    """GET with one transient-error retry. Raises IssuesFetchError on
    final non-200."""
    for attempt in range(2):
        resp = client.get(url, params=params)
        if resp.status_code == 200:
            return resp
        if not _is_retryable(resp.status_code):
            break
        if attempt == 0:
            if log_retries:
                logger.info(
                    "GET issues for %s/%s (page %d, label=%r) got %d; "
                    "retrying once after %ds backoff",
                    owner,
                    name,
                    page,
                    label,
                    resp.status_code,
                    _RETRY_BACKOFF_SECONDS,
                )
            time.sleep(_RETRY_BACKOFF_SECONDS)
    raise IssuesFetchError(
        f"GET issues for {owner}/{name} (page {page}, label={label!r}) "
        f"failed: {resp.status_code} {resp.text[:200]}"
    )


def _coerce(raw: dict[str, Any]) -> OpenIssue:
    labels = []
    for lab in raw.get("labels") or []:
        if isinstance(lab, dict) and "name" in lab:
            labels.append(str(lab["name"]))
        elif isinstance(lab, str):
            labels.append(lab)
    return OpenIssue(
        number=int(raw["number"]),
        title=str(raw.get("title", "")),
        body=str(raw.get("body") or ""),
        html_url=str(raw.get("html_url", "")),
        labels=labels,
    )
