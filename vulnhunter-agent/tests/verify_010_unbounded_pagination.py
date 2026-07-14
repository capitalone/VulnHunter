"""Security test: VULN-010 — verify-path pagination must be bounded.

CWE-400. list_comments / list_events follow Link: rel="next" with no page cap
and no cumulative body budget. A page cap and a total-body budget must bound
the work regardless of attacker comment/event volume.
"""

import asyncio

import pytest

from agent import _github_verify as ghv


class _FakeResp:
    def __init__(self, page, more=True):
        self._page = page
        self.headers = (
            {"link": '<https://api.github.com/next>; rel="next"'} if more else {}
        )

    def json(self):
        return self._page


def _install_infinite_comments(monkeypatch, body="x" * 1000):
    calls = {"n": 0}

    async def _fake(client, method, url, **kwargs):
        calls["n"] += 1
        page = [{
            "id": calls["n"], "user": {"login": "a"},
            "created_at": "", "body": body,
        }]
        # Safety stop so an unfixed (uncapped) loop still terminates the test.
        return _FakeResp(page, more=calls["n"] < 300)

    monkeypatch.setattr(ghv, "_request_with_retry", _fake)
    return calls


def test_list_comments_stops_at_page_cap(monkeypatch):
    calls = _install_infinite_comments(monkeypatch, body="short")
    comments = asyncio.run(
        ghv.list_comments(object(), "github.com", ghv.IssueRef("o", "r", 42))
    )
    assert calls["n"] <= ghv._MAX_COMMENT_PAGES
    assert len(comments) <= ghv._MAX_COMMENT_PAGES


def test_list_comments_stops_at_byte_budget(monkeypatch):
    # Each page carries a body just over 1/3 of the budget, so the cumulative
    # budget trips well before the page cap.
    big = "x" * (ghv._MAX_TIMELINE_BYTES // 3 + 1)
    calls = _install_infinite_comments(monkeypatch, body=big)
    asyncio.run(ghv.list_comments(object(), "github.com", ghv.IssueRef("o", "r", 42)))
    assert calls["n"] <= 4, "byte budget did not stop pagination early"


def test_list_events_stops_at_page_cap(monkeypatch):
    calls = {"n": 0}

    async def _fake(client, method, url, **kwargs):
        calls["n"] += 1
        return _FakeResp([{"event": "commented", "actor": {"login": "a"},
                           "created_at": "", "commit_id": ""}], more=calls["n"] < 300)

    monkeypatch.setattr(ghv, "_request_with_retry", _fake)
    asyncio.run(ghv.list_events(object(), "github.com", ghv.IssueRef("o", "r", 42)))
    assert calls["n"] <= ghv._MAX_EVENT_PAGES
