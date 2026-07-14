"""Security test: VULN-011 — per-edit diff bodies must be bounded.

CWE-400. userContentEdits(first:100) caps node count but each per-node diff
string is materialized unbounded (diff=str(diff)). A per-diff size cap and a
cumulative edit-history byte budget must bound the work.
"""

import asyncio

from agent import _github_verify as ghv


class _FakeResp:
    def __init__(self, nodes):
        self._nodes = nodes

    def json(self):
        return {"data": {"repository": {"issue": {"userContentEdits": {"nodes": self._nodes}}}}}


def _install(monkeypatch, nodes):
    async def _fake(client, method, url, **kwargs):
        return _FakeResp(nodes)

    monkeypatch.setattr(ghv, "_request_with_retry", _fake)


def test_oversized_diff_is_truncated(monkeypatch):
    huge = "A" * (ghv._MAX_EDIT_DIFF_BYTES * 4)
    _install(monkeypatch, [{"editedAt": "t", "editor": {"login": "a"}, "diff": huge}])
    edits = asyncio.run(
        ghv.list_user_content_edits(object(), "github.com", ghv.IssueRef("o", "r", 42))
    )
    assert len(edits) == 1
    assert len(edits[0].diff.encode("utf-8")) <= ghv._MAX_EDIT_DIFF_BYTES


def test_cumulative_budget_caps_total(monkeypatch):
    one = "B" * (ghv._MAX_EDIT_DIFF_BYTES)
    nodes = [
        {"editedAt": "t", "editor": {"login": "a"}, "diff": one} for _ in range(100)
    ]
    _install(monkeypatch, nodes)
    edits = asyncio.run(
        ghv.list_user_content_edits(object(), "github.com", ghv.IssueRef("o", "r", 42))
    )
    total = sum(len(e.diff.encode("utf-8")) for e in edits)
    assert total <= ghv._MAX_EDIT_TOTAL_BYTES
