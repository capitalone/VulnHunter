"""Tests for issues_fetch: pagination, PR filtering, max-cap behavior."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from agent import issues_fetch as fetch_mod
from agent.config import AgentConfig, GitHubConfig, IssuesConfig
from agent.issues_fetch import IssuesFetchError, fetch_open_issues_with_label
from tests.conftest import _build_agent_config


@pytest.fixture(autouse=True)
def _stub_resolve_verify(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fetch_mod, "resolve_verify", lambda tls: True)


def _cfg(
    *,
    scan_token: str = "ghp_test",
    issues_overrides: dict[str, Any] | None = None,
) -> AgentConfig:
    """Build an AgentConfig with the fields issues_fetch reads."""
    gh = GitHubConfig(
        host="github.com",
        scan_token=scan_token,
        reports_token="",
        broker_token_dir="",
    )
    overrides: dict[str, Any] = {"github": gh}
    if issues_overrides is not None:
        overrides["issues"] = _icfg(**issues_overrides)
    return _build_agent_config(**overrides)


def _icfg(**overrides: object) -> IssuesConfig:
    base = dict(
        enabled=True,
        target_repo="",
        labels=["security", "vulnhunter"],
        dedup_label="vulnhunter",
        haiku_model="claude-haiku",
        sonnet_model="claude-sonnet",
        semantic_dedup=True,
        request_timeout_seconds=30,
        max_open_issues=1000,
        token_budget_fraction=0.7,
        model_context_tokens=200_000,
        notify_clean_scan=True,
        clean_scan_label="VulnHunter: clean-scan",
    )
    base.update(overrides)  # type: ignore[arg-type]
    return IssuesConfig(**base)  # type: ignore[arg-type]


def _issue(n: int, *, is_pr: bool = False, body: str = "", labels: list[str] | None = None) -> dict:
    out = {
        "number": n,
        "title": f"issue {n}",
        "body": body,
        "html_url": f"https://github.com/o/r/issues/{n}",
        "labels": [{"name": lab} for lab in (labels or ["vulnhunter"])],
    }
    if is_pr:
        out["pull_request"] = {"url": f"https://github.com/o/r/pulls/{n}"}
    return out


class TestFetchOpenIssues:
    @respx.mock
    def test_single_page(self) -> None:
        respx.get("https://api.github.com/repos/o/r/issues").mock(
            return_value=httpx.Response(200, json=[_issue(1), _issue(2)])
        )
        out = fetch_open_issues_with_label(
            "https://github.com/o/r",
            "vulnhunter",
            config=_cfg(),
        )
        assert [i.number for i in out] == [1, 2]

    @respx.mock
    def test_filters_out_pull_requests(self) -> None:
        respx.get("https://api.github.com/repos/o/r/issues").mock(
            return_value=httpx.Response(
                200, json=[_issue(1), _issue(2, is_pr=True), _issue(3)]
            )
        )
        out = fetch_open_issues_with_label(
            "https://github.com/o/r",
            "vulnhunter",
            config=_cfg(),
        )
        assert [i.number for i in out] == [1, 3]

    @respx.mock
    def test_pagination_stops_on_short_page(self) -> None:
        # Page 1 returns a full page (100), page 2 returns short → stop.
        page1 = [_issue(n) for n in range(1, 101)]
        page2 = [_issue(101), _issue(102)]
        route = respx.get("https://api.github.com/repos/o/r/issues").mock(
            side_effect=[
                httpx.Response(200, json=page1),
                httpx.Response(200, json=page2),
            ]
        )
        out = fetch_open_issues_with_label(
            "https://github.com/o/r",
            "vulnhunter",
            config=_cfg(),
        )
        assert len(out) == 102
        assert route.call_count == 2

    @respx.mock
    def test_hits_max_cap(self) -> None:
        respx.get("https://api.github.com/repos/o/r/issues").mock(
            return_value=httpx.Response(
                200, json=[_issue(n) for n in range(1, 101)]
            )
        )
        with pytest.raises(IssuesFetchError, match="hit max_open_issues"):
            fetch_open_issues_with_label(
                "https://github.com/o/r",
                "vulnhunter",
                config=_cfg(issues_overrides={"max_open_issues": 10}),
            )

    @respx.mock
    def test_non_200_raises(self) -> None:
        respx.get("https://api.github.com/repos/o/r/issues").mock(
            return_value=httpx.Response(403, text="forbidden")
        )
        with pytest.raises(IssuesFetchError, match="403"):
            fetch_open_issues_with_label(
                "https://github.com/o/r",
                "vulnhunter",
                config=_cfg(),
            )

    @respx.mock
    def test_5xx_retries_then_succeeds(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Single retry on 5xx — no real sleep in tests.
        monkeypatch.setattr(fetch_mod.time, "sleep", lambda s: None)
        route = respx.get(
            "https://api.github.com/repos/o/r/issues"
        ).mock(
            side_effect=[
                httpx.Response(503, text="busy"),
                httpx.Response(200, json=[_issue(1)]),
            ]
        )
        out = fetch_open_issues_with_label(
            "https://github.com/o/r",
            "vulnhunter",
            config=_cfg(),
        )
        assert [i.number for i in out] == [1]
        assert route.call_count == 2

    @respx.mock
    def test_5xx_persistent_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(fetch_mod.time, "sleep", lambda s: None)
        respx.get("https://api.github.com/repos/o/r/issues").mock(
            return_value=httpx.Response(503, text="still busy")
        )
        with pytest.raises(IssuesFetchError, match="503"):
            fetch_open_issues_with_label(
                "https://github.com/o/r",
                "vulnhunter",
                config=_cfg(),
            )

    def test_missing_token_raises(self) -> None:
        with pytest.raises(IssuesFetchError, match="scan_token"):
            fetch_open_issues_with_label(
                "https://github.com/o/r",
                "vulnhunter",
                config=_cfg(scan_token=""),
            )
