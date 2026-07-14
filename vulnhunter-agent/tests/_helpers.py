"""Shared test helpers reused across the issues-stage test files.

Each test module previously defined its own ``_TM`` (fake token
manager) and ``_finding(...)`` factory. They diverged in subtle ways
(default key, default fid, override semantics), so we centralize them
here. Tests should import what they need rather than re-defining.
"""

from __future__ import annotations

from typing import Any

from agent.issues_extract import Finding
from agent.issues_fetch import OpenIssue


class FakeTokenManager:
    """Stand-in for ``agent.auth.OAuthTokenManager`` in tests.

    Returns a constant token so call_json / extract / dedup don't have
    to hit a real OAuth endpoint.
    """

    def __init__(self, token: str = "test-token") -> None:
        self._token = token

    def get_valid_token(self) -> str:
        return self._token


def make_finding(
    *,
    fid: str = "VULN-001",
    title: str | None = None,
    cwe: str = "CWE-89",
    cwe_name: str = "SQL Injection",
    severity: str = "High",
    location: str | None = None,
    root_cause: str = "rc",
    data_flow: str = "df",
    entry_point: str = "ep",
    exploit_description: str = "ed",
    exploit_impact: str = "ei",
    fix_strategy: str = "fs",
    severity_rationale: str = "sr",
    poc_path: str | None = None,
    exploit_test_path: str | None = None,
    vulnfix_key: str | None = None,
    **extra: Any,
) -> Finding:
    """Build a Finding with sensible test defaults.

    ``title`` and ``location`` default to per-fid placeholders so two
    findings created without overrides have distinct location/title
    (helpful when a test exercises N-finding scenarios).
    """
    if title is None:
        title = f"finding {fid}"
    if location is None:
        location = f"src/{fid}.py:1"
    if vulnfix_key is None:
        vulnfix_key = f"key_{fid}"
    return Finding(
        id=fid,
        title=title,
        cwe=cwe,
        cwe_name=cwe_name,
        severity=severity,
        location=location,
        root_cause=root_cause,
        data_flow=data_flow,
        entry_point=entry_point,
        exploit_description=exploit_description,
        exploit_impact=exploit_impact,
        fix_strategy=fix_strategy,
        severity_rationale=severity_rationale,
        poc_path=poc_path,
        exploit_test_path=exploit_test_path,
        vulnfix_key=vulnfix_key,
    )


def make_open_issue(
    n: int, *, body: str = "", title: str | None = None
) -> OpenIssue:
    """Build an OpenIssue with conventional test defaults."""
    return OpenIssue(
        number=n,
        title=title if title is not None else f"issue {n}",
        body=body,
        html_url=f"https://example.com/issues/{n}",
        labels=[],
    )
