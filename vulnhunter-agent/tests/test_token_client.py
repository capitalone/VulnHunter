"""Tests for agent.token_client.get_github_token.

Two paths exercised: standalone (read from config) and broker (read
from atomic-renamed JSON files on disk). Broker mode tests the 50ms
retry that absorbs the wrapper's tmpfile→rename window.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable
from unittest.mock import patch

import pytest

from agent.config import AgentConfig, GitHubConfig
from agent.token_client import BrokerTokenAuth, get_github_token

import httpx


def _gh(
    *,
    scan_token: str = "",
    reports_token: str = "",
    broker_token_dir: str = "",
    host: str = "github.com",
) -> GitHubConfig:
    return GitHubConfig(
        host=host,
        scan_token=scan_token,
        reports_token=reports_token,
        broker_token_dir=broker_token_dir,
    )


def _write_broker(dir_: Path, role: str, token: str) -> None:
    (dir_ / f"{role}.json").write_text(
        json.dumps({"token": token, "expires_at": "2099-01-01T00:00:00Z", "app_id": "1"})
    )


class TestStandaloneMode:
    """broker_token_dir unset → literal tokens from config."""

    def test_scan_returns_literal(
        self, agent_config: Callable[..., AgentConfig]
    ) -> None:
        cfg = agent_config(github=_gh(scan_token="ghs_scan_xyz", reports_token="ghs_rep"))
        assert get_github_token("scan", cfg) == "ghs_scan_xyz"

    def test_reports_returns_literal(
        self, agent_config: Callable[..., AgentConfig]
    ) -> None:
        cfg = agent_config(github=_gh(scan_token="x", reports_token="ghs_rep_xyz"))
        assert get_github_token("reports", cfg) == "ghs_rep_xyz"

    def test_empty_literal_returns_empty(
        self, agent_config: Callable[..., AgentConfig]
    ) -> None:
        # Standalone with no token configured returns "" — caller (validate /
        # preflight / module) decides whether to reject.
        cfg = agent_config(github=_gh())
        assert get_github_token("scan", cfg) == ""
        assert get_github_token("reports", cfg) == ""

    def test_unknown_role_raises(
        self, agent_config: Callable[..., AgentConfig]
    ) -> None:
        cfg = agent_config(github=_gh(scan_token="x"))
        with pytest.raises(ValueError, match="unknown GitHub role"):
            get_github_token("nope", cfg)  # type: ignore[arg-type]


class TestBrokerMode:
    """broker_token_dir set → read from {dir}/{role}.json."""

    def test_scan_reads_broker_file(
        self,
        agent_config: Callable[..., AgentConfig],
        tmp_path: Path,
    ) -> None:
        _write_broker(tmp_path, "scan", "ghs_from_broker_scan")
        cfg = agent_config(
            github=_gh(
                broker_token_dir=str(tmp_path),
                # Standalone literals MUST be ignored when broker is set —
                # otherwise a misconfiguration could leak a stale token.
                scan_token="STALE_should_not_be_returned",
            )
        )
        assert get_github_token("scan", cfg) == "ghs_from_broker_scan"

    def test_reports_reads_broker_file(
        self,
        agent_config: Callable[..., AgentConfig],
        tmp_path: Path,
    ) -> None:
        _write_broker(tmp_path, "reports", "ghs_from_broker_reports")
        cfg = agent_config(github=_gh(broker_token_dir=str(tmp_path)))
        assert get_github_token("reports", cfg) == "ghs_from_broker_reports"

    def test_missing_file_raises_after_retry(
        self,
        agent_config: Callable[..., AgentConfig],
        tmp_path: Path,
    ) -> None:
        # No file on disk; expect FileNotFoundError after the 50ms retry.
        cfg = agent_config(github=_gh(broker_token_dir=str(tmp_path)))
        with patch("agent.token_client.time.sleep") as sleep_mock:
            with pytest.raises(FileNotFoundError):
                get_github_token("scan", cfg)
            # Retry-once budget: exactly one sleep between the two read attempts.
            sleep_mock.assert_called_once()

    def test_corrupt_json_raises_after_retry(
        self,
        agent_config: Callable[..., AgentConfig],
        tmp_path: Path,
    ) -> None:
        (tmp_path / "scan.json").write_text("{not json")
        cfg = agent_config(github=_gh(broker_token_dir=str(tmp_path)))
        with patch("agent.token_client.time.sleep"):
            with pytest.raises(json.JSONDecodeError):
                get_github_token("scan", cfg)

    def test_rename_window_recovery(
        self,
        agent_config: Callable[..., AgentConfig],
        tmp_path: Path,
    ) -> None:
        """First read fails (broker mid-rename), retry succeeds."""
        target = tmp_path / "scan.json"
        cfg = agent_config(github=_gh(broker_token_dir=str(tmp_path)))

        def fake_sleep(_secs: float) -> None:
            # Simulate the broker's atomic rename landing during the 50ms
            # backoff window.
            _write_broker(tmp_path, "scan", "ghs_recovered_after_rename")

        with patch("agent.token_client.time.sleep", side_effect=fake_sleep):
            assert get_github_token("scan", cfg) == "ghs_recovered_after_rename"
        assert target.exists()  # post-condition: file is there

    def test_missing_token_field_raises(
        self,
        agent_config: Callable[..., AgentConfig],
        tmp_path: Path,
    ) -> None:
        # Valid JSON but no 'token' key — broker is broken; surface a clear error.
        (tmp_path / "scan.json").write_text(
            json.dumps({"expires_at": "2099-01-01T00:00:00Z", "app_id": "1"})
        )
        cfg = agent_config(github=_gh(broker_token_dir=str(tmp_path)))
        with pytest.raises(ValueError, match="missing or has empty 'token' field"):
            get_github_token("scan", cfg)

    def test_empty_token_field_raises(
        self,
        agent_config: Callable[..., AgentConfig],
        tmp_path: Path,
    ) -> None:
        (tmp_path / "scan.json").write_text(
            json.dumps({"token": "", "expires_at": "x", "app_id": "1"})
        )
        cfg = agent_config(github=_gh(broker_token_dir=str(tmp_path)))
        with pytest.raises(ValueError, match="missing or has empty 'token' field"):
            get_github_token("scan", cfg)

    def test_no_in_agent_cache(
        self,
        agent_config: Callable[..., AgentConfig],
        tmp_path: Path,
    ) -> None:
        """Pins TOKEN-CLIENT-004: every call hits the file fresh.

        Without this guarantee, a refresh on the wrapper side wouldn't
        propagate to a long-lived agent operation.
        """
        _write_broker(tmp_path, "scan", "ghs_v1")
        cfg = agent_config(github=_gh(broker_token_dir=str(tmp_path)))
        assert get_github_token("scan", cfg) == "ghs_v1"
        # Simulate broker refresh.
        _write_broker(tmp_path, "scan", "ghs_v2_refreshed")
        assert get_github_token("scan", cfg) == "ghs_v2_refreshed"


class TestBrokerTokenAuth:
    """Pins the no-cache contract at the *request* boundary, not just the
    function-call boundary. Without this, an httpx session that captured
    the token once in a long-lived ``headers`` dict would keep using a
    stale token after the wrapper daemon's refresh.
    """

    def test_auth_flow_resolves_token_per_request(
        self,
        agent_config: Callable[..., AgentConfig],
        tmp_path: Path,
    ) -> None:
        _write_broker(tmp_path, "scan", "tok_v1")
        cfg = agent_config(github=_gh(broker_token_dir=str(tmp_path)))
        auth = BrokerTokenAuth("scan", cfg)

        # First request: file has tok_v1.
        req1 = httpx.Request("GET", "https://api.github.com/octocat")
        gen = auth.auth_flow(req1)
        next(gen)
        assert req1.headers["Authorization"] == "Bearer tok_v1"

        # Wrapper daemon writes a new token between requests.
        _write_broker(tmp_path, "scan", "tok_v2_refreshed")

        # Second request: file now has tok_v2. Auth must pick it up.
        req2 = httpx.Request("POST", "https://api.github.com/octocat/issues")
        gen = auth.auth_flow(req2)
        next(gen)
        assert req2.headers["Authorization"] == "Bearer tok_v2_refreshed"

    def test_auth_flow_overrides_existing_authorization(
        self,
        agent_config: Callable[..., AgentConfig],
        tmp_path: Path,
    ) -> None:
        """If a stale Authorization is on the request, BrokerTokenAuth overwrites it."""
        _write_broker(tmp_path, "scan", "fresh")
        cfg = agent_config(github=_gh(broker_token_dir=str(tmp_path)))
        auth = BrokerTokenAuth("scan", cfg)

        req = httpx.Request("GET", "https://api.github.com/octocat")
        req.headers["Authorization"] = "Bearer STALE"
        gen = auth.auth_flow(req)
        next(gen)
        assert req.headers["Authorization"] == "Bearer fresh"

    def test_auth_flow_standalone_mode_uses_config_literal(
        self,
        agent_config: Callable[..., AgentConfig],
    ) -> None:
        """Standalone mode: BrokerTokenAuth returns the config-literal
        token (no file read, no broker dependency)."""
        cfg = agent_config(github=_gh(scan_token="pat_literal"))
        auth = BrokerTokenAuth("scan", cfg)
        req = httpx.Request("GET", "https://api.github.com/octocat")
        next(auth.auth_flow(req))
        assert req.headers["Authorization"] == "Bearer pat_literal"

    def test_reports_role_uses_reports_token(
        self,
        agent_config: Callable[..., AgentConfig],
        tmp_path: Path,
    ) -> None:
        _write_broker(tmp_path, "reports", "reports_tok")
        _write_broker(tmp_path, "scan", "scan_tok")
        cfg = agent_config(github=_gh(broker_token_dir=str(tmp_path)))
        auth = BrokerTokenAuth("reports", cfg)
        req = httpx.Request("GET", "https://api.github.com/repos")
        next(auth.auth_flow(req))
        assert req.headers["Authorization"] == "Bearer reports_tok"
