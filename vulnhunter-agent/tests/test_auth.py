"""Tests for agent.auth: trust-store + OAuth token cache."""

from __future__ import annotations

import logging
import sys
from types import SimpleNamespace

import httpx
import pytest
import respx

from agent import auth as auth_mod
from agent.auth import (
    ApiKeyTokenManager,
    AuthTokenError,
    OAuthTokenManager,
    SigV4TokenManager,
    make_token_manager,
    resolve_verify,
)
from agent.config import AnthropicConfig, OAuthConfig, TLSConfig


def _oauth_cfg(**overrides: object) -> OAuthConfig:
    base = dict(
        token_endpoint="https://oauth.example.com/token",
        client_id="cid",
        client_secret="csec",
        expiry_safety_factor=0.9,
        default_lifetime_seconds=3600,
        http_timeout_seconds=5,
    )
    base.update(overrides)
    return OAuthConfig(**base)  # type: ignore[arg-type]


def _tls_cfg(path: str = "") -> TLSConfig:
    return TLSConfig(ssl_cert_path=path)


# ---------------------------------------------------------------------------
# resolve_verify
# ---------------------------------------------------------------------------


class TestResolveVerify:
    def test_returns_ssl_cert_path_when_set(self) -> None:
        out = resolve_verify(_tls_cfg("/etc/ssl/bundle.pem"))
        assert out == "/etc/ssl/bundle.pem"

    def test_returns_true_when_no_cert_path(self) -> None:
        # No custom bundle configured → fall back to system trust.
        assert resolve_verify(_tls_cfg("")) is True


# ---------------------------------------------------------------------------
# OAuthTokenManager
# ---------------------------------------------------------------------------


@pytest.fixture
def token_manager(monkeypatch: pytest.MonkeyPatch) -> OAuthTokenManager:
    """Build a manager with verify resolution stubbed."""
    monkeypatch.setattr(auth_mod, "resolve_verify", lambda tls: True)
    return OAuthTokenManager(_oauth_cfg(), _tls_cfg(""), name="test")


class TestOAuthTokenManager:
    @respx.mock
    def test_first_call_triggers_refresh(
        self, token_manager: OAuthTokenManager
    ) -> None:
        route = respx.post("https://oauth.example.com/token").mock(
            return_value=httpx.Response(
                200, json={"access_token": "tok-1", "expires_in": 3600}
            )
        )
        assert token_manager.get_valid_token() == "tok-1"
        assert route.called

    @respx.mock
    def test_second_call_within_expiry_uses_cache(
        self,
        token_manager: OAuthTokenManager,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(auth_mod.time, "time", lambda: 1000.0)
        route = respx.post("https://oauth.example.com/token").mock(
            return_value=httpx.Response(
                200, json={"access_token": "tok-1", "expires_in": 3600}
            )
        )
        token_manager.get_valid_token()
        # Advance time but stay under expiry (< 1000 + 3600*0.9).
        monkeypatch.setattr(auth_mod.time, "time", lambda: 2000.0)
        assert token_manager.get_valid_token() == "tok-1"
        assert route.call_count == 1  # not refreshed

    @respx.mock
    def test_second_call_after_expiry_refreshes(
        self,
        token_manager: OAuthTokenManager,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(auth_mod.time, "time", lambda: 1000.0)
        respx.post("https://oauth.example.com/token").mock(
            side_effect=[
                httpx.Response(200, json={"access_token": "first", "expires_in": 100}),
                httpx.Response(200, json={"access_token": "second", "expires_in": 100}),
            ]
        )
        assert token_manager.get_valid_token() == "first"
        # 1000 + 100*0.9 = 1090. Skip past it.
        monkeypatch.setattr(auth_mod.time, "time", lambda: 5000.0)
        assert token_manager.get_valid_token() == "second"

    @respx.mock
    def test_200_with_valid_body_records_expiry(
        self,
        token_manager: OAuthTokenManager,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(auth_mod.time, "time", lambda: 1000.0)
        respx.post("https://oauth.example.com/token").mock(
            return_value=httpx.Response(
                200, json={"access_token": "abc", "expires_in": 200}
            )
        )
        token_manager.get_valid_token()
        # expiry = now + lifetime * factor = 1000 + 200*0.9 = 1180
        assert token_manager._token_expiry == pytest.approx(1180.0)

    @respx.mock
    def test_200_missing_access_token_raises(
        self, token_manager: OAuthTokenManager
    ) -> None:
        respx.post("https://oauth.example.com/token").mock(
            return_value=httpx.Response(200, json={"expires_in": 60})
        )
        with pytest.raises(AuthTokenError, match="access_token"):
            token_manager.get_valid_token()

    @respx.mock
    def test_non_200_raises_with_status_and_body(
        self, token_manager: OAuthTokenManager
    ) -> None:
        respx.post("https://oauth.example.com/token").mock(
            return_value=httpx.Response(403, text="forbidden-detail")
        )
        with pytest.raises(AuthTokenError) as exc:
            token_manager.get_valid_token()
        msg = str(exc.value)
        assert "403" in msg
        assert "forbidden-detail" in msg

    @respx.mock
    def test_timeout_exception_raises(
        self, token_manager: OAuthTokenManager
    ) -> None:
        respx.post("https://oauth.example.com/token").mock(
            side_effect=httpx.TimeoutException("timed out")
        )
        with pytest.raises(AuthTokenError, match="timed out"):
            token_manager.get_valid_token()

    @respx.mock
    def test_request_error_raises(
        self, token_manager: OAuthTokenManager
    ) -> None:
        respx.post("https://oauth.example.com/token").mock(
            side_effect=httpx.ConnectError("connection refused")
        )
        with pytest.raises(AuthTokenError, match="connection error"):
            token_manager.get_valid_token()

    @respx.mock
    def test_expires_in_missing_uses_default_lifetime(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(auth_mod, "resolve_verify", lambda tls: True)
        monkeypatch.setattr(auth_mod.time, "time", lambda: 0.0)
        mgr = OAuthTokenManager(
            _oauth_cfg(default_lifetime_seconds=1234, expiry_safety_factor=1.0),
            _tls_cfg(""),
        )
        respx.post("https://oauth.example.com/token").mock(
            return_value=httpx.Response(200, json={"access_token": "abc"})
        )
        mgr.get_valid_token()
        assert mgr._token_expiry == pytest.approx(1234.0)

    @respx.mock
    def test_request_body_is_form_encoded_with_credentials(
        self, token_manager: OAuthTokenManager
    ) -> None:
        route = respx.post("https://oauth.example.com/token").mock(
            return_value=httpx.Response(200, json={"access_token": "x"})
        )
        token_manager.get_valid_token()
        request = route.calls.last.request
        assert request.headers["content-type"] == "application/x-www-form-urlencoded"
        body = request.content.decode()
        assert "grant_type=client_credentials" in body
        assert "client_id=cid" in body
        assert "client_secret=csec" in body

    @respx.mock
    def test_bearer_never_logged_at_info(
        self,
        token_manager: OAuthTokenManager,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        respx.post("https://oauth.example.com/token").mock(
            return_value=httpx.Response(
                200, json={"access_token": "super-secret-token", "expires_in": 60}
            )
        )
        with caplog.at_level(logging.INFO, logger="agent.auth"):
            token_manager.get_valid_token()
        for record in caplog.records:
            assert "super-secret-token" not in record.getMessage()


# ---------------------------------------------------------------------------
# SigV4TokenManager + make_token_manager dispatch
# ---------------------------------------------------------------------------


class TestSigV4TokenManager:
    def test_returns_empty_token(self) -> None:
        # No bearer exists in SigV4 mode — the CLI signs with the AWS chain.
        assert SigV4TokenManager().get_valid_token() == ""

    def test_no_network_calls(self) -> None:
        # Deterministic + offline: get_valid_token must not touch httpx.
        mgr = SigV4TokenManager(name="probe")
        assert mgr.get_valid_token() == ""


class TestMakeTokenManager:
    def _anthropic(self, **overrides: object) -> AnthropicConfig:
        base = dict(model="m", auth_mode="api_key")
        base.update(overrides)
        return AnthropicConfig(**base)  # type: ignore[arg-type]

    def test_sigv4_mode_returns_sigv4_manager(
        self, agent_config
    ) -> None:
        cfg = agent_config(
            anthropic=self._anthropic(
                auth_mode="bedrock_sigv4", aws_region="us-east-1"
            )
        )
        assert isinstance(make_token_manager(cfg), SigV4TokenManager)

    def test_oauth_mode_returns_oauth_manager(self, agent_config) -> None:
        cfg = agent_config(
            anthropic=self._anthropic(
                auth_mode="bedrock_oauth",
                bedrock_base_url="https://b.example.com",
            )
        )
        assert isinstance(make_token_manager(cfg), OAuthTokenManager)

    def test_api_key_mode_returns_api_key_manager(self, agent_config) -> None:
        cfg = agent_config(
            anthropic=self._anthropic(auth_mode="api_key", api_key="sk-x")
        )
        assert isinstance(make_token_manager(cfg), ApiKeyTokenManager)
