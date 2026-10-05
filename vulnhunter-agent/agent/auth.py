"""Anthropic auth providers for the agent.

Three token providers share a ``get_valid_token()`` interface so call sites
don't care which auth mode is active:

- ``ApiKeyTokenManager`` — direct Anthropic API. ``get_valid_token()``
  returns the configured API key verbatim (no network, no expiry).
- ``OAuthTokenManager`` — OAuth2 client-credentials flow: redeem
  client_id + client_secret against the token endpoint, cache the access
  token, and refresh after a fraction of its declared lifetime. The bearer
  is forwarded to a Bedrock proxy as ANTHROPIC_AUTH_TOKEN.
- ``SigV4TokenManager`` — Amazon Bedrock with SigV4 request signing. There
  is no bearer token: the bundled Claude Code CLI signs each request with
  the standard AWS credential chain (env vars, shared config/credentials,
  SSO, container/instance role). ``get_valid_token()`` returns an empty
  string so the shared call-site interface is preserved.

``make_token_manager(config)`` returns the right one for the configured
``anthropic.auth_mode``.

TLS trust store resolution (OAuth path):
    1. tls.ssl_cert_path from config, if set
    2. system trust (httpx default, backed by certifi)
"""

from __future__ import annotations

import logging
import time
from typing import Protocol

import httpx

from .config import AgentConfig, OAuthConfig, TLSConfig

logger = logging.getLogger(__name__)


class TokenProvider(Protocol):
    """The shared interface every auth-mode token manager implements.

    Call sites annotate against this instead of a concrete manager so they
    stay auth-mode agnostic (see ``make_token_manager``).
    """

    def get_valid_token(self) -> str: ...


class AuthTokenError(RuntimeError):
    """Raised when the OAuth token endpoint refuses or misbehaves."""


def resolve_verify(tls: TLSConfig) -> str | bool:
    """Resolve the verify= parameter passed to httpx for TLS validation."""
    if tls.ssl_cert_path:
        logger.info("Using CA bundle from config: %s", tls.ssl_cert_path)
        return tls.ssl_cert_path
    return True


class ApiKeyTokenManager:
    """Token provider for direct Anthropic API auth.

    Mirrors :class:`OAuthTokenManager`'s ``get_valid_token()`` interface so
    the rest of the agent is auth-mode agnostic. Returns the configured API
    key unchanged; there is nothing to mint or refresh.
    """

    def __init__(self, api_key: str, name: str = "vulnhunter"):
        self._api_key = api_key
        self._name = name

    def get_valid_token(self) -> str:
        return self._api_key


class SigV4TokenManager:
    """Token provider for Amazon Bedrock SigV4 auth.

    No bearer token exists in this mode: the bundled Claude Code CLI signs
    Bedrock requests with the standard AWS credential chain. This provider
    exists only to satisfy the shared ``get_valid_token()`` interface, so
    every call site (LLM calls, issues, verify) stays auth-mode agnostic.
    Returns an empty string — ``build_settings`` deliberately omits
    ``ANTHROPIC_AUTH_TOKEN`` for this mode, so the empty value is never
    consumed as a credential.
    """

    def __init__(self, name: str = "vulnhunter"):
        self._name = name

    def get_valid_token(self) -> str:
        return ""


class OAuthTokenManager:
    def __init__(self, oauth: OAuthConfig, tls: TLSConfig, name: str = "vulnhunter"):
        self._oauth = oauth
        self._tls = tls
        self._name = name
        self._access_token: str | None = None
        self._token_expiry: float | None = None
        self._verify = resolve_verify(tls)

    def get_valid_token(self) -> str:
        if (
            self._access_token is None
            or self._token_expiry is None
            or time.time() >= self._token_expiry
        ):
            logger.info("%s token expired or missing, refreshing...", self._name)
            return self._refresh()
        return self._access_token

    def _refresh(self) -> str:
        try:
            with httpx.Client(verify=self._verify) as client:
                response = client.post(
                    self._oauth.token_endpoint,
                    data={
                        "grant_type": "client_credentials",
                        "client_id": self._oauth.client_id,
                        "client_secret": self._oauth.client_secret,
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=self._oauth.http_timeout_seconds,
                )
        except httpx.TimeoutException as exc:
            raise AuthTokenError(f"Token request timed out: {exc}") from exc
        except httpx.RequestError as exc:
            raise AuthTokenError(f"Token request connection error: {exc}") from exc

        if response.status_code != 200:
            raise AuthTokenError(
                f"Token request failed: {response.status_code} - {response.text}"
            )

        body = response.json()
        if "access_token" not in body:
            raise AuthTokenError(
                f"No access_token in response (keys: {list(body.keys())})"
            )

        lifetime = int(body.get("expires_in", self._oauth.default_lifetime_seconds))
        self._access_token = str(body["access_token"])
        self._token_expiry = time.time() + (lifetime * self._oauth.expiry_safety_factor)
        logger.info("%s token refreshed; expires in %ds", self._name, lifetime)
        return self._access_token


def make_token_manager(
    config: AgentConfig, name: str = "vulnhunter"
) -> ApiKeyTokenManager | OAuthTokenManager | SigV4TokenManager:
    """Return the Anthropic token provider for the configured auth mode.

    All providers expose ``get_valid_token()``, so callers can use the
    result without caring whether auth is API-key, Bedrock/OAuth, or
    Bedrock/SigV4.
    """
    if config.anthropic.auth_mode == "bedrock_oauth":
        return OAuthTokenManager(config.oauth, config.tls, name=name)
    if config.anthropic.auth_mode == "bedrock_sigv4":
        return SigV4TokenManager(name=name)
    return ApiKeyTokenManager(config.anthropic.api_key, name=name)
