"""Origin/path handling for the OrcaRouter provider.

Authentication and inference live on DIFFERENT public origins and use
different path layouts. The fixed paths here are the single source of
truth for the provider so nothing derives one origin from the other by
swapping a hostname or blindly appending ``/v1``:

* authorize  — ``{auth_base}/auth``
* exchange   — ``{auth_base}/api/v1/auth/keys``   (NOT ``/v1/auth/keys``)
* catalog    — ``{api_base}/models``
"""

from __future__ import annotations

from urllib.parse import urlparse

# Fixed auth paths (OrcaRouter API).
AUTHORIZE_PATH = "/auth"
EXCHANGE_PATH = "/api/v1/auth/keys"

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


class OriginError(ValueError):
    """An OrcaRouter origin is malformed or violates the network policy."""


def validated_origin(url: str, *, what: str) -> str:
    """Validate and normalize a base URL, returning it without a trailing ``/``.

    Requires an ``http``/``https`` scheme and a host, rejects embedded
    userinfo, and enforces HTTPS for anything that is not loopback. HTTP is
    permitted only for loopback development (``localhost`` / ``127.0.0.1`` /
    ``[::1]``), which is also what the OAuth callback URL rules allow.
    """
    text = (url or "").strip()
    if not text:
        raise OriginError(f"{what} must not be empty")
    parsed = urlparse(text)
    if parsed.scheme not in ("http", "https"):
        raise OriginError(f"{what} must be an http(s) URL, got {text!r}")
    if parsed.username or parsed.password:
        raise OriginError(f"{what} must not embed userinfo credentials")
    host = (parsed.hostname or "").lower()
    if not host:
        raise OriginError(f"{what} must include a host, got {text!r}")
    if parsed.scheme == "http" and host not in _LOOPBACK_HOSTS:
        raise OriginError(
            f"{what} must use HTTPS for a non-loopback host, got {text!r}"
        )
    return text.rstrip("/")


def join_path(base: str, path: str) -> str:
    """Join a validated base URL with a fixed absolute path."""
    return base.rstrip("/") + "/" + path.lstrip("/")


def cli_base_url(api_base_url: str) -> str:
    """Derive the Claude Code CLI ``ANTHROPIC_BASE_URL`` from the API base.

    The CLI appends ``/v1/messages`` to ``ANTHROPIC_BASE_URL`` itself, so
    pointing it at the ``/v1`` inference base double-appends the segment and
    the request 404s. We therefore strip a trailing ``/v1`` from the SAME
    configured API origin (never from a different origin) so a self-hosted
    override keeps working.
    """
    base = api_base_url.rstrip("/")
    if base.endswith("/v1"):
        base = base[:-3]
    return base
