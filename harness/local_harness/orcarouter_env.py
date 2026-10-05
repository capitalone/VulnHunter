"""OrcaRouter environment bridge for the harness's ``claude`` subprocesses.

The harness drives the ``claude`` CLI directly and relies on the CLI's own
ambient authentication. To route those invocations at OrcaRouter we inject
the inference origin and an API key into the subprocess environment.

The harness is a dev tool with no config file, so it reads the same ``ORCA_*``
environment variables the agent honors. If a key is not supplied via env, it
tries the agent's persisted credential store (an optional dependency here —
imported only when present). Nothing is set unless OrcaRouter is actually
configured, so the harness's default behavior is byte-identical.

There is no OAuth/PKCE here and none should be added: the harness is not a
credential-acquisition surface, it is a consumer of a credential obtained
(either by exporting env or by ``python -m agent --mode=orcarouter login``).
"""

import os

# The CLI appends its version segment to ANTHROPIC_BASE_URL itself, so this
# must be the inference origin WITHOUT a trailing /v1.
_BASE_URL_ENV = "ANTHROPIC_BASE_URL"
_API_KEY_ENV = "ANTHROPIC_API_KEY"

# Env vars the agent also honors, in priority order.
_KEY_ENV_NAMES = ("ORCA_API_KEY", "ORCAROUTER_API_KEY")
_BASE_ENV_NAMES = ("ORCA_API_BASE_URL", "ORCA_BASE_URL")
_DEFAULT_API_BASE = "https://api.orcarouter.ai/v1"


def _configured() -> bool:
    return any(os.environ.get(name) for name in (*_KEY_ENV_NAMES, *_BASE_ENV_NAMES))


def _api_base() -> str:
    for name in _BASE_ENV_NAMES:
        value = os.environ.get(name)
        if value and value.strip():
            return value.strip()
    return _DEFAULT_API_BASE


def _cli_base_url(api_base: str) -> str:
    """Strip a trailing ``/v1`` (the CLI appends its own version segment)."""
    base = api_base.rstrip("/")
    return base[:-3] if base.endswith("/v1") else base


def _api_key() -> str:
    for name in _KEY_ENV_NAMES:
        value = os.environ.get(name)
        if value and value.strip():
            return value.strip()
    # Fall back to the agent's persisted credential store (whatever the user
    # established via API key or OAuth login). Optional: the agent package is
    # a sibling subtree that may not be installed in a harness-only checkout.
    try:
        from agent.config import load_orcarouter_config
        from agent.orcarouter import ConnectCredentialProvider
    except ImportError:
        return ""
    try:
        config = load_orcarouter_config()
        return ConnectCredentialProvider(config).resolve().api_key
    except Exception:
        return ""


def orcarouter_env() -> dict:
    """Return the CLI env overrides for OrcaRouter, or an empty dict."""
    if not _configured():
        return {}
    key = _api_key()
    if not key:
        raise RuntimeError(
            "OrcaRouter is configured (ORCA_* env set) but no API key is "
            "available. Export ORCA_API_KEY, or run "
            "`python -m agent --mode=orcarouter login` first."
        )
    return {_BASE_URL_ENV: _cli_base_url(_api_base()), _API_KEY_ENV: key}


def claude_env() -> dict | None:
    """Environment for a ``claude`` subprocess, or ``None`` to inherit.

    ``None`` (the default when OrcaRouter is not configured) tells the
    ``subprocess`` call to inherit the parent environment unchanged, so the
    harness's existing behavior is preserved exactly.
    """
    overrides = orcarouter_env()
    if not overrides:
        return None
    return {**os.environ, **overrides}
