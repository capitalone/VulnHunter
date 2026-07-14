"""Agent-side accessor for GitHub identity tokens.

The agent has two GitHub identities — ``scan`` (clone target + post
issues) and ``reports`` (push report + read prior report). At runtime,
the agent never resolves these from its own config: it asks this module
for the right token by role at the moment of use, per spec
TOKEN-CLIENT-001/002/003/004.

Two modes:

- **Standalone**: ``[github] broker_token_dir`` is empty. ``get_github_token``
  returns the literal ``scan_token`` / ``reports_token`` from config —
  typically a classic PAT or fine-grained token supplied via TOML or env.

- **Broker** (``broker_token_dir`` set):
  ``broker_token_dir`` is a directory an external parent process
  populates with one JSON file per role
  (``scan.json`` / ``reports.json``). Each file contains
  ``{"token": "...", "expires_at": "...", "app_id": "..."}``. The wrapper
  refreshes these files every 30s; this module just reads them on demand.
  There is intentionally NO in-agent cache — the broker is the cache.

Callers should use ``BrokerTokenAuth`` (an ``httpx.Auth`` subclass) when
constructing httpx clients, rather than capturing ``get_github_token``'s
return into a long-lived ``headers`` dict. The Auth class re-resolves the
token on every outgoing request, so the no-cache contract holds at the
request boundary — not just at the call-site boundary.

The 50ms retry-once on FileNotFoundError / JSONDecodeError absorbs the
atomic-rename window between the wrapper's tmpfile write and the
``os.rename`` onto the canonical path (TOKEN-FILE-002). The retry is
deliberately short so callers stay snappy; a persistent missing-file
condition surfaces as the underlying exception after one extra read.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Literal

import httpx

from .config import AgentConfig

logger = logging.getLogger(__name__)

GitHubRole = Literal["scan", "reports"]

_RETRY_SLEEP_SECONDS = 0.050


def get_github_token(role: GitHubRole, config: AgentConfig) -> str:
    """Return the bearer token for ``role`` ('scan' or 'reports')."""
    broker_dir = config.github.broker_token_dir
    if broker_dir:
        return _read_broker_file(role, Path(broker_dir))
    if role == "scan":
        return config.github.scan_token
    if role == "reports":
        return config.github.reports_token
    raise ValueError(f"unknown GitHub role: {role!r}")


class BrokerTokenAuth(httpx.Auth):
    """Per-request token resolution for the agent's GitHub API calls.

    Hooks into httpx's ``auth_flow`` so that ``get_github_token`` runs on
    every outgoing request, not once per session. This makes the
    no-in-agent-cache contract (TOKEN-CLIENT-004) hold at the *request*
    boundary, not just at the function-call boundary — so a long-running
    httpx.Client / AsyncClient that crosses the broker daemon's refresh
    point picks up the new token transparently instead of 401'ing on the
    remaining requests.

    Works for both ``httpx.Client`` (sync) and ``httpx.AsyncClient``
    because ``httpx.Auth.auth_flow`` is a synchronous generator that
    httpx invokes from either context.
    """

    requires_request_body = False
    requires_response_body = False

    def __init__(self, role: GitHubRole, config: AgentConfig):
        self._role = role
        self._config = config

    def auth_flow(self, request: httpx.Request):
        token = get_github_token(self._role, self._config)
        request.headers["Authorization"] = f"Bearer {token}"
        yield request


def _read_broker_file(role: GitHubRole, broker_dir: Path) -> str:
    path = broker_dir / f"{role}.json"
    try:
        return _read_token_field(path)
    except (FileNotFoundError, json.JSONDecodeError):
        time.sleep(_RETRY_SLEEP_SECONDS)
        return _read_token_field(path)


def _read_token_field(path: Path) -> str:
    data = json.loads(path.read_text())
    token = data.get("token")
    if not isinstance(token, str) or not token:
        raise ValueError(
            f"broker token file at {path} missing or has empty 'token' field"
        )
    return token
