"""Shared URL helpers for cloning and publishing.

Both the clone stage (cloning the target repo) and the publish stage
(cloning the destination repo and pushing back) need to (a) inject a
GitHub token only into URLs whose host matches the configured one and
(b) redact basic-auth credentials before logging. This module owns those
two operations so neither caller has to reach into the other's privates.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import urlparse, urlunparse

_BASIC_AUTH_RE = re.compile(r"://[^@/]+@")
# Authorization: Bearer/token <secret>  (case-insensitive header name+scheme).
_BEARER_RE = re.compile(r"(?i)(authorization\s*:\s*(?:bearer|token)\s+)(\S+)")
# ?access_token=<secret> / &token=<secret> query parameters.
_QUERY_TOKEN_RE = re.compile(r"(?i)([?&](?:access_token|token)=)([^&\s]+)")
# Raw token prefixes GitHub / Anthropic emit. Prefix is preserved so an
# operator can still tell what kind of token leaked; the secret body is masked.
_RAW_TOKEN_RE = re.compile(
    r"(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|sk-ant-)[A-Za-z0-9_-]+"
)


def redact(text: str) -> str:
    """Mask credentials embedded in ``text`` before it is logged or audited.

    Four passes (CWE-532) — ``text`` is treated as free-form audit content,
    not just a URL:

    1. URL basic-auth (``://userinfo@``).
    2. ``Authorization: Bearer/token <secret>`` header values.
    3. ``?access_token=`` / ``&token=`` query parameters.
    4. Known raw token prefixes (``ghp_``, ``gho_``, ``ghu_``, ``ghs_``,
       ``ghr_``, ``github_pat_``, ``sk-ant-``) — the prefix is preserved so
       the token kind stays identifiable while the secret body is masked.
    """
    s = _BASIC_AUTH_RE.sub("://***@", text)
    s = _BEARER_RE.sub(r"\1***", s)
    s = _QUERY_TOKEN_RE.sub(r"\1***", s)
    s = _RAW_TOKEN_RE.sub(r"\1***", s)
    # Residual risk (VULN-012, CWE-532): redaction is pattern-based over
    # enumerated token formats; a novel/unknown secret format not in the pass
    # list above would still pass through to the audit stream.
    return s


def _normalize_repo_path(path: str) -> str:
    """Normalize a URL path to a bare ``owner/repo`` form for prefix matching.

    Strips the leading/trailing slashes and a trailing ``.git`` so
    ``/acme/shared-libs.git`` and ``acme/shared-libs`` compare equal.
    """
    p = path.strip("/")
    if p.endswith(".git"):
        p = p[:-4]
    return p


def _path_is_authorized(path: str, allowed_path_prefixes: Iterable[str]) -> bool:
    """True if ``path`` falls under one of ``allowed_path_prefixes``.

    A prefix matches when the normalized path equals it or is nested under
    it (``acme`` authorizes ``acme/repo``; ``acme/repo`` authorizes only
    ``acme/repo`` and anything beneath it).
    """
    candidate = _normalize_repo_path(path)
    for raw in allowed_path_prefixes:
        prefix = _normalize_repo_path(raw)
        if not prefix:
            continue
        if candidate == prefix or candidate.startswith(prefix + "/"):
            return True
    return False


def inject_token(
    repo_url: str,
    token: str,
    expected_host: str,
    *,
    allowed_path_prefixes: Iterable[str] | None = None,
) -> str:
    """Return repo_url with the token injected as basic-auth user info.

    Only rewrites HTTPS URLs whose host matches expected_host (case-
    insensitive) and that don't already carry credentials. Non-matching
    URLs are returned unchanged so a token never leaks to a different host.

    ``allowed_path_prefixes`` scopes token attachment by repo path
    (confused-deputy guard, CWE-441):

    * ``None`` (default) — attach on host match, no path restriction. Used
      for the operator-supplied target-repo clone, which is trusted.
    * an iterable (possibly empty) — attach only when the URL path is under
      one of the authorized prefixes. An empty iterable therefore denies all
      token attachment. Used for attacker-influenceable additional-repo
      clones so a same-host but attacker-chosen owner never receives the
      operator's token.
    """
    if not token:
        return repo_url

    parsed = urlparse(repo_url)
    if parsed.scheme not in ("http", "https"):
        return repo_url
    if parsed.username or parsed.password:
        return repo_url
    if not parsed.hostname:
        return repo_url
    if parsed.hostname.lower() != expected_host.lower():
        return repo_url
    if allowed_path_prefixes is not None and not _path_is_authorized(
        parsed.path, allowed_path_prefixes
    ):
        return repo_url

    # GitHub accepts "x-access-token:<token>@host" for both classic PATs and
    # fine-grained tokens.
    netloc = f"x-access-token:{token}@{parsed.hostname}"
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return urlunparse(parsed._replace(netloc=netloc))
