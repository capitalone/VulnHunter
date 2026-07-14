"""Shared GitHub helpers used by the publish and issues stages.

Owns the small bits both stages need: REST API base URL resolution,
owner/repo extraction from a clone URL, and the YYYY-MM-DD-HHMMSS
suffix parser used to namespace per-run results directories.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse


# Skill convention: results dirs end in YYYY-MM-DD-HHMMSS (see SKILL.md
# step 2). The publish stage promotes the timestamp to its own path
# segment so a single day's runs sort cleanly under each (owner, repo).
_TIMESTAMP_RE = re.compile(r"(\d{4}-\d{2}-\d{2}-\d{6})$")


class GitHubURLError(ValueError):
    """Raised when a URL can't be parsed as a GitHub repo URL."""


def api_base(host: str) -> str:
    """Resolve the REST API root for a GitHub host.

    github.com → https://api.github.com
    GitHub Enterprise Server → https://<host>/api/v3
    """
    if host == "github.com" or host.endswith(".github.com"):
        return "https://api.github.com"
    return f"https://{host}/api/v3"


def parse_owner_repo(repo_url: str) -> tuple[str, str]:
    """Extract (owner, name) from a GitHub repo URL.

    Handles both https://host/owner/repo(.git) and the SSH-style
    git@host:owner/repo(.git). Tree URLs like
    https://github.com/owner/repo/tree/main are tolerated — we always
    take the first two path segments.
    """
    parsed = urlparse(repo_url)
    if parsed.scheme in ("http", "https"):
        path = parsed.path or ""
    elif ":" in repo_url and "://" not in repo_url:
        path = repo_url.split(":", 1)[1]
    else:
        path = parsed.path or repo_url
    path = path.strip("/")
    if path.endswith(".git"):
        path = path[: -len(".git")]
    parts = [p for p in path.split("/") if p]
    if len(parts) < 2:
        raise GitHubURLError(f"can't parse <owner>/<repo> from {repo_url}")
    return parts[0], parts[1]


def extract_timestamp(results_dir_name: str) -> str:
    """Return the YYYY-MM-DD-HHMMSS suffix of a results dir, or 'unknown'."""
    match = _TIMESTAMP_RE.search(results_dir_name)
    return match.group(1) if match else "unknown"
