"""Resolve optional per-repo metadata tags stamped onto findings records.

The findings stream can carry an arbitrary, operator-defined set of
string fields describing the target's operational context (e.g. an
application identifier, an owning team, a component name). Which fields
exist — and where they come from — is fully configurable:

- ``[repo_properties].github_property_map`` in the agent config maps a
  GitHub custom-property name (as returned by
  ``GET /repos/{owner}/{repo}/properties/values``) to the field name
  emitted on the findings stream.
- ``--repo-property NAME=VALUE`` on ``python -m agent`` supplies per-run
  overrides keyed by the emitted field name.

Values are resolved with the following precedence (highest wins):

1. **CLI override** — explicit operator input always wins.
2. **GitHub custom properties** — fetched per the configured map.
3. **Blank** — every field is optional; a field with no value is
   dropped from the emitted findings record.

When the configured map is empty and no CLI overrides are given, no
properties are fetched or emitted. Failures fetching from GitHub (no
token, 404, network error) are logged and downgraded to blank — the
audit trail continues.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

from ._github import api_base, parse_owner_repo
from .auth import resolve_verify
from .config import AgentConfig
from .token_client import BrokerTokenAuth, get_github_token

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RepoProperties:
    """Resolved metadata tags: emitted field name → string value.

    A thin value object over an ordered mapping. Empty by default;
    blank values are dropped when the findings record is emitted.
    """

    values: dict[str, str] = field(default_factory=dict)

    def is_empty(self) -> bool:
        return not any(self.values.values())

    def get(self, name: str) -> str:
        return self.values.get(name, "")


def resolve(
    *,
    cli_overrides: RepoProperties,
    github: RepoProperties | None,
) -> RepoProperties:
    """Apply CLI-over-GitHub-over-blank precedence to produce the final values.

    Overlay is per-field, not per-record: a CLI-supplied value for one
    field still lets a GitHub-supplied value for a *different* field
    through. The result is the union of both key sets, with a non-blank
    CLI value winning any collision.
    """
    fetched = github.values if github is not None else {}
    merged: dict[str, str] = dict(fetched)
    for key, value in cli_overrides.values.items():
        if value:
            merged[key] = value
        else:
            merged.setdefault(key, value)
    return RepoProperties(values=merged)


def fetch_from_github(
    repo_url: str,
    *,
    config: AgentConfig,
    timeout_seconds: int = 30,
) -> RepoProperties:
    """Best-effort ``GET /repos/{owner}/{repo}/properties/values``.

    Returns an empty ``RepoProperties`` when no property map is
    configured (the feature is opt-in) or on ANY failure (missing token,
    404, network error, malformed response). The audit trail continues
    without the fields rather than aborting the scan — the fields are
    optional and the caller has an explicit CLI override path when
    GitHub is unreachable.

    Auth uses the ``scan`` role token, matching the pattern in
    ``issues_fetch.py`` — this is a read on the target repo, same
    trust boundary as cloning + listing issues.
    """
    property_map = config.repo_properties.github_property_map
    if not property_map:
        # Nothing configured to fetch — skip the round-trip entirely.
        return RepoProperties()

    try:
        owner, name = parse_owner_repo(repo_url)
    except Exception as exc:  # noqa: BLE001
        logger.info(
            "Skipping GitHub properties fetch: cannot parse owner/repo "
            "from %r (%s)",
            repo_url,
            exc,
        )
        return RepoProperties()

    token = get_github_token("scan", config)
    if not token:
        logger.info(
            "Skipping GitHub properties fetch: no scan_token configured "
            "for %s/%s (fields will be blank unless overridden by CLI).",
            owner,
            name,
        )
        return RepoProperties()

    api = api_base(config.github.host)
    url = f"{api}/repos/{owner}/{name}/properties/values"
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    verify = resolve_verify(config.tls)

    try:
        with httpx.Client(
            verify=verify,
            timeout=timeout_seconds,
            headers=headers,
            auth=BrokerTokenAuth("scan", config),
        ) as client:
            resp = client.get(url)
    except httpx.HTTPError as exc:
        logger.warning(
            "GitHub properties fetch failed for %s/%s: %s (fields blank)",
            owner,
            name,
            exc,
        )
        return RepoProperties()

    if resp.status_code == 404:
        # Repo has no custom properties defined — normal case.
        logger.info(
            "GitHub returned 404 on properties/values for %s/%s "
            "(no custom properties defined).",
            owner,
            name,
        )
        return RepoProperties()
    if resp.status_code in (401, 403):
        logger.warning(
            "GitHub denied properties access for %s/%s (status %d); "
            "fields blank.",
            owner,
            name,
            resp.status_code,
        )
        return RepoProperties()
    if resp.status_code >= 400:
        logger.warning(
            "GitHub properties fetch returned %d for %s/%s: %s",
            resp.status_code,
            owner,
            name,
            resp.text[:200],
        )
        return RepoProperties()

    try:
        payload = resp.json()
    except ValueError as exc:
        logger.warning(
            "GitHub properties response is not JSON for %s/%s: %s",
            owner,
            name,
            exc,
        )
        return RepoProperties()

    return _coerce_from_payload(payload, property_map)


def _coerce_from_payload(
    payload: Any, property_map: dict[str, str]
) -> RepoProperties:
    """Convert the ``[{property_name, value}, ...]`` list into a dataclass.

    ``property_map`` maps GitHub property names to emitted field names;
    properties not in the map are ignored.
    """
    if not isinstance(payload, list):
        logger.warning(
            "GitHub properties payload is not a list (got %s); ignoring.",
            type(payload).__name__,
        )
        return RepoProperties()
    values: dict[str, str] = {}
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        prop = entry.get("property_name")
        if not isinstance(prop, str):
            continue
        field_name = property_map.get(prop)
        if field_name is None:
            continue
        values[field_name] = _stringify(entry.get("value"))
    return RepoProperties(values=values)


def _stringify(value: Any) -> str:
    """Normalize GitHub property values to a single string.

    Custom-property types on GitHub can be ``string``, ``single_select``,
    or ``multi_select``. Multi-select returns a JSON array — join with
    commas so a single string field can carry the whole set. ``None``
    (property defined but unset) maps to blank.
    """
    if value is None:
        return ""
    if isinstance(value, list):
        return ",".join(str(v).strip() for v in value if v is not None)
    return str(value).strip()
