"""Issue intake primitives for in-place mode.

Ported (and simplified) from the upstream vulnhunter agent under
`../sdk/vulnhunter/agent/`. Three responsibilities:

1. **Marker extraction.** Pull the three machine markers /vulnhunt
   embeds in every issue it posts (`vulnfix-key`, `vulnhunt-finding-id`,
   `vulnhunt-results-dir`) from a body string.
2. **Body reconstruction.** If a developer edited the issue body, walk
   the GraphQL `userContentEdits` snapshots and return the oldest one.
   (Currently unused — the v1 in-place flow trusts current bodies and
   skips edited ones. Reserved for re-adding tampered-body recovery.)
3. **Homogeneity check.** A single in-place run must operate against
   exactly one (owner, repo, results_dir) tuple — same constraint
   verify enforces so all findings tie back to the same scan.

This module is `gh`-shell-out free and network-free. The prompt
(`parse_issues.md`) gathers raw issue JSON via `gh` in Bash blocks,
then calls these primitives from a `python3 -c` snippet.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass


# ---- markers ---------------------------------------------------------------


# Anchored to the HTML-comment open/close so stray prose in the body
# can't false-match. Case-insensitive to match what verify accepts.
_RE_VULNFIX_KEY = re.compile(
    r"<!--\s*vulnfix-key:\s*([0-9a-f]{16})\s*-->", re.IGNORECASE
)
_RE_FINDING_ID = re.compile(
    r"<!--\s*vulnhunt-finding-id:\s*(VULN-\d{3})\s*-->", re.IGNORECASE
)
_RE_RESULTS_DIR = re.compile(
    r"<!--\s*vulnhunt-results-dir:\s*([^\s<>]+)\s*-->", re.IGNORECASE
)


class MarkerExtractionError(ValueError):
    """One of the three machine markers is missing or malformed."""


@dataclass(frozen=True)
class ExtractedMarkers:
    vulnfix_key: str    # 16 lowercase hex chars — SHA-256 prefix
    finding_id: str     # VULN-NNN
    results_dir: str    # results-dir basename


def extract_markers(body: str, *, source_label: str = "issue body") -> ExtractedMarkers:
    """Pull the three /vulnhunt machine markers out of an issue body.

    Raises `MarkerExtractionError` naming the missing marker(s) if any
    of the three can't be found. `source_label` is included in the
    error message so the caller's log can distinguish "current body"
    from "reconstructed original body" failures.
    """
    m_key = _RE_VULNFIX_KEY.search(body)
    m_id = _RE_FINDING_ID.search(body)
    m_dir = _RE_RESULTS_DIR.search(body)
    missing: list[str] = []
    if m_key is None:
        missing.append("vulnfix-key")
    if m_id is None:
        missing.append("vulnhunt-finding-id")
    if m_dir is None:
        missing.append("vulnhunt-results-dir")
    if missing:
        raise MarkerExtractionError(
            f"{source_label}: missing required marker(s): {', '.join(missing)}"
        )
    assert m_key is not None and m_id is not None and m_dir is not None
    return ExtractedMarkers(
        vulnfix_key=m_key.group(1).lower(),
        finding_id=m_id.group(1).upper(),
        results_dir=m_dir.group(1),
    )


# ---- body reconstruction --------------------------------------------------


class DiffApplyError(ValueError):
    """Edit history can't be used to reconstruct an original body."""


def reconstruct_original(current_body: str, edits: list[dict]) -> str:
    """Recover the earliest captured issue body from GitHub's edit history.

    `edits` is a list of dicts shaped like GraphQL `UserContentEdit`
    nodes — each must have `"editedAt"` (ISO-8601 string) and `"diff"`
    (the body snapshot at that edit's after-state; despite the name,
    not a unified diff). With zero edits the current body is returned
    unchanged. With one or more, the oldest snapshot's `diff` is
    returned — the closest available to the body at creation time.

    Raises `DiffApplyError` on missing or non-string fields.
    """
    if not edits:
        return current_body
    try:
        sorted_edits = sorted(edits, key=lambda e: e["editedAt"])
    except KeyError as exc:
        raise DiffApplyError(f"Edit missing required field: {exc}") from exc
    oldest = sorted_edits[0]
    snapshot = oldest.get("diff")
    if snapshot is None:
        raise DiffApplyError(
            f"Oldest edit at {oldest.get('editedAt', '?')} has no diff "
            "(body-snapshot) field; cannot reconstruct original body."
        )
    if not isinstance(snapshot, str):
        raise DiffApplyError(
            f"Oldest edit's diff field is {type(snapshot).__name__}, "
            "expected string."
        )
    return snapshot


# ---- homogeneity ----------------------------------------------------------


@dataclass(frozen=True)
class IssueRecord:
    """One harvested issue plus its extracted markers."""

    owner: str
    repo: str
    number: int
    url: str
    title: str
    body_tampered: bool
    original_body: str
    markers: ExtractedMarkers


def enforce_homogeneity(records: list[IssueRecord]) -> tuple[str, str, str]:
    """Confirm every record shares (owner, repo, results_dir).

    Returns the shared tuple. Raises `ValueError` listing distinct
    tuples otherwise. Same invariant verify enforces — one report per
    run, all findings tie back to the same scan.
    """
    if not records:
        raise ValueError("No issues to enforce homogeneity over")
    keys = {
        (r.owner.lower(), r.repo.lower(), r.markers.results_dir)
        for r in records
    }
    if len(keys) == 1:
        owner, repo, results_dir = next(iter(keys))
        return owner, repo, results_dir
    rendered = "\n".join(
        f"  - {o}/{r} @ {rd}" for o, r, rd in sorted(keys)
    )
    raise ValueError(
        "In-place run requires all issues to share the same "
        "(repo, scan_id). Got:\n" + rendered
    )


# ---- vulnfix key ----------------------------------------------------------


# Match `CWE-NNN` anywhere in a CWE string. The upstream agent writes
# only the primary CWE into issue body markers, so when callers pass a
# multi-CWE string like "CWE-918 / CWE-74" we must hash the first one.
# Same normalization parse_results.primary_cwe uses — kept in sync.
_PRIMARY_CWE_RE = re.compile(r"CWE-\d+")


def _primary_cwe(cwe: str) -> str:
    m = _PRIMARY_CWE_RE.search(cwe or "")
    return m.group(0) if m else ""


def compute_vulnfix_key(location: str, cwe: str, root_cause: str) -> str:
    """SHA-256 prefix used as a cross-scan idempotency marker.

    Same definition vulnhunter, verify, vulnhunter-fix and
    parse_results all use — so a finding parsed by parse_results
    (which may carry a multi-CWE string) collides with the issue
    body marker (which carries only the primary). Both sides must
    normalize to the primary CWE first.
    """
    raw = f"{location}|{_primary_cwe(cwe)}|{root_cause}".encode()
    return hashlib.sha256(raw).hexdigest()[:16]
