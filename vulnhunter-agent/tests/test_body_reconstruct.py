"""Tests for ``agent/_body_reconstruct.py``.

GitHub's GraphQL ``UserContentEdit.diff`` field doesn't return a
unified diff — it returns the **body snapshot at that edit's
after-state** (plain text). Reconstruction is therefore a simple
"return the oldest snapshot" operation rather than the unidiff-
based reverse-apply chain the design originally specified.

These tests cover the actual semantics:

- Zero edits → current body unchanged.
- One edit → that edit's ``diff`` IS the recovered body.
- Multiple edits → oldest by ``editedAt`` wins.
- Edits supplied newest-first (matches GitHub's GraphQL ordering)
  must still recover the oldest by timestamp.
- Missing ``editedAt`` / missing ``diff`` / non-string ``diff``
  raise ``DiffApplyError`` so the caller aborts the run cleanly.
- The empirical erase-the-body scenario the design was originally
  built to handle (now trivial: the oldest snapshot has the
  markers).
"""

from __future__ import annotations

import pytest

from agent._body_reconstruct import (
    DiffApplyError,
    reconstruct_original,
)


# ---------- empty / no-op cases --------------------------------------------


def test_empty_edit_list_returns_current_body_unchanged() -> None:
    """Issue was never edited → the current REST body IS the original."""
    body = "the original body\nwith markers\n"
    assert reconstruct_original(body, []) == body


def test_single_edit_recovers_snapshot() -> None:
    """One edit recorded → its ``diff`` field is the recovered body.

    GitHub doesn't capture the issue creation as a UserContentEdit,
    so a "one edit" history means: creation body → state captured
    in edit[0]'s diff. We return edit[0]'s diff as our best
    reconstruction of the original.
    """
    current = "user wiped it"
    snapshot = (
        "## Original Finding\n\n<!-- vulnfix-key: 0123456789abcdef -->\n"
        "<!-- vulnhunt-finding-id: VULN-001 -->\n"
        "<!-- vulnhunt-results-dir: x_VULNHUNT_RESULTS_y -->\n"
    )
    edits = [{"editedAt": "2026-06-27T15:00:00Z", "diff": snapshot}]
    assert reconstruct_original(current, edits) == snapshot


# ---------- multi-edit chains: oldest wins ---------------------------------


def test_oldest_snapshot_wins_when_sorted_oldest_first() -> None:
    older = "ORIGINAL BODY with markers"
    newer = "USER EDITED LATER"
    current = "USER WIPED LAST"
    edits = [
        {"editedAt": "2026-06-27T09:00:00Z", "diff": older},
        {"editedAt": "2026-06-27T15:00:00Z", "diff": newer},
    ]
    assert reconstruct_original(current, edits) == older


def test_oldest_snapshot_wins_when_sorted_newest_first() -> None:
    """GitHub's GraphQL returns edits newest-first. The function
    must internally sort by timestamp, not rely on input order."""
    older = "ORIGINAL BODY with markers"
    newer = "USER EDITED LATER"
    current = "USER WIPED LAST"
    edits = [
        {"editedAt": "2026-06-27T15:00:00Z", "diff": newer},
        {"editedAt": "2026-06-27T09:00:00Z", "diff": older},
    ]
    assert reconstruct_original(current, edits) == older


def test_oldest_wins_across_three_edits() -> None:
    v0 = "ORIGINAL with <!-- vulnfix-key: 0123456789abcdef -->"
    v1 = "user added a typo"
    v2 = "user fixed it back"
    v3 = "user erased everything"
    edits = [
        {"editedAt": "2026-06-27T11:00:00Z", "diff": v2},
        {"editedAt": "2026-06-27T09:00:00Z", "diff": v0},
        {"editedAt": "2026-06-27T13:00:00Z", "diff": v3},
        {"editedAt": "2026-06-27T10:00:00Z", "diff": v1},
    ]
    # Current body is whatever's there now; reconstruct should ignore
    # it whenever edits are present and pick the oldest snapshot.
    assert reconstruct_original("(current body irrelevant)", edits) == v0


# ---------- error paths ----------------------------------------------------


def test_edit_missing_editedAt_field_raises() -> None:
    edits = [{"diff": "snapshot"}]
    with pytest.raises(DiffApplyError, match="editedAt"):
        reconstruct_original("current", edits)


def test_edit_missing_diff_field_raises() -> None:
    """Oldest edit has no ``diff`` key → we have no snapshot to use."""
    edits = [{"editedAt": "2026-06-27T09:00:00Z"}]
    with pytest.raises(DiffApplyError, match="no diff"):
        reconstruct_original("current", edits)


def test_edit_null_diff_field_raises() -> None:
    """``diff`` explicitly null — same failure as missing key, but the
    error message says "no diff" rather than masking it as a
    silent unchanged-body return."""
    edits = [{"editedAt": "2026-06-27T09:00:00Z", "diff": None}]
    with pytest.raises(DiffApplyError, match="no diff"):
        reconstruct_original("current", edits)


def test_edit_non_string_diff_raises() -> None:
    """Defensive — if GitHub ever returns a structured diff object
    instead of a raw string, fail loudly so we notice the schema
    change rather than producing junk."""
    edits = [{"editedAt": "2026-06-27T09:00:00Z", "diff": {"complex": "obj"}}]
    with pytest.raises(DiffApplyError, match="expected string"):
        reconstruct_original("current", edits)


# ---------- realistic GitHub-shaped fixture --------------------------------


def test_erase_then_reconstruct_recovers_markers() -> None:
    """The bug-report scenario: user erases the issue body via the
    GitHub web UI, leaving only "SCOTT ERASED THE EVIDENCE" as the
    current body. GraphQL returns two userContentEdits: the older
    one's ``diff`` is the body in its pre-erasure state (with
    markers); the newer one's ``diff`` is the current body.
    Reconstruction must return the older snapshot so marker
    extraction succeeds."""
    pre_erase_body = (
        "## Security Finding: CWE-400 — example\n"
        "\n"
        "### Finding\n"
        "Body prose here.\n"
        "\n"
        "<!-- vulnfix-key: 0123456789abcdef -->\n"
        "<!-- vulnhunt-finding-id: VULN-001 -->\n"
        "<!-- vulnhunt-results-dir: widget_VULNHUNT_RESULTS_opus47_2026 -->\n"
    )
    current_body = "SCOTT ERASED THE EVIDENCE"
    edits = [
        # GraphQL returns edits newest-first; the field name is
        # "diff" but the value is the body snapshot AT that edit.
        {"editedAt": "2026-06-28T03:06:09Z", "diff": current_body},
        {"editedAt": "2026-06-27T22:47:37Z", "diff": pre_erase_body},
    ]
    recovered = reconstruct_original(current_body, edits)
    assert "<!-- vulnfix-key: 0123456789abcdef -->" in recovered
    assert "<!-- vulnhunt-finding-id: VULN-001 -->" in recovered
    assert (
        "<!-- vulnhunt-results-dir: widget_VULNHUNT_RESULTS_opus47_2026 -->"
        in recovered
    )
