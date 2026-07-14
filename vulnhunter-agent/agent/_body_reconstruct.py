"""Recover an issue body's original text from GitHub's edit history.

GitHub's GraphQL ``userContentEdits`` connection on an Issue returns
a list of edits, each with an ``editedAt`` timestamp and a ``diff``
string field. Despite the field's name, our empirical observation
on GHE Cloud is that **``diff`` is not a unified diff** — it's the
**raw body snapshot at that edit's after-state** (plain text, no
``@@`` hunk headers, no ``+``/``-`` line prefixes). Our design doc
originally assumed the unified-diff semantics the field's name
implies; that assumption is wrong on the API as it actually behaves
today.

Given that, reconstruction is trivial: walk the edits in
oldest-first order and return the OLDEST edit's ``diff`` field —
that's the body in its earliest captured state, which is the
closest we can get to "the body at issue creation time." If there
are zero edits, the body is unchanged from creation and we return
the current body unchanged. Failure modes (a malformed or missing
``editedAt`` on an edit) raise ``DiffApplyError`` so the caller can
abort the verify run cleanly (per design §14 — reconstruction
failure is a hard stop, never a silent best-effort).

Limitation: GitHub does not capture the issue *creation* body as a
``UserContentEdit``. If the very first edit was the user removing
the /vulnhunt markers, the oldest snapshot we see is already
marker-less and reconstruction yields the post-marker-removal
state. Downstream marker extraction then fails by design — better
to refuse than to silently verify the wrong body.
"""

from __future__ import annotations


class DiffApplyError(ValueError):
    """Raised when the edit history can't be used to reconstruct a body.

    Kept under the original name (rather than e.g. ``ReconstructError``)
    so caller error-handling that already catches this exception type
    keeps working after the unidiff approach was abandoned.
    """


def reconstruct_original(
    current_body: str, edits: list[dict]
) -> str:
    """Recover the earliest captured issue body from GitHub's edit
    history.

    ``edits`` is a list of dicts shaped like the GraphQL
    ``UserContentEdit`` nodes: each must have a ``"diff"`` key (the
    body snapshot at that edit's after-state, as plain text) and an
    ``"editedAt"`` key (ISO-8601 timestamp string used to identify
    the oldest entry).

    With zero edits, returns ``current_body`` unchanged (the issue
    body hasn't been touched since creation, so the current REST
    body IS the original).

    With one or more edits, returns the ``diff`` value of the
    oldest edit (the one with the smallest ``editedAt`` timestamp).
    GitHub doesn't surface the literal creation body as an edit
    entry, so the oldest snapshot is the best reconstruction
    available — typically the body in its earliest user-touched
    state. For an issue that was created with /vulnhunt markers
    and only edited (or erased) afterward, this returns a body
    that still contains the markers.

    Raises ``DiffApplyError`` on missing or non-string fields. Never
    partially reconstructs — either we have a valid snapshot for the
    oldest edit or we abort.
    """
    if not edits:
        return current_body
    try:
        sorted_edits = sorted(edits, key=lambda e: e["editedAt"])
    except KeyError as exc:
        raise DiffApplyError(
            f"Edit missing required field: {exc}"
        ) from exc
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
