"""Delivery-time honesty guards and helpers (REQ-HON-005..009).

Consumed by delivery-time prompts (``prompts/deliver.md``) and by tests
(``tests/test_hand_wave_guard.py``).

Public surface:

- Constants: ``HAND_WAVE_PATTERNS``, ``TIER_ONE_LINERS``, ``SAFE_PHRASE_PATTERNS``
- Exceptions: ``HonestyGuardError``, ``HandWaveResidualError``,
  ``EmptyResidualError``, ``FullTierWithResidualsError``
- Guards: ``check_hand_wave``, ``check_tier_residual_consistency``
- Renderers: ``render_residual_risk_section``, ``render_pr_body_with_residuals``
- Helpers: ``pr_draft_state_for_tier``, ``cwe_to_descriptor``,
  ``compute_masked_branch_name``, ``compute_idempotency_key``

Verification-table rendering lands with Bundle 2; the Gate 1 mirror of
``SAFE_PHRASE_PATTERNS`` lives in ``scripts/check-severity-mask.py`` and is
kept byte-identical by ``scripts/safe-phrase-sync-lint.py`` (REQ-GAT-008).

Branch-naming helpers (``cwe_to_descriptor``, ``compute_masked_branch_name``)
were restored here after ``headless/scripts/deliver_repo.py`` was removed
in commit e782ac5 (main). ``prompts/implement.md`` and ``prompts/plan.md``
now import from this module.
"""

from __future__ import annotations

import hashlib
import html
import re


# CANON-44: residual_vectors entries are LLM/finding-derived and get
# interpolated into the '## Residual Risk' markdown appended to the PR/issue
# body. The hand-wave / consistency guards reject vague or empty entries but do
# NOT escape, so an entry could carry raw HTML (``<script>``) or a markdown
# link (``[x](javascript:...)``) into the rendered body (CWE-79 / CWE-116).
# Neutralize each entry so metacharacters render as literal text: html.escape
# handles angle brackets / ampersands; backslash-escaping the markdown
# link/code metacharacters neutralizes ``[text](url)`` and inline code.
_RESIDUAL_MD_ESCAPE_CHARS = ("\\", "`", "[", "]")


def _escape_residual_entry(entry) -> str:
    """Neutralize markdown/HTML metacharacters in a residual-vector entry so it
    renders as literal text inside the '## Residual Risk' bullet list."""
    s = html.escape(str(entry), quote=False)
    for ch in _RESIDUAL_MD_ESCAPE_CHARS:
        s = s.replace(ch, "\\" + ch)
    return s


# REQ-HON-006 hand-wave regex source of truth.
HAND_WAVE_PATTERNS = (
    "future work", "more work needed", "to be done", "tbd", "later",
    # Vague-assurance hand-waves: a residual that claims the risk is already
    # handled is not a residual (12-seg review S3).
    "adequately handled", "adequately handles", "properly validated",
    "properly handled", "handled properly", "handled safely",
)
_HAND_WAVE_RE = re.compile(
    "|".join(re.escape(p) for p in HAND_WAVE_PATTERNS), re.IGNORECASE
)

TIER_ONE_LINERS = {
    "MITIGATION": "partially blocked; residual exposure remains",
    "WORKAROUND": "not blocked; a compensating control was applied instead",
}


# REQ-GAT-002 / REQ-GAT-008: canonical safe-list. See references/severity-mask-rule.md.
# The tuple is byte-compared against scripts/check-severity-mask.py by
# scripts/safe-phrase-sync-lint.py in CI. Do not add phrases without updating
# both sides in the same PR.
SAFE_PHRASE_PATTERNS = (
    "non-critical",
    "criticality",
    "Critical Section",
    "criticism",
    "critique",
)


# REQ-GRA-011: canonical 8-column verification table headers. Consumed by
# render_verification_table below and validated by
# scripts/validate-verification.py.
VERIFICATION_TABLE_HEADERS = (
    "#",
    "VULN-NNN",
    "Stated vector closed?",
    "Test exercises real attack?",
    "Default fail-closed?",
    "Residual risk documented?",
    "All call sites covered?",
    "Sweep complete?",
    "Verdict",
)


class HonestyGuardError(Exception):
    """Raised when a honesty guard refuses to render a PR/issue body."""


class HandWaveResidualError(HonestyGuardError):
    """REQ-HON-006: residual entry matches the hand-wave regex."""


class EmptyResidualError(HonestyGuardError):
    """REQ-HON-007: completeness_tier != FULL but residual_vectors is empty."""


class FullTierWithResidualsError(HonestyGuardError):
    """result-schema R-2: completeness_tier == FULL requires empty residual_vectors."""


def check_hand_wave(residual_vectors):
    """Raise HandWaveResidualError if any entry matches the hand-wave regex.

    REQ-HON-006. Returns None on clean input.
    """
    for entry in residual_vectors or ():
        if _HAND_WAVE_RE.search(entry):
            raise HandWaveResidualError(
                f"residual entry matches hand-wave regex (REQ-HON-006): {entry!r}"
            )


def check_tier_residual_consistency(tier, residual_vectors):
    """Enforce REQ-HON-005 / REQ-HON-007 / result-schema R-1/R-2 cross-field rule.

    - tier != FULL and empty residuals → EmptyResidualError.
    - tier == FULL and non-empty residuals → FullTierWithResidualsError.
    """
    is_full = tier == "FULL"
    has_residuals = bool(residual_vectors)
    if is_full and has_residuals:
        raise FullTierWithResidualsError(
            "completeness_tier == FULL requires empty residual_vectors[] "
            "(REQ-HON-005; schema R-2)"
        )
    if (not is_full) and (not has_residuals):
        raise EmptyResidualError(
            f"completeness_tier == {tier} requires non-empty residual_vectors[] "
            "(REQ-HON-007)"
        )


def render_residual_risk_section(vuln_id, tier, residual_vectors, issue_number=None):
    """Render the '## Residual Risk' section from templates/residual_risk_section.md.

    Applies REQ-HON-006 / REQ-HON-007 / REQ-HON-009. Returns the rendered
    Markdown string. Raises HonestyGuardError subclasses on guard failure.
    Returns empty string when tier == FULL (no section rendered).
    """
    check_tier_residual_consistency(tier, residual_vectors)
    if tier == "FULL":
        return ""
    check_hand_wave(residual_vectors)

    bullets = "\n".join(
        f"- {_escape_residual_entry(entry)}" for entry in residual_vectors
    )
    one_liner = TIER_ONE_LINERS.get(tier, "not fully closed")
    issue_ref = f" (see #{issue_number})" if issue_number else ""
    return (
        "## Residual Risk\n\n"
        f"This fix ships as **{tier}** — the stated attack vector is "
        f"{one_liner}. The following vectors remain open and require "
        f"follow-up work{issue_ref}:\n\n"
        f"{bullets}\n"
    )


def render_pr_body_with_residuals(vuln_id, tier, residual_vectors, base_body=""):
    """Render a PR body with the Residual Risk section appended.

    Wraps ``render_residual_risk_section`` for the test surface that TS-2
    (``tests/test_hand_wave_guard.py``) exercises. Returns ``base_body``
    unchanged when tier == FULL.
    """
    section = render_residual_risk_section(vuln_id, tier, residual_vectors)
    if not section:
        return base_body
    if not base_body:
        return section
    return base_body.rstrip() + "\n\n" + section


def pr_draft_state_for_tier(tier):
    """REQ-HON-008: WORKAROUND opens Draft, FULL and MITIGATION open Ready."""
    return tier == "WORKAROUND"


# ---------- Verification table (Bundle 2b, REQ-GRA-011 / REQ-GRA-013 / REQ-GRA-014) ----------


def _column7_cell(graph_callers, routed_callers, sidecar_confidence):
    """Render the `All call sites covered?` cell with truncation policy.

    REQ-GRA-013: enumerate all callers ≤ 20; when > 20, list the first 20
    lexicographic + `... N more via callers_of()`. REQ-GRA-020: annotate
    with `(grep_fallback)` under confidence=low.
    """
    routed = set(routed_callers or ())
    graph = list(graph_callers or ())
    if not graph:
        return "n/a"
    if not routed.issuperset(set(graph)) and sidecar_confidence == "high":
        return "no"

    total = len(graph)
    ordered = sorted(graph)
    if total <= 20:
        listed = " ".join(f"({c})" for c in ordered)
        anno = " (grep_fallback)" if sidecar_confidence == "low" else ""
        return f"yes{anno} {listed}".strip()

    head = ordered[:20]
    remaining = total - 20
    listed = " ".join(f"({c})" for c in head)
    anno = " (grep_fallback)" if sidecar_confidence == "low" else ""
    return f"yes{anno} {listed} ... {remaining} more via callers_of()".strip()


def _derive_verdict(row_cells):
    """Compute the Verdict cell from the seven data cells per REQ-GRA-014."""
    stated_closed, test_real, fail_closed, residual_doc, callers_covered, sweep_ok = row_cells

    def is_yes(v):
        return v.strip().lower().startswith("yes")

    def is_no(v):
        return v.strip().lower() == "no"

    def is_na(v):
        return v.strip().lower() in ("n/a", "na")

    if is_no(stated_closed):
        return "NEEDS_REWORK — stated vector not closed"
    if is_no(test_real):
        return "NEEDS_REWORK — test does not exercise real attack"
    if is_no(residual_doc):
        return "NEEDS_REWORK — non-FULL tier missing residual documentation"

    yes_or_na = lambda v: is_yes(v) or is_na(v)  # noqa: E731
    if (is_yes(stated_closed) and is_yes(test_real) and is_yes(fail_closed)
            and yes_or_na(residual_doc) and yes_or_na(callers_covered) and yes_or_na(sweep_ok)):
        return "FULL"
    if (is_yes(stated_closed) and is_yes(test_real) and is_yes(fail_closed)
            and is_yes(residual_doc)):
        return "MITIGATION"
    if is_yes(stated_closed) and is_yes(test_real) and is_no(fail_closed) and is_yes(residual_doc):
        return "WORKAROUND"
    return "NEEDS_REWORK"


def render_verification_row(index, vuln_id, cells6, graph_callers=None,
                             routed_callers=None, sidecar_confidence="high"):
    """Render one row of the 9-column verification table.

    `cells6` is a 6-tuple (stated_closed, test_real, fail_closed,
    residual_doc, sweep_ok, verdict_placeholder). Column 7 (call sites)
    is computed from graph_callers + routed_callers.
    """
    stated_closed, test_real, fail_closed, residual_doc, sweep_ok, _placeholder = cells6
    col7 = _column7_cell(graph_callers, routed_callers, sidecar_confidence)
    data_cells = (stated_closed, test_real, fail_closed, residual_doc, col7, sweep_ok)
    verdict = _derive_verdict(data_cells)
    return "| " + " | ".join([str(index), vuln_id, *data_cells, verdict]) + " |"


def render_verification_table(rows):
    """Render the full 9-column verification table.

    `rows` is a list of dicts, each with keys:
        index, vuln_id, stated_closed, test_real, fail_closed,
        residual_doc, sweep_ok, graph_callers, routed_callers,
        sidecar_confidence
    """
    header = "| " + " | ".join(VERIFICATION_TABLE_HEADERS) + " |"
    sep = "| " + " | ".join("---" for _ in VERIFICATION_TABLE_HEADERS) + " |"
    body_rows = [
        render_verification_row(
            r["index"],
            r["vuln_id"],
            (r.get("stated_closed", "n/a"),
             r.get("test_real", "n/a"),
             r.get("fail_closed", "n/a"),
             r.get("residual_doc", "n/a"),
             r.get("sweep_ok", "n/a"),
             ""),
            graph_callers=r.get("graph_callers"),
            routed_callers=r.get("routed_callers"),
            sidecar_confidence=r.get("sidecar_confidence", "high"),
        )
        for r in rows
    ]
    return "\n".join([header, sep, *body_rows])


# ---------------------------------------------------------------------------
# Branch-naming helpers (REQ-SEC-002 / REQ-SEC-003)
#
# Restored here after headless/scripts/deliver_repo.py was removed on main
# (commit e782ac5). The prompts implement.md and plan.md import these.

# CWE → generalized descriptor. Keeps the branch name from leaking the
# specific vulnerability class per REQ-SEC-003.
_CWE_DESCRIPTOR_MAP = {
    # Injection family
    22: "input-validation", 78: "input-validation", 79: "input-validation",
    89: "input-validation", 94: "input-validation", 434: "input-validation",
    502: "input-validation", 601: "input-validation", 611: "input-validation",
    918: "input-validation",
    # Authz / access
    287: "auth-handling", 290: "auth-handling", 306: "auth-handling",
    352: "auth-handling", 862: "access-control", 863: "access-control",
    639: "access-control", 915: "access-control",
    # Crypto
    295: "crypto-handling", 326: "crypto-handling", 327: "crypto-handling",
    328: "crypto-handling", 330: "crypto-handling", 345: "crypto-handling",
    347: "crypto-handling",
    # Memory / resource
    400: "memory-handling", 401: "memory-handling", 415: "memory-handling",
    416: "memory-handling", 476: "memory-handling",
    # Concurrency
    362: "concurrency-handling", 366: "concurrency-handling", 367: "concurrency-handling",
    # Information exposure
    200: "information-handling", 209: "information-handling", 532: "information-handling",
    117: "information-handling",
    # Network
    319: "network-handling", 693: "network-handling",
    # Credentials
    259: "credential-handling", 798: "credential-handling", 522: "credential-handling",
    # Configuration
    16: "configuration-handling", 732: "configuration-handling",
}


def cwe_to_descriptor(cwe: str) -> str:
    """Map a CWE identifier (e.g. 'CWE-89') to a generalized descriptor.

    REQ-SEC-003: descriptor must not reveal the specific vulnerability
    class. Returns 'general-hardening' for unmapped CWEs.
    """
    m = re.match(r"CWE-(\d+)$", cwe or "")
    if not m:
        return "general-hardening"
    return _CWE_DESCRIPTOR_MAP.get(int(m.group(1)), "general-hardening")


def compute_idempotency_key(location: str, cwe: str, root_cause: str) -> str:
    """SHA-256 prefix used as the cross-tool idempotency marker.

    Shape-compatible with scripts/parse_results.py:compute_vulnfix_key so
    the marker correlates across tools (16 hex chars). This function is
    kept in delivery.py as the delivery-time producer; parse_results.py
    is the intake-time producer. They must return the same value for
    the same inputs.
    """
    # Use only the primary CWE (first `CWE-N` match) to match parse_results.
    m = re.search(r"CWE-\d+", cwe or "")
    primary = m.group(0) if m else ""
    raw = f"{location}|{primary}|{root_cause}".encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def compute_masked_branch_name(cwe: str, idempotency_key: str) -> str:
    """REQ-SEC-002: `fix/code-quality-<descriptor>-<hash[:8]>`.

    Truncates the idempotency key to 8 hex chars so the branch name
    stays short. Legacy `vulnfix/VULN-NNN-*` branches are still parseable
    elsewhere for backward compat, but new branches always use this
    masked pattern.
    """
    descriptor = cwe_to_descriptor(cwe)
    key_prefix = (idempotency_key or "")[:8]
    return f"fix/code-quality-{descriptor}-{key_prefix}"
