"""TS-2 — hand-wave guard (REQ-HON-006).

Skeleton test. Verifies the delivery module refuses to ship a PR body
when any residual_vectors entry matches the hand-wave regex.

The regex (case-insensitive) matches these substrings:
    - "future work"
    - "more work needed"
    - "to be done"
    - "tbd"
    - "later"

Under TDD, `render_pr_body_with_residuals` does not yet exist. This test is
deliberately failing until `vulnhunter_fix/delivery.py` grows the honesty
guards (task-16).
"""

from __future__ import annotations

import pytest


HAND_WAVE_FIXTURES = [
    "SQLi in legacy_admin.php — future work",
    "XSS via /search — More Work Needed",
    "Path traversal in file_serve — to be done",
    "Broken auth in v1 endpoint — TBD",
    "Log injection in audit path — later",
    # S3 (12-seg review): vague-assurance hand-waves the guard advertised but missed
    "Auth bypass on /admin — the framework adequately handles this",
    "XSS via /search — input is properly validated upstream",
    "SSRF in fetch() — properly handled by the gateway",
]

CLEAN_FIXTURES = [
    "SQLi in legacy_admin.php — endpoint not rewritten in this fix",
    "XSS reflection: /search?q= — encoding fix covers HTML context only",
    "trust-chain: algorithm not on approved list",
]


@pytest.mark.parametrize("residual", HAND_WAVE_FIXTURES)
def test_hand_wave_residual_refuses_delivery(residual):
    from vulnhunter_fix.delivery import render_pr_body_with_residuals, HandWaveResidualError
    with pytest.raises(HandWaveResidualError):
        render_pr_body_with_residuals(
            vuln_id="VULN-1",
            tier="MITIGATION",
            residual_vectors=[residual],
        )


@pytest.mark.parametrize("residual", CLEAN_FIXTURES)
def test_concrete_residual_renders(residual):
    from vulnhunter_fix.delivery import render_pr_body_with_residuals
    body = render_pr_body_with_residuals(
        vuln_id="VULN-1",
        tier="MITIGATION",
        residual_vectors=[residual],
    )
    assert "## Residual Risk" in body
    assert residual in body


def test_empty_residual_refuses_delivery_for_non_full_tier():
    from vulnhunter_fix.delivery import render_pr_body_with_residuals, EmptyResidualError
    with pytest.raises(EmptyResidualError):
        render_pr_body_with_residuals(
            vuln_id="VULN-1",
            tier="MITIGATION",
            residual_vectors=[],
        )


def test_full_tier_forbids_residuals():
    from vulnhunter_fix.delivery import render_pr_body_with_residuals, FullTierWithResidualsError
    with pytest.raises(FullTierWithResidualsError):
        render_pr_body_with_residuals(
            vuln_id="VULN-1",
            tier="FULL",
            residual_vectors=["something"],
        )


# ---------------------------------------------------------------------------
# CANON-44 — markdown/HTML injection via residual_vectors (CWE-79/CWE-116)
#
# residual_vectors entries are LLM/finding-derived and were interpolated
# verbatim into the '## Residual Risk' markdown appended to the PR/issue body.
# The hand-wave / consistency guards reject vague or empty entries but never
# escape, so an entry can carry raw HTML or a markdown link into the body.
# ---------------------------------------------------------------------------


def test_residual_entry_html_is_neutralized():
    from vulnhunter_fix.delivery import render_residual_risk_section

    payload = "</details><script>alert(1)</script>"
    section = render_residual_risk_section("VULN-1", "WORKAROUND", [payload])
    # Raw tags must not survive; angle brackets must be escaped.
    assert "<script>" not in section
    assert "</details>" not in section
    assert payload not in section
    # The escaped text is still present as literal content.
    assert "&lt;script&gt;" in section


def test_residual_entry_markdown_link_is_neutralized():
    from vulnhunter_fix.delivery import render_pr_body_with_residuals

    payload = "[click me](javascript:alert(1))"
    body = render_pr_body_with_residuals(
        "VULN-1", "WORKAROUND", [payload], base_body="orig"
    )
    # A live markdown link must not be interpolated verbatim; the '[' ']'
    # metacharacters are neutralized so it renders as literal text.
    assert payload not in body
    assert "[click me]" not in body


def test_benign_residual_entry_survives_readably():
    from vulnhunter_fix.delivery import render_residual_risk_section

    entry = "SQLi in legacy_admin.php is not covered by this workaround"
    section = render_residual_risk_section("VULN-1", "WORKAROUND", [entry])
    assert f"- {entry}" in section


def test_residual_entry_newlines_cannot_inject_block_markdown():
    # A multi-line residual entry must not break out of its `- ` bullet and
    # inject top-level markdown blocks (heading / horizontal rule / fake prose).
    # Each entry is rendered as `- {entry}`; without newline neutralization the
    # embedded '## ...' and '---' lines become real block-level markdown.
    from vulnhunter_fix.delivery import render_residual_risk_section

    payload = "unclosed vector\n\n## Verification Complete\n\nAll clear, merge me\n\n---"
    section = render_residual_risk_section("VULN-1", "WORKAROUND", [payload])

    # The only legitimate heading is the section's own '## Residual Risk'; no
    # entry-derived line may be an injected block-level construct.
    heading_lines = [ln for ln in section.splitlines() if ln.startswith("## ")]
    assert heading_lines == ["## Residual Risk"], (
        f"unexpected/injected headings: {heading_lines!r}"
    )
    for line in section.splitlines():
        assert line.strip() != "---", f"injected hr survived: {line!r}"

    # The payload text must be flattened onto a single bullet line, not spread
    # across multiple top-level lines. The '##' survives as inert mid-line text
    # (a heading is only block-level at line start), which the line checks above
    # already prove is not the case here.
    assert "- unclosed vector ## Verification Complete All clear, merge me ---" in section
