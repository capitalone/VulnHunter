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
