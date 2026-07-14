"""TS-7c — LLM_REVIEW resolution flow (REQ-HON-013 through REQ-HON-016).

Skeleton test. Verifies the executor:
1. Never writes `LLM_REVIEW` as a terminal tier in result.json.
2. Invokes the bounded LLM prompt when the deterministic classifier
   returns `LLM_REVIEW`.
3. Retries once on malformed LLM output, then routes to
   `NEEDS_MANUAL_REVIEW` with `tier_judgment.failure_reason` populated.
4. Populates `tier_judgment` with `invoked=true`, `final_tier`, and
   `rationale` when the LLM resolves successfully.

Under TDD, the executor wiring lands in task-24. This file is deliberately
failing until then.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
CLASSIFIER = REPO_ROOT / "scripts" / "compute-completeness-tier.py"


NO_SIGNAL_DIFF = """\
--- a/x.py
+++ b/x.py
@@ -1 +1 @@
-x = 1
+x = 2
"""


def _run_classifier(diff_text: str, tmp_path: Path) -> dict:
    diff_path = tmp_path / "d.diff"
    diff_path.write_text(diff_text)
    proc = subprocess.run(
        [sys.executable, str(CLASSIFIER), "--diff", str(diff_path)],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(proc.stdout)


def test_classifier_returns_llm_review_when_no_signal_matches(tmp_path):
    result = _run_classifier(NO_SIGNAL_DIFF, tmp_path)
    assert result["tier"] == "LLM_REVIEW"
    assert "prompts/tier_judgment.md" in result["reason"]


def test_classifier_never_picks_full_silently(tmp_path):
    result = _run_classifier(NO_SIGNAL_DIFF, tmp_path)
    assert result["tier"] != "FULL", "REQ-HON-004: classifier must never silently pick FULL"


# --- S3 (12-seg review): FULL signal sourcing must not be gameable ---------

_SIG_CHANGE_DIFF = """\
--- a/auth.py
+++ b/auth.py
@@ -1,3 +1,4 @@
-def check(user):
+def check(user, session):
     return True
"""


def _run_full(tmp_path, *, discrimination, routed):
    """Run the classifier over a diff that trips sink_signature_changed, with a
    plan claiming superset coverage and a result carrying the given
    discrimination evidence + routed-caller list."""
    diff = tmp_path / "fix.diff"; diff.write_text(_SIG_CHANGE_DIFF, encoding="utf-8")
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({
        "vuln_id": "VULN-001", "cwe": "CWE-89", "strategy": "route callers",
        "callers_routed_coverage": "superset", "files_to_change": ["auth.py"],
        "why_this_works": "parameterized", "projected_completeness_tier": "FULL",
        "tier_judgment": {"invoked": False, "phase": None, "final_tier": None,
                          "rationale": None, "failure_reason": None},
    }), encoding="utf-8")
    result = tmp_path / "result.json"
    result.write_text(json.dumps({
        "vuln_id": "VULN-001", "status": "VERIFIED", "cwe": "CWE-89", "file_path": "auth.py",
        "completeness_tier": "FULL", "residual_vectors": [],
        "tier_judgment": {"invoked": False, "phase": None, "final_tier": None,
                          "rationale": None, "failure_reason": None},
        "callers_routed_through_fix": routed, "callers_not_routed": [],
        "discrimination_evidence": discrimination,
    }), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(CLASSIFIER), "--diff", str(diff), "--plan", str(plan),
         "--result", str(result), "--phase", "verify"],
        capture_output=True, text=True, check=True,
    )
    return json.loads(proc.stdout)


_FULL_DISC = {"method": "stash-and-run", "pre_fix_result": "fail",
              "post_fix_result": "pass", "assertion_target": "tests/verify_VULN_001.py::t"}


def test_full_denied_when_discrimination_is_a_two_field_stub(tmp_path):
    """S3: the classifier credited full.test_discriminates on pre==fail &&
    post==pass alone — so a two-field stub (no method, no assertion_target)
    earned the terminal FULL signal. That's the headline bypass. A stub must
    NOT earn FULL."""
    out = _run_full(tmp_path, discrimination={"pre_fix_result": "fail", "post_fix_result": "pass"},
                    routed=["auth.py:login"])
    assert out["tier"] != "FULL", f"two-field stub earned FULL: {out}"
    assert "full.test_discriminates" not in out["signals"]


def test_full_denied_when_no_callers_routed(tmp_path):
    """S3: full.callers_routed_through_fix was bare string equality on
    plan.callers_routed_coverage=='superset' with no cross-check — a plan can
    claim 'superset' over zero routed callers. Require a non-empty routed set."""
    out = _run_full(tmp_path, discrimination=_FULL_DISC, routed=[])
    assert out["tier"] != "FULL", f"superset over empty routed set earned FULL: {out}"
    assert "full.callers_routed_through_fix" not in out["signals"]


def test_full_granted_with_complete_evidence(tmp_path):
    """Allow-path guard: signature change + non-empty routed + a complete
    discrimination payload must STILL earn FULL after the tightening."""
    out = _run_full(tmp_path, discrimination=_FULL_DISC, routed=["auth.py:login", "auth.py:register"])
    assert out["tier"] == "FULL", f"complete evidence wrongly denied FULL: {out}"


@pytest.mark.skip(reason="harness pending task-24 (executor LLM_REVIEW→tier_judgment wiring)")
def test_llm_review_never_appears_as_terminal_tier_in_result_json():
    """No result.json in the produced artifact set may carry
    completeness_tier == 'LLM_REVIEW'."""


@pytest.mark.skip(reason="harness pending task-24 (executor LLM_REVIEW→tier_judgment wiring)")
def test_llm_success_populates_tier_judgment_rationale():
    """When the LLM resolves successfully, result.tier_judgment.invoked=true,
    final_tier is set, and rationale is non-empty (REQ-HON-016)."""


@pytest.mark.skip(reason="harness pending task-24 (executor LLM_REVIEW→tier_judgment wiring)")
def test_llm_failure_after_two_attempts_routes_to_needs_manual_review():
    """After two failed LLM attempts, the finding routes to
    NEEDS_MANUAL_REVIEW and result.tier_judgment.failure_reason is set
    (REQ-HON-015)."""


@pytest.mark.skip(reason="harness pending task-24 (executor LLM_REVIEW→tier_judgment wiring)")
def test_llm_returns_llm_review_is_invalid_and_retried():
    """If the LLM's response is `{"final_tier": "LLM_REVIEW", ...}`, the
    executor rejects it as invalid and retries (REQ-HON-013 excludes
    LLM_REVIEW as a terminal value)."""
