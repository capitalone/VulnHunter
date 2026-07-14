"""Cross-artifact contract tests (SCH-* alignment — now GREEN, kept as guards).

These tests reproduce the schema/producer drift blockers peer review flagged in
Review 1 (B1) and Review 4 (SCH-1 through SCH-5). Each test is a
minimal reproduction: it constructs the payload a producer would emit
today, feeds it to the consumer that validates it, and asserts the
consumer accepts it.

Marked `@pytest.mark.contract` so they're addressable as a group with
`pytest -m contract`. The SCH-* alignment fixes have landed, so these are
GREEN and serve as regression coverage.

Failure of any of these tests in a future PR is a signal that a
producer-schema pair has drifted again — the class of bug the audit
found five instances of.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
REFERENCES = REPO_ROOT / "references"
PROMPTS = REPO_ROOT / "prompts"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_first_json_block(md_path: Path, near_marker: str) -> str:
    """Return the raw JSON block appearing right after `near_marker` in the file."""
    text = md_path.read_text(encoding="utf-8")
    idx = text.find(near_marker)
    if idx == -1:
        raise AssertionError(f"marker {near_marker!r} not found in {md_path}")
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text[idx:], re.DOTALL)
    if not m:
        raise AssertionError(f"no fenced JSON block after {near_marker!r} in {md_path}")
    return m.group(1)


def _substitute_placeholders(raw: str) -> str:
    """Substitute template placeholders with concrete values.

    Workers copy the template verbatim then fill placeholders. We do the
    same substitution here so we can validate the resulting object.
    """
    substitutions = {
        "VULN-NNN": "VULN-001",
        "group-NNN": "group-001",
        "CWE-XXX": "CWE-89",
        # Enums with pipe-separated options — pick the first.
    }
    for placeholder, value in substitutions.items():
        raw = raw.replace(placeholder, value)
    # Pipe-delimited enum placeholders like "VERIFIED|FAILED|..." — pick
    # the first token before the first pipe (JSON-string aware).
    raw = re.sub(
        r'"([A-Z_]+)\|[^"]*"', lambda m: f'"{m.group(1)}"', raw
    )
    raw = re.sub(
        r'"([a-z_-]+)\|[^"]*"', lambda m: f'"{m.group(1)}"', raw
    )
    return raw


def _load_schema(name: str) -> dict:
    return json.loads((REFERENCES / name).read_text(encoding="utf-8"))


def _validate_or_raise(payload: dict, schema_path: str) -> None:
    schema = _load_schema(schema_path)
    Draft202012Validator.check_schema(schema)
    v = Draft202012Validator(schema)
    errors = sorted(v.iter_errors(payload), key=lambda e: list(e.absolute_path))
    if errors:
        details = "\n".join(
            f"  {'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
            for e in errors
        )
        raise AssertionError(
            f"{schema_path} rejected payload:\n{details}\n"
            f"payload keys: {sorted(payload.keys())}"
        )


# ---------------------------------------------------------------------------
# SCH-0 / SCH-3 — worker result template
# ---------------------------------------------------------------------------

@pytest.mark.contract
def test_worker_result_template_validates_result_schema():
    """Extract the result-JSON template from worker_agent_common.md, fill
    placeholders, validate against result-schema.json.

    RED today: template emits ``finding_id`` (schema requires ``vuln_id``)
    and omits Bundle 1/2 required fields (completeness_tier,
    residual_vectors, tier_judgment, callers_routed_through_fix,
    callers_not_routed).

    GREEN after Commit 3: template uses ``vuln_id`` + adds all six
    required fields.
    """
    raw = _extract_first_json_block(
        PROMPTS / "worker_agent_common.md",
        near_marker="### 3. Write Result",
    )
    raw = _substitute_placeholders(raw)
    # Handle known-invalid enum strings the template uses ("must-pass|best-effort|skip", etc.)
    payload = json.loads(raw)
    _validate_or_raise(payload, "result-schema.json")


@pytest.mark.contract
def test_verify_md_alreadyfixed_template_validates_result_schema():
    """verify.md L124 headless-mode ``ALREADY_FIXED`` template.

    RED today: ``finding_id`` instead of ``vuln_id``. Also missing
    Bundle 1/2 required fields.
    GREEN after Commit 3.
    """
    text = (PROMPTS / "verify.md").read_text(encoding="utf-8")
    # First fenced JSON block that contains "ALREADY_FIXED"
    for m in re.finditer(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL):
        if "ALREADY_FIXED" in m.group(1):
            payload = json.loads(_substitute_placeholders(m.group(1)))
            _validate_or_raise(payload, "result-schema.json")
            return
    pytest.fail("no ALREADY_FIXED template found in verify.md")


# ---------------------------------------------------------------------------
# SCH-1 — finding-schema files shape
# ---------------------------------------------------------------------------

@pytest.mark.contract
def test_finding_schema_accepts_object_files_shape():
    """Producers (parse_results.py:129, parse_issues.md:571) emit
    ``files`` as an object with poc/exploit_test keys. Schema currently
    requires array of strings.

    RED today: schema rejects the object shape.
    GREEN after Commit 3: schema loosened to accept object.
    """
    payload = {
        "id": "VULN-001",
        "title": "example",
        "cwe": "CWE-89",
        "severity": "High",
        "status": "Confirmed",
        "files": {
            "poc": "results/poc/VULN-001_poc.py",
            "exploit_test": "results/exploit_tests/vuln_001_test.py",
        },
    }
    _validate_or_raise(payload, "finding-schema.json")


# ---------------------------------------------------------------------------
# SCH-2 — FULL tier reachable
# ---------------------------------------------------------------------------

@pytest.mark.contract
def test_full_tier_reachable_from_realistic_plan_and_result(tmp_path):
    """compute-completeness-tier.py gates FULL on three signals:
    sink_signature_changed, callers_routed_through_fix (from plan),
    test_discriminates (from result's discrimination_evidence).

    Today the classifier reads discrimination_evidence from the plan
    (wrong location) and callers_routed_coverage is emitted by no
    producer. A realistic plan+result can never hit FULL.

    RED today: classifier returns MITIGATION even with all evidence.
    GREEN after Commit 3: classifier accepts (diff, plan, result); reads
    each field from its natural producer.
    """
    diff = tmp_path / "fix.diff"
    diff.write_text(
        # Signature-changed signal — the sink function's arg count changed
        "--- a/auth.py\n+++ b/auth.py\n"
        "@@ -1,3 +1,4 @@\n"
        "-def check(user):\n"
        "+def check(user, session):\n"
        "     return True\n",
        encoding="utf-8",
    )
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps({
            "vuln_id": "VULN-001",
            "cwe": "CWE-89",
            "strategy": "route all callers through parameterized query",
            "callers_routed_coverage": "superset",  # not on schema today
            "files_to_change": ["auth.py"],
            "why_this_works": "parameterization eliminates the sink",
            "projected_completeness_tier": "FULL",
            "tier_judgment": {"invoked": False, "phase": None, "final_tier": None,
                              "rationale": None, "failure_reason": None},
        }),
        encoding="utf-8",
    )
    result = tmp_path / "result.json"
    result.write_text(
        json.dumps({
            "vuln_id": "VULN-001",
            "status": "VERIFIED",
            "cwe": "CWE-89",
            "file_path": "auth.py",
            "completeness_tier": "FULL",
            "residual_vectors": [],
            "tier_judgment": {"invoked": False, "phase": None, "final_tier": None,
                              "rationale": None, "failure_reason": None},
            "callers_routed_through_fix": ["auth.py:login", "auth.py:register"],
            "callers_not_routed": [],
            "discrimination_evidence": {
                "method": "stash-and-run",
                "pre_fix_result": "fail",
                "post_fix_result": "pass",
                "assertion_target": "tests/verify_VULN_001.py::test_injection_blocked",
            },
        }),
        encoding="utf-8",
    )
    script = SCRIPTS / "compute-completeness-tier.py"
    # Post-Commit 3 signature: (diff, plan, result). Today's signature: (diff, plan).
    # This test invokes with all three; classifier must handle it.
    proc = subprocess.run(  # nosec B603
        [sys.executable, str(script), "--diff", str(diff), "--plan", str(plan),
         "--result", str(result), "--phase", "verify"],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, f"classifier errored: {proc.stderr}"
    out = json.loads(proc.stdout)
    assert out["tier"] == "FULL", (
        f"expected FULL, got {out['tier']!r}. Signals: {out.get('signals')}\n"
        f"stderr: {proc.stderr}"
    )


# ---------------------------------------------------------------------------
# SCH-4 — tier_judgment.md output matches tierJudgment schema
# ---------------------------------------------------------------------------

@pytest.mark.contract
def test_tier_judgment_output_matches_schema():
    """tier_judgment.md documents the LLM output shape. That shape must
    round-trip through the tierJudgment $def in result-schema.json.

    RED today: prompt emits {final_tier, rationale, matched_signals,
    residual_vectors_if_not_full}. Schema requires {invoked, phase,
    final_tier, rationale, failure_reason} with additionalProperties=False.

    GREEN after Commit 3: prompt emits the schema shape; extras move to
    a sidecar via scripts/parse-tier-judgment.py.
    """
    text = (PROMPTS / "tier_judgment.md").read_text(encoding="utf-8")
    m = re.search(r"```\s*(\{[^`]*?\})\s*```", text, re.DOTALL)
    assert m, "no fenced JSON example found in tier_judgment.md"
    payload_from_prompt = json.loads(m.group(1))

    # Load the full schema so internal $refs (completenessTier) resolve
    schema = _load_schema("result-schema.json")
    # Build a wrapper schema that $refs into the tierJudgment def so the
    # validator resolves nested references against the whole document.
    wrapper = {"$ref": "#/$defs/tierJudgment", "$defs": schema["$defs"]}
    Draft202012Validator.check_schema(wrapper)
    v = Draft202012Validator(wrapper)
    errors = sorted(v.iter_errors(payload_from_prompt), key=lambda e: list(e.absolute_path))
    if errors:
        details = "\n".join(
            f"  {'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
            for e in errors
        )
        raise AssertionError(
            f"tier_judgment.md output rejected by tierJudgment $def:\n{details}"
        )


# ---------------------------------------------------------------------------
# SCH-5 — sweep pass1 anchors on sink_symbol from triage sidecar
# ---------------------------------------------------------------------------

@pytest.mark.contract
def test_sweep_pass1_reads_sink_symbol_from_triage_sidecar(tmp_path):
    """sweep-root-causes.py:203 reads sink_symbol from result JSON.
    sink_symbol lives on triage-schema.json (sidecar), not on
    result-schema.json — workers don't carry it. Pass-1 graph anchoring
    silently degrades.

    RED today: sink from result is None → placeholder → no Pass-1 hits.
    GREEN after Commit 3: sweep loads triage sidecar via
    _load_sidecar_for_vuln and reads sink_symbol from there.
    """
    # Fixture: a graph where `sink_fn` has two callers, one already routed
    # (`caller_ok`) and one not (`caller_bad`).
    graph = tmp_path / "graph.json"
    graph.write_text(
        json.dumps({
            "schema_version": "1",
            "graphify_version": "test",
            "generated_at": "2026-07-02T00:00:00Z",
            "backend": "ast",
            "confidence": "high",
            "content_hash": "sha256:0",
            "root_dir": str(tmp_path),
            "nodes": {
                "n_sink": {"kind": "function", "name": "sink_fn", "file": "auth.py",
                           "line": 1, "qualified_name": "auth.py:sink_fn", "language": "python"},
                "n_ok": {"kind": "function", "name": "caller_ok", "file": "auth.py",
                         "line": 10, "qualified_name": "auth.py:caller_ok", "language": "python"},
                "n_bad": {"kind": "function", "name": "caller_bad", "file": "auth.py",
                          "line": 20, "qualified_name": "auth.py:caller_bad", "language": "python"},
            },
            "edges": [
                {"from": "n_ok", "to": "n_sink", "kind": "calls"},
                {"from": "n_bad", "to": "n_sink", "kind": "calls"},
            ],
        }),
        encoding="utf-8",
    )
    # Triage sidecar with sink_symbol (per REQ-GRA-008)
    triage_dir = tmp_path / "triage"
    triage_dir.mkdir()
    (triage_dir / "VULN-001.json").write_text(
        json.dumps({
            "vuln_id": "VULN-001",
            "confidence": "high",
            "sink_symbol": "auth.py:sink_fn",
            "callers_of_sink": ["auth.py:caller_ok", "auth.py:caller_bad"],
            "generated_at": "2026-07-02T00:00:00Z",
        }),
        encoding="utf-8",
    )
    # Result JSON without sink_symbol (workers today don't carry it)
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    (results_dir / "VULN-001_result.json").write_text(
        json.dumps({
            "vuln_id": "VULN-001",
            "status": "VERIFIED",
            "cwe": "CWE-89",
            "file_path": "auth.py",
            "callers_routed_through_fix": ["auth.py:caller_ok"],  # caller_bad is a sibling
        }),
        encoding="utf-8",
    )
    patterns = tmp_path / "patterns.md"
    patterns.write_text("```\nclass: injection\ncwes: [89]\npatterns: []\n```\n", encoding="utf-8")

    script = SCRIPTS / "sweep-root-causes.py"
    out_path = tmp_path / "sweep.json"
    proc = subprocess.run(  # nosec B603
        [sys.executable, str(script),
         "--repo-root", str(tmp_path),
         "--graph", str(graph),
         "--patterns", str(patterns),
         "--results-dir", str(results_dir),
         "--triage-dir", str(triage_dir),
         "--out", str(out_path)],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, f"sweep errored: {proc.stderr}"
    out = json.loads(out_path.read_text(encoding="utf-8"))
    rows = out.get("rows", [])
    assert rows, "sweep emitted no rows"
    row = rows[0]
    # Pass-1 should have found the un-routed sibling
    assert row.get("pass1_siblings"), (
        f"Pass-1 anchoring failed; pass1_siblings empty. Row: {row}"
    )
    assert "auth.py:caller_bad" in row["pass1_siblings"], (
        f"expected auth.py:caller_bad in siblings, got {row['pass1_siblings']}"
    )


# ---------------------------------------------------------------------------
# SCH-adjacent — the parse-tier-judgment.py script referenced by tier_judgment.md
# ---------------------------------------------------------------------------

@pytest.mark.contract
def test_parse_tier_judgment_script_exists():
    """tier_judgment.md:102 documents a script that doesn't exist today.
    Commit 3 adds it; this test locks that in."""
    assert (SCRIPTS / "parse-tier-judgment.py").is_file(), (
        "scripts/parse-tier-judgment.py referenced by tier_judgment.md but not present"
    )
