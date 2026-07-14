"""Security test: VULN-007 — render_body must neutralize attacker markup.

CWE-79. Attacker-influenced Finding fields must not inject active HTML or
markdown links into the issue body posted under the operator's identity.
"""

from agent.issues_extract import ExtractedReport, Finding
from agent.issues_render import render_body


def _render(**overrides):
    base = dict(
        id="VULN-001", title="t", cwe="CWE-79", cwe_name="XSS", severity="Low",
        location="agent/x.py", root_cause="rc", data_flow="df", entry_point="ep",
        exploit_description="ed", exploit_impact="ei", fix_strategy="fs",
        severity_rationale="sr", vulnfix_key="deadbeefdeadbeef",
    )
    base.update(overrides)
    finding = Finding(**base)
    report = ExtractedReport(
        findings=[finding], scan_date="2026-07-12", results_dir_name="scan_2026-07-12"
    )
    return render_body(finding, report=report, report_url="https://example/report")


def test_raw_html_img_is_escaped():
    body = _render(exploit_description='<img src="https://attacker/pixel.gif">')
    assert '<img src="https://attacker/pixel.gif">' not in body
    assert "&lt;img" in body


def test_raw_anchor_is_escaped():
    body = _render(root_cause='<a href="https://attacker/steal">docs</a>')
    assert '<a href="https://attacker/steal">' not in body
    assert "&lt;a href" in body


def test_html_comment_is_neutralized():
    body = _render(exploit_impact="<!-- INJECTED_VULN007 -->")
    assert "<!-- INJECTED_VULN007 -->" not in body


def test_markdown_link_is_neutralized():
    body = _render(
        exploit_description="[click me](https://attacker.example/phish?t=OP)"
    )
    assert "[click me](https://attacker.example/phish?t=OP)" not in body


def test_machine_markers_still_parse():
    body = _render(title="benign")
    # Footer markers must remain machine-parseable (unsanitized).
    assert "<!-- vulnfix-key: deadbeefdeadbeef -->" in body
    assert "<!-- vulnhunt-finding-id: VULN-001 -->" in body


def test_benign_content_still_readable():
    body = _render(title="SQL injection in login", root_cause="unparameterized query")
    assert "SQL injection in login" in body
    assert "unparameterized query" in body
