"""Tests for scripts/parse_results.py — summary table and detail parsing."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from parse_results import (
    compute_vulnfix_key,
    parse_finding_detail,
    parse_summary_table,
    primary_cwe,
)


class TestPrimaryCwe:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("CWE-89", "CWE-89"),
            ("CWE-918 / CWE-74", "CWE-918"),
            ("CWE-22, CWE-23", "CWE-22"),
            ("CWE-918 | CWE-74", "CWE-918"),
            ("", ""),
            ("not a cwe", ""),
            ("  CWE-1234  ", "CWE-1234"),
        ],
    )
    def test_extracts_first_cwe(self, raw, expected):
        assert primary_cwe(raw) == expected


class TestComputeVulnfixKey:
    def test_deterministic(self):
        k1 = compute_vulnfix_key("src/a.py:1", "CWE-89", "rc")
        k2 = compute_vulnfix_key("src/a.py:1", "CWE-89", "rc")
        assert k1 == k2

    def test_length_and_hex(self):
        k = compute_vulnfix_key("a.py:1", "CWE-89", "rc")
        assert len(k) == 16
        assert all(c in "0123456789abcdef" for c in k)

    def test_multi_cwe_collapses_to_primary(self):
        """Findings with `CWE-918 / CWE-74` must key the same as a
        synthetic finding with just `CWE-918` — the upstream agent
        only embeds the primary CWE in issue bodies, so multi-CWE
        rows must collapse for cross-tool collision."""
        multi = compute_vulnfix_key("a.py:1", "CWE-918 / CWE-74", "rc")
        primary = compute_vulnfix_key("a.py:1", "CWE-918", "rc")
        assert multi == primary

    def test_matches_issue_intake_definition(self):
        """parse_results and issue_intake must compute identical keys
        for the same single-CWE finding — they're the join key between
        findings.json and intake.json."""
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
        from issue_intake import compute_vulnfix_key as intake_key

        location, cwe, rc = "src/db.py:42", "CWE-89", "unsanitized"
        assert compute_vulnfix_key(location, cwe, rc) == intake_key(location, cwe, rc)


class TestParseSummaryTable:
    """Verify parse_summary_table handles both plain and markdown-linked IDs."""

    PLAIN_TABLE = """\
| ID | Title | CWE | Severity | Exploit Test | Status |
|---|---|---|---|---|---|
| VULN-001 | SQL Injection in login | CWE-89 | High | test_sqli.py — PASS | Confirmed |
| VULN-002 | XSS in search | CWE-79 | Medium | test_xss.py — PASS | Confirmed |
"""

    LINKED_TABLE = """\
| ID | Title | CWE | Severity | Exploit Test | Status |
|---|---|---|---|---|---|
| [VULN-001](poc/VULN-001_ssrf.md) | SSRF via zipball_url | CWE-918 | Medium | [Test](exploit_tests/test_vuln_001.py) — PASS | Confirmed |
| [VULN-003](poc/VULN-003_zip_bomb.md) | Zip bomb DoS | CWE-409 | Low | [Test](exploit_tests/test_vuln_003.py) — PASS | Confirmed |
| [VULN-004](poc/VULN-004_path.md) | Path traversal via rename | CWE-22 | Low | [Test](exploit_tests/test_vuln_004.py) — PASS | Confirmed |
"""

    MIXED_TABLE = """\
| ID | Title | CWE | Severity | Exploit Test | Status |
|---|---|---|---|---|---|
| VULN-001 | Plain ID finding | CWE-89 | High | test.py — PASS | Confirmed |
| [VULN-002](poc/VULN-002.md) | Linked ID finding | CWE-79 | Medium | [Test](t.py) — PASS | Confirmed |
"""

    def test_parses_plain_ids(self) -> None:
        findings = parse_summary_table(self.PLAIN_TABLE)
        assert len(findings) == 2
        assert findings[0]["id"] == "VULN-001"
        assert findings[0]["cwe"] == "CWE-89"
        assert findings[0]["severity"] == "High"
        assert findings[0]["status"] == "Confirmed"
        assert findings[1]["id"] == "VULN-002"

    def test_parses_markdown_linked_ids(self) -> None:
        findings = parse_summary_table(self.LINKED_TABLE)
        assert len(findings) == 3
        assert findings[0]["id"] == "VULN-001"
        assert findings[0]["cwe"] == "CWE-918"
        assert findings[0]["severity"] == "Medium"
        assert findings[1]["id"] == "VULN-003"
        assert findings[2]["id"] == "VULN-004"
        assert findings[2]["cwe"] == "CWE-22"

    def test_parses_mixed_plain_and_linked(self) -> None:
        findings = parse_summary_table(self.MIXED_TABLE)
        assert len(findings) == 2
        assert findings[0]["id"] == "VULN-001"
        assert findings[1]["id"] == "VULN-002"

    def test_empty_content_returns_empty(self) -> None:
        assert parse_summary_table("") == []
        assert parse_summary_table("No table here") == []

    def test_linked_id_with_anchor(self) -> None:
        """IDs with anchor links like [VULN-001](#vuln-001) should parse."""
        content = "| [VULN-005](#vuln-005) | Title | CWE-200 | Low | test — PASS | Confirmed |"
        findings = parse_summary_table(content)
        assert len(findings) == 1
        assert findings[0]["id"] == "VULN-005"

    def test_multi_cwe_with_slash(self) -> None:
        """Rows with `CWE-918 / CWE-74` must parse — multi-CWE is common
        for findings that span more than one taxonomy entry. Regression
        guard for a real bug where the regex character class lacked `/`
        and silently dropped these rows."""
        content = (
            "| VULN-008 | Tag-management URL injection | CWE-918 / CWE-74 | "
            "High | test.py — PASS | Confirmed |\n"
            "| VULN-009 | CO2 callback URL injection | CWE-918 / CWE-74 | "
            "High | test.py — PASS | Confirmed |"
        )
        findings = parse_summary_table(content)
        assert len(findings) == 2
        assert findings[0]["id"] == "VULN-008"
        assert findings[0]["cwe"] == "CWE-918 / CWE-74"
        assert findings[1]["id"] == "VULN-009"

    def test_multi_cwe_with_comma(self) -> None:
        """Comma-separated multi-CWE rows must also parse."""
        content = (
            "| VULN-010 | Path issues | CWE-22, CWE-23 | Medium | "
            "test.py — PASS | Confirmed |"
        )
        findings = parse_summary_table(content)
        assert len(findings) == 1
        assert findings[0]["cwe"] == "CWE-22, CWE-23"


class TestParseFindingDetail:
    """Verify detail extraction from individual finding sections."""

    SECTION = """\
## VULN-001: SQL Injection in login

| Field | Value |
|---|---|
| **Location** | `src/auth/login.py:42` |
| **Root Cause** | Unsanitized user input in SQL query |
| **Entry Point** | POST /api/login |
| **Data Flow** | request.body → query string |

### Proposed Fix

**Strategy**: Use parameterized queries
**Files to change**: src/auth/login.py
**Why this works**: Prevents SQL injection by separating data from code
"""

    LINKED_SECTION = """\
## [VULN-002](#vuln-002): XSS in search

| Field | Value |
|---|---|
| **Location** | `src/web/search.py:18` |
| **Root Cause** | Unescaped user input in HTML output |
"""

    def test_extracts_location(self) -> None:
        detail = parse_finding_detail(self.SECTION, "VULN-001")
        assert detail["location"] == "src/auth/login.py:42"

    def test_extracts_root_cause(self) -> None:
        detail = parse_finding_detail(self.SECTION, "VULN-001")
        assert "Unsanitized" in detail["root_cause"]

    def test_extracts_proposed_fix(self) -> None:
        detail = parse_finding_detail(self.SECTION, "VULN-001")
        assert "parameterized" in detail["proposed_fix"]["strategy"]
        assert detail["proposed_fix"]["files_to_change"] == "src/auth/login.py"

    def test_linked_heading_still_matches(self) -> None:
        detail = parse_finding_detail(self.LINKED_SECTION, "VULN-002")
        assert detail["location"] == "src/web/search.py:18"

    def test_nonexistent_vuln_returns_empty(self) -> None:
        detail = parse_finding_detail(self.SECTION, "VULN-999")
        assert detail == {}
