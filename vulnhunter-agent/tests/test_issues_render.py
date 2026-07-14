"""Tests for issues_render: title format, body substitution, footer markers."""

from __future__ import annotations

import re

import pytest

from agent.issues_extract import ExtractedReport, Finding
from agent.issues_render import (
    CleanScanContext,
    _build_report_url,
    _github_anchor,
    render_body,
    render_clean_scan_body,
    render_clean_scan_comment,
    render_clean_scan_title,
    render_title,
)


def _finding(**overrides: object) -> Finding:
    base = dict(
        id="VULN-001",
        title="SQL injection in user lookup",
        cwe="CWE-89",
        cwe_name="SQL Injection",
        severity="High",
        location="src/db.py:42",
        root_cause="Unparameterized query.",
        data_flow="HTTP body → query string",
        entry_point="POST /users",
        exploit_description="An attacker can read every row.",
        exploit_impact="Full DB read.",
        fix_strategy="Use a parameterized query.",
        severity_rationale="Direct PII disclosure.",
        poc_path=None,
        exploit_test_path=None,
        vulnfix_key="abc123def4567890",
    )
    base.update(overrides)  # type: ignore[arg-type]
    return Finding(**base)  # type: ignore[arg-type]


def _report(**overrides: object) -> ExtractedReport:
    base = dict(
        findings=[],
        scan_date="2026-06-23",
        results_dir_name="myrepo_VULNHUNT_RESULTS_opus47_2026-06-23-141824",
    )
    base.update(overrides)  # type: ignore[arg-type]
    return ExtractedReport(**base)  # type: ignore[arg-type]


class TestRenderTitle:
    def test_includes_cwe_no_vuln_id(self) -> None:
        title = render_title(_finding())
        assert title == "Security Finding: CWE-89: SQL injection in user lookup"
        # Title must NOT contain the scan-local VULN-NNN id.
        assert "VULN-" not in title

    def test_unknown_cwe_falls_back(self) -> None:
        title = render_title(_finding(cwe=""))
        assert "Unknown CWE" in title

    def test_untitled_finding(self) -> None:
        title = render_title(_finding(title=""))
        assert "(untitled)" in title


class TestRenderBody:
    def test_no_unfilled_placeholders(self) -> None:
        body = render_body(
            _finding(),
            report=_report(),
            report_url="https://example/blob/main/.../README.md",
        )
        leftovers = re.findall(r"\{[A-Z_]+\}", body)
        assert leftovers == []

    def test_footer_markers_present(self) -> None:
        finding = _finding()
        body = render_body(
            finding,
            report=_report(),
            report_url="https://example/README.md",
        )
        assert f"<!-- vulnfix-key: {finding.vulnfix_key} -->" in body
        assert f"<!-- vulnhunt-finding-id: {finding.id} -->" in body
        assert (
            "<!-- vulnhunt-results-dir: myrepo_VULNHUNT_RESULTS_opus47_"
            "2026-06-23-141824 -->" in body
        )

    def test_report_url_in_body(self) -> None:
        body = render_body(
            _finding(),
            report=_report(),
            report_url="https://github.com/x/y/blob/main/o/r/2026-06-23-141824/abc/dir/README.md",
        )
        # Now appended with a section anchor.
        assert (
            "Full report: https://github.com/x/y/blob/main/o/r/"
            "2026-06-23-141824/abc/dir/README.md#" in body
        )

    def test_report_url_includes_finding_anchor(self) -> None:
        body = render_body(
            _finding(
                id="VULN-003",
                title="Query parameter injection via lastEvaluatedKey",
            ),
            report=_report(),
            report_url="https://example.com/x/blob/main/r/README.md",
        )
        assert (
            "https://example.com/x/blob/main/r/README.md"
            "#vuln-003-query-parameter-injection-via-lastevaluatedkey"
            in body
        )

    def test_no_anchor_when_id_missing(self) -> None:
        body = render_body(
            _finding(id=""),
            report=_report(),
            report_url="https://example.com/r/README.md",
        )
        # Falls back to plain URL without fragment.
        assert "Full report: https://example.com/r/README.md\n" in body
        assert "Full report: https://example.com/r/README.md#" not in body

    def test_missing_optional_fields_render_placeholders_not_blanks(self) -> None:
        body = render_body(
            _finding(
                exploit_description="",
                exploit_impact="",
                fix_strategy="",
                severity_rationale="",
            ),
            report=_report(),
            report_url="https://example/README.md",
        )
        # Defensive defaults rather than empty strings.
        assert "(not specified in report)" in body
        assert "(see full report)" in body

    def test_status_line_hints_vulnhunter_fix(self) -> None:
        body = render_body(
            _finding(),
            report=_report(),
            report_url="https://example/README.md",
        )
        assert "https://github.com/capitalone/vulnhunter" in body
        assert "/vulnhunter-fix" in body

    def test_report_access_message_is_generic(self) -> None:
        # The report-access guidance is intentionally generic — it names no
        # business application, entitlement, or group.
        body = render_body(
            _finding(),
            report=_report(),
            report_url="https://example/README.md",
        )
        assert "request access from your security team" in body
        assert "Membership" not in body

    def test_report_access_message_falls_back_without_ba(self) -> None:
        body = render_body(
            _finding(),
            report=_report(),
            report_url="https://example/README.md",
        )
        assert "request access from your security team" in body
        assert "Membership" not in body


class TestBuildReportUrl:
    def test_blob_url_layout(self) -> None:
        url = _build_report_url(
            publish_destination_repo="https://github.com/your-org/dest",
            publish_branch="main",
            source_repo_url="https://github.com/your-org/myservice",
            source_commit_hash="abc1234",
            timestamp="2026-06-23-141824",
            results_dir_name="myservice_VULNHUNT_RESULTS_opus47_2026-06-23-141824",
        )
        assert url == (
            "https://github.com/your-org/dest/blob/main/"
            "your-org/myservice/2026-06-23-141824/abc1234/"
            "myservice_VULNHUNT_RESULTS_opus47_2026-06-23-141824/README.md"
        )

    def test_strips_dot_git_suffix(self) -> None:
        url = _build_report_url(
            publish_destination_repo="https://github.com/o/r.git",
            publish_branch="main",
            source_repo_url="https://github.com/x/y",
            source_commit_hash="abc",
            timestamp="2026-06-23-141824",
            results_dir_name="results",
        )
        assert ".git/blob" not in url
        assert url.startswith("https://github.com/o/r/blob/main/")


class TestGithubAnchor:
    def test_real_world_example(self) -> None:
        # The anchor format the user pointed to in the deep-link request.
        out = _github_anchor(
            "VULN-003: Query parameter injection via lastEvaluatedKey"
        )
        assert out == "vuln-003-query-parameter-injection-via-lastevaluatedkey"

    def test_strips_punctuation(self) -> None:
        # Colons, parens, and other punctuation are dropped.
        out = _github_anchor("VULN-001: A (very) tricky, finding!")
        assert out == "vuln-001-a-very-tricky-finding"

    def test_lowercases(self) -> None:
        assert _github_anchor("CamelCaseHeading") == "camelcaseheading"

    def test_preserves_hyphens(self) -> None:
        # Hyphens in the original heading are preserved (not stripped).
        assert _github_anchor("foo-bar baz") == "foo-bar-baz"


def _clean_scan_ctx(**overrides: object) -> CleanScanContext:
    base = dict(
        scan_id="myrepo_VULNHUNT_RESULTS_opus47_2026-07-06-183014",
        repo_slug="your-org/foo",
        commit_sha_short="abc1234",
        app_id="EXAMPLE-APP",
        scan_started_at="2026-07-06T18:30:14Z",
        scan_completed_at="2026-07-06T18:42:51Z",
        duration_seconds=757,
        model_version="claude-opus-4-8",
        skill_version="3500d0c-clean",
        report_url="https://example.com/reports/foo/README.md",
    )
    base.update(overrides)
    return CleanScanContext(**base)  # type: ignore[arg-type]


class TestCleanScanTitle:
    def test_static_title(self) -> None:
        title = render_clean_scan_title()
        assert title == "[VulnHunter] Clean scan — no findings detected"

    def test_no_placeholders_leak(self) -> None:
        # Title is a constant — no template braces should be present.
        assert "{" not in render_clean_scan_title()


class TestCleanScanBody:
    def test_populates_all_fields(self) -> None:
        body = render_clean_scan_body(_clean_scan_ctx())
        assert "myrepo_VULNHUNT_RESULTS_opus47_2026-07-06-183014" in body
        assert "your-org/foo" in body
        assert "abc1234" in body
        assert "757 seconds" in body
        assert "claude-opus-4-8" in body
        assert "3500d0c-clean" in body
        assert "example.com/reports/foo/README.md" in body

    def test_no_report_url_omits_report_line(self) -> None:
        body = render_clean_scan_body(_clean_scan_ctx(report_url=""))
        assert "Full scan report" not in body
        # The rest of the receipt still renders.
        assert "VulnHunter Scan Complete" in body

    def test_missing_duration_renders_dash(self) -> None:
        body = render_clean_scan_body(_clean_scan_ctx(duration_seconds=None))
        # Row still exists; value is a dash rather than "None seconds".
        assert "None seconds" not in body
        # The "Duration" row shows a dash.
        assert re.search(r"Duration\s*\|\s*—", body)

    def test_missing_skill_version_shows_unknown(self) -> None:
        body = render_clean_scan_body(_clean_scan_ctx(skill_version=""))
        assert "unknown" in body

    def test_all_placeholders_filled(self) -> None:
        body = render_clean_scan_body(_clean_scan_ctx())
        # Any leftover {UPPER_CASE} would signal an unfilled placeholder.
        assert not re.search(r"\{[A-Z_]+\}", body)

    def test_parens_in_report_url_are_escaped(self) -> None:
        # A URL containing bare ) would break the markdown link. Cheap
        # defense: percent-encode both parens.
        body = render_clean_scan_body(
            _clean_scan_ctx(
                report_url="https://example.com/path(with)parens/README.md"
            )
        )
        # The link brackets close cleanly on the encoded URL...
        assert "https://example.com/path%28with%29parens/README.md" in body
        # ...and the raw parens do not appear inside the URL slot.
        # (Parens still appear in the surrounding table borders, so we
        # spot-check the specific pattern that would break the link.)
        assert "path(with)parens" not in body


class TestCleanScanComment:
    def test_compact_shape(self) -> None:
        comment = render_clean_scan_comment(_clean_scan_ctx())
        # Comment omits the full-body preamble ("No Findings", etc.).
        assert "VulnHunter Scan Complete" not in comment
        # But still carries per-scan facts.
        assert "abc1234" in comment
        assert "757 seconds" in comment
        assert "2026-07-06T18:42:51Z" in comment
