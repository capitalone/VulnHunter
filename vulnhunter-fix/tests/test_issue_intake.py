"""Unit tests for scripts/issue_intake.py.

Covers marker extraction, body reconstruction, homogeneity check, and
vulnfix-key derivation. No network, no subprocess — pure logic tests.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from issue_intake import (  # noqa: E402
    DiffApplyError,
    ExtractedMarkers,
    IssueRecord,
    MarkerExtractionError,
    compute_vulnfix_key,
    enforce_homogeneity,
    extract_markers,
    reconstruct_original,
)


# ---- canonical body fixtures ----------------------------------------------


CANONICAL_BODY = """## Security Finding: CWE-89 — SQL Injection in user lookup

| Field | Value |
|-------|-------|
| CWE | CWE-89 |
| Severity | High |

<!-- vulnfix-key: abcdef0123456789 -->
<!-- vulnhunt-finding-id: VULN-001 -->
<!-- vulnhunt-results-dir: myapp_VULNHUNT_RESULTS_2026-06-28-120000 -->
"""


def _markers(
    key: str = "abcdef0123456789",
    finding_id: str = "VULN-001",
    results_dir: str = "myapp_VULNHUNT_RESULTS_2026-06-28-120000",
) -> ExtractedMarkers:
    return ExtractedMarkers(
        vulnfix_key=key, finding_id=finding_id, results_dir=results_dir
    )


def _record(
    owner: str = "org",
    repo: str = "r",
    number: int = 1,
    markers: ExtractedMarkers | None = None,
) -> IssueRecord:
    return IssueRecord(
        owner=owner,
        repo=repo,
        number=number,
        url=f"https://github.com/{owner}/{repo}/issues/{number}",
        title="",
        body_tampered=False,
        original_body="",
        markers=markers or _markers(),
    )


# ---- extract_markers ------------------------------------------------------


class TestExtractMarkers:
    def test_canonical_body(self):
        m = extract_markers(CANONICAL_BODY)
        assert m.vulnfix_key == "abcdef0123456789"
        assert m.finding_id == "VULN-001"
        assert m.results_dir == "myapp_VULNHUNT_RESULTS_2026-06-28-120000"

    def test_case_insensitive_match(self):
        body = (
            "<!-- VULNFIX-KEY: AAAABBBBCCCCDDDD -->\n"
            "<!-- Vulnhunt-Finding-Id: VULN-042 -->\n"
            "<!-- vulnhunt-results-dir: scan_VULNHUNT_RESULTS_foo -->\n"
        )
        m = extract_markers(body)
        # vulnfix_key normalized to lowercase, finding_id to uppercase.
        assert m.vulnfix_key == "aaaabbbbccccdddd"
        assert m.finding_id == "VULN-042"
        assert m.results_dir == "scan_VULNHUNT_RESULTS_foo"

    def test_extra_whitespace_inside_marker(self):
        body = (
            "<!--   vulnfix-key:    abcdef0123456789   -->\n"
            "<!--vulnhunt-finding-id: VULN-001-->\n"
            "<!-- vulnhunt-results-dir: r -->\n"
        )
        assert extract_markers(body).vulnfix_key == "abcdef0123456789"

    def test_missing_all_three(self):
        with pytest.raises(MarkerExtractionError) as excinfo:
            extract_markers("plain prose, no markers")
        msg = str(excinfo.value)
        assert "vulnfix-key" in msg
        assert "vulnhunt-finding-id" in msg
        assert "vulnhunt-results-dir" in msg

    def test_missing_one_marker(self):
        body = (
            "<!-- vulnfix-key: abcdef0123456789 -->\n"
            "<!-- vulnhunt-finding-id: VULN-001 -->\n"
        )
        with pytest.raises(MarkerExtractionError) as excinfo:
            extract_markers(body)
        msg = str(excinfo.value)
        assert "vulnhunt-results-dir" in msg
        assert "vulnfix-key" not in msg

    def test_source_label_in_error(self):
        with pytest.raises(MarkerExtractionError) as excinfo:
            extract_markers("", source_label="custom-label #99")
        assert "custom-label #99" in str(excinfo.value)

    def test_finding_id_must_be_zero_padded(self):
        body = (
            "<!-- vulnfix-key: abcdef0123456789 -->\n"
            "<!-- vulnhunt-finding-id: VULN-7 -->\n"
            "<!-- vulnhunt-results-dir: r -->\n"
        )
        with pytest.raises(MarkerExtractionError):
            extract_markers(body)

    def test_vulnfix_key_must_be_16_hex(self):
        body = (
            "<!-- vulnfix-key: notenoughh -->\n"
            "<!-- vulnhunt-finding-id: VULN-001 -->\n"
            "<!-- vulnhunt-results-dir: r -->\n"
        )
        with pytest.raises(MarkerExtractionError):
            extract_markers(body)

    def test_results_dir_value_with_underscores_and_dashes(self):
        # The vulnhunter scanner produces dirs like
        # `<repo>_VULNHUNT_RESULTS_2026-06-28-120000`; the regex must
        # accept underscores, dashes, and digits in the value.
        body = (
            "<!-- vulnfix-key: 0000000000000000 -->\n"
            "<!-- vulnhunt-finding-id: VULN-001 -->\n"
            "<!-- vulnhunt-results-dir: my-app_VULNHUNT_RESULTS_2026-06-28-120000 -->\n"
        )
        m = extract_markers(body)
        assert m.results_dir == "my-app_VULNHUNT_RESULTS_2026-06-28-120000"

    def test_markers_anywhere_in_body(self):
        # Markers don't need to be in any specific position — verify
        # they're found even when scattered.
        body = (
            "Some narrative paragraph.\n\n"
            "<!-- vulnhunt-results-dir: r -->\n\n"
            "More narrative.\n\n"
            "<!-- vulnfix-key: 0123456789abcdef -->\n\n"
            "Closing.\n\n"
            "<!-- vulnhunt-finding-id: VULN-999 -->\n"
        )
        m = extract_markers(body)
        assert m.vulnfix_key == "0123456789abcdef"
        assert m.finding_id == "VULN-999"


# ---- reconstruct_original -------------------------------------------------


class TestReconstructOriginal:
    def test_no_edits_returns_current_body(self):
        assert reconstruct_original("current text", []) == "current text"

    def test_picks_oldest_snapshot(self):
        edits = [
            {"editedAt": "2026-06-28T12:00:00Z", "diff": "middle"},
            {"editedAt": "2026-06-28T11:00:00Z", "diff": "oldest"},
            {"editedAt": "2026-06-28T13:00:00Z", "diff": "newest"},
        ]
        assert reconstruct_original("current", edits) == "oldest"

    def test_single_edit(self):
        edits = [{"editedAt": "2026-06-28T12:00:00Z", "diff": "the snapshot"}]
        assert reconstruct_original("current", edits) == "the snapshot"

    def test_missing_editedAt_raises(self):
        edits = [{"diff": "the snapshot"}]
        with pytest.raises(DiffApplyError, match="editedAt"):
            reconstruct_original("current", edits)

    def test_missing_diff_field_raises(self):
        edits = [{"editedAt": "2026-06-28T12:00:00Z"}]
        with pytest.raises(DiffApplyError, match="has no diff"):
            reconstruct_original("current", edits)

    def test_non_string_diff_raises(self):
        edits = [{"editedAt": "2026-06-28T12:00:00Z", "diff": 12345}]
        with pytest.raises(DiffApplyError, match="expected string"):
            reconstruct_original("current", edits)

    def test_iso_timestamp_lexical_sort_matches_chronological(self):
        # ISO-8601 strings sort lexically in chronological order, so a
        # later-in-the-year edit must come after an earlier one even
        # without parsing. Regression guard against switching to a
        # broken comparator.
        edits = [
            {"editedAt": "2027-01-01T00:00:00Z", "diff": "future"},
            {"editedAt": "2026-12-31T23:59:59Z", "diff": "past"},
        ]
        assert reconstruct_original("current", edits) == "past"


# ---- enforce_homogeneity --------------------------------------------------


class TestEnforceHomogeneity:
    def test_single_record(self):
        m = _markers()
        owner, repo, results = enforce_homogeneity([_record(markers=m)])
        assert (owner, repo, results) == ("org", "r", m.results_dir)

    def test_multiple_records_same_tuple(self):
        m = _markers()
        records = [
            _record(number=1, markers=m),
            _record(number=2, markers=m),
            _record(number=3, markers=m),
        ]
        owner, repo, results = enforce_homogeneity(records)
        assert owner == "org" and repo == "r" and results == m.results_dir

    def test_owner_case_insensitive_match(self):
        # GitHub treats owner/repo as case-insensitive; the check
        # should too.
        records = [
            _record(owner="Org", repo="R", markers=_markers()),
            _record(owner="ORG", repo="r", markers=_markers()),
        ]
        owner, _, _ = enforce_homogeneity(records)
        assert owner == "org"

    def test_different_results_dir_raises(self):
        m1 = _markers(results_dir="scan_a")
        m2 = _markers(results_dir="scan_b")
        with pytest.raises(ValueError, match="same.*scan_id"):
            enforce_homogeneity([_record(markers=m1), _record(markers=m2)])

    def test_different_repo_raises(self):
        with pytest.raises(ValueError):
            enforce_homogeneity([
                _record(owner="a", repo="x", markers=_markers()),
                _record(owner="a", repo="y", markers=_markers()),
            ])

    def test_empty_list_raises(self):
        with pytest.raises(ValueError, match="No issues"):
            enforce_homogeneity([])

    def test_error_lists_all_distinct_tuples(self):
        m1 = _markers(results_dir="scan_a")
        m2 = _markers(results_dir="scan_b")
        m3 = _markers(results_dir="scan_c")
        with pytest.raises(ValueError) as excinfo:
            enforce_homogeneity([
                _record(markers=m1),
                _record(markers=m2),
                _record(markers=m3),
            ])
        msg = str(excinfo.value)
        assert "scan_a" in msg and "scan_b" in msg and "scan_c" in msg


# ---- compute_vulnfix_key --------------------------------------------------


class TestComputeVulnfixKey:
    def test_deterministic(self):
        k1 = compute_vulnfix_key("src/a.py:1", "CWE-89", "rc")
        k2 = compute_vulnfix_key("src/a.py:1", "CWE-89", "rc")
        assert k1 == k2

    def test_length_and_hex(self):
        k = compute_vulnfix_key("src/x.py:1", "CWE-22", "unsanitized path")
        assert len(k) == 16
        assert all(c in "0123456789abcdef" for c in k)

    def test_location_change_alters_key(self):
        k1 = compute_vulnfix_key("a.py:1", "CWE-89", "rc")
        k2 = compute_vulnfix_key("a.py:2", "CWE-89", "rc")
        assert k1 != k2

    def test_cwe_change_alters_key(self):
        k1 = compute_vulnfix_key("a.py:1", "CWE-89", "rc")
        k2 = compute_vulnfix_key("a.py:1", "CWE-22", "rc")
        assert k1 != k2

    def test_root_cause_change_alters_key(self):
        k1 = compute_vulnfix_key("a.py:1", "CWE-89", "rc1")
        k2 = compute_vulnfix_key("a.py:1", "CWE-89", "rc2")
        assert k1 != k2

    def test_matches_upstream_definition(self):
        # Upstream vulnhunter agent uses SHA-256(f"{location}|{cwe}|{root_cause}")[:16].
        # Hard-coded expected value protects against accidental schema drift.
        import hashlib

        raw = "src/db.py:42|CWE-89|input is concatenated".encode()
        expected = hashlib.sha256(raw).hexdigest()[:16]
        got = compute_vulnfix_key("src/db.py:42", "CWE-89", "input is concatenated")
        assert got == expected

    def test_multi_cwe_collapses_to_primary(self):
        """Real findings sometimes carry multi-CWE strings ("CWE-918 /
        CWE-74") while issue body markers only carry the primary CWE.
        Both sides must collapse to the primary so the cross-tool join
        in parse_issues.md Step 6 matches. Regression guard for a
        real bug where the two sides hashed differently."""
        multi = compute_vulnfix_key("a.py:1", "CWE-918 / CWE-74", "rc")
        primary = compute_vulnfix_key("a.py:1", "CWE-918", "rc")
        assert multi == primary

    def test_collides_with_parse_results_on_multi_cwe(self):
        """parse_results.compute_vulnfix_key and
        issue_intake.compute_vulnfix_key must produce identical keys
        for the same multi-CWE input — they're the join key between
        findings.json (parse_results) and intake.json (issue_intake).
        Single-CWE collision is already tested in test_parse_results;
        this extends the guarantee to the multi-CWE shape."""
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
        from parse_results import compute_vulnfix_key as pr_key

        loc, multi_cwe, rc = "a.go:42", "CWE-918 / CWE-74", "ssrf"
        assert compute_vulnfix_key(loc, multi_cwe, rc) == pr_key(loc, multi_cwe, rc)
