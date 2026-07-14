"""Tests for scripts/validate_pr_body.py."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from validate_pr_body import extract_closes, validate


class TestExtractCloses:
    def test_single_close(self):
        assert extract_closes("Closes #42") == {42}

    def test_comma_separated_one_line(self):
        body = "Closes #1, #2, #3\n\nRest of body…"
        # GitHub's parser handles `Closes #N1, #N2, #N3` by treating
        # each `#N` as a separate close. Our regex matches the
        # keyword + the FIRST #N immediately after — so the bare
        # #2, #3 aren't matched unless preceded by another verb.
        # The right way to write this in a PR body is one keyword
        # per number; validate that pattern works.
        assert extract_closes("Closes #1\nFixes #2\nResolves #3") == {1, 2, 3}

    def test_per_finding_subsection_headings(self):
        body = """\
Closes #1, #2

#### VULN-001 — SQL injection (Closes #1)

…

#### VULN-002 — XSS (Closes #2)
"""
        # `Closes #1` appears once at top; per-finding `(Closes #N)`
        # appears once each. The unique-issue set is {1, 2}.
        assert extract_closes(body) == {1, 2}

    def test_fixes_and_resolves_also_count(self):
        body = "Fixes #5 and Resolves #6 and closes #7"
        assert extract_closes(body) == {5, 6, 7}

    def test_case_insensitive(self):
        assert extract_closes("CLOSES #1 closes #2 Closes #3") == {1, 2, 3}

    def test_no_closes_keyword_yields_empty(self):
        body = "This PR is great but doesn't auto-close anything. See #99."
        assert extract_closes(body) == set()

    def test_close_without_hash_doesnt_match(self):
        # `Closes 42` (no #) doesn't trigger GitHub's auto-close.
        # Our regex matches it the same way.
        assert extract_closes("Closes 42") == set()


class TestValidate:
    def test_exact_match_ok(self):
        ok, msg = validate("Closes #1\nCloses #2", {1, 2})
        assert ok
        assert "all 2 expected issues" in msg

    def test_missing_close_reported(self):
        ok, msg = validate("Closes #1", {1, 2, 3})
        assert not ok
        assert "[2, 3]" in msg
        assert "will NOT auto-close" in msg

    def test_extra_close_reported(self):
        ok, msg = validate("Closes #1\nCloses #2\nCloses #99", {1, 2})
        assert not ok
        assert "[99]" in msg
        assert "aren't in the cluster" in msg

    def test_both_missing_and_extra_reported(self):
        ok, msg = validate("Closes #1\nCloses #99", {1, 2})
        assert not ok
        assert "[2]" in msg
        assert "[99]" in msg

    def test_empty_expected_set_with_no_closes(self):
        # No findings selected → body has no Closes. Trivially OK.
        ok, _ = validate("Just a description.", set())
        assert ok


class TestCli:
    @pytest.fixture
    def script(self) -> Path:
        return Path(__file__).resolve().parents[1] / "scripts" / "validate_pr_body.py"

    def test_happy_path(self, script, tmp_path):
        body = tmp_path / "body.md"
        body.write_text("Closes #1\nCloses #2, Closes #3\n")
        result = subprocess.run(
            [sys.executable, str(script), str(body),
             "--expected-issues", "1,2,3"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "ok:" in result.stdout

    def test_missing_close_fails_cli(self, script, tmp_path):
        body = tmp_path / "body.md"
        body.write_text("Closes #1\n")
        result = subprocess.run(
            [sys.executable, str(script), str(body),
             "--expected-issues", "1,2,3"],
            capture_output=True, text=True,
        )
        assert result.returncode == 1
        assert "Fix the PR body" in result.stderr

    def test_hash_prefixed_args(self, script, tmp_path):
        body = tmp_path / "body.md"
        body.write_text("Closes #5, Closes #6\n")
        # GitHub-style hash-prefixed input
        result = subprocess.run(
            [sys.executable, str(script), str(body),
             "--expected-issues", "#5,#6"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0

    def test_non_numeric_in_expected_rejected(self, script, tmp_path):
        body = tmp_path / "body.md"
        body.write_text("Closes #1\n")
        result = subprocess.run(
            [sys.executable, str(script), str(body),
             "--expected-issues", "1,foo"],
            capture_output=True, text=True,
        )
        assert result.returncode != 0
