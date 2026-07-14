"""Tests for agent._github: REST API base URL, owner/repo parsing, timestamp extraction."""

from __future__ import annotations

import pytest

from agent._github import (
    GitHubURLError,
    api_base,
    extract_timestamp,
    parse_owner_repo,
)


# ---------------------------------------------------------------------------
# api_base
# ---------------------------------------------------------------------------


class TestApiBase:
    def test_github_com_returns_public_api(self) -> None:
        assert api_base("github.com") == "https://api.github.com"

    def test_subdomain_of_github_com_returns_public_api(self) -> None:
        # Per the function's contract: any *.github.com host maps to the
        # public API (covers redirects and Pages-style hostnames that
        # the agent might be passed).
        assert api_base("api.github.com") == "https://api.github.com"
        assert api_base("raw.github.com") == "https://api.github.com"

    def test_ghes_host_returns_api_v3_path(self) -> None:
        # GitHub Enterprise Server uses the /api/v3 URL prefix.
        assert (
            api_base("github.example.com")
            == "https://github.example.com/api/v3"
        )

    def test_arbitrary_ghes_host(self) -> None:
        assert api_base("ghe.example.org") == "https://ghe.example.org/api/v3"


# ---------------------------------------------------------------------------
# parse_owner_repo
# ---------------------------------------------------------------------------


class TestParseOwnerRepo:
    def test_https_basic(self) -> None:
        assert parse_owner_repo("https://github.com/octocat/Hello-World") == (
            "octocat",
            "Hello-World",
        )

    def test_https_with_git_suffix_stripped(self) -> None:
        assert parse_owner_repo("https://github.com/octocat/Hello-World.git") == (
            "octocat",
            "Hello-World",
        )

    def test_tree_path_still_takes_first_two_segments(self) -> None:
        # Tree URLs like /owner/repo/tree/main should still resolve to the
        # repo identity — explicit per the docstring.
        assert parse_owner_repo(
            "https://github.com/octocat/Hello-World/tree/main"
        ) == ("octocat", "Hello-World")

    def test_blob_path_still_takes_first_two_segments(self) -> None:
        assert parse_owner_repo(
            "https://github.com/octocat/Hello-World/blob/main/README.md"
        ) == ("octocat", "Hello-World")

    def test_ssh_url_with_colon_separator(self) -> None:
        assert parse_owner_repo("git@github.com:octocat/Hello-World.git") == (
            "octocat",
            "Hello-World",
        )

    def test_ssh_url_without_git_suffix(self) -> None:
        assert parse_owner_repo("git@github.com:owner/repo") == ("owner", "repo")

    def test_trailing_slash_tolerated(self) -> None:
        assert parse_owner_repo("https://github.com/owner/repo/") == (
            "owner",
            "repo",
        )

    def test_ghes_host(self) -> None:
        assert parse_owner_repo(
            "https://github.example.com/your-org/vulnhunter"
        ) == ("your-org", "vulnhunter")

    def test_url_with_only_one_segment_raises(self) -> None:
        with pytest.raises(GitHubURLError, match="can't parse"):
            parse_owner_repo("https://github.com/onlyone")

    def test_empty_path_raises(self) -> None:
        with pytest.raises(GitHubURLError):
            parse_owner_repo("https://github.com/")

    def test_completely_unparseable_raises(self) -> None:
        with pytest.raises(GitHubURLError):
            parse_owner_repo("notaurl")

    def test_GitHubURLError_is_ValueError_subclass(self) -> None:
        # Callers catching ValueError should also catch GitHubURLError.
        assert issubclass(GitHubURLError, ValueError)


# ---------------------------------------------------------------------------
# extract_timestamp
# ---------------------------------------------------------------------------


class TestExtractTimestamp:
    def test_extracts_canonical_suffix(self) -> None:
        assert (
            extract_timestamp("myrepo_VULNHUNT_RESULTS_opus_2026-06-29-013012")
            == "2026-06-29-013012"
        )

    def test_extracts_when_only_timestamp_is_present(self) -> None:
        assert extract_timestamp("2026-01-01-000000") == "2026-01-01-000000"

    def test_returns_unknown_when_no_timestamp(self) -> None:
        assert extract_timestamp("myrepo_VULNHUNT_RESULTS_no_timestamp") == "unknown"

    def test_returns_unknown_for_empty_string(self) -> None:
        assert extract_timestamp("") == "unknown"

    def test_only_matches_at_end_of_string(self) -> None:
        # Pattern is anchored with `$` — timestamps mid-string shouldn't match.
        assert extract_timestamp("2026-06-29-013012_extra") == "unknown"

    def test_wrong_digit_count_does_not_match(self) -> None:
        # Timestamps with the wrong shape (e.g., missing leading zeros, extra
        # digits, wrong separators) should not match.
        assert extract_timestamp("dir_2026-6-29-013012") == "unknown"
        assert extract_timestamp("dir_26-06-29-013012") == "unknown"
        assert extract_timestamp("dir_2026/06/29-013012") == "unknown"
