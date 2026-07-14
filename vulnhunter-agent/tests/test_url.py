"""Tests for agent._url: token injection + redaction invariants."""

from __future__ import annotations

import pytest
from hypothesis import given, settings, strategies as st

from agent._url import inject_token, redact


# ---------------------------------------------------------------------------
# inject_token
# ---------------------------------------------------------------------------


class TestInjectToken:
    def test_returns_input_unchanged_when_token_is_empty(self) -> None:
        url = "https://github.com/owner/repo"
        assert inject_token(url, "", "github.com") == url

    @pytest.mark.parametrize(
        "url",
        [
            "git@github.com:owner/repo.git",
            "ssh://git@github.com/owner/repo.git",
            "ftp://github.com/owner/repo",
        ],
    )
    def test_returns_input_unchanged_for_non_http_schemes(self, url: str) -> None:
        assert inject_token(url, "tk", "github.com") == url

    def test_returns_input_unchanged_when_url_already_has_credentials(self) -> None:
        url = "https://existing:secret@github.com/owner/repo"
        assert inject_token(url, "tk", "github.com") == url

    def test_returns_input_unchanged_when_url_has_username_only(self) -> None:
        url = "https://existing@github.com/owner/repo"
        assert inject_token(url, "tk", "github.com") == url

    def test_returns_input_unchanged_when_host_mismatches(self) -> None:
        url = "https://gitlab.example.com/owner/repo"
        assert inject_token(url, "tk", "github.com") == url

    @pytest.mark.parametrize(
        "url_host,configured_host",
        [
            ("GitHub.com", "github.com"),
            ("github.com", "GitHub.com"),
            ("GITHUB.COM", "github.com"),
        ],
    )
    def test_case_insensitive_host_match(self, url_host: str, configured_host: str) -> None:
        url = f"https://{url_host}/owner/repo"
        out = inject_token(url, "tk", configured_host)
        assert "x-access-token:tk@" in out

    def test_injects_x_access_token_for_matching_host(self) -> None:
        out = inject_token("https://github.com/owner/repo", "tk", "github.com")
        assert out == "https://x-access-token:tk@github.com/owner/repo"

    def test_preserves_port(self) -> None:
        out = inject_token(
            "https://github.example.com:8443/owner/repo",
            "tk",
            "github.example.com",
        )
        assert out == "https://x-access-token:tk@github.example.com:8443/owner/repo"

    def test_returns_input_unchanged_when_hostname_missing(self) -> None:
        # urlparse gives hostname=None for path-only URLs.
        url = "https:///owner/repo"
        assert inject_token(url, "tk", "github.com") == url

    def test_works_with_query_and_fragment(self) -> None:
        url = "https://github.com/owner/repo?ref=main#frag"
        out = inject_token(url, "tk", "github.com")
        assert out == "https://x-access-token:tk@github.com/owner/repo?ref=main#frag"

    def test_http_scheme_supported(self) -> None:
        out = inject_token("http://github.com/owner/repo", "tk", "github.com")
        assert out.startswith("http://x-access-token:tk@github.com/")


# ---------------------------------------------------------------------------
# redact
# ---------------------------------------------------------------------------


class TestRedact:
    def test_replaces_basic_auth_with_asterisks(self) -> None:
        assert (
            redact("https://user:pass@github.com/owner/repo")
            == "https://***@github.com/owner/repo"
        )

    def test_credential_free_url_unchanged(self) -> None:
        url = "https://github.com/owner/repo"
        assert redact(url) == url

    def test_handles_x_access_token_credentials(self) -> None:
        assert (
            redact("https://x-access-token:ghp_123@github.com/o/r")
            == "https://***@github.com/o/r"
        )

    def test_idempotent(self) -> None:
        url = "https://user:pass@github.com/owner/repo"
        assert redact(redact(url)) == redact(url)

    def test_handles_username_only(self) -> None:
        # The regex matches ://<no-@-or-/>+@.
        assert redact("https://user@github.com/o/r") == "https://***@github.com/o/r"


# ---------------------------------------------------------------------------
# Hypothesis property tests
# ---------------------------------------------------------------------------

# Restrict to ASCII alphanumerics + a few harmless chars so we generate
# parseable URLs; the security invariants don't require Unicode coverage.
_ALPHA = st.text(
    alphabet=st.characters(min_codepoint=0x30, max_codepoint=0x7A, blacklist_characters="@/:?#"),
    min_size=1,
    max_size=12,
)
_HOST_CHARS = st.text(
    alphabet=st.characters(min_codepoint=0x61, max_codepoint=0x7A),
    min_size=1,
    max_size=10,
)


@st.composite
def _https_url(draw: st.DrawFn) -> str:
    host = draw(_HOST_CHARS)
    org = draw(_ALPHA)
    repo = draw(_ALPHA)
    return f"https://{host}.example.com/{org}/{repo}"


@settings(max_examples=50, deadline=None)
@given(url=_https_url(), token=_ALPHA)
def test_property_redact_after_inject_never_reveals_token(url: str, token: str) -> None:
    """Whatever the input URL, redact(inject_token(...)) must hide the token.

    A short token can coincidentally match characters elsewhere in the
    URL (e.g. token "0" appearing in a path "/0/0"). That isn't a leak —
    the redactor only needs to scrub the basic-auth segment it produced.
    Skip the case where the token already appears in the original URL.
    """
    from urllib.parse import urlparse

    host = urlparse(url).hostname or ""
    if token and token in url:
        return  # not a real leak — the token was already in the URL
    injected = inject_token(url, token, host)
    redacted = redact(injected)
    if token and injected != url:
        assert token not in redacted


@settings(max_examples=50, deadline=None)
@given(url=_https_url(), token=_ALPHA)
def test_property_redact_is_idempotent(url: str, token: str) -> None:
    injected = inject_token(url, token, "noop-host")  # mostly no-op host mismatches
    once = redact(injected)
    twice = redact(once)
    assert once == twice


@settings(max_examples=50, deadline=None)
@given(
    url=_https_url(),
    token=_ALPHA,
    other_host=_HOST_CHARS,
)
def test_property_inject_only_modifies_matching_host(
    url: str, token: str, other_host: str
) -> None:
    """inject_token must leave URLs alone when the host doesn't match."""
    from urllib.parse import urlparse

    parsed_host = urlparse(url).hostname or ""
    # other_host is generated to be a single label; pair it with a unique
    # tld so it can't collide with parsed_host (which ends in '.example.com').
    expected = f"{other_host}.different-tld"
    if parsed_host.lower() == expected.lower():
        return  # skip the rare collision
    out = inject_token(url, token, expected)
    assert out == url
