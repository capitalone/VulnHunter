"""Security test: VULN-012 — redact() must cover all token forms.

CWE-532. redact() is used as a general-purpose token redactor over free-text
audit content, but only rewrites basic-auth URLs. It must also redact bearer
headers, access_token query params, and raw token prefixes.
"""

from agent._url import redact


def test_basic_auth_still_redacted():
    assert redact("https://user:ghp_secret@github.com/o/r.git") == (
        "https://***@github.com/o/r.git"
    )


def test_bearer_header_redacted():
    out = redact("Authorization: Bearer ghp_AAAA1111BBBB2222CCCC3333")
    assert "AAAA1111BBBB2222" not in out
    assert "***" in out


def test_access_token_query_redacted():
    out = redact("https://api.github.com/x?access_token=ghp_SECRET1234ABCD&y=1")
    assert "SECRET1234ABCD" not in out
    assert "y=1" in out  # non-secret query params preserved


def test_raw_token_prefixes_redacted_prefix_preserved():
    for prefix, secret in [
        ("ghp_", "abcdef0123456789abcdef0123456789abcd"),
        ("gho_", "0123456789abcdef0123456789abcdef0123"),
        ("github_pat_", "11ABCDEF0000abcdef1234567890"),
        ("sk-ant-", "api03-DEADBEEFDEADBEEFDEADBEEF"),
    ]:
        out = redact(f"leaked token {prefix}{secret} in log")
        assert secret not in out, prefix
        assert prefix in out, f"prefix {prefix} should be preserved for triage"


def test_benign_text_unchanged():
    assert redact("just a normal log line about issue #42") == (
        "just a normal log line about issue #42"
    )
