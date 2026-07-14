"""Security test: VULN-001 — resolve_repo_hint must host-allow-list URL hints.

CWE-918 SSRF. An attacker-authored comment can surface a URL-shaped repo_hint
pointing at an internal/link-local host. resolve_repo_hint must NOT return a
URL whose host is outside the configured allow-list; such hints resolve to
None (unresolvable) so the clone sink is never reached.
"""

from agent.verify_resolve import resolve_repo_hint

_ALLOWED = ("github.com",)


def test_link_local_url_hint_is_rejected():
    attacker = "https://169.254.169.254:80/latest/meta-data"
    assert resolve_repo_hint(attacker, {}, allowed_hosts=_ALLOWED) is None


def test_foreign_host_url_hint_is_rejected():
    for url in (
        "https://attacker.example/evil/repo.git",
        "http://10.0.0.5/internal.git",
        "ssh://attacker.example/x.git",
        "git@attacker.example:evil/repo.git",
    ):
        assert resolve_repo_hint(url, {}, allowed_hosts=_ALLOWED) is None, url


def test_allowed_host_url_hint_passes():
    ok = "https://github.com/octocat/Hello-World.git"
    assert resolve_repo_hint(ok, {}, allowed_hosts=_ALLOWED) == ok


def test_operator_alias_still_resolves_regardless_of_host():
    aliases = {"shared-validators": "https://internal.example/shared/validators.git"}
    assert (
        resolve_repo_hint("shared-validators", aliases, allowed_hosts=_ALLOWED)
        == "https://internal.example/shared/validators.git"
    )


def test_unknown_bare_hint_is_unresolvable():
    assert resolve_repo_hint("../platform-validators", {}, allowed_hosts=_ALLOWED) is None
