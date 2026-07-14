"""Security test: VULN-002 — inject_token must scope the operator token to
authorized repo paths (confused-deputy guard, CWE-441).

inject_token attaches the operator's scan token to a URL only when the host
matches. That lets an attacker-chosen owner/repo on the same host receive the
token (confused deputy). With allowed_path_prefixes supplied, the token must
attach ONLY when the URL path is under an authorized prefix.
"""

from agent._url import inject_token

_HOST = "github.com"
_TOKEN = "SECRET-SCAN-TOKEN"


def test_token_not_attached_to_unauthorized_owner():
    attacker = "https://github.com/attacker-owner/evil-repo.git"
    out = inject_token(attacker, _TOKEN, _HOST, allowed_path_prefixes=("acme",))
    assert out == attacker, "token must NOT be attached to a non-authorized owner"
    assert _TOKEN not in out


def test_token_attached_to_authorized_owner_prefix():
    ok = "https://github.com/acme/shared-libs.git"
    out = inject_token(ok, _TOKEN, _HOST, allowed_path_prefixes=("acme",))
    assert out.startswith(f"https://x-access-token:{_TOKEN}@github.com/acme/shared-libs")


def test_token_attached_to_authorized_owner_repo_prefix():
    ok = "https://github.com/acme/only-this-repo.git"
    out = inject_token(
        ok, _TOKEN, _HOST, allowed_path_prefixes=("acme/only-this-repo",)
    )
    assert _TOKEN in out
    denied = "https://github.com/acme/other-repo.git"
    assert inject_token(
        denied, _TOKEN, _HOST, allowed_path_prefixes=("acme/only-this-repo",)
    ) == denied


def test_empty_prefix_list_denies_all():
    url = "https://github.com/acme/repo.git"
    assert inject_token(url, _TOKEN, _HOST, allowed_path_prefixes=()) == url


def test_none_prefixes_preserves_legacy_target_clone_behavior():
    # Target-repo clones (operator-supplied URL) pass allowed_path_prefixes=None
    # and must still get the token on a host match.
    url = "https://github.com/acme/target.git"
    out = inject_token(url, _TOKEN, _HOST, allowed_path_prefixes=None)
    assert _TOKEN in out
    # And the default (no kwarg) is the same legacy behavior.
    assert _TOKEN in inject_token(url, _TOKEN, _HOST)
