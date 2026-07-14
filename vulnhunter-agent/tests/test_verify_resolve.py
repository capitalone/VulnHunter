"""Unit tests for ``agent/verify_resolve.py`` — the pure-function pieces.

The git-touching pieces (``clone_target_repo``, ``clone_additional_repo``,
``stage_report``) are integration-level and need network access; we
cover their parameter wiring via a thin set of monkeypatched tests
rather than the real ``shallow_clone`` / ``download_named_report``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent import verify_resolve
from agent.verify_resolve import (
    ResolveError,
    clone_additional_repo,
    clone_target_repo,
    resolve_repo_hint,
)


# ---------- resolve_repo_hint -----------------------------------------------


# Updated for VULN-001: URL-shaped hints now pass through only when their
# host is in allowed_hosts (CWE-918 SSRF guard). A URL on a non-allow-listed
# host resolves to None instead of passing through unchanged.
@pytest.mark.parametrize(
    "hint",
    [
        "https://github.com/foo/bar",
        "https://github.com/foo/bar.git",
        "git@github.com:foo/bar.git",
        "ssh://git@github.com/foo/bar.git",
    ],
)
def test_resolve_repo_hint_passes_through_allowed_host_urls(hint: str) -> None:
    assert resolve_repo_hint(hint, aliases={}, allowed_hosts=("github.com",)) == hint


# Updated for VULN-001: a URL on a host outside the allow-list must not resolve.
def test_resolve_repo_hint_rejects_non_allowlisted_host_url() -> None:
    assert (
        resolve_repo_hint(
            "http://example.com/foo/bar.git", aliases={}, allowed_hosts=("github.com",)
        )
        is None
    )


def test_resolve_repo_hint_resolves_via_alias() -> None:
    aliases = {
        "platform-validators": "https://github.com/org/platform-validators.git",
        "shared-libs": "https://github.com/org/shared-libs.git",
    }
    assert (
        resolve_repo_hint("platform-validators", aliases)
        == "https://github.com/org/platform-validators.git"
    )


@pytest.mark.parametrize(
    "hint",
    [
        "platform-validators",         # alias not in dict → None
        "../sibling-repo",              # path-like, not an alias
        "github.com/org/repo",          # missing scheme → not a URL match
        "some-bare-name",               # no scheme, no alias
        "",                             # empty
        "   ",                          # whitespace
    ],
)
def test_resolve_repo_hint_unresolvable_returns_none(hint: str) -> None:
    # No aliases configured for any of these.
    assert resolve_repo_hint(hint, aliases={}) is None


def test_resolve_repo_hint_does_not_infer_org_from_target() -> None:
    """Design §8.3: no same-org inference. A bare 'platform-validators'
    must NOT resolve to e.g. 'https://github.com/<target-org>/platform-validators'
    even when there's an obvious-looking org to borrow from. The
    function takes no target-org parameter, so this is structural —
    the test just documents the property."""
    # Even with an alias present for a different name, the bare hint
    # doesn't resolve.
    aliases = {"other-name": "https://github.com/org/other.git"}
    assert resolve_repo_hint("platform-validators", aliases) is None


def test_resolve_repo_hint_handles_whitespace_padding() -> None:
    """Hints may arrive with surrounding whitespace from the verifier's
    free-form payload; .strip() normalizes."""
    aliases = {"foo": "https://github.com/org/foo.git"}
    assert (
        resolve_repo_hint("  foo  ", aliases)
        == "https://github.com/org/foo.git"
    )


# ---------- clone_additional_repo (wiring with monkeypatch) ----------------


def test_clone_additional_repo_calls_shallow_clone_with_args(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict = {}

    def fake_shallow_clone(repo_url, clone_base_dir, **kwargs):
        captured["repo_url"] = repo_url
        captured["clone_base_dir"] = Path(clone_base_dir)
        captured["kwargs"] = kwargs
        return Path(clone_base_dir) / "fake"

    monkeypatch.setattr(verify_resolve, "shallow_clone", fake_shallow_clone)

    out = clone_additional_repo(
        "https://github.com/x/y.git",
        tmp_path / "extras",
        github_token="tok",
        github_host="github.com",
        timeout_seconds=42,
    )
    assert out == tmp_path / "extras" / "fake"
    assert captured["repo_url"] == "https://github.com/x/y.git"
    assert captured["clone_base_dir"] == tmp_path / "extras"
    assert captured["kwargs"]["github_token"] == "tok"
    assert captured["kwargs"]["github_host"] == "github.com"
    assert captured["kwargs"]["timeout_seconds"] == 42


def test_clone_additional_repo_wraps_runtime_error_as_resolve_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_shallow_clone(*a, **kw):
        raise RuntimeError("simulated clone failure")

    monkeypatch.setattr(verify_resolve, "shallow_clone", fake_shallow_clone)

    with pytest.raises(ResolveError, match="simulated clone failure"):
        clone_additional_repo(
            "https://github.com/x/y.git",
            tmp_path / "extras",
            github_token="",
            github_host="github.com",
            timeout_seconds=1,
        )


# ---------- clone_target_repo ----------------------------------------------


def test_clone_target_repo_uses_shallow_clone_when_no_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    called: dict = {}

    def fake_shallow_clone(repo_url, clone_base_dir, **kwargs):
        called["shallow"] = True
        return Path(clone_base_dir) / "x"

    def fake_clone_at_commit(*a, **kw):
        called["pinned"] = True
        return Path(a[1]) / "x"

    monkeypatch.setattr(verify_resolve, "shallow_clone", fake_shallow_clone)
    monkeypatch.setattr(verify_resolve, "clone_at_commit", fake_clone_at_commit)

    clone_target_repo(
        "https://github.com/x/y.git",
        tmp_path / "target",
        commit=None,
        github_token="",
        github_host="github.com",
        timeout_seconds=10,
    )
    assert called == {"shallow": True}


def test_clone_target_repo_uses_clone_at_commit_when_commit_given(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    called: dict = {}

    def fake_shallow_clone(*a, **kw):
        called["shallow"] = True
        return Path(a[1]) / "x"

    def fake_clone_at_commit(repo_url, clone_base_dir, commit, **kwargs):
        called["pinned"] = True
        called["commit"] = commit
        return Path(clone_base_dir) / "x"

    monkeypatch.setattr(verify_resolve, "shallow_clone", fake_shallow_clone)
    monkeypatch.setattr(verify_resolve, "clone_at_commit", fake_clone_at_commit)

    clone_target_repo(
        "https://github.com/x/y.git",
        tmp_path / "target",
        commit="abc1234",
        github_token="",
        github_host="github.com",
        timeout_seconds=10,
    )
    assert called == {"pinned": True, "commit": "abc1234"}


def test_clone_target_repo_wraps_runtime_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_shallow_clone(*a, **kw):
        raise RuntimeError("nope")

    monkeypatch.setattr(verify_resolve, "shallow_clone", fake_shallow_clone)

    with pytest.raises(ResolveError, match="nope"):
        clone_target_repo(
            "https://github.com/x/y.git",
            tmp_path / "target",
            commit=None,
            github_token="",
            github_host="github.com",
            timeout_seconds=10,
        )
