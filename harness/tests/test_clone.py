"""Tests for local_harness.clone."""

import subprocess
import types

import pytest

import local_harness.clone as clone


def _proc(returncode=0, stdout="", stderr=""):
    return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def test_parse_source_url():
    url = "https://github.com/acme/widget/tree/abcdef1234567890"
    repo_url, repo_name, commit = clone.parse_source_url(url)
    assert repo_url == "https://github.com/acme/widget"
    assert repo_name == "widget"
    assert commit == "abcdef1234567890"


def test_parse_source_url_trailing_slash():
    url = "https://github.com/acme/widget/tree/deadbeef/"
    repo_url, repo_name, commit = clone.parse_source_url(url)
    assert commit == "deadbeef"
    assert repo_name == "widget"


def test_target_dir_name_truncates_commit():
    assert clone.target_dir_name("repo", "0123456789abcdef") == "repo_01234567"


def test_is_at_commit_match(monkeypatch):
    monkeypatch.setattr(clone.subprocess, "run",
                        lambda *a, **k: _proc(0, stdout="0123456789\n"))
    assert clone.is_at_commit("/tmp/x", "01234567abc") is True


def test_is_at_commit_mismatch(monkeypatch):
    monkeypatch.setattr(clone.subprocess, "run",
                        lambda *a, **k: _proc(0, stdout="ffffffff\n"))
    assert clone.is_at_commit("/tmp/x", "01234567") is False


def test_is_at_commit_nonzero(monkeypatch):
    monkeypatch.setattr(clone.subprocess, "run",
                        lambda *a, **k: _proc(1, stdout=""))
    assert clone.is_at_commit("/tmp/x", "01234567") is False


def test_is_at_commit_timeout(monkeypatch):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="git", timeout=10)
    monkeypatch.setattr(clone.subprocess, "run", boom)
    assert clone.is_at_commit("/tmp/x", "01234567") is False


def test_is_at_commit_git_missing(monkeypatch):
    def boom(*a, **k):
        raise FileNotFoundError()
    monkeypatch.setattr(clone.subprocess, "run", boom)
    assert clone.is_at_commit("/tmp/x", "01234567") is False


def test_clone_at_commit_reuse_existing(monkeypatch, tmp_path):
    target = str(tmp_path / "clone")
    monkeypatch.setattr(clone.os.path, "isdir", lambda p: True)
    monkeypatch.setattr(clone, "is_at_commit", lambda d, c: True)
    result_dir, err = clone.clone_at_commit("url", "abc", target)
    assert result_dir == target and err is None


def test_clone_at_commit_fast_fetch_success(monkeypatch, tmp_path):
    target = str(tmp_path / "clone")
    # First isdir(target) -> False so we proceed to fetch path.
    monkeypatch.setattr(clone.os.path, "isdir", lambda p: False)
    monkeypatch.setattr(clone.os, "makedirs", lambda *a, **k: None)

    calls = []

    def fake_run(cmd, **k):
        calls.append(cmd)
        if cmd[:2] == ["git", "fetch"]:
            return _proc(0)
        if cmd[:2] == ["git", "checkout"]:
            return _proc(0)
        return _proc(0)

    monkeypatch.setattr(clone.subprocess, "run", fake_run)
    result_dir, err = clone.clone_at_commit("url", "abcdef12", target)
    assert err is None
    assert ["git", "fetch", "--depth=1", "origin", "abcdef12"] in calls


def test_clone_at_commit_fast_fetch_timeout_then_full_clone(monkeypatch, tmp_path):
    target = str(tmp_path / "clone")
    isdir_seq = iter([False, False])  # initial check, cleanup check after fetch

    monkeypatch.setattr(clone.os.path, "isdir", lambda p: next(isdir_seq, False))
    monkeypatch.setattr(clone.os, "makedirs", lambda *a, **k: None)

    def fake_run(cmd, **k):
        if cmd[:2] == ["git", "fetch"]:
            raise subprocess.TimeoutExpired(cmd="git fetch", timeout=1)
        if cmd[:2] == ["git", "clone"]:
            return _proc(0)
        if cmd[:2] == ["git", "checkout"]:
            return _proc(0)
        return _proc(0)

    monkeypatch.setattr(clone.subprocess, "run", fake_run)
    result_dir, err = clone.clone_at_commit("url", "abcdef12", target)
    assert err is None


def test_clone_at_commit_full_clone_fails(monkeypatch, tmp_path):
    target = str(tmp_path / "clone")
    isdir_seq = iter([False, False])
    monkeypatch.setattr(clone.os.path, "isdir", lambda p: next(isdir_seq, False))
    monkeypatch.setattr(clone.os, "makedirs", lambda *a, **k: None)

    def fake_run(cmd, **k):
        if cmd[:2] == ["git", "fetch"]:
            return _proc(1)  # fetch fails (non-timeout)
        if cmd[:2] == ["git", "clone"]:
            return _proc(128, stderr="fatal: repo not found")
        return _proc(0)

    monkeypatch.setattr(clone.subprocess, "run", fake_run)
    result_dir, err = clone.clone_at_commit("url", "abcdef12", target)
    assert "repo not found" in err


def test_clone_at_commit_checkout_fails(monkeypatch, tmp_path):
    target = str(tmp_path / "clone")
    isdir_seq = iter([False, False])
    monkeypatch.setattr(clone.os.path, "isdir", lambda p: next(isdir_seq, False))
    monkeypatch.setattr(clone.os, "makedirs", lambda *a, **k: None)

    def fake_run(cmd, **k):
        if cmd[:2] == ["git", "fetch"]:
            return _proc(1)
        if cmd[:2] == ["git", "clone"]:
            return _proc(0)
        if cmd[:2] == ["git", "checkout"]:
            return _proc(1, stderr="checkout boom")
        return _proc(0)

    monkeypatch.setattr(clone.subprocess, "run", fake_run)
    result_dir, err = clone.clone_at_commit("url", "abcdef12", target)
    assert "checkout boom" in err


def test_clone_at_commit_git_unavailable(monkeypatch, tmp_path):
    target = str(tmp_path / "clone")
    monkeypatch.setattr(clone, "CLONE_BASE_DIR", str(tmp_path / "base"))

    def boom(*a, **k):
        raise FileNotFoundError("git not on PATH")
    monkeypatch.setattr(clone.subprocess, "run", boom)
    result_dir, err = clone.clone_at_commit("url", "abcdef12", target)
    assert "git unavailable" in err


def test_clone_at_commit_init_nonzero_falls_back(monkeypatch, tmp_path):
    target = str(tmp_path / "clone")
    monkeypatch.setattr(clone, "CLONE_BASE_DIR", str(tmp_path / "base"))

    def fake_run(cmd, **k):
        if cmd[:2] == ["git", "init"]:
            return _proc(1)  # init fails -> skip fast fetch, go to full clone
        if cmd[:2] == ["git", "clone"]:
            return _proc(0)
        if cmd[:2] == ["git", "checkout"]:
            return _proc(0)
        return _proc(0)

    monkeypatch.setattr(clone.subprocess, "run", fake_run)
    result_dir, err = clone.clone_at_commit("url", "abcdef12", target)
    assert err is None


def test_clone_at_commit_full_clone_timeout(monkeypatch, tmp_path):
    target = str(tmp_path / "clone")
    isdir_seq = iter([False, False])
    monkeypatch.setattr(clone.os.path, "isdir", lambda p: next(isdir_seq, False))
    monkeypatch.setattr(clone.os, "makedirs", lambda *a, **k: None)

    def fake_run(cmd, **k):
        if cmd[:2] == ["git", "fetch"]:
            return _proc(1)
        if cmd[:2] == ["git", "clone"]:
            raise subprocess.TimeoutExpired(cmd="git clone", timeout=1)
        return _proc(0)

    monkeypatch.setattr(clone.subprocess, "run", fake_run)
    result_dir, err = clone.clone_at_commit("url", "abcdef12", target)
    assert "timed out" in err


def test_clone_at_commit_wrong_commit_removed(monkeypatch, tmp_path):
    target = str(tmp_path / "clone")
    # exists at first check, is_at_commit False -> rmtree, then proceed & fail fast
    isdir_seq = iter([True, False])
    monkeypatch.setattr(clone.os.path, "isdir", lambda p: next(isdir_seq, False))
    monkeypatch.setattr(clone, "is_at_commit", lambda d, c: False)
    removed = {}
    monkeypatch.setattr(clone.shutil, "rmtree", lambda p: removed.setdefault("r", p))
    monkeypatch.setattr(clone.os, "makedirs", lambda *a, **k: None)
    monkeypatch.setattr(clone.subprocess, "run",
                        lambda cmd, **k: _proc(0) if cmd[:2] == ["git", "fetch"] else _proc(0))
    result_dir, err = clone.clone_at_commit("url", "abcdef12", target)
    assert removed["r"] == target


def test_shallow_clone_reuse(monkeypatch, tmp_path):
    target = str(tmp_path / "c")
    monkeypatch.setattr(clone.os.path, "isdir", lambda p: True)
    result_dir, err = clone.shallow_clone("url", target)
    assert err is None and result_dir == target


def test_shallow_clone_reclone(monkeypatch, tmp_path):
    target = str(tmp_path / "c")
    monkeypatch.setattr(clone.os.path, "isdir", lambda p: True)
    removed = []
    monkeypatch.setattr(clone.shutil, "rmtree", lambda p: removed.append(p))
    monkeypatch.setattr(clone.os, "makedirs", lambda *a, **k: None)
    monkeypatch.setattr(clone.subprocess, "run", lambda *a, **k: _proc(0))
    result_dir, err = clone.shallow_clone("url", target, re_clone=True)
    assert err is None and removed == [target]


def test_shallow_clone_success(monkeypatch, tmp_path):
    target = str(tmp_path / "c")
    monkeypatch.setattr(clone.os.path, "isdir", lambda p: False)
    monkeypatch.setattr(clone.os, "makedirs", lambda *a, **k: None)
    monkeypatch.setattr(clone.subprocess, "run", lambda *a, **k: _proc(0))
    result_dir, err = clone.shallow_clone("url", target)
    assert err is None


def test_shallow_clone_fails(monkeypatch, tmp_path):
    target = str(tmp_path / "c")
    monkeypatch.setattr(clone.os.path, "isdir", lambda p: False)
    monkeypatch.setattr(clone.os, "makedirs", lambda *a, **k: None)
    monkeypatch.setattr(clone.subprocess, "run",
                        lambda *a, **k: _proc(1, stderr="no such repo"))
    result_dir, err = clone.shallow_clone("url", target)
    assert "no such repo" in err


def test_shallow_clone_timeout(monkeypatch, tmp_path):
    target = str(tmp_path / "c")
    monkeypatch.setattr(clone.os.path, "isdir", lambda p: False)
    monkeypatch.setattr(clone.os, "makedirs", lambda *a, **k: None)

    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="git", timeout=120)
    monkeypatch.setattr(clone.subprocess, "run", boom)
    result_dir, err = clone.shallow_clone("url", target)
    assert "timed out" in err


def test_shallow_clone_git_unavailable(monkeypatch, tmp_path):
    target = str(tmp_path / "c")
    monkeypatch.setattr(clone.os.path, "isdir", lambda p: False)
    monkeypatch.setattr(clone.os, "makedirs", lambda *a, **k: None)

    def boom(*a, **k):
        raise FileNotFoundError("git not on PATH")
    monkeypatch.setattr(clone.subprocess, "run", boom)
    result_dir, err = clone.shallow_clone("url", target)
    assert "git unavailable" in err
