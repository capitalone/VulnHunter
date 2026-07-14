"""Tests for the in-place mode addition in scripts/preflight.py.

Preflight is local-only now (no network calls — auth + reachability
are done by the prompt's Bash tool, which has the working network
context Python doesn't). So these tests only exercise filesystem +
git probes.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import preflight  # noqa: E402


def _init_repo(tmp_path: Path, origin: str | None = None) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.t"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    (repo / "README").write_text("hi\n")
    subprocess.run(["git", "add", "README"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "x"], cwd=repo, check=True)
    if origin:
        subprocess.run(
            ["git", "remote", "add", "origin", origin], cwd=repo, check=True
        )
    return repo


@pytest.fixture(autouse=True)
def reset_counters():
    preflight.CHECKS_PASSED = 0
    preflight.CHECKS_FAILED = 0
    yield


class TestCheckInPlaceMode:
    def test_no_op_outside_git_repo(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        preflight.check_in_place_mode()
        out = capsys.readouterr().out
        assert "In-place mode:" not in out
        assert preflight.CHECKS_FAILED == 0

    def test_no_op_when_origin_is_non_github(self, tmp_path, monkeypatch, capsys):
        repo = _init_repo(tmp_path, origin="https://gitlab.com/a/b.git")
        monkeypatch.chdir(repo)
        preflight.check_in_place_mode()
        out = capsys.readouterr().out
        assert "In-place mode:" not in out

    def test_clean_tree_passes(self, tmp_path, monkeypatch, capsys):
        repo = _init_repo(tmp_path, origin="https://github.com/a/b.git")
        monkeypatch.chdir(repo)
        preflight.check_in_place_mode()
        out = capsys.readouterr().out
        assert "[ok] Working tree is clean" in out

    def test_dirty_tree_fails(self, tmp_path, monkeypatch, capsys):
        repo = _init_repo(tmp_path, origin="https://github.com/a/b.git")
        (repo / "README").write_text("modified\n")
        monkeypatch.chdir(repo)
        preflight.check_in_place_mode()
        out = capsys.readouterr().out
        assert "[FAIL] Working tree is clean" in out
        assert preflight.CHECKS_FAILED >= 1

    def test_staged_changes_fail(self, tmp_path, monkeypatch, capsys):
        repo = _init_repo(tmp_path, origin="https://github.com/a/b.git")
        (repo / "newfile").write_text("x\n")
        subprocess.run(["git", "add", "newfile"], cwd=repo, check=True)
        monkeypatch.chdir(repo)
        preflight.check_in_place_mode()
        out = capsys.readouterr().out
        assert "[FAIL] Working tree is clean" in out

    def test_worktree_prune_runs_on_clean_repo(
        self, tmp_path, monkeypatch, capsys
    ):
        repo = _init_repo(tmp_path, origin="https://github.com/a/b.git")
        monkeypatch.chdir(repo)
        preflight.check_in_place_mode()
        out = capsys.readouterr().out
        assert "[ok] git worktree prune" in out

    def test_no_network_calls_made(self, tmp_path, monkeypatch, capsys):
        """Regression guard: preflight must not call urllib or `gh api`
        / `gh repo view` itself — those network paths don't work from
        Python subprocesses in the target environments.
        """
        repo = _init_repo(tmp_path, origin="https://github.com/a/b.git")
        monkeypatch.chdir(repo)
        # If urllib.request was somehow re-imported and called, we'd
        # see it via this spy.
        try:
            import urllib.request
            called = {"urlopen": False}
            orig = urllib.request.urlopen
            def spy(*a, **kw):
                called["urlopen"] = True
                return orig(*a, **kw)
            monkeypatch.setattr(urllib.request, "urlopen", spy)
        except ImportError:
            called = {"urlopen": False}
        preflight.check_in_place_mode()
        assert called["urlopen"] is False


class TestDetectInPlaceRoot:
    def test_returns_repo_root_inside_github_repo(self, tmp_path, monkeypatch):
        repo = _init_repo(tmp_path, origin="https://github.com/a/b.git")
        monkeypatch.chdir(repo)
        root = preflight._detect_in_place_root()
        assert root is not None
        assert Path(root).resolve() == repo.resolve()

    def test_returns_none_outside_git_repo(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert preflight._detect_in_place_root() is None

    def test_returns_none_for_non_github_origin(self, tmp_path, monkeypatch):
        repo = _init_repo(tmp_path, origin="https://gitlab.com/a/b.git")
        monkeypatch.chdir(repo)
        assert preflight._detect_in_place_root() is None

    def test_returns_none_when_no_origin(self, tmp_path, monkeypatch):
        repo = _init_repo(tmp_path)
        monkeypatch.chdir(repo)
        assert preflight._detect_in_place_root() is None


class TestProbeSkipping:
    """The clone-writable probe must NOT run when CWD is already a
    checked-out target repo."""

    def test_probe_skipped_when_in_place(self, tmp_path, monkeypatch, capsys):
        repo = _init_repo(tmp_path, origin="https://github.com/a/b.git")
        monkeypatch.chdir(repo)
        for fn in (
            "check_python", "check_git", "check_gh_cli", "check_claude_cli",
            "check_memory", "check_disk_space", "check_in_place_mode",
        ):
            monkeypatch.setattr(preflight, fn, lambda *a, **kw: None)
        called = {"probe": False}
        def probe_spy():
            called["probe"] = True
        monkeypatch.setattr(preflight, "check_git_clone_writable", probe_spy)
        with pytest.raises(SystemExit):
            preflight.main()
        out = capsys.readouterr().out
        assert called["probe"] is False
        assert "Filesystem:" not in out

    def test_probe_runs_when_fork_mode(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        for fn in (
            "check_python", "check_git", "check_gh_cli", "check_claude_cli",
            "check_memory", "check_disk_space", "check_in_place_mode",
        ):
            monkeypatch.setattr(preflight, fn, lambda *a, **kw: None)
        called = {"probe": False}
        def probe_spy():
            called["probe"] = True
        monkeypatch.setattr(preflight, "check_git_clone_writable", probe_spy)
        with pytest.raises(SystemExit):
            preflight.main()
        out = capsys.readouterr().out
        assert called["probe"] is True
        assert "Filesystem:" in out


class TestNoNetworkProbesInMain:
    """Regression guard: main() must not invoke any network probes."""

    def test_main_has_no_check_gh_auth(self):
        assert not hasattr(preflight, "check_gh_auth"), (
            "check_gh_auth was removed because urllib subprocesses "
            "can't reach GitHub in the target environments; auth is "
            "now verified by the prompt's Bash tool."
        )

    def test_main_has_no_check_network(self):
        assert not hasattr(preflight, "check_network"), (
            "check_network was removed for the same reason as "
            "check_gh_auth — network verification now lives in the "
            "prompt's Bash tool."
        )

    def test_main_has_no_check_repo_access(self):
        assert not hasattr(preflight, "_check_repo_access"), (
            "_check_repo_access was removed; repo access surfaces "
            "via downstream `gh pr create` / `gh issue close` calls "
            "from the prompt's Bash tool."
        )
