"""Tests for agent.clone: shallow_clone + repo-name derivation."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from agent import clone as clone_mod
from agent.clone import _derive_repo_name, shallow_clone


# ---------------------------------------------------------------------------
# _derive_repo_name
# ---------------------------------------------------------------------------


class TestDeriveRepoName:
    @pytest.mark.parametrize(
        "url,expected",
        [
            ("https://github.com/org/repo", "repo"),
            ("https://github.com/org/repo.git", "repo"),
            ("git@github.com:org/repo", "repo"),
            ("git@github.com:org/repo.git", "repo"),
            ("https://github.com/org/repo/", "repo"),
            # urlparse treats "#" as a fragment delimiter, so this URL's
            # path is "/org/repo!@" — only two special chars get
            # sanitized, not four.
            ("https://github.com/org/repo!@#$.git", "repo__"),
            ("", "repo"),
            ("https://github.com/", "repo"),
        ],
    )
    def test_derive(self, url: str, expected: str) -> None:
        assert _derive_repo_name(url) == expected


# ---------------------------------------------------------------------------
# shallow_clone
# ---------------------------------------------------------------------------


class _FakeCompleted:
    def __init__(self, returncode: int = 0) -> None:
        self.returncode = returncode
        self.stdout = ""
        self.stderr = ""


@pytest.fixture
def captured_runs(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Patch subprocess.run inside agent.clone and capture every call.

    Pins ``_GIT_EXECUTABLE = "git"`` so the legacy cmd-shape assertions
    keep passing — the Bandit-B607 hardening swaps cmd[0] from "git"
    to the absolute path resolved by shutil.which at module load.
    """
    calls: list[dict[str, Any]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> _FakeCompleted:
        calls.append({"cmd": cmd, "kwargs": kwargs})
        # Create the target directory so the clone is treated as success.
        target = Path(cmd[-1])
        target.mkdir(parents=True, exist_ok=True)
        return _FakeCompleted(returncode=0)

    monkeypatch.setattr(clone_mod, "_GIT_EXECUTABLE", "git")
    monkeypatch.setattr(clone_mod.subprocess, "run", fake_run)
    return calls


class TestShallowClone:
    def test_existing_dir_no_reclone_skips_subprocess(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        target = tmp_path / "myrepo"
        target.mkdir()
        called: list[Any] = []
        monkeypatch.setattr(
            clone_mod.subprocess, "run", lambda *a, **k: called.append(a) or _FakeCompleted(0)
        )
        out = shallow_clone(
            "https://github.com/org/myrepo", tmp_path, re_clone=False
        )
        assert out == target
        assert called == []

    def test_existing_dir_with_reclone_removes_and_runs(
        self,
        tmp_path: Path,
        captured_runs: list[dict[str, Any]],
    ) -> None:
        target = tmp_path / "myrepo"
        target.mkdir()
        (target / "marker.txt").write_text("old content")
        out = shallow_clone(
            "https://github.com/org/myrepo", tmp_path, re_clone=True
        )
        assert out == target
        assert len(captured_runs) == 1
        # The marker file from the previous "clone" must be gone.
        assert not (target / "marker.txt").exists()

    def test_subprocess_returns_zero_returns_path(
        self, tmp_path: Path, captured_runs: list[dict[str, Any]]
    ) -> None:
        out = shallow_clone(
            "https://github.com/org/myrepo", tmp_path
        )
        assert out == tmp_path / "myrepo"
        assert len(captured_runs) == 1

    def test_timeout_expired_cleanup_and_runtime_error(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def fake_run(cmd: list[str], **kwargs: Any) -> _FakeCompleted:
            target = Path(cmd[-1])
            target.mkdir(parents=True, exist_ok=True)
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 1))

        monkeypatch.setattr(clone_mod.subprocess, "run", fake_run)
        with pytest.raises(RuntimeError, match="timed out"):
            shallow_clone(
                "https://github.com/org/myrepo",
                tmp_path,
                timeout_seconds=1,
            )
        assert not (tmp_path / "myrepo").exists()

    def test_subprocess_nonzero_cleanup_and_runtime_error(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def fake_run(cmd: list[str], **kwargs: Any) -> _FakeCompleted:
            target = Path(cmd[-1])
            target.mkdir(parents=True, exist_ok=True)
            return _FakeCompleted(returncode=128)

        monkeypatch.setattr(clone_mod.subprocess, "run", fake_run)
        with pytest.raises(RuntimeError, match="git clone failed"):
            shallow_clone("https://github.com/org/myrepo", tmp_path)
        assert not (tmp_path / "myrepo").exists()

    def test_git_terminal_prompt_env_set(
        self, tmp_path: Path, captured_runs: list[dict[str, Any]]
    ) -> None:
        shallow_clone("https://github.com/org/myrepo", tmp_path)
        env = captured_runs[0]["kwargs"]["env"]
        assert env["GIT_TERMINAL_PROMPT"] == "0"

    def test_token_injected_when_host_matches(
        self, tmp_path: Path, captured_runs: list[dict[str, Any]]
    ) -> None:
        shallow_clone(
            "https://github.com/org/myrepo",
            tmp_path,
            github_token="ghp_secret",
            github_host="github.com",
        )
        cmd = captured_runs[0]["cmd"]
        # The injected URL is the second-to-last argument (target is last).
        injected_url = cmd[-2]
        assert "x-access-token:ghp_secret@github.com" in injected_url

    def test_token_scrubbed_from_origin_after_clone(
        self, tmp_path: Path, captured_runs: list[dict[str, Any]]
    ) -> None:
        """After a token-bearing clone, .git/config must not retain the token.

        We achieve this by running `git remote set-url origin <plain>`
        immediately after the clone succeeds, before the orchestrator
        ever sees the working tree. Verifies the second subprocess call
        is the scrub.
        """
        shallow_clone(
            "https://github.com/org/myrepo",
            tmp_path,
            github_token="ghp_secret",
            github_host="github.com",
        )
        # First call is the clone; second call must be the scrub.
        assert len(captured_runs) >= 2
        scrub_cmd = captured_runs[1]["cmd"]
        assert scrub_cmd[:3] == ["git", "remote", "set-url"]
        assert scrub_cmd[3] == "origin"
        # The URL we set is the *plain* one — no token, no x-access-token.
        assert scrub_cmd[4] == "https://github.com/org/myrepo"
        assert "ghp_secret" not in scrub_cmd[4]
        assert "x-access-token" not in scrub_cmd[4]

    def test_no_scrub_when_no_token_injected(
        self, tmp_path: Path, captured_runs: list[dict[str, Any]]
    ) -> None:
        """If we didn't inject a token, there's nothing to scrub."""
        shallow_clone(
            "https://github.com/org/myrepo",
            tmp_path,
            github_token="",  # no token
            github_host="github.com",
        )
        # Only the clone runs — no scrub.
        assert len(captured_runs) == 1
        assert captured_runs[0]["cmd"][:2] == ["git", "clone"]

    def test_token_not_injected_when_host_differs(
        self, tmp_path: Path, captured_runs: list[dict[str, Any]]
    ) -> None:
        shallow_clone(
            "https://gitlab.example.com/org/myrepo",
            tmp_path,
            github_token="ghp_secret",
            github_host="github.com",
        )
        cmd = captured_runs[0]["cmd"]
        injected_url = cmd[-2]
        assert "x-access-token" not in injected_url
        assert "ghp_secret" not in injected_url

    def test_url_redacted_in_error_message(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def fake_run(cmd: list[str], **kwargs: Any) -> _FakeCompleted:
            target = Path(cmd[-1])
            target.mkdir(parents=True, exist_ok=True)
            return _FakeCompleted(returncode=1)

        monkeypatch.setattr(clone_mod.subprocess, "run", fake_run)
        with pytest.raises(RuntimeError) as exc:
            shallow_clone(
                "https://user:secret@github.com/org/repo",
                tmp_path,
            )
        msg = str(exc.value)
        assert "secret" not in msg
        assert "***@github.com" in msg

    def test_url_redacted_in_timeout_error_message(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def fake_run(cmd: list[str], **kwargs: Any) -> _FakeCompleted:
            raise subprocess.TimeoutExpired(cmd, 1)

        monkeypatch.setattr(clone_mod.subprocess, "run", fake_run)
        with pytest.raises(RuntimeError) as exc:
            shallow_clone(
                "https://user:secret@github.com/org/repo",
                tmp_path,
                timeout_seconds=1,
            )
        assert "secret" not in str(exc.value)

    def test_git_not_on_path_raises_runtime_error(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When ``_GIT_EXECUTABLE`` is None (git missing from PATH at
        module load), ``shallow_clone`` must raise a clear RuntimeError
        rather than letting an OSError surface from subprocess. Lock-
        down for the Bandit B607 hardening."""
        called: list[Any] = []

        def fake_run(*a: Any, **k: Any) -> Any:
            called.append(a)
            raise AssertionError("subprocess.run must not be called")

        monkeypatch.setattr(clone_mod, "_GIT_EXECUTABLE", None)
        monkeypatch.setattr(clone_mod.subprocess, "run", fake_run)
        with pytest.raises(RuntimeError, match="git not on PATH"):
            shallow_clone(
                "https://github.com/org/myrepo",
                tmp_path,
            )
        assert called == []

    def test_subprocess_receives_absolute_git_path(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The argv list passed to subprocess.run must start with the
        absolute path resolved at module load, not the bare 'git'
        string. Lock-down for Bandit B607."""
        captured: list[list[str]] = []

        def fake_run(cmd: list[str], **kwargs: Any) -> _FakeCompleted:
            captured.append(cmd)
            Path(cmd[-1]).mkdir(parents=True, exist_ok=True)
            return _FakeCompleted(returncode=0)

        monkeypatch.setattr(clone_mod, "_GIT_EXECUTABLE", "/usr/bin/git")
        monkeypatch.setattr(clone_mod.subprocess, "run", fake_run)
        shallow_clone(
            "https://github.com/org/myrepo",
            tmp_path,
        )
        assert captured[0][0] == "/usr/bin/git"
        assert captured[0][1] == "clone"
