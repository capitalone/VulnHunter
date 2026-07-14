"""End-to-end tests for scripts/setup_worktree.sh.

Bash script can't be unit-tested in isolation — exercise it as a
subprocess against a real throwaway git repo built in a pytest
tmp_path. Each test verifies a specific behavior (initial creation,
idempotency, slug sanitization, exclude wiring, base-branch fallback).
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest


SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts" / "setup_worktree.sh"
)


def _init_repo(tmp_path: Path, default_branch: str = "main") -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.t"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    (repo / "README").write_text("hello\n")
    subprocess.run(["git", "add", "README"], cwd=repo, check=True)
    subprocess.run(
        ["git", "commit", "-q", "-m", "initial"], cwd=repo, check=True
    )
    # Rename whatever the default branch is to the requested name.
    subprocess.run(
        ["git", "branch", "-M", default_branch], cwd=repo, check=True
    )
    return repo


def _run_setup(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        cwd=repo,
        capture_output=True,
        text=True,
    )


class TestSetupWorktree:
    def test_creates_worktree_with_explicit_base(self, tmp_path):
        repo = _init_repo(tmp_path)
        result = _run_setup(repo, "abcdef0123456789", "sql-injection-fix", "main")
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout.splitlines()[-1])
        assert payload["status"] == "ok"
        assert payload["reused"] is False
        assert payload["branch"] == "vulnfix/sql-injection-fix"
        assert payload["base"] == "main"
        wt_path = Path(payload["path"])
        assert wt_path.exists()
        assert (wt_path / ".git").exists()

    def test_second_run_reuses_existing_worktree(self, tmp_path):
        repo = _init_repo(tmp_path)
        _run_setup(repo, "abcdef0123456789", "sql-injection-fix", "main")
        result = _run_setup(repo, "abcdef0123456789", "sql-injection-fix", "main")
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout.splitlines()[-1])
        assert payload["reused"] is True

    def test_adds_workdir_to_git_exclude(self, tmp_path):
        repo = _init_repo(tmp_path)
        _run_setup(repo, "abcdef0123456789", "x", "main")
        exclude = (repo / ".git" / "info" / "exclude").read_text()
        assert ".vulnhunter-fix/" in exclude

    def test_does_not_duplicate_exclude_entry(self, tmp_path):
        repo = _init_repo(tmp_path)
        _run_setup(repo, "abcdef0123456789", "x", "main")
        _run_setup(repo, "1111222233334444", "y", "main")
        exclude = (repo / ".git" / "info" / "exclude").read_text()
        # Only one occurrence.
        assert exclude.count(".vulnhunter-fix/") == 1

    def test_slug_is_sanitized(self, tmp_path):
        repo = _init_repo(tmp_path)
        result = _run_setup(repo, "abcdef0123456789", "SQL Injection / Login!!", "main")
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout.splitlines()[-1])
        # Lowercase, spaces and slashes collapsed to single dash,
        # special chars stripped.
        assert payload["branch"] == "vulnfix/sql-injection-login"

    def test_two_distinct_keys_yield_two_worktrees(self, tmp_path):
        repo = _init_repo(tmp_path)
        r1 = _run_setup(repo, "aaaaaaaaaaaaaaaa", "first", "main")
        r2 = _run_setup(repo, "bbbbbbbbbbbbbbbb", "second", "main")
        assert r1.returncode == 0 and r2.returncode == 0
        p1 = json.loads(r1.stdout.splitlines()[-1])["path"]
        p2 = json.loads(r2.stdout.splitlines()[-1])["path"]
        assert p1 != p2
        assert Path(p1).exists() and Path(p2).exists()

    def test_falls_back_to_gh_default_when_no_base_supplied(
        self, tmp_path, monkeypatch
    ):
        # When `gh` is unavailable we expect the script to fall back to
        # "main" rather than crashing. Simulate that by setting PATH to
        # a directory with only `git`.
        repo = _init_repo(tmp_path)
        stub_dir = tmp_path / "stub-path"
        stub_dir.mkdir()
        for tool in ("git", "bash", "mkdir", "sed", "tr", "cat", "echo",
                      "grep", "printf", "rm", "ls"):
            real = subprocess.run(
                ["which", tool], capture_output=True, text=True
            ).stdout.strip()
            if real:
                os.symlink(real, stub_dir / tool)
        env = os.environ.copy()
        env["PATH"] = str(stub_dir)
        result = subprocess.run(
            ["bash", str(SCRIPT), "abcdef0123456789", "no-gh-fix"],
            cwd=repo,
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout.splitlines()[-1])
        assert payload["base"] == "main"

    def test_empty_slug_after_sanitization_errors(self, tmp_path):
        repo = _init_repo(tmp_path)
        result = _run_setup(repo, "abcdef0123456789", "!!!@@@###", "main")
        assert result.returncode != 0
        assert "sanitized to empty" in result.stderr

    def test_rejects_non_hex_key(self, tmp_path):
        repo = _init_repo(tmp_path)
        # 16 chars but contains a non-hex char — would otherwise
        # flow into WT_PATH as a directory component.
        result = _run_setup(repo, "abcdef012345678z", "fix", "main")
        assert result.returncode != 0
        assert "invalid vulnfix_key" in result.stderr

    def test_rejects_wrong_length_key(self, tmp_path):
        repo = _init_repo(tmp_path)
        result = _run_setup(repo, "abc", "fix", "main")
        assert result.returncode != 0
        assert "invalid vulnfix_key" in result.stderr

    def test_rejects_path_traversal_key(self, tmp_path):
        repo = _init_repo(tmp_path)
        # Defense-in-depth: a `..` in the key would escape the
        # worktree dir if the validator didn't reject it.
        result = _run_setup(repo, "../etc/passwdaaaa", "fix", "main")
        assert result.returncode != 0
        assert "invalid vulnfix_key" in result.stderr

    def test_attaches_to_existing_branch_with_no_worktree(self, tmp_path):
        """The script's `show-ref --verify refs/heads/<branch>` path:
        if the branch already exists (e.g., from a previous crashed run
        or a manual `git branch` invocation) but no worktree is
        attached, the script must reattach it via `git worktree add
        <path> <branch>` rather than try to create the branch fresh
        (which would fail with "branch already exists")."""
        repo = _init_repo(tmp_path)

        # Pre-create the branch the script will compute (from slug
        # "sql-injection-fix") so the show-ref check finds it.
        subprocess.run(
            ["git", "branch", "vulnfix/sql-injection-fix", "main"],
            cwd=repo, check=True,
        )

        result = _run_setup(repo, "abcdef0123456789", "sql-injection-fix", "main")
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout.splitlines()[-1])
        assert payload["status"] == "ok"
        assert payload["reused"] is False  # worktree was new...
        assert payload["branch"] == "vulnfix/sql-injection-fix"
        # ...but the branch ref was reused. Confirm by checking the
        # worktree's HEAD matches the pre-created branch.
        wt = Path(payload["path"])
        head = subprocess.run(
            ["git", "-C", str(wt), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        main_head = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "main"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        assert head == main_head, (
            "reattached worktree should point at the same commit as "
            "the pre-existing branch (main, in this test)"
        )
