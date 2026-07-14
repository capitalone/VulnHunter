"""End-to-end tests for scripts/detect_mode.sh.

Exercises every dispatch branch by setting CWD + env vars and
asserting on the script's stdout. Bash is run as a subprocess so
we test the canonical implementation, not a Python re-derivation
of it.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "detect_mode.sh"


def _run(cwd: Path, *args: str, **env_overrides: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    # Make sure no inherited env muddies the test.
    env.pop("TARGET_REPO", None)
    env.pop("RESULTS_PATH", None)
    env.update(env_overrides)
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        env=env,
    )


def _init_repo(tmp_path: Path, origin: str | None = None) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.t"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    if origin:
        subprocess.run(
            ["git", "remote", "add", "origin", origin], cwd=repo, check=True
        )
    return repo


class TestInPlace:
    def test_https_github_origin(self, tmp_path):
        repo = _init_repo(tmp_path, origin="https://github.com/acme/widgets.git")
        result = _run(repo)
        assert result.returncode == 0, result.stderr
        assert "mode=in_place" in result.stdout
        assert "owner_repo=acme/widgets" in result.stdout

    def test_ssh_github_origin(self, tmp_path):
        repo = _init_repo(tmp_path, origin="git@github.com:acme/widgets.git")
        result = _run(repo)
        assert result.returncode == 0
        assert "mode=in_place" in result.stdout
        assert "owner_repo=acme/widgets" in result.stdout

    def test_github_enterprise_origin(self, tmp_path):
        repo = _init_repo(
            tmp_path, origin="https://github.example.com/team/repo.git"
        )
        result = _run(repo)
        assert result.returncode == 0
        assert "mode=in_place" in result.stdout
        assert "owner_repo=team/repo" in result.stdout


class TestFork:
    def test_args_no_git_repo(self, tmp_path):
        # CWD has no .git/ — fork mode required to make any sense.
        result = _run(
            tmp_path,
            "https://github.com/acme/widgets", "/tmp/results",
        )
        assert result.returncode == 0
        assert "mode=fork" in result.stdout
        assert "target=https://github.com/acme/widgets" in result.stdout
        assert "results=/tmp/results" in result.stdout

    def test_args_via_env_vars(self, tmp_path):
        result = _run(
            tmp_path,
            TARGET_REPO="https://github.com/x/y",
            RESULTS_PATH="/tmp/r",
        )
        assert result.returncode == 0
        assert "mode=fork" in result.stdout


class TestAmbiguous:
    def test_args_supplied_while_in_github_repo(self, tmp_path):
        repo = _init_repo(tmp_path, origin="https://github.com/acme/widgets.git")
        result = _run(
            repo,
            "https://github.com/other/repo", "/tmp/r",
        )
        # Exit 2 = caller must resolve.
        assert result.returncode == 2
        assert "mode=ambiguous" in result.stdout
        assert "owner_repo=acme/widgets" in result.stdout
        assert "target=https://github.com/other/repo" in result.stdout


class TestInPlaceWithResultsPath:
    """RESULTS_PATH alone inside a GitHub checkout resolves cleanly to
    mode=in_place with an optional results=<path> field. Per peer review 4
    collapse: findings-source is a property of the work, not the mode."""

    def test_positional_results_path_only(self, tmp_path):
        repo = _init_repo(tmp_path, origin="https://github.com/acme/widgets.git")
        result = _run(repo, "", "/tmp/vulnhunt-results")
        assert result.returncode == 0
        assert "mode=in_place" in result.stdout
        # It's mode=in_place, NOT mode=in_place_local
        assert "mode=in_place_local" not in result.stdout
        assert "owner_repo=acme/widgets" in result.stdout
        assert "results=/tmp/vulnhunt-results" in result.stdout

    def test_env_results_path_only(self, tmp_path):
        repo = _init_repo(tmp_path, origin="https://github.com/acme/widgets.git")
        result = _run(repo, RESULTS_PATH="/tmp/vulnhunt-results")
        assert result.returncode == 0
        assert "mode=in_place" in result.stdout
        assert "mode=in_place_local" not in result.stdout
        assert "results=/tmp/vulnhunt-results" in result.stdout

    def test_target_repo_only_still_ambiguous(self, tmp_path):
        """TARGET_REPO alone inside a checkout stays ambiguous —
        legitimately unclear whether the operator wants in-place or fork."""
        repo = _init_repo(tmp_path, origin="https://github.com/acme/widgets.git")
        result = _run(repo, TARGET_REPO="https://github.com/other/repo")
        assert result.returncode == 2
        assert "mode=ambiguous" in result.stdout

    def test_both_args_still_ambiguous(self, tmp_path):
        """When both are set, keep the original ambiguity guard."""
        repo = _init_repo(tmp_path, origin="https://github.com/acme/widgets.git")
        result = _run(repo, "https://github.com/other/repo", "/tmp/r")
        assert result.returncode == 2
        assert "mode=ambiguous" in result.stdout

    def test_results_path_without_git_still_fork(self, tmp_path):
        """Outside a checkout, RESULTS_PATH alone falls through to fork
        (pre-existing behavior; not the RESULTS_PATH short-circuit path)."""
        result = _run(tmp_path, RESULTS_PATH="/tmp/r")
        assert result.returncode == 0
        assert "mode=fork" in result.stdout


class TestNone:
    def test_no_git_no_args(self, tmp_path):
        result = _run(tmp_path)
        assert result.returncode == 0
        assert "mode=none" in result.stdout

    def test_git_but_non_github_origin(self, tmp_path):
        repo = _init_repo(tmp_path, origin="https://gitlab.com/a/b.git")
        result = _run(repo)
        # Non-GitHub remotes don't qualify for in-place; with no args,
        # we have nothing to do → mode=none.
        assert result.returncode == 0
        assert "mode=none" in result.stdout

    def test_gitlab_with_github_in_path_not_in_place(self, tmp_path):
        # Regression: the previous `*github*` glob over-matched paths
        # like `gitlab.com/<org>/github-mirror` and routed them through
        # in-place mode by mistake. The host check now rejects them.
        repo = _init_repo(
            tmp_path, origin="https://gitlab.com/myorg/github-mirror.git"
        )
        result = _run(repo)
        assert result.returncode == 0
        assert "mode=none" in result.stdout

    def test_git_with_no_origin(self, tmp_path):
        repo = _init_repo(tmp_path)  # no origin remote
        result = _run(repo)
        assert result.returncode == 0
        assert "mode=none" in result.stdout
