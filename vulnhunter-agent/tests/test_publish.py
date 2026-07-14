"""Tests for agent.publish: GitHub API + git push orchestration."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Callable

import httpx
import pytest
import respx

from agent import publish as publish_mod
from agent._github import api_base
from agent.config import AgentConfig, GitHubConfig, PublishConfig, TLSConfig
from agent.publish import (
    PublishError,
    _parse_owner_repo,
    _run,
    _validate_token_compatibility,
    ensure_destination_repo,
    publish_results,
)
from tests.conftest import _build_agent_config


def _publish_cfg(**overrides: object) -> PublishConfig:
    base = dict(
        enabled=True,
        destination_repo="https://github.com/owner/name",
        branch="main",
        commit_author_name="Bot",
        commit_author_email="bot@example.com",
    )
    base.update(overrides)
    return PublishConfig(**base)  # type: ignore[arg-type]


def cfg(**github_overrides: object) -> AgentConfig:
    """Build an AgentConfig with publish-friendly defaults.

    Plain helper (not a fixture) so test methods can call it inline
    without declaring it as a parameter.

    Usage:
        cfg()                                    → reports_token=ghp_xxx, host=github.com
        cfg(reports_token="ghp_test")            → override the reports token
        cfg(host="enterprise.example.com")       → override the host
        cfg(tls=TLSConfig("/etc/x.pem"))         → swap TLS config
    """
    tls = github_overrides.pop("tls", None)
    gh = GitHubConfig(
        host=str(github_overrides.pop("host", "github.com")),
        scan_token=str(github_overrides.pop("scan_token", "ghp_xxx")),
        reports_token=str(github_overrides.pop("reports_token", "ghp_xxx")),
        broker_token_dir=str(github_overrides.pop("broker_token_dir", "")),
    )
    if github_overrides:
        raise TypeError(f"unexpected kwargs: {sorted(github_overrides)}")
    overrides: dict[str, Any] = {"github": gh}
    if tls is not None:
        overrides["tls"] = tls  # type: ignore[assignment]
    return _build_agent_config(**overrides)


# ---------------------------------------------------------------------------
# api_base
# ---------------------------------------------------------------------------


class TestApiBase:
    def test_dotcom(self) -> None:
        assert api_base("github.com") == "https://api.github.com"

    def test_enterprise(self) -> None:
        assert api_base("enterprise.example.com") == "https://enterprise.example.com/api/v3"

    def test_dotcom_subdomain(self) -> None:
        assert api_base("api.github.com") == "https://api.github.com"


# ---------------------------------------------------------------------------
# _parse_owner_repo
# ---------------------------------------------------------------------------


class TestParseOwnerRepo:
    def test_basic(self) -> None:
        assert _parse_owner_repo("https://github.com/owner/repo") == ("owner", "repo")

    def test_strips_dot_git(self) -> None:
        assert _parse_owner_repo("https://github.com/owner/repo.git") == ("owner", "repo")

    def test_single_segment_raises(self) -> None:
        with pytest.raises(PublishError):
            _parse_owner_repo("https://github.com/owner")

    def test_empty_owner_raises(self) -> None:
        with pytest.raises(PublishError):
            _parse_owner_repo("https://github.com//repo")

    def test_ssh_style(self) -> None:
        assert _parse_owner_repo("git@github.com:owner/repo.git") == ("owner", "repo")

    def test_ssh_style_no_git_suffix(self) -> None:
        assert _parse_owner_repo("git@github.com:owner/repo") == ("owner", "repo")

    def test_tree_url_takes_first_two_segments(self) -> None:
        # Source URLs are sometimes pasted with /tree/<branch> appended.
        assert _parse_owner_repo(
            "https://github.com/owner/repo/tree/main"
        ) == ("owner", "repo")

    def test_trailing_slash_tolerated(self) -> None:
        assert _parse_owner_repo("https://github.com/owner/repo/") == ("owner", "repo")


# ---------------------------------------------------------------------------
# _validate_token_compatibility
# ---------------------------------------------------------------------------


class TestValidateTokenCompatibility:
    def test_non_http_raises(self) -> None:
        publish = _publish_cfg(destination_repo="git@github.com:o/r.git")
        with pytest.raises(PublishError, match="http"):
            _validate_token_compatibility(publish, cfg())

    def test_host_mismatch_raises(self) -> None:
        publish = _publish_cfg(destination_repo="https://gitlab.example.com/o/r")
        with pytest.raises(PublishError, match="host"):
            _validate_token_compatibility(publish, cfg(host="github.com"))

    def test_host_match_case_insensitive_ok(self) -> None:
        publish = _publish_cfg(destination_repo="https://GitHub.com/o/r")
        _validate_token_compatibility(publish, cfg(host="github.com"))

    def test_empty_token_raises(self) -> None:
        publish = _publish_cfg()
        with pytest.raises(PublishError, match="reports_token"):
            _validate_token_compatibility(publish, cfg(reports_token=""))


# ---------------------------------------------------------------------------
# ensure_destination_repo
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _stub_resolve_verify(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(publish_mod, "resolve_verify", lambda tls: True)


class TestEnsureDestinationRepo:
    @respx.mock
    def test_get_200_returns_false(self) -> None:
        respx.get("https://api.github.com/repos/owner/name").mock(
            return_value=httpx.Response(200, json={"id": 1})
        )
        out = ensure_destination_repo(_publish_cfg(), cfg())
        assert out is False

    @respx.mock
    def test_get_404_then_org_create_returns_true(self) -> None:
        respx.get("https://api.github.com/repos/owner/name").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://api.github.com/users/owner").mock(
            return_value=httpx.Response(200, json={"type": "Organization"})
        )
        create = respx.post("https://api.github.com/orgs/owner/repos").mock(
            return_value=httpx.Response(201, json={"id": 99})
        )
        out = ensure_destination_repo(_publish_cfg(), cfg())
        assert out is True
        # httpx serializes JSON without inter-key whitespace; assert against
        # the parsed form so we don't pin the exact byte layout.
        import json as _json
        body = _json.loads(create.calls.last.request.read())
        assert body["private"] is True
        assert body["auto_init"] is True

    @respx.mock
    def test_get_404_then_user_self_returns_true(self) -> None:
        respx.get("https://api.github.com/repos/owner/name").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://api.github.com/users/owner").mock(
            return_value=httpx.Response(200, json={"type": "User"})
        )
        respx.get("https://api.github.com/user").mock(
            return_value=httpx.Response(200, json={"login": "owner"})
        )
        respx.post("https://api.github.com/user/repos").mock(
            return_value=httpx.Response(201, json={"id": 100})
        )
        out = ensure_destination_repo(_publish_cfg(), cfg())
        assert out is True

    @respx.mock
    def test_user_namespace_token_mismatch_raises(self) -> None:
        respx.get("https://api.github.com/repos/owner/name").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://api.github.com/users/owner").mock(
            return_value=httpx.Response(200, json={"type": "User"})
        )
        respx.get("https://api.github.com/user").mock(
            return_value=httpx.Response(200, json={"login": "someone-else"})
        )
        with pytest.raises(PublishError, match="user namespace"):
            ensure_destination_repo(_publish_cfg(), cfg())

    @respx.mock
    def test_get_5xx_raises(self) -> None:
        respx.get("https://api.github.com/repos/owner/name").mock(
            return_value=httpx.Response(500, text="boom")
        )
        with pytest.raises(PublishError, match="500"):
            ensure_destination_repo(_publish_cfg(), cfg())

    @respx.mock
    def test_owner_lookup_404_raises(self) -> None:
        respx.get("https://api.github.com/repos/owner/name").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://api.github.com/users/owner").mock(
            return_value=httpx.Response(404, text="Not Found")
        )
        with pytest.raises(PublishError, match="not found"):
            ensure_destination_repo(_publish_cfg(), cfg())

    @respx.mock
    def test_create_non_201_raises(self) -> None:
        respx.get("https://api.github.com/repos/owner/name").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://api.github.com/users/owner").mock(
            return_value=httpx.Response(200, json={"type": "Organization"})
        )
        respx.post("https://api.github.com/orgs/owner/repos").mock(
            return_value=httpx.Response(422, text="validation failed")
        )
        with pytest.raises(PublishError, match="422"):
            ensure_destination_repo(_publish_cfg(), cfg())

    @respx.mock
    def test_authorization_header_sent(self) -> None:
        route = respx.get("https://api.github.com/repos/owner/name").mock(
            return_value=httpx.Response(200, json={})
        )
        ensure_destination_repo(_publish_cfg(), cfg(reports_token="ghp_test"))
        headers = route.calls.last.request.headers
        assert headers["authorization"] == "Bearer ghp_test"
        assert headers["x-github-api-version"] == "2022-11-28"

    def test_missing_token_raises(self) -> None:
        with pytest.raises(PublishError, match="reports_token"):
            ensure_destination_repo(_publish_cfg(), cfg(reports_token=""))

    @respx.mock
    def test_verify_param_honored(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # When ssl_cert_path is set, resolve_verify should return that path,
        # which httpx then uses; we just verify resolve_verify gets the cfg.
        seen: list[TLSConfig] = []

        def fake_resolve(tls: TLSConfig) -> str | bool:
            seen.append(tls)
            return True

        monkeypatch.setattr(publish_mod, "resolve_verify", fake_resolve)
        respx.get("https://api.github.com/repos/owner/name").mock(
            return_value=httpx.Response(200, json={})
        )
        tls = TLSConfig("/etc/ssl/test-bundle.pem")
        ensure_destination_repo(_publish_cfg(), cfg(tls=tls))
        assert seen == [tls]


# ---------------------------------------------------------------------------
# publish_results
# ---------------------------------------------------------------------------


@pytest.fixture
def results_dir(tmp_path: Path) -> Path:
    # Match the skill's actual naming convention so the timestamp regex
    # in _extract_timestamp catches the suffix. The skill uses
    # YYYY-MM-DD-HHMMSS, not just YYYY-MM-DD.
    rd = tmp_path / "vulnhunter_VULNHUNT_RESULTS_opus47_2026-01-01-141824"
    rd.mkdir()
    (rd / "report.md").write_text("findings\n")
    return rd


class _FakeCompleted:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@pytest.fixture
def captured_run(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Capture every subprocess.run call publish_results makes.

    The new flow uses init+fetch instead of clone, and dest_clone is
    created via Path.mkdir() in publish_results itself, so we don't need
    to mkdir from inside fake_run. Default scripts the existing-branch
    happy path (fetch returncode=0).

    Pins ``_GIT_EXECUTABLE = "git"`` so the legacy cmd-shape assertions
    keep passing — the Bandit-B607 hardening swaps cmd[0] from "git" to
    the absolute path resolved by shutil.which at module load, which in
    tests would otherwise be /usr/bin/git or similar.
    """
    calls: list[dict[str, Any]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> _FakeCompleted:
        calls.append({"cmd": cmd, "kwargs": kwargs})
        if cmd[:2] == ["git", "status"]:
            return _FakeCompleted(stdout=" M results/file\n")
        if cmd[:2] == ["git", "rev-parse"]:
            return _FakeCompleted(stdout="abcdef1234567890\n")
        return _FakeCompleted()

    monkeypatch.setattr(publish_mod, "_GIT_EXECUTABLE", "git")
    monkeypatch.setattr(publish_mod.subprocess, "run", fake_run)
    return calls


class TestPublishResults:
    SOURCE_URL = "https://github.com/source-org/source-repo"
    COMMIT = "abc1234"

    def test_results_dir_missing_raises(self, tmp_path: Path) -> None:
        with pytest.raises(PublishError, match="not a directory"):
            publish_results(
                tmp_path / "nope",
                _publish_cfg(),
                cfg(),
                source_repo_url=self.SOURCE_URL,
                source_commit_hash=self.COMMIT,
            )

    @respx.mock
    def test_happy_path_orders_subprocess_calls(
        self,
        results_dir: Path,
        captured_run: list[dict[str, Any]],
    ) -> None:
        respx.get("https://api.github.com/repos/owner/name").mock(
            return_value=httpx.Response(200, json={})
        )
        sha = publish_results(
            results_dir,
            _publish_cfg(),
            cfg(),
            source_repo_url=self.SOURCE_URL,
                source_commit_hash=self.COMMIT,
        )
        assert sha == "abcdef1234567890"
        # New flow: init -> remote add -> fetch -> reset -> add -> status
        # -> commit -> rev-parse -> push.
        first_args = [c["cmd"][:2] for c in captured_run]
        assert first_args == [
            ["git", "init"],
            ["git", "remote"],
            ["git", "fetch"],
            ["git", "reset"],
            ["git", "add"],
            ["git", "status"],
            ["git", "commit"],
            ["git", "rev-parse"],
            ["git", "push"],
        ]
        # Push is plain (not --set-upstream) when the branch already existed.
        push = next(c["cmd"] for c in captured_run if c["cmd"][:2] == ["git", "push"])
        assert "--set-upstream" not in push
        # The git add receives the <owner>/<repo>/<sha>/<results> path.
        add_cmd = next(c["cmd"] for c in captured_run if c["cmd"][:2] == ["git", "add"])
        assert (
            add_cmd[-1]
            == f"source-org/source-repo/2026-01-01-141824/{self.COMMIT}/{results_dir.name}"
        )

    @respx.mock
    def test_unknown_commit_hash_lands_under_unknown_segment(
        self,
        results_dir: Path,
        captured_run: list[dict[str, Any]],
    ) -> None:
        respx.get("https://api.github.com/repos/owner/name").mock(
            return_value=httpx.Response(200, json={})
        )
        publish_results(
            results_dir,
            _publish_cfg(),
            cfg(),
            source_repo_url=self.SOURCE_URL,
            source_commit_hash="",
        )
        add_cmd = next(c["cmd"] for c in captured_run if c["cmd"][:2] == ["git", "add"])
        assert (
            add_cmd[-1]
            == f"source-org/source-repo/2026-01-01-141824/unknown/{results_dir.name}"
        )

    @respx.mock
    def test_results_dir_without_timestamp_lands_under_unknown_segment(
        self,
        tmp_path: Path,
        captured_run: list[dict[str, Any]],
    ) -> None:
        """A results dir without a YYYY-MM-DD-HHMMSS suffix should land
        under '/unknown/' for the timestamp segment, not crash."""
        rd = tmp_path / "weirdly_named_results_dir"
        rd.mkdir()
        (rd / "report.md").write_text("findings\n")
        respx.get("https://api.github.com/repos/owner/name").mock(
            return_value=httpx.Response(200, json={})
        )
        publish_results(
            rd,
            _publish_cfg(),
            cfg(),
            source_repo_url=self.SOURCE_URL,
            source_commit_hash=self.COMMIT,
        )
        add_cmd = next(c["cmd"] for c in captured_run if c["cmd"][:2] == ["git", "add"])
        assert (
            add_cmd[-1]
            == f"source-org/source-repo/unknown/{self.COMMIT}/{rd.name}"
        )

    @respx.mock
    def test_branch_missing_creates_with_set_upstream(
        self,
        results_dir: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When the configured branch doesn't exist on the remote (empty
        repo or fresh repo without the configured branch), fetch returns
        non-zero, we skip the reset, and the push uses --set-upstream so
        the branch comes into existence on the remote.
        """
        respx.get("https://api.github.com/repos/owner/name").mock(
            return_value=httpx.Response(200, json={})
        )
        calls: list[list[str]] = []

        def fake_run(cmd: list[str], **kwargs: Any) -> _FakeCompleted:
            calls.append(cmd)
            if cmd[:2] == ["git", "fetch"]:
                # Mimic "fatal: Remote branch main not found in upstream origin"
                return _FakeCompleted(returncode=128, stderr="branch not found")
            if cmd[:2] == ["git", "status"]:
                return _FakeCompleted(stdout=" M file\n")
            if cmd[:2] == ["git", "rev-parse"]:
                return _FakeCompleted(stdout="deadbeefdeadbeef\n")
            return _FakeCompleted()

        monkeypatch.setattr(publish_mod, "_GIT_EXECUTABLE", "git")
        monkeypatch.setattr(publish_mod.subprocess, "run", fake_run)
        sha = publish_results(
            results_dir,
            _publish_cfg(),
            cfg(),
            source_repo_url=self.SOURCE_URL,
                source_commit_hash=self.COMMIT,
        )
        assert sha == "deadbeefdeadbeef"
        # No `git reset` was issued — there was nothing to reset onto.
        assert all(c[:2] != ["git", "reset"] for c in calls)
        # Push used --set-upstream so the branch is created remotely.
        push = next(c for c in calls if c[:2] == ["git", "push"])
        assert "--set-upstream" in push

    @respx.mock
    def test_empty_status_raises_no_changes(
        self,
        results_dir: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        respx.get("https://api.github.com/repos/owner/name").mock(
            return_value=httpx.Response(200, json={})
        )
        def fake_run(cmd: list[str], **kwargs: Any) -> _FakeCompleted:
            if cmd[:2] == ["git", "status"]:
                return _FakeCompleted(stdout="")
            return _FakeCompleted()

        monkeypatch.setattr(publish_mod.subprocess, "run", fake_run)
        with pytest.raises(PublishError, match="No changes"):
            publish_results(
                results_dir,
                _publish_cfg(),
                cfg(),
                source_repo_url=self.SOURCE_URL,
                source_commit_hash=self.COMMIT,
            )

    @respx.mock
    def test_author_env_vars_set(
        self,
        results_dir: Path,
        captured_run: list[dict[str, Any]],
    ) -> None:
        respx.get("https://api.github.com/repos/owner/name").mock(
            return_value=httpx.Response(200, json={})
        )
        publish_results(
            results_dir,
            _publish_cfg(commit_author_name="Test Bot", commit_author_email="t@x.com"),
            cfg(),
            source_repo_url=self.SOURCE_URL,
                source_commit_hash=self.COMMIT,
        )
        # Inspect any subprocess call's env (they all share the same env).
        env = captured_run[0]["kwargs"]["env"]
        assert env["GIT_AUTHOR_NAME"] == "Test Bot"
        assert env["GIT_AUTHOR_EMAIL"] == "t@x.com"
        assert env["GIT_COMMITTER_NAME"] == "Test Bot"
        assert env["GIT_COMMITTER_EMAIL"] == "t@x.com"

    @respx.mock
    def test_temp_workdir_cleaned_up_on_failure(
        self,
        results_dir: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        respx.get("https://api.github.com/repos/owner/name").mock(
            return_value=httpx.Response(200, json={})
        )
        seen_workdirs: list[Path] = []

        def fake_run(cmd: list[str], **kwargs: Any) -> _FakeCompleted:
            cwd = kwargs.get("cwd")
            if cwd is not None:
                seen_workdirs.append(Path(cwd))
            if cmd[:2] == ["git", "init"]:
                # Fail at init so we exercise the finally branch.
                return _FakeCompleted(returncode=1, stderr="boom")
            return _FakeCompleted()

        monkeypatch.setattr(publish_mod.subprocess, "run", fake_run)
        with pytest.raises(PublishError):
            publish_results(
                results_dir,
                _publish_cfg(),
                cfg(),
                source_repo_url=self.SOURCE_URL,
                source_commit_hash=self.COMMIT,
            )
        assert seen_workdirs, "expected at least one git invocation in the workdir"
        # The temp workdir must no longer exist after cleanup.
        assert not seen_workdirs[0].exists()

    @respx.mock
    def test_token_redacted_in_failure_message(
        self,
        results_dir: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        respx.get("https://api.github.com/repos/owner/name").mock(
            return_value=httpx.Response(200, json={})
        )

        def fake_run(cmd: list[str], **kwargs: Any) -> _FakeCompleted:
            if cmd[:2] == ["git", "remote"]:
                # Stderr leaks the remote-add argv, which has the token in it.
                stderr = " ".join(cmd) + " failed"
                return _FakeCompleted(returncode=1, stderr=stderr)
            return _FakeCompleted()

        monkeypatch.setattr(publish_mod, "_GIT_EXECUTABLE", "git")
        monkeypatch.setattr(publish_mod.subprocess, "run", fake_run)
        with pytest.raises(PublishError) as exc:
            publish_results(
                results_dir,
                _publish_cfg(),
                cfg(reports_token="ghp_supersecret"),
                source_repo_url=self.SOURCE_URL,
                source_commit_hash=self.COMMIT,
            )
        msg = str(exc.value)
        assert "ghp_supersecret" not in msg
        assert "***@github.com" in msg


# ---------------------------------------------------------------------------
# _run — Bandit B607 hardening lock-down
# ---------------------------------------------------------------------------


class TestRunGitExecutableHardening:
    def test_run_swaps_bare_git_for_absolute_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``_run(["git", ...])`` must replace ``cmd[0]`` with the
        absolute path resolved at module load (Bandit B607)."""
        captured: list[list[str]] = []

        class _R:
            returncode = 0
            stdout = ""
            stderr = ""

        def fake_run(cmd: list[str], **kwargs: Any) -> _R:
            captured.append(cmd)
            return _R()

        monkeypatch.setattr(publish_mod, "_GIT_EXECUTABLE", "/usr/bin/git")
        monkeypatch.setattr(publish_mod.subprocess, "run", fake_run)
        _run(["git", "status", "--porcelain"])
        assert captured[0] == ["/usr/bin/git", "status", "--porcelain"]

    def test_run_raises_publisherror_when_git_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When ``_GIT_EXECUTABLE`` is None, ``_run`` raises ``PublishError``
        before reaching subprocess.run — no surprise OSError mid-publish."""
        called: list[Any] = []

        def fake_run(*a: Any, **k: Any) -> Any:
            called.append(a)
            raise AssertionError("subprocess.run must not be called")

        monkeypatch.setattr(publish_mod, "_GIT_EXECUTABLE", None)
        monkeypatch.setattr(publish_mod.subprocess, "run", fake_run)
        with pytest.raises(PublishError, match="git not on PATH"):
            _run(["git", "init"])
        assert called == []

    def test_run_non_git_cmd_passes_through_unchanged(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The rewrite only fires for ``cmd[0] == "git"``. Any other
        argv passes through untouched — this is defensive (no caller
        does this today, but the rewrite shouldn't quietly remap
        arbitrary commands)."""
        captured: list[list[str]] = []

        class _R:
            returncode = 0
            stdout = ""
            stderr = ""

        def fake_run(cmd: list[str], **kwargs: Any) -> _R:
            captured.append(cmd)
            return _R()

        monkeypatch.setattr(publish_mod, "_GIT_EXECUTABLE", "/usr/bin/git")
        monkeypatch.setattr(publish_mod.subprocess, "run", fake_run)
        _run(["/usr/bin/echo", "hello"])
        assert captured[0] == ["/usr/bin/echo", "hello"]
