"""Tests for agent.__main__: argparse + main() exit-code matrix."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from agent import __main__ as main_mod
from agent.__main__ import _build_parser, main
from agent.issues_remote_report import DownloadedReport
from agent.publish import PublishError


# ---------------------------------------------------------------------------
# _build_parser
# ---------------------------------------------------------------------------


class TestBuildParser:
    def test_minimal_args_parse(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["--mode=scan", "https://github.com/o/r"])
        assert args.targets == ["https://github.com/o/r"]
        assert args.publish is None
        assert args.verbose == 0

    @pytest.mark.parametrize(
        "argv",
        [
            ["--mode=scan", "url", "--config", "/tmp/c.toml"],
            ["--mode=scan", "url", "--model", "claude-opus-4-8"],
            ["--mode=scan", "url", "--clone-dir", "/tmp/clones"],
            ["--mode=scan", "url", "--re-clone"],
            ["--mode=scan", "url", "--scan-id", "abc"],
            ["--mode=scan", "url", "--publish"],
            ["--mode=scan", "url", "--no-publish"],
            ["--mode=scan", "url", "-v"],
            ["--mode=scan", "url", "-vv"],
            ["--mode=scan", "url", "--log-level", "DEBUG"],
        ],
    )
    def test_flags_parse_without_exception(self, argv: list[str]) -> None:
        _build_parser().parse_args(argv)

    def test_publish_and_no_publish_mutually_exclusive(self) -> None:
        parser = _build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--mode=scan", "url", "--publish", "--no-publish"])

    def test_verbose_increments(self) -> None:
        parser = _build_parser()
        assert parser.parse_args(["--mode=scan", "url", "-v"]).verbose == 1
        assert parser.parse_args(["--mode=scan", "url", "-vv"]).verbose == 2


# ---------------------------------------------------------------------------
# main() end-to-end
# ---------------------------------------------------------------------------


def _patch_main_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    *,
    config: Any,
    clone_dir: Path,
    results_dir: Path | None,
    publish_sha: str | None = None,
    publish_error: Exception | None = None,
    load_config_error: Exception | None = None,
    run_vulnhunt_error: Exception | None = None,
    download_result: "DownloadedReport | None" = None,
    download_error: Exception | None = None,
    issues_summary: Any = None,
    issues_error: Exception | None = None,
) -> dict[str, Any]:
    """Patch every external collaborator main() reaches."""
    calls: dict[str, Any] = {
        "publish": 0,
        "shallow": 0,
        "run": 0,
        "download": 0,
        "post_issues": 0,
    }

    def fake_load_config(path: Any) -> Any:
        if load_config_error is not None:
            raise load_config_error
        return config

    def fake_shallow_clone(*a: object, **k: object) -> Path:
        calls["shallow"] += 1
        return clone_dir

    async def fake_run_vulnhunt(*a: object, **k: object) -> Path | None:
        calls["run"] += 1
        if run_vulnhunt_error is not None:
            raise run_vulnhunt_error
        return results_dir

    def fake_publish_results(*a: object, **k: object) -> str:
        calls["publish"] += 1
        if publish_error is not None:
            raise publish_error
        assert publish_sha is not None
        return publish_sha

    def fake_download(*a: object, **k: object) -> "DownloadedReport":
        calls["download"] += 1
        if download_error is not None:
            raise download_error
        assert download_result is not None
        return download_result

    def fake_post_issues(*a: object, **k: object) -> Any:
        calls["post_issues"] += 1
        if issues_error is not None:
            raise issues_error
        from agent.issues import PostSummary

        return issues_summary if issues_summary is not None else PostSummary()

    async def fake_post_issues_async(*a: object, **k: object) -> Any:
        return fake_post_issues(*a, **k)

    class _FakeOAuth:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        def get_valid_token(self) -> str:
            return "t"

    monkeypatch.setattr(main_mod, "load_config", fake_load_config)
    monkeypatch.setattr(main_mod, "shallow_clone", fake_shallow_clone)
    monkeypatch.setattr(main_mod, "run_vulnhunt", fake_run_vulnhunt)
    monkeypatch.setattr(main_mod, "publish_results", fake_publish_results)
    monkeypatch.setattr(main_mod, "download_latest_report", fake_download)
    monkeypatch.setattr(main_mod.issues_stage, "post_issues", fake_post_issues_async)
    monkeypatch.setattr(main_mod, "make_token_manager", lambda *a, **k: _FakeOAuth())
    # Standalone preflight makes a real HTTP call to GitHub; stub it out
    # in pipeline-level tests. Dedicated preflight tests below patch the
    # underlying httpx.Client and exercise the real function.
    monkeypatch.setattr(main_mod, "_preflight_standalone_tokens", lambda **_kw: None)
    # Repo-properties resolution runs GET /repos/../properties/values
    # against GitHub. Not exercised in pipeline-level tests; substitute
    # a blank RepoProperties so we don't build a real httpx.Client
    # (which would trigger the str-verify deprecation).
    monkeypatch.setattr(
        main_mod.repo_props,
        "fetch_from_github",
        lambda *_a, **_k: main_mod.repo_props.RepoProperties(),
    )
    return calls


def test_main_no_publish_prints_clone_and_results(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    clone = tmp_path / "clone"
    clone.mkdir()
    results = clone / "x_VULNHUNT_RESULTS_y"
    results.mkdir()
    _patch_main_dependencies(
        monkeypatch,
        config=populated_agent_config,
        clone_dir=clone,
        results_dir=results,
    )
    rc = main(["--mode=scan", "https://github.com/o/r", "--no-publish"])
    captured = capsys.readouterr().out
    assert rc == 0
    assert f"Clone:    {clone}" in captured
    assert f"Results:  {results}" in captured
    assert "Publish:  skipped (--no-publish flag)" in captured


def test_main_publish_enabled_succeeds(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    agent_config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agent.config import GitHubConfig, PublishConfig

    cfg = agent_config(
        github=GitHubConfig(host="github.com", scan_token="ghp_x", reports_token="ghp_x", broker_token_dir=""),
        publish=PublishConfig(
            enabled=True,
            destination_repo="https://github.com/o/results",
            branch="main",
            commit_author_name="Bot",
            commit_author_email="bot@x.com",
        ),
    )
    clone = tmp_path / "clone"
    clone.mkdir()
    results = clone / "x_VULNHUNT_RESULTS_y"
    results.mkdir()
    _patch_main_dependencies(
        monkeypatch,
        config=cfg,
        clone_dir=clone,
        results_dir=results,
        publish_sha="abcdef1234",
    )
    rc = main(["--mode=scan", "https://github.com/o/r", "--publish"])
    captured = capsys.readouterr().out
    assert rc == 0
    assert "Publish:  https://github.com/o/results@main (abcdef12)" in captured


def test_main_publish_disabled_via_config(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    clone = tmp_path / "clone"
    clone.mkdir()
    results = clone / "x_VULNHUNT_RESULTS_y"
    results.mkdir()
    _patch_main_dependencies(
        monkeypatch,
        config=populated_agent_config,
        clone_dir=clone,
        results_dir=results,
    )
    rc = main(["--mode=scan", "https://github.com/o/r"])
    captured = capsys.readouterr().out
    assert rc == 0
    assert "Publish:  skipped" in captured
    assert "[publish] enabled = false in config" in captured


def test_main_publish_disabled_via_flag(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    agent_config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agent.config import PublishConfig

    cfg = agent_config(
        publish=PublishConfig(
            enabled=True,
            destination_repo="https://github.com/o/r",
            branch="main",
            commit_author_name="b",
            commit_author_email="b@x.com",
        )
    )
    clone = tmp_path / "clone"
    clone.mkdir()
    results = clone / "x_VULNHUNT_RESULTS_y"
    results.mkdir()
    _patch_main_dependencies(
        monkeypatch,
        config=cfg,
        clone_dir=clone,
        results_dir=results,
    )
    rc = main(["--mode=scan", "url", "--no-publish"])
    captured = capsys.readouterr().out
    assert rc == 0
    assert "Publish:  skipped (--no-publish flag)" in captured


def test_main_no_results_dir_returns_1(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    clone = tmp_path / "clone"
    clone.mkdir()
    _patch_main_dependencies(
        monkeypatch,
        config=populated_agent_config,
        clone_dir=clone,
        results_dir=None,
    )
    rc = main(["--mode=scan", "url"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "no *_VULNHUNT_RESULTS_*" in out


def test_main_publish_error_returns_2(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    agent_config,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agent.config import GitHubConfig, PublishConfig

    cfg = agent_config(
        github=GitHubConfig(host="github.com", scan_token="t", reports_token="t", broker_token_dir=""),
        publish=PublishConfig(
            enabled=True,
            destination_repo="https://github.com/o/r",
            branch="main",
            commit_author_name="b",
            commit_author_email="b@x.com",
        ),
    )
    clone = tmp_path / "clone"
    clone.mkdir()
    results = clone / "x_VULNHUNT_RESULTS_y"
    results.mkdir()
    _patch_main_dependencies(
        monkeypatch,
        config=cfg,
        clone_dir=clone,
        results_dir=results,
        publish_error=PublishError("nope"),
    )
    rc = main(["--mode=scan", "url", "--publish"])
    out = capsys.readouterr().out
    # Publish failed = exit 2 per HLD §9 / SCAN-AGENT-006 (not 3).
    assert rc == 2
    assert "Publish:  FAILED" in out
    # AGENT-MANIFEST-002: no manifest on publish failure (phantom success marker).
    assert not (results / "scan_manifest.json").exists()


def test_main_file_not_found_from_config_returns_64(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _patch_main_dependencies(
        monkeypatch,
        config=None,
        clone_dir=tmp_path,
        results_dir=None,
        load_config_error=FileNotFoundError("missing config"),
    )
    rc = main(["--mode=scan", "url"])
    # Usage/config error = exit 64 (EX_USAGE) per HLD §9, not 2 (publish_failed).
    assert rc == 64


def test_main_keyboard_interrupt_returns_130(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config,
) -> None:
    _patch_main_dependencies(
        monkeypatch,
        config=populated_agent_config,
        clone_dir=tmp_path,
        results_dir=None,
        run_vulnhunt_error=KeyboardInterrupt(),
    )
    rc = main(["--mode=scan", "url"])
    assert rc == 130


def test_main_unhandled_exception_returns_1(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _patch_main_dependencies(
        monkeypatch,
        config=populated_agent_config,
        clone_dir=tmp_path,
        results_dir=None,
        run_vulnhunt_error=RuntimeError("kaboom"),
    )
    import logging

    with caplog.at_level(logging.ERROR):
        rc = main(["--mode=scan", "url"])
    assert rc == 1
    # Traceback / error logged.
    assert any("kaboom" in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------------------
# _validate_modes — toggle coherence
# ---------------------------------------------------------------------------


from dataclasses import replace  # noqa: E402

from agent.__main__ import _validate_modes  # noqa: E402


class TestValidateModes:
    def test_all_off_raises(self, populated_agent_config) -> None:
        with pytest.raises(ValueError, match="Nothing to do"):
            _validate_modes(
                scan=False, publish=False, issues=False, config=populated_agent_config
            )

    def test_scan_no_publish_with_issues_raises(self, populated_agent_config) -> None:
        cfg = replace(
            populated_agent_config,
            github=replace(populated_agent_config.github, scan_token="ghp_x", reports_token="ghp_x"),
        )
        with pytest.raises(ValueError, match="incoherent"):
            _validate_modes(scan=True, publish=False, issues=True, config=cfg)

    def test_no_scan_issues_without_destination_raises(
        self, populated_agent_config
    ) -> None:
        cfg = replace(
            populated_agent_config,
            github=replace(populated_agent_config.github, scan_token="ghp_x", reports_token="ghp_x"),
        )
        # publish.destination_repo is empty by default in the fixture.
        with pytest.raises(ValueError, match="destination_repo"):
            _validate_modes(scan=False, publish=False, issues=True, config=cfg)

    def test_issues_without_github_token_raises(
        self, populated_agent_config
    ) -> None:
        cfg = replace(
            populated_agent_config,
            github=replace(populated_agent_config.github, scan_token="", reports_token=""),
            publish=replace(
                populated_agent_config.publish,
                destination_repo="https://github.com/o/dest",
                enabled=True,
            ),
        )
        with pytest.raises(ValueError, match="scan_token"):
            _validate_modes(scan=True, publish=True, issues=True, config=cfg)

    def test_scan_publish_issues_passes(self, populated_agent_config) -> None:
        cfg = replace(
            populated_agent_config,
            github=replace(populated_agent_config.github, scan_token="ghp_x", reports_token="ghp_x"),
            publish=replace(
                populated_agent_config.publish,
                destination_repo="https://github.com/o/dest",
                enabled=True,
            ),
        )
        # No exception.
        _validate_modes(scan=True, publish=True, issues=True, config=cfg)

    def test_scan_only_passes(self, populated_agent_config) -> None:
        # Default fixture: no token, no destination — scan-only is fine.
        _validate_modes(
            scan=True, publish=False, issues=False, config=populated_agent_config
        )

    def test_scan_publish_no_issues_passes(self, populated_agent_config) -> None:
        cfg = replace(
            populated_agent_config,
            github=replace(populated_agent_config.github, reports_token="ghp_x"),
            publish=replace(
                populated_agent_config.publish,
                destination_repo="https://github.com/o/dest",
                enabled=True,
            ),
        )
        _validate_modes(scan=True, publish=True, issues=False, config=cfg)

    def test_no_scan_issues_with_destination_passes(
        self, populated_agent_config
    ) -> None:
        cfg = replace(
            populated_agent_config,
            github=replace(populated_agent_config.github, scan_token="ghp_x", reports_token="ghp_x"),
            publish=replace(
                populated_agent_config.publish,
                destination_repo="https://github.com/o/dest",
            ),
        )
        _validate_modes(scan=False, publish=False, issues=True, config=cfg)


class TestBuildParserNewFlags:
    def test_scan_no_scan_mutually_exclusive(self) -> None:
        with pytest.raises(SystemExit):
            _build_parser().parse_args(["--mode=scan", "url", "--scan", "--no-scan"])

    def test_issues_no_issues_mutually_exclusive(self) -> None:
        with pytest.raises(SystemExit):
            _build_parser().parse_args(["--mode=scan", "url", "--issues", "--no-issues"])

    def test_issues_target_repo_override(self) -> None:
        args = _build_parser().parse_args(
            ["--mode=scan", "url", "--issues-target-repo", "https://github.com/x/y"]
        )
        assert args.issues_target_repo == "https://github.com/x/y"

    def test_no_scan_parses(self) -> None:
        args = _build_parser().parse_args(["--mode=scan", "url", "--no-scan"])
        assert args.scan is False

    def test_no_issues_parses(self) -> None:
        args = _build_parser().parse_args(["--mode=scan", "url", "--no-issues"])
        assert args.issues is False

    def test_read_only_default_is_none(self) -> None:
        args = _build_parser().parse_args(["--mode=scan", "url"])
        assert args.read_only is None  # __main__ defaults to True at use-time

    def test_read_only_flag(self) -> None:
        args = _build_parser().parse_args(["--mode=scan", "url", "--read-only"])
        assert args.read_only is True

    def test_no_read_only_flag(self) -> None:
        args = _build_parser().parse_args(["--mode=scan", "url", "--no-read-only"])
        assert args.read_only is False

    def test_read_only_mutually_exclusive(self) -> None:
        with pytest.raises(SystemExit):
            _build_parser().parse_args(["--mode=scan", "url", "--read-only", "--no-read-only"])

    def test_enable_bash_default_is_false(self) -> None:
        args = _build_parser().parse_args(["--mode=scan", "url"])
        assert args.enable_bash is False

    def test_enable_bash_flag_sets_true(self) -> None:
        args = _build_parser().parse_args(["--mode=scan", "url", "--enable-bash"])
        assert args.enable_bash is True


def _stub_main_environment_for_args(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Patch out everything _main needs so we can drive arg validation paths
    without running an actual scan. Stubs in just enough for the early
    pairing-check to fire.
    """
    import agent.__main__ as _m
    from agent.config import (
        AgentConfig,
        AnthropicConfig,
        GitHubConfig,
        IssuesConfig,
        LoggingConfig,
        OAuthConfig,
        PublishConfig,
        SandboxConfig,
        ScanConfig,
        TLSConfig,
        TelemetryConfig,
    )

    def fake_load_config(*_a: object, **_k: object) -> AgentConfig:
        return AgentConfig(
            anthropic=AnthropicConfig(
                bedrock_base_url="https://bedrock.example.com",
                aws_region="us-east-1",
                model="claude-opus-4-8",
            ),
            oauth=OAuthConfig(
                token_endpoint="https://oauth.example.com/token",
                client_id="x",
                client_secret="y",
                expiry_safety_factor=0.9,
                default_lifetime_seconds=3600,
                http_timeout_seconds=30,
            ),
            tls=TLSConfig(ssl_cert_path=""),
            sandbox=SandboxConfig(
                enabled=True,
                fail_if_unavailable=True,
                allow_unsandboxed_commands=False,
            ),
            telemetry=TelemetryConfig(enabled=False, otel_exporter_otlp_endpoint=""),
            scan=ScanConfig(
                clone_base_dir=str(tmp_path / "clones"),
                clone_timeout_seconds=300,
                allowed_tools=["Read", "Grep"],
                permission_mode="acceptEdits",
                autocompact_pct_override=85,
                async_agent_stall_timeout_ms=1_200_000,
            ),
            github=GitHubConfig(host="github.com", scan_token="", reports_token="", broker_token_dir=""),
            publish=PublishConfig(
                enabled=False,
                destination_repo="",
                branch="main",
                commit_author_name="x",
                commit_author_email="x@example.com",
            ),
            issues=IssuesConfig(
                enabled=False,
                target_repo="",
                labels=[],
                dedup_label="x",
                haiku_model="x",
                sonnet_model="y",
                semantic_dedup=True,
                request_timeout_seconds=60,
                max_open_issues=1000,
                token_budget_fraction=0.7,
                model_context_tokens=200_000,
                notify_clean_scan=True,
                clean_scan_label="VulnHunter: clean-scan",
            ),
            logging=LoggingConfig(per_turn_usage=False, retries=False),
            source_path=None,
        )

    monkeypatch.setattr(_m, "load_config", fake_load_config)


def test_main_rejects_enable_bash_with_read_only(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--enable-bash without --no-read-only is nonsensical (read-only mode
    forbids code execution) and must be rejected at arg-validation time
    before any clone / SDK invocation happens.
    """
    _stub_main_environment_for_args(monkeypatch, tmp_path)
    import agent.__main__ as _m

    with pytest.raises(SystemExit):
        _m.main(["--mode=scan", "https://example.com/x", "--enable-bash"])
    err = capsys.readouterr().err
    assert "--enable-bash requires --no-read-only" in err


def test_main_rejects_no_read_only_without_enable_bash(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--no-read-only without --enable-bash means "execute code without
    a tool to execute it" — also nonsensical. Reject up-front.
    """
    _stub_main_environment_for_args(monkeypatch, tmp_path)
    import agent.__main__ as _m

    with pytest.raises(SystemExit):
        _m.main(["--mode=scan", "https://example.com/x", "--no-read-only"])
    err = capsys.readouterr().err
    assert "--no-read-only requires --enable-bash" in err


def test_main_no_scan_does_not_enforce_bash_pairing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """--no-scan paths don't touch the SDK, so the --enable-bash /
    --no-read-only pairing isn't enforced — passing either alone with
    --no-scan must let main() proceed past arg-validation. Drive it
    through main() (not just argparse) so a regression that moves the
    pairing check earlier would surface here.
    """
    _stub_main_environment_for_args(monkeypatch, tmp_path)
    import agent.__main__ as _m

    # Patch the body of _amain to a no-op coroutine so main() exits cleanly
    # after arg-validation; we're only asserting the pairing check skips.
    async def _noop_amain(_args: object) -> int:
        return 0

    monkeypatch.setattr(_m, "_amain", _noop_amain)

    # --no-scan + --no-read-only alone — would normally trip the
    # "requires --enable-bash" pairing check; --no-scan must waive it.
    rc = _m.main(["--mode=scan", "https://example.com/x", "--no-scan", "--no-read-only"])
    assert rc == 0

    # --no-scan + --enable-bash alone — same deal in the other direction.
    rc = _m.main(["--mode=scan", "https://example.com/x", "--no-scan", "--enable-bash"])
    assert rc == 0


def test_main_warns_when_read_only_with_no_scan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config: Any,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """--read-only is meaningless with --no-scan; main should warn."""
    import logging as _logging
    from dataclasses import replace as _r

    cfg = _r(
        populated_agent_config,
        github=_r(populated_agent_config.github, scan_token="ghp_x", reports_token="ghp_x"),
        publish=_r(
            populated_agent_config.publish,
            destination_repo="https://github.com/o/dest",
        ),
        issues=_r(populated_agent_config.issues, enabled=True),
    )
    workdir = tmp_path / "wd"
    workdir.mkdir()
    downloaded = workdir / "x_VULNHUNT_RESULTS_a"
    downloaded.mkdir()
    _patch_main_dependencies(
        monkeypatch,
        config=cfg,
        clone_dir=tmp_path,
        results_dir=None,
        download_result=DownloadedReport(
            path=downloaded, rel_path_in_dest="x/y/abc/x_VULNHUNT_RESULTS_a", workdir=workdir
        ),
    )
    with caplog.at_level(_logging.WARNING):
        rc = main(["--mode=scan", "https://github.com/o/r", "--no-scan", "--read-only"])
    assert rc == 0
    assert any("read-only is ignored" in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------------------
# _configure_logging — direct
# ---------------------------------------------------------------------------


class TestConfigureLogging:
    def test_default_level_is_info(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import logging as logging_mod

        captured: dict[str, Any] = {}

        def fake_basic_config(**kw: Any) -> None:
            captured.update(kw)

        monkeypatch.setattr(logging_mod, "basicConfig", fake_basic_config)
        main_mod._configure_logging(None, 0)
        assert captured["level"] == logging_mod.INFO

    def test_debug_level_promotes_sdk_logger(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import logging as logging_mod

        monkeypatch.setattr(logging_mod, "basicConfig", lambda **kw: None)
        # Reset to a known state.
        sdk_logger = logging_mod.getLogger("claude_agent_sdk")
        sdk_logger.setLevel(logging_mod.WARNING)
        main_mod._configure_logging("DEBUG", 0)
        assert sdk_logger.level == logging_mod.DEBUG

    def test_double_v_promotes_sdk_logger(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import logging as logging_mod

        monkeypatch.setattr(logging_mod, "basicConfig", lambda **kw: None)
        sdk_logger = logging_mod.getLogger("claude_agent_sdk")
        sdk_logger.setLevel(logging_mod.WARNING)
        main_mod._configure_logging(None, 2)
        assert sdk_logger.level == logging_mod.DEBUG


# ---------------------------------------------------------------------------
# _short_sha — direct
# ---------------------------------------------------------------------------


class TestShortSha:
    def test_returns_sha_on_success(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        class _Result:
            returncode = 0
            stdout = "abc1234\n"
            stderr = ""

        monkeypatch.setattr(
            main_mod.subprocess, "run", lambda *a, **k: _Result()
        )
        assert main_mod._short_sha(tmp_path) == "abc1234"

    def test_returns_unknown_when_returncode_nonzero(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        import logging as logging_mod

        class _Result:
            returncode = 128
            stdout = ""
            stderr = "fatal: not a git repository"

        monkeypatch.setattr(
            main_mod.subprocess, "run", lambda *a, **k: _Result()
        )
        with caplog.at_level(logging_mod.WARNING):
            assert main_mod._short_sha(tmp_path) == "unknown"
        assert any(
            "git rev-parse failed" in r.getMessage() for r in caplog.records
        )

    def test_returns_unknown_on_oserror(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        import logging as logging_mod

        def boom(*a: object, **k: object) -> None:
            raise OSError("git not on PATH")

        monkeypatch.setattr(main_mod.subprocess, "run", boom)
        with caplog.at_level(logging_mod.WARNING):
            assert main_mod._short_sha(tmp_path) == "unknown"
        assert any(
            "Could not resolve source commit hash" in r.getMessage()
            for r in caplog.records
        )

    def test_returns_unknown_when_stdout_empty(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        class _Result:
            returncode = 0
            stdout = "   \n"  # whitespace-only after strip()
            stderr = ""

        monkeypatch.setattr(
            main_mod.subprocess, "run", lambda *a, **k: _Result()
        )
        assert main_mod._short_sha(tmp_path) == "unknown"


# ---------------------------------------------------------------------------
# _resolve_modes — explicit-flag branches
# ---------------------------------------------------------------------------


class TestResolveModes:
    def test_explicit_issues_false_overrides_config(
        self, populated_agent_config: Any
    ) -> None:
        from agent.config import IssuesConfig
        from dataclasses import replace as _r

        cfg = _r(
            populated_agent_config,
            issues=_r(populated_agent_config.issues, enabled=True),
        )
        args = _build_parser().parse_args(["--mode=scan", "url", "--no-issues"])
        scan, publish, issues = main_mod._resolve_modes(args, cfg)
        assert issues is False

    def test_explicit_issues_true_overrides_config(
        self, populated_agent_config: Any
    ) -> None:
        from dataclasses import replace as _r

        cfg = _r(
            populated_agent_config,
            issues=_r(populated_agent_config.issues, enabled=False),
        )
        args = _build_parser().parse_args(["--mode=scan", "url", "--issues"])
        scan, publish, issues = main_mod._resolve_modes(args, cfg)
        assert issues is True


# ---------------------------------------------------------------------------
# main() — _amain integration paths covering issues stage
# ---------------------------------------------------------------------------


def _full_pipeline_config(populated_agent_config: Any) -> Any:
    """All three stages enabled, with valid token + destination."""
    from dataclasses import replace as _r

    return _r(
        populated_agent_config,
        github=_r(populated_agent_config.github, scan_token="ghp_x", reports_token="ghp_x"),
        publish=_r(
            populated_agent_config.publish,
            enabled=True,
            destination_repo="https://github.com/o/dest",
            branch="main",
        ),
        issues=_r(populated_agent_config.issues, enabled=True),
    )


def test_main_full_pipeline_happy_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cfg = _full_pipeline_config(populated_agent_config)
    clone = tmp_path / "clone"
    clone.mkdir()
    results = clone / "x_VULNHUNT_RESULTS_opus47_2026-06-23-141824"
    results.mkdir()
    # Stub _short_sha so we don't shell out.
    monkeypatch.setattr(main_mod, "_short_sha", lambda d: "abc1234")
    calls = _patch_main_dependencies(
        monkeypatch,
        config=cfg,
        clone_dir=clone,
        results_dir=results,
        publish_sha="abcdef1234567890",
    )
    rc = main(["--mode=scan", "https://github.com/o/r"])
    captured = capsys.readouterr().out
    assert rc == 0
    assert "Publish:  https://github.com/o/dest@main (abcdef12)" in captured
    assert "Issues:" in captured
    assert calls["post_issues"] == 1


def test_main_issues_summary_failed_returns_3(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config: Any,
) -> None:
    from agent.issues import FailedIssue, PostSummary

    cfg = _full_pipeline_config(populated_agent_config)
    clone = tmp_path / "clone"
    clone.mkdir()
    results = clone / "x_VULNHUNT_RESULTS_opus47_2026-06-23-141824"
    results.mkdir()
    monkeypatch.setattr(main_mod, "_short_sha", lambda d: "abc1234")
    summary = PostSummary(
        failed=[FailedIssue(finding_id="V1", title="t", error="boom")]
    )
    _patch_main_dependencies(
        monkeypatch,
        config=cfg,
        clone_dir=clone,
        results_dir=results,
        publish_sha="abcdef12",
        issues_summary=summary,
    )
    rc = main(["--mode=scan", "https://github.com/o/r"])
    # Partial issue post = exit 3 per HLD §9 / SCAN-AGENT-011 (not 4 = crash).
    assert rc == 3


def test_main_issues_stage_exception_returns_4(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cfg = _full_pipeline_config(populated_agent_config)
    clone = tmp_path / "clone"
    clone.mkdir()
    results = clone / "x_VULNHUNT_RESULTS_opus47_2026-06-23-141824"
    results.mkdir()
    monkeypatch.setattr(main_mod, "_short_sha", lambda d: "abc1234")
    _patch_main_dependencies(
        monkeypatch,
        config=cfg,
        clone_dir=clone,
        results_dir=results,
        publish_sha="abcdef12",
        issues_error=RuntimeError("oauth refused"),
    )
    rc = main(["--mode=scan", "https://github.com/o/r"])
    captured = capsys.readouterr().out
    assert rc == 4
    assert "Issues:   FAILED" in captured


def test_main_no_scan_issues_downloads_and_posts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cfg = _full_pipeline_config(populated_agent_config)
    workdir = tmp_path / "fake_workdir"
    workdir.mkdir()
    downloaded = workdir / "downloaded_VULNHUNT_RESULTS_opus47_2026-06-23-141824"
    downloaded.mkdir()
    rel_path = "o/r/abc1234/downloaded_VULNHUNT_RESULTS_opus47_2026-06-23-141824"
    _patch_main_dependencies(
        monkeypatch,
        config=cfg,
        clone_dir=tmp_path,
        results_dir=None,
        download_result=DownloadedReport(
            path=downloaded, rel_path_in_dest=rel_path, workdir=workdir
        ),
    )
    rc = main(["--mode=scan", "https://github.com/o/r", "--no-scan"])
    captured = capsys.readouterr().out
    assert rc == 0
    assert "Clone:    skipped (--no-scan)" in captured
    assert f"Download: {downloaded}" in captured


def test_main_no_scan_download_failure_returns_4(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from agent.issues_remote_report import RemoteReportError

    cfg = _full_pipeline_config(populated_agent_config)
    _patch_main_dependencies(
        monkeypatch,
        config=cfg,
        clone_dir=tmp_path,
        results_dir=None,
        download_error=RemoteReportError("nothing published"),
    )
    rc = main(["--mode=scan", "https://github.com/o/r", "--no-scan"])
    captured = capsys.readouterr().out
    assert rc == 4
    assert "Download: FAILED" in captured


def test_main_value_error_from_validate_modes_returns_64(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    populated_agent_config: Any,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """--scan --no-publish --issues triggers _validate_modes ValueError."""
    import logging as logging_mod
    from dataclasses import replace as _r

    cfg = _r(
        populated_agent_config,
        github=_r(populated_agent_config.github, scan_token="ghp_x", reports_token="ghp_x"),
        issues=_r(populated_agent_config.issues, enabled=True),
    )
    _patch_main_dependencies(
        monkeypatch,
        config=cfg,
        clone_dir=tmp_path,
        results_dir=None,
    )
    with caplog.at_level(logging_mod.ERROR):
        rc = main(["--mode=scan", "https://github.com/o/r", "--no-publish", "--issues"])
    # Usage error (incoherent flags) = exit 64 (EX_USAGE) per HLD §9, not 2.
    assert rc == 64
    assert any("incoherent" in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------------------
# -v / -vv force LoggingConfig flags on
# ---------------------------------------------------------------------------


class TestVerboseForcesLoggingFlags:
    """A user running `-v` shouldn't need to edit config.toml to see token
    use and retry logs — both LoggingConfig flags must be flipped to True
    before run_vulnhunt is called.
    """

    def _run_with_verbose(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        config: Any,
        argv_extra: list[str],
    ) -> Any:
        clone = tmp_path / "clone"
        clone.mkdir()
        results = clone / "x_VULNHUNT_RESULTS_y"
        results.mkdir()
        captured: dict[str, Any] = {"config": None}

        async def fake_run_vulnhunt(_clone: Path, cfg: Any, **_k: Any) -> Path:
            captured["config"] = cfg
            return results

        _patch_main_dependencies(
            monkeypatch,
            config=config,
            clone_dir=clone,
            results_dir=results,
        )
        # Override run_vulnhunt to capture the config it was called with.
        monkeypatch.setattr(main_mod, "run_vulnhunt", fake_run_vulnhunt)
        rc = main(
            ["--mode=scan", "https://github.com/o/r", "--no-publish", "--no-issues"]
            + argv_extra
        )
        assert rc == 0
        return captured["config"]

    def test_v_forces_both_flags_on(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        populated_agent_config,
    ) -> None:
        # Baseline config has both flags False (per conftest factory).
        assert populated_agent_config.logging.per_turn_usage is False
        assert populated_agent_config.logging.retries is False
        cfg = self._run_with_verbose(
            monkeypatch, tmp_path, populated_agent_config, ["-v"]
        )
        assert cfg.logging.per_turn_usage is True
        assert cfg.logging.retries is True

    def test_vv_forces_both_flags_on(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        populated_agent_config,
    ) -> None:
        cfg = self._run_with_verbose(
            monkeypatch, tmp_path, populated_agent_config, ["-vv"]
        )
        assert cfg.logging.per_turn_usage is True
        assert cfg.logging.retries is True

    def test_no_verbose_leaves_flags_alone(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        populated_agent_config,
    ) -> None:
        # Without -v, config defaults are preserved.
        cfg = self._run_with_verbose(
            monkeypatch, tmp_path, populated_agent_config, []
        )
        assert cfg.logging.per_turn_usage is False
        assert cfg.logging.retries is False

    def test_v_does_not_downgrade_preexisting_true(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        populated_agent_config,
    ) -> None:
        # Config already has per_turn_usage=True; -v must not flip it back.
        from dataclasses import replace
        from agent.config import LoggingConfig

        config = replace(
            populated_agent_config,
            logging=LoggingConfig(per_turn_usage=True, retries=False),
        )
        cfg = self._run_with_verbose(monkeypatch, tmp_path, config, ["-v"])
        assert cfg.logging.per_turn_usage is True
        assert cfg.logging.retries is True  # flipped on by -v


class TestShortShaGitExecutableHardening:
    """Lock-downs for the Bandit B607 hardening applied to ``_short_sha``."""

    def test_short_sha_returns_unknown_when_git_missing(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """``_GIT_EXECUTABLE`` None at module load (no git on PATH) must
        short-circuit ``_short_sha`` to its "unknown" fallback without
        calling subprocess.run."""
        called: list[Any] = []

        def fake_run(*a: Any, **k: Any) -> Any:
            called.append(a)
            raise AssertionError("subprocess.run must not be called")

        monkeypatch.setattr(main_mod, "_GIT_EXECUTABLE", None)
        monkeypatch.setattr(main_mod.subprocess, "run", fake_run)
        sha = main_mod._short_sha(tmp_path)
        assert sha == "unknown"
        assert called == []

    def test_short_sha_uses_absolute_git_path(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """argv must start with the absolute path resolved at module
        load, not the bare "git" string."""
        captured: list[list[str]] = []

        class _R:
            returncode = 0
            stdout = "abc1234\n"
            stderr = ""

        def fake_run(cmd: list[str], **kwargs: Any) -> _R:
            captured.append(cmd)
            return _R()

        monkeypatch.setattr(main_mod, "_GIT_EXECUTABLE", "/usr/bin/git")
        monkeypatch.setattr(main_mod.subprocess, "run", fake_run)
        sha = main_mod._short_sha(tmp_path)
        assert sha == "abc1234"
        assert captured[0] == [
            "/usr/bin/git",
            "rev-parse",
            "--short",
            "HEAD",
        ]


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# --mode dispatch and cross-mode flag rejection
# ---------------------------------------------------------------------------


class TestModeDispatchAndFlagRejection:
    """The CLI requires --mode explicitly (no implicit default — see
    design §3). Each mode has its own positional shape and rejects
    the other mode's flags. These are unit-level checks against the
    parser/main wiring, not end-to-end runs."""

    def test_missing_mode_emits_friendly_error(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The default argparse error ('the following arguments are
        required: --mode') would be confusing given that --mode is a
        deliberate breaking change. main() emits a custom message
        via parser.error so callers know what to add."""
        with pytest.raises(SystemExit) as excinfo:
            main(["https://github.com/o/r"])
        assert excinfo.value.code == 2
        err = capsys.readouterr().err
        assert "--mode is required" in err
        assert "scan or verify" in err

    def test_verify_mode_dispatches_to_verify_amain(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """--mode=verify routes through agent.verify.run_verify, not
        the scan-mode pipeline. We don't run the real orchestrator —
        we replace it with a recording stub and confirm it received
        the parsed CLI arguments."""
        captured: dict[str, Any] = {}

        from agent import verify as verify_module

        async def fake_run_verify(**kwargs: Any) -> int:
            captured.update(kwargs)
            return 0

        # Monkey-patch the orchestrator: the verify-mode entry path
        # in __main__ does `from . import verify as verify_module`
        # locally, so patching the attribute on the module object
        # works through the import-from indirection.
        monkeypatch.setattr(verify_module, "run_verify", fake_run_verify)

        # Avoid any real config loading.
        from agent.config import (
            AgentConfig,
            AnthropicConfig,
            AuditConfig,
            GitHubConfig,
            IssuesConfig,
            LoggingConfig,
            OAuthConfig,
            PublishConfig,
            SandboxConfig,
            ScanConfig,
            TLSConfig,
            TelemetryConfig,
            VerifyConfig,
        )

        fake_cfg = AgentConfig(
            anthropic=AnthropicConfig(
                bedrock_base_url="https://b.example",
                aws_region="us-east-1",
                model="claude-opus-4-8",
            ),
            oauth=OAuthConfig(
                token_endpoint="https://o.example",
                client_id="x",
                client_secret="y",
                expiry_safety_factor=0.9,
                default_lifetime_seconds=3600,
                http_timeout_seconds=30,
            ),
            tls=TLSConfig(ssl_cert_path=""),
            sandbox=SandboxConfig(
                enabled=True,
                fail_if_unavailable=True,
                allow_unsandboxed_commands=False,
            ),
            telemetry=TelemetryConfig(
                enabled=False, otel_exporter_otlp_endpoint=""
            ),
            scan=ScanConfig(
                clone_base_dir="./clones",
                clone_timeout_seconds=300,
                allowed_tools=["Read"],
                permission_mode="acceptEdits",
                autocompact_pct_override=None,
                async_agent_stall_timeout_ms=0,
            ),
            # Dual-token shape (post PR #38). scan+reports both set so
            # the mock config satisfies any downstream stage this test
            # ends up exercising via the fake orchestrator.
            github=GitHubConfig(
                host="github.com",
                scan_token="t",
                reports_token="t",
                broker_token_dir="",
            ),
            publish=PublishConfig(
                enabled=False,
                destination_repo="",
                branch="main",
                commit_author_name="x",
                commit_author_email="y",
            ),
            issues=IssuesConfig(
                enabled=False,
                target_repo="",
                labels=[],
                dedup_label="x",
                haiku_model="x",
                sonnet_model="x",
                semantic_dedup=False,
                request_timeout_seconds=60,
                max_open_issues=10,
                token_budget_fraction=0.7,
                model_context_tokens=200000,
                notify_clean_scan=True,
                clean_scan_label="VulnHunter: clean-scan",
            ),
            logging=LoggingConfig(per_turn_usage=False, retries=False),
            verify=VerifyConfig(
                scratch_base_dir="./verify_runs",
                clone_timeout_seconds=300,
                repo_aliases={},
            ),
            audit=AuditConfig(
                enabled=False,
                events_path="/tmp/vulnhunter-test-audit.jsonl",
                findings_path="/tmp/vulnhunter-test-findings.jsonl",
                stdout=False,
                app_id="NA",
                actor="vulnhunter-agent-test",
                strict=False,
            ),
            source_path=None,
        )
        monkeypatch.setattr(main_mod, "load_config", lambda path: fake_cfg)

        rc = main(
            [
                "--mode=verify",
                "https://github.com/org/repo/issues/42",
                "--commit",
                "abc1234",
                "--no-post",
            ]
        )
        assert rc == 0
        assert captured["issue_urls"] == ["https://github.com/org/repo/issues/42"]
        assert captured["commit"] == "abc1234"
        assert captured["no_post"] is True
        assert captured["no_reopen"] is False

    @pytest.mark.parametrize(
        "extra",
        [
            ["--re-clone"],
            ["--clone-dir", "/tmp/x"],
            ["--scan-id", "abc"],
            ["--scan"],
            ["--no-scan"],
            ["--publish"],
            ["--no-publish"],
            ["--issues"],
            ["--no-issues"],
            ["--issues-target-repo", "https://github.com/x/y"],
            ["--read-only"],
            ["--no-read-only"],
            ["--enable-bash"],
        ],
    )
    def test_verify_mode_rejects_scan_only_flags(
        self,
        capsys: pytest.CaptureFixture[str],
        extra: list[str],
    ) -> None:
        """Each scan-mode-only flag must be rejected when paired with
        --mode=verify, with a clear error listing the offending flag(s)."""
        with pytest.raises(SystemExit) as excinfo:
            main(
                [
                    "--mode=verify",
                    "https://github.com/org/repo/issues/42",
                ]
                + extra
            )
        assert excinfo.value.code == 2
        err = capsys.readouterr().err
        assert "scan-mode only" in err

    @pytest.mark.parametrize(
        "extra",
        [
            ["--commit", "abc"],
            ["--scratch-dir", "/tmp/x"],
            ["--no-post"],
            ["--no-reopen"],
        ],
    )
    def test_scan_mode_rejects_verify_only_flags(
        self,
        capsys: pytest.CaptureFixture[str],
        extra: list[str],
    ) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main(
                [
                    "--mode=scan",
                    "https://github.com/o/r",
                ]
                + extra
            )
        assert excinfo.value.code == 2
        err = capsys.readouterr().err
        assert "verify-mode only" in err

    def test_scan_mode_requires_exactly_one_target(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Scan mode takes exactly one repo URL; multiple positionals
        should fail with a friendly error."""
        with pytest.raises(SystemExit) as excinfo:
            main(["--mode=scan", "url-a", "url-b"])
        assert excinfo.value.code == 2
        err = capsys.readouterr().err
        assert "exactly one positional" in err


# ---------------------------------------------------------------------------
# TOKEN-CLIENT-005 — standalone-mode preflight
# ---------------------------------------------------------------------------

import httpx  # noqa: E402
import respx  # noqa: E402
from dataclasses import replace as _replace_dc  # noqa: E402

from agent.__main__ import (  # noqa: E402
    PreflightError,
    _preflight_standalone_tokens,
    _required_roles,
)


class TestRequiredRoles:
    """Per-stage role enumeration — feed for the preflight loop."""

    def test_scan_only_no_roles(self) -> None:
        # Clone-only path may or may not need a token (private repo); the
        # preflight has no way to know and the clone itself fails loudly.
        assert _required_roles(scan=True, publish=False, issues=False) == []

    def test_issues_only_role(self) -> None:
        assert _required_roles(scan=True, publish=True, issues=True) == [
            "scan",
            "reports",
        ]

    def test_publish_without_issues_reports_only(self) -> None:
        assert _required_roles(scan=True, publish=True, issues=False) == ["reports"]

    def test_no_scan_issues_needs_reports_for_download(self) -> None:
        # Verify the download-prior-report path requires reports_token.
        assert _required_roles(scan=False, publish=False, issues=True) == [
            "scan",
            "reports",
        ]


class TestPreflightStandaloneTokens:
    """TOKEN-CLIENT-005: GET /installation/repositories per required role.

    The respx mocks let us assert the agent hits the right endpoint with
    the right Authorization header without ever leaving the test process.
    """

    @pytest.fixture(autouse=True)
    def _stub_verify(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # resolve_verify returns a CA-bundle path when one is configured,
        # which httpx's newer versions treat as a deprecated str-verify.
        # Pin it to True so the preflight builds an httpx.Client cleanly.
        monkeypatch.setattr(main_mod, "resolve_verify", lambda tls: True)

    def _cfg(
        self,
        populated_agent_config: Any,
        *,
        scan_token: str = "ghp_scan",
        reports_token: str = "ghp_reports",
        host: str = "github.com",
        broker_token_dir: str = "",
    ) -> Any:
        return _replace_dc(
            populated_agent_config,
            github=_replace_dc(
                populated_agent_config.github,
                host=host,
                scan_token=scan_token,
                reports_token=reports_token,
                broker_token_dir=broker_token_dir,
            ),
        )

    @respx.mock
    def test_no_required_roles_is_noop(self, populated_agent_config: Any) -> None:
        # Scan-only — no preflight calls should fire.
        route = respx.get("https://api.github.com/installation/repositories").mock(
            return_value=httpx.Response(200, json={})
        )
        _preflight_standalone_tokens(
            config=self._cfg(populated_agent_config),
            scan=True,
            publish=False,
            issues=False,
        )
        assert route.call_count == 0

    @respx.mock
    def test_200_accepts(self, populated_agent_config: Any) -> None:
        respx.get("https://api.github.com/installation/repositories").mock(
            return_value=httpx.Response(200, json={"repositories": []})
        )
        _preflight_standalone_tokens(
            config=self._cfg(populated_agent_config),
            scan=True,
            publish=True,
            issues=True,
        )

    @respx.mock
    def test_404_accepts(self, populated_agent_config: Any) -> None:
        # Classic PATs are not installation-scoped; they 404 on this endpoint
        # but the auth header was checked on the way to the 404, which is what
        # we actually care about.
        respx.get("https://api.github.com/installation/repositories").mock(
            return_value=httpx.Response(404)
        )
        _preflight_standalone_tokens(
            config=self._cfg(populated_agent_config),
            scan=True,
            publish=True,
            issues=True,
        )

    @respx.mock
    def test_401_raises_with_role(self, populated_agent_config: Any) -> None:
        respx.get("https://api.github.com/installation/repositories").mock(
            return_value=httpx.Response(401, json={"message": "Bad credentials"})
        )
        with pytest.raises(PreflightError, match="scan_token failed preflight"):
            _preflight_standalone_tokens(
                config=self._cfg(populated_agent_config),
                scan=True,
                publish=True,
                issues=True,
            )

    @respx.mock
    def test_403_raises_with_role(self, populated_agent_config: Any) -> None:
        # A "real" 403 — not the App-endpoint-vs-PAT mismatch — must still
        # fail preflight. E.g. token revoked, SSO not authorized.
        respx.get("https://api.github.com/installation/repositories").mock(
            return_value=httpx.Response(
                403,
                json={"message": "Resource not accessible by personal access token"},
            )
        )
        with pytest.raises(PreflightError, match="status 403"):
            _preflight_standalone_tokens(
                config=self._cfg(populated_agent_config),
                scan=True,
                publish=True,
                issues=True,
            )

    @respx.mock
    def test_403_pat_on_app_endpoint_passes(self, populated_agent_config: Any) -> None:
        """Classic/fine-grained PATs get a 403 with the "must authenticate
        with an installation access token" body on the App-only endpoint.
        The auth layer already accepted the token — preflight must
        recognize this shape and pass, not fail."""
        respx.get("https://api.github.com/installation/repositories").mock(
            return_value=httpx.Response(
                403,
                json={
                    "message": (
                        "You must authenticate with an installation access "
                        "token in order to list repositories for an "
                        "installation."
                    ),
                    "documentation_url": "https://docs.github.com/rest/apps/installations",
                    "status": "403",
                },
            )
        )
        _preflight_standalone_tokens(
            config=self._cfg(populated_agent_config),
            scan=True,
            publish=True,
            issues=True,
        )  # no raise

    @respx.mock
    def test_403_includes_body_headers_and_fingerprint(
        self, populated_agent_config: Any
    ) -> None:
        """Preflight error must carry GitHub's actual response + a token
        fingerprint so the operator can distinguish scope vs. SSO vs.
        stale-token-in-container from a single log line."""
        respx.get("https://api.github.com/installation/repositories").mock(
            return_value=httpx.Response(
                403,
                headers={
                    "X-GitHub-Request-Id": "AAAA:BBBB:CCCC",
                    "X-OAuth-Scopes": "repo, read:org",
                    "X-Accepted-OAuth-Scopes": "",
                    "X-GitHub-SSO": "required; url=https://github.com/orgs/foo/sso",
                },
                json={"message": "Resource not accessible by personal access token"},
            )
        )
        with pytest.raises(PreflightError) as exc_info:
            _preflight_standalone_tokens(
                # Realistic 40-char PAT so the fingerprint uses the
                # prefix/suffix format we want operators to see.
                config=self._cfg(
                    populated_agent_config,
                    scan_token="ghp_" + "x" * 36,
                    reports_token="ghp_" + "y" * 36,
                ),
                scan=True,
                publish=True,
                issues=True,
            )
        msg = str(exc_info.value)
        # GitHub response body is embedded.
        assert "Resource not accessible" in msg
        # Diagnostic headers are called out by name.
        assert "X-GitHub-Request-Id: AAAA:BBBB:CCCC" in msg
        assert "X-OAuth-Scopes: repo, read:org" in msg
        assert "X-GitHub-SSO" in msg
        # Token fingerprint exposes prefix/suffix + length (no full token).
        assert "Token fingerprint:" in msg
        assert "(len=40)" in msg
        # The token itself never appears — only the 4-char prefix/suffix.
        assert "ghp_x" * 36 not in msg

    @respx.mock
    def test_network_error_surfaces_as_preflight_error(
        self, populated_agent_config: Any
    ) -> None:
        respx.get("https://api.github.com/installation/repositories").mock(
            side_effect=httpx.ConnectError("network down")
        )
        with pytest.raises(PreflightError, match="failed to reach"):
            _preflight_standalone_tokens(
                config=self._cfg(populated_agent_config),
                scan=True,
                publish=True,
                issues=True,
            )

    @respx.mock
    def test_auth_header_carries_scan_token_first(
        self, populated_agent_config: Any
    ) -> None:
        """For scan+publish+issues, both roles checked; scan goes first."""
        route = respx.get(
            "https://api.github.com/installation/repositories"
        ).mock(return_value=httpx.Response(200, json={}))
        _preflight_standalone_tokens(
            config=self._cfg(
                populated_agent_config,
                scan_token="ghp_scan_xyz",
                reports_token="ghp_rep_xyz",
            ),
            scan=True,
            publish=True,
            issues=True,
        )
        # Two calls, in order: scan, reports.
        assert route.call_count == 2
        headers = [c.request.headers["authorization"] for c in route.calls]
        assert headers == ["Bearer ghp_scan_xyz", "Bearer ghp_rep_xyz"]

    @respx.mock
    def test_enterprise_host_uses_v3_api_base(
        self, populated_agent_config: Any
    ) -> None:
        route = respx.get(
            "https://enterprise.example.com/api/v3/installation/repositories"
        ).mock(return_value=httpx.Response(200, json={}))
        _preflight_standalone_tokens(
            config=self._cfg(populated_agent_config, host="enterprise.example.com"),
            scan=True,
            publish=False,
            issues=True,
        )
        assert route.call_count == 1


