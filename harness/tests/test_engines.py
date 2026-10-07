"""Tests for multi-engine scan/judge command construction."""

import pytest

import local_harness.config as config
import local_harness.scan as scan
from local_harness.benchmark import judge


class TestScanCommandBuilders:
    def test_claude_code_argv_matches_historical_shape(self):
        argv = scan.build_scan_command(
            "/repos/app", "/vulnhunt /repos/app", engine="claude-code"
        )
        assert argv[0] == "claude"
        assert argv[1] == "-p"
        assert argv[argv.index("--output-format") + 1] == "stream-json"
        assert argv[argv.index("--permission-mode") + 1] == "acceptEdits"
        assert argv[argv.index("--model") + 1] == config.MODEL
        assert "--add-dir" in argv
        # tool allow-list stays positional after --allowedTools
        i = argv.index("--allowedTools")
        assert argv[i + 1 : i + 6] == ["Read", "Write", "Edit", "Bash", "Agent"]

    def test_hermes_argv_read_only(self):
        argv = scan.build_scan_command(
            "/repos/app", "PROMPT", engine="hermes", readonly=True
        )
        assert argv[0] == "hermes"
        assert argv[1:5] == ["chat", "-Q", "-s", "vulnhunt"]
        assert argv[argv.index("-t") + 1] == "file,delegation"
        assert argv[argv.index("-m") + 1] == config.MODEL
        assert argv[-2] == "-q" and argv[-1] == "PROMPT"

    def test_hermes_argv_bash_includes_terminal(self):
        argv = scan.build_scan_command(
            "/repos/app", "PROMPT", engine="hermes", readonly=False
        )
        assert argv[argv.index("-t") + 1] == "file,terminal,delegation"

    @pytest.mark.parametrize("engine", ["copilot", "codex"])
    def test_unshipped_engine_raises(self, engine):
        with pytest.raises(ValueError, match="unknown engine"):
            scan.build_scan_command("/repos/app", "PROMPT", engine=engine)

    def test_unknown_engine_raises(self):
        with pytest.raises(ValueError, match="unknown engine"):
            scan.build_scan_command("/repos/app", "P", engine="skynet")


class TestJudgeCommandBuilders:
    def test_claude_code_judge_argv_matches_historical_shape(self):
        argv = judge.build_judge_command("PROMPT", "SYS", "claude-opus-4-8", engine="claude-code")
        assert argv == [
            "claude", "-p", "PROMPT",
            "--output-format", "text",
            "--model", "claude-opus-4-8",
            "--system-prompt", "SYS",
        ]

    def test_hermes_judge_embeds_system_prompt(self):
        argv = judge.build_judge_command("PROMPT", "SYS", "m", engine="hermes")
        assert argv[0] == "hermes"
        assert argv[argv.index("-m") + 1] == "m"
        combined = argv[argv.index("-q") + 1]
        assert "SYS" in combined and "PROMPT" in combined

    @pytest.mark.parametrize("engine", ["copilot", "codex"])
    def test_unshipped_judge_engine_raises(self, engine):
        with pytest.raises(ValueError, match="unknown engine"):
            judge.build_judge_command("PROMPT", "SYS", "m", engine=engine)

    def test_unknown_judge_engine_raises(self):
        with pytest.raises(ValueError, match="unknown engine"):
            judge.build_judge_command("P", "S", "m", engine="nope")


class TestEngineConfig:
    def test_default_engine_is_claude_code(self, monkeypatch):
        monkeypatch.delenv("VULNHUNT_HARNESS_ENGINE", raising=False)
        monkeypatch.delenv("VULNHUNT_HARNESS_JUDGE_ENGINE", raising=False)
        import importlib
        cfg = importlib.reload(config)
        assert cfg.ENGINE == "claude-code"
        assert cfg.JUDGE_ENGINE == "claude-code"
        assert cfg.ENGINE_SKILLS_DIR == cfg.SKILLS_DIR
        importlib.reload(config)  # restore for other tests

    def test_engine_env_selection(self, monkeypatch):
        monkeypatch.setenv("VULNHUNT_HARNESS_ENGINE", "hermes")
        monkeypatch.delenv("VULNHUNT_HARNESS_JUDGE_ENGINE", raising=False)
        import importlib
        cfg = importlib.reload(config)
        assert cfg.ENGINE == "hermes"
        assert cfg.JUDGE_ENGINE == "hermes"  # follows scan engine by default
        assert cfg.ENGINE_SKILLS_DIR.endswith(".hermes/skills/vulnhunt")
        importlib.reload(config)

    def test_unknown_engine_env_does_not_break_import(self, monkeypatch):
        """A typo'd env var must NOT raise at import time.

        Validation is deferred to the point of use so merely importing the
        config (as --help paths and unrelated tooling do) stays safe. No
        reload sequencing is needed to clean up global state.
        """
        monkeypatch.setenv("VULNHUNT_HARNESS_ENGINE", "bad-engine")
        import importlib
        cfg = importlib.reload(config)  # must not raise
        assert cfg.ENGINE == "bad-engine"
        # It fails clearly at the point of use instead:
        with pytest.raises(ValueError, match="unknown harness engine"):
            cfg.validate_engine(cfg.ENGINE)
        monkeypatch.delenv("VULNHUNT_HARNESS_ENGINE")
        importlib.reload(config)

    def test_validate_engine_accepts_known(self):
        for name in ("claude-code", "hermes"):
            assert config.validate_engine(name) == name

    @pytest.mark.parametrize("name", ["copilot", "codex"])
    def test_validate_engine_rejects_unshipped(self, name):
        with pytest.raises(ValueError, match="unknown harness engine"):
            config.validate_engine(name)

    def test_skills_dir_for_validates(self):
        assert config.skills_dir_for("hermes").endswith(".hermes/skills/vulnhunt")
        with pytest.raises(ValueError, match="unknown harness engine"):
            config.skills_dir_for("nope")
