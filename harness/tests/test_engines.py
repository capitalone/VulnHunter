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

    def test_copilot_argv(self):
        argv = scan.build_scan_command("/repos/app", "PROMPT", engine="copilot")
        assert argv == ["copilot", "-p", "PROMPT"]

    def test_codex_argv(self):
        argv = scan.build_scan_command("/repos/app", "PROMPT", engine="codex")
        assert argv[0] == "codex"
        assert argv[1] == "exec"
        assert argv[argv.index("-C") + 1] == "/repos/app"
        assert argv[argv.index("-s") + 1] == "workspace-write"
        assert argv[argv.index("-m") + 1] == config.MODEL
        assert argv[-1] == "PROMPT"

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

    def test_copilot_judge_embeds_system_prompt(self):
        argv = judge.build_judge_command("PROMPT", "SYS", "m", engine="copilot")
        assert argv == ["copilot", "-p", "SYS\n\n---\n\nPROMPT"]

    def test_codex_judge_skips_git_check(self):
        argv = judge.build_judge_command("PROMPT", "SYS", "m", engine="codex")
        assert argv[0] == "codex"
        assert "--skip-git-repo-check" in argv
        assert argv[argv.index("-m") + 1] == "m"
        combined = argv[-1]
        assert "SYS" in combined and "PROMPT" in combined

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

    def test_unknown_engine_env_rejected(self, monkeypatch):
        monkeypatch.setenv("VULNHUNT_HARNESS_ENGINE", "bad-engine")
        import importlib
        with pytest.raises(ValueError, match="unknown harness engine"):
            importlib.reload(config)
        monkeypatch.delenv("VULNHUNT_HARNESS_ENGINE")
        importlib.reload(config)
