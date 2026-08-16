"""Tests for the pluggable scan engines (agent/engines/).

All subprocess execution is faked — these tests verify command
construction, pre-staging (results dir, prior-results guard), the
results-directory success contract, and config wiring. No real hermes /
copilot / claude invocation happens.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent import engines
from agent.engines import ENGINE_NAMES, ScanSpec, get_engine
from agent.engines.claude_code import ClaudeCodeEngine
from agent.engines.codex import CodexEngine
from agent.engines.copilot import CopilotCliEngine
from agent.engines.hermes import EngineError, HermesEngine


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestGetEngine:
    @pytest.mark.parametrize("name,cls", [
        ("claude-code", ClaudeCodeEngine),
        ("hermes", HermesEngine),
        ("copilot", CopilotCliEngine),
        ("codex", CodexEngine),
    ])
    def test_returns_engine_for_known_names(self, name: str, cls: type) -> None:
        cfg = SimpleNamespace(scan=SimpleNamespace(engine=name))
        engine = get_engine(cfg)
        assert isinstance(engine, cls)
        assert engine.name == name

    def test_unknown_engine_raises(self) -> None:
        cfg = SimpleNamespace(scan=SimpleNamespace(engine="skynet"))
        with pytest.raises(ValueError, match="unknown scan engine"):
            get_engine(cfg)

    def test_engine_names_cover_registry(self) -> None:
        assert ENGINE_NAMES == ("claude-code", "hermes", "copilot", "codex")


# ---------------------------------------------------------------------------
# Config wiring
# ---------------------------------------------------------------------------


class TestEngineConfig:
    def _toml(self, engine_block: str) -> str:
        return (
            """
[anthropic]
model = "claude-opus-4-8"

[oauth]
token_endpoint = "https://oauth.example.com/token"
client_id = "cid"
client_secret = "csec"
"""
            + engine_block
        )

    def test_default_engine_is_claude_code(self, tmp_path: Path) -> None:
        from agent.config import load_config

        path = tmp_path / "cfg.toml"
        path.write_text(self._toml(""))
        cfg = load_config(path)
        assert cfg.scan.engine == "claude-code"
        assert cfg.scan.engine_timeout_seconds == 21_600
        assert cfg.scan.engine_extra_args == []

    def test_hermes_engine_fields_from_toml(self, tmp_path: Path) -> None:
        from agent.config import load_config

        path = tmp_path / "cfg.toml"
        path.write_text(
            self._toml(
                """
[scan]
engine = "hermes"
engine_command = "/opt/hermes/bin/hermes"
engine_provider = "anthropic"
engine_timeout_seconds = 3600
engine_extra_args = "--accept-hooks,--reasoning=high"
"""
            )
        )
        cfg = load_config(path)
        assert cfg.scan.engine == "hermes"
        assert cfg.scan.engine_command == "/opt/hermes/bin/hermes"
        assert cfg.scan.engine_provider == "anthropic"
        assert cfg.scan.engine_timeout_seconds == 3600
        assert cfg.scan.engine_extra_args == ["--accept-hooks", "--reasoning=high"]

    def test_invalid_engine_rejected(self, tmp_path: Path) -> None:
        from agent.config import load_config

        path = tmp_path / "cfg.toml"
        path.write_text(self._toml('[scan]\nengine = "nope"\n'))
        with pytest.raises(ValueError, match=r"\[scan\] engine"):
            load_config(path)


# ---------------------------------------------------------------------------
# Hermes engine
# ---------------------------------------------------------------------------


class _FakeProc:
    def __init__(self, returncode: int = 0, stdout: bytes = b"ok", stderr: bytes = b""):
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr
        self.killed = False

    async def communicate(self):
        return (self._stdout, self._stderr)

    def kill(self):
        self.killed = True

    async def wait(self):
        return self.returncode


def _hermes_spec(tmp_path: Path, **scan_overrides) -> ScanSpec:
    scan_fields = dict(
        engine="hermes",
        engine_command="/fake/hermes",
        engine_provider="",
        engine_timeout_seconds=60,
        engine_extra_args=[],
    )
    scan_fields.update(scan_overrides)
    scan = SimpleNamespace(**scan_fields)
    audit = SimpleNamespace(app_id="app", actor="tester")
    return ScanSpec(
        clone_dir=tmp_path / "clone",
        config=SimpleNamespace(scan=scan, audit=audit, anthropic=SimpleNamespace()),
        model="claude-opus-4-8",
        read_only=True,
        enable_bash=False,
    )


@pytest.fixture
def hermes_skill(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    skill = tmp_path / "SKILL.md"
    skill.write_text("# vulnhunt\n")
    monkeypatch.setattr(
        "agent.engines.hermes._HERMES_SKILL_CANDIDATES", (skill,)
    )
    return skill


class TestHermesEngine:
    async def test_missing_skill_raises(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(
            "agent.engines.hermes._HERMES_SKILL_CANDIDATES",
            (tmp_path / "nope" / "SKILL.md",),
        )
        spec = _hermes_spec(tmp_path)
        with pytest.raises(EngineError, match="install.sh --target hermes"):
            await HermesEngine().run_scan(spec)

    async def test_missing_binary_raises(self, tmp_path: Path, hermes_skill, monkeypatch):
        monkeypatch.setattr("agent.engines.hermes.shutil.which", lambda name: None)
        spec = _hermes_spec(tmp_path, engine_command="")
        spec.clone_dir.mkdir(parents=True)
        with pytest.raises(EngineError, match="hermes binary not found"):
            await HermesEngine().run_scan(spec)

    async def test_command_construction_read_only(
        self, tmp_path: Path, hermes_skill, monkeypatch
    ) -> None:
        captured: list[tuple] = []

        async def fake_exec(*cmd, **kw):
            captured.append((cmd, kw))
            return _FakeProc(0)

        monkeypatch.setattr(engines.hermes.asyncio, "create_subprocess_exec", fake_exec)
        spec = _hermes_spec(tmp_path)
        spec.clone_dir.mkdir(parents=True)
        results = await HermesEngine().run_scan(spec)

        cmd = captured[0][0]
        assert cmd[0] == "/fake/hermes"
        assert cmd[1:5] == ("chat", "-Q", "-s", "vulnhunt")
        assert "-t" in cmd and cmd[cmd.index("-t") + 1] == "file,delegation"
        assert cmd[cmd.index("-m") + 1] == "claude-opus-4-8"
        assert cmd[-2] == "-q"
        assert "/vulnhunt" in cmd[-1]
        assert "VULNHUNT_DIR" in cmd[-1]
        assert "read-only" in cmd[-1]
        assert 'action="list"' in cmd[-1]  # delegation wait protocol
        # Success contract: the pre-created results dir is returned.
        assert results is not None
        assert "_VULNHUNT_RESULTS_" in results.name

    async def test_command_construction_bash_and_provider(
        self, tmp_path: Path, hermes_skill, monkeypatch
    ) -> None:
        captured: list[tuple] = []

        async def fake_exec(*cmd, **kw):
            captured.append((cmd, kw))
            return _FakeProc(0)

        monkeypatch.setattr(engines.hermes.asyncio, "create_subprocess_exec", fake_exec)
        scan_cfg = SimpleNamespace(
            engine="hermes",
            engine_command="/fake/hermes",
            engine_provider="anthropic",
            engine_timeout_seconds=60,
            engine_extra_args=["--reasoning=high"],
        )
        spec = ScanSpec(
            clone_dir=tmp_path / "clone",
            config=SimpleNamespace(
                scan=scan_cfg,
                audit=SimpleNamespace(app_id="app", actor="tester"),
                anthropic=SimpleNamespace(),
            ),
            model="claude-opus-4-8",
            read_only=False,
            enable_bash=True,
        )
        spec.clone_dir.mkdir(parents=True)
        await HermesEngine().run_scan(spec)

        cmd = captured[0][0]
        assert cmd[cmd.index("-t") + 1] == "file,terminal,delegation"
        assert cmd[cmd.index("--provider") + 1] == "anthropic"
        assert "--reasoning=high" in cmd

    async def test_nonzero_exit_no_results_raises(
        self, tmp_path: Path, hermes_skill, monkeypatch
    ) -> None:
        async def fake_exec(*cmd, **kw):
            return _FakeProc(3, stdout=b"", stderr=b"boom")

        monkeypatch.setattr(engines.hermes.asyncio, "create_subprocess_exec", fake_exec)
        # Simulate "hermes produced nothing": results-dir discovery misses.
        monkeypatch.setattr("agent.runner._find_results_dir", lambda d: None)
        spec = _hermes_spec(tmp_path)
        spec.clone_dir.mkdir(parents=True)
        with pytest.raises(EngineError, match="exited 3"):
            await HermesEngine().run_scan(spec)

    async def test_nonzero_exit_with_results_returns_them(
        self, tmp_path: Path, hermes_skill, monkeypatch
    ) -> None:
        async def fake_exec(*cmd, **kw):
            return _FakeProc(1, stdout=b"warning", stderr=b"")

        monkeypatch.setattr(engines.hermes.asyncio, "create_subprocess_exec", fake_exec)
        spec = _hermes_spec(tmp_path)
        spec.clone_dir.mkdir(parents=True)
        results = await HermesEngine().run_scan(spec)
        assert results is not None and "_VULNHUNT_RESULTS_" in results.name

    async def test_timeout_kills_process(
        self, tmp_path: Path, hermes_skill, monkeypatch
    ) -> None:
        proc_holder: dict = {}

        async def fake_exec(*cmd, **kw):
            proc = _FakeProc(0)

            async def communicate():
                await asyncio.sleep(999)

            proc.communicate = communicate
            proc_holder["proc"] = proc
            return proc

        monkeypatch.setattr(engines.hermes.asyncio, "create_subprocess_exec", fake_exec)
        spec = _hermes_spec(tmp_path, engine_timeout_seconds=0)
        spec.clone_dir.mkdir(parents=True)
        with pytest.raises(EngineError, match="engine_timeout_seconds"):
            await HermesEngine().run_scan(spec)
        assert proc_holder["proc"].killed


# ---------------------------------------------------------------------------
# Copilot engine
# ---------------------------------------------------------------------------


class TestCopilotEngine:
    async def test_missing_skill_raises(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(
            "agent.engines.copilot._COPILOT_SKILL", tmp_path / "nope.md"
        )
        spec = _hermes_spec(tmp_path)  # config shape is shared
        with pytest.raises(EngineError, match="install.sh --target copilot"):
            await CopilotCliEngine().run_scan(spec)

    async def test_kickoff_points_at_skill_and_metadata(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        skill = tmp_path / "SKILL.md"
        skill.write_text("# vulnhunt\n")
        monkeypatch.setattr("agent.engines.copilot._COPILOT_SKILL", skill)
        captured: list[tuple] = []

        async def fake_exec(*cmd, **kw):
            captured.append((cmd, kw))
            return _FakeProc(0)

        monkeypatch.setattr(engines.copilot.asyncio, "create_subprocess_exec", fake_exec)
        scan = SimpleNamespace(
            engine="copilot",
            engine_command="/fake/copilot",
            engine_provider="",
            engine_timeout_seconds=60,
            engine_extra_args=["--allow-tool", "write"],
        )
        spec = ScanSpec(
            clone_dir=tmp_path / "clone",
            config=SimpleNamespace(
                scan=scan, audit=SimpleNamespace(app_id="a", actor="t"), anthropic=SimpleNamespace()
            ),
            model="claude-opus-4-8",
            read_only=True,
        )
        spec.clone_dir.mkdir(parents=True)
        results = await CopilotCliEngine().run_scan(spec)

        cmd = captured[0][0]
        assert cmd[0] == "/fake/copilot"
        assert cmd[1] == "-p"
        prompt = cmd[2]
        assert str(skill) in prompt
        assert "VULNHUNT_DIR" in prompt
        assert "opus48" in prompt  # model tag derived
        assert "--allow-tool" in cmd and "write" in cmd
        assert results is not None and "_VULNHUNT_RESULTS_" in results.name


# ---------------------------------------------------------------------------
# Codex engine
# ---------------------------------------------------------------------------


class TestCodexEngine:
    async def test_missing_skill_raises(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr("agent.engines.codex._CODEX_SKILL", tmp_path / "nope.md")
        spec = _hermes_spec(tmp_path)  # config shape is shared
        with pytest.raises(EngineError, match="install.sh --target codex"):
            await CodexEngine().run_scan(spec)

    async def test_command_and_kickoff(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        skill = tmp_path / "SKILL.md"
        skill.write_text("# vulnhunt\n")
        monkeypatch.setattr("agent.engines.codex._CODEX_SKILL", skill)
        captured: list[tuple] = []

        async def fake_exec(*cmd, **kw):
            captured.append((cmd, kw))
            return _FakeProc(0)

        monkeypatch.setattr(engines.codex.asyncio, "create_subprocess_exec", fake_exec)
        scan = SimpleNamespace(
            engine="codex",
            engine_command="/fake/codex",
            engine_provider="",
            engine_timeout_seconds=60,
            engine_extra_args=["--skip-git-repo-check"],
        )
        spec = ScanSpec(
            clone_dir=tmp_path / "clone",
            config=SimpleNamespace(
                scan=scan, audit=SimpleNamespace(app_id="a", actor="t"), anthropic=SimpleNamespace()
            ),
            model="claude-opus-4-8",
            read_only=True,
        )
        spec.clone_dir.mkdir(parents=True)
        results = await CodexEngine().run_scan(spec)

        cmd = captured[0][0]
        assert cmd[0] == "/fake/codex"
        assert cmd[1] == "exec"
        assert cmd[cmd.index("-C") + 1] == str(spec.clone_dir)
        assert cmd[cmd.index("-s") + 1] == "workspace-write"
        assert cmd[cmd.index("-m") + 1] == "claude-opus-4-8"
        assert "--skip-git-repo-check" in cmd
        prompt = cmd[-1]
        assert str(skill) in prompt
        assert "VULNHUNT_DIR" in prompt
        assert "read-only" in prompt
        assert results is not None and "_VULNHUNT_RESULTS_" in results.name
