"""Tests for the pluggable scan engines (agent/engines/).

All subprocess execution is faked — these tests verify command
construction, pre-staging (results dir, prior-results guard), the
*contents-based* results-directory success contract (an empty results dir
is a failure, not a clean scan), timeout handling, and config wiring. No
real Hermes or Claude invocation happens.

Hermes exercises the generic ``SubprocessEngine`` behaviors (success
contract, non-zero exit, timeout, and extra args) once. Future CLI-backed
engines inherit that tested path rather than copying it.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent import engines
from agent.engines import _subprocess as _subprocess_mod
from agent.engines import ENGINE_NAMES, EngineError, ScanSpec, get_engine
from agent.engines.claude_code import ClaudeCodeEngine
from agent.engines.hermes import EngineError as HermesEngineError
from agent.engines.hermes import HermesEngine

# A README long enough to clear the >100-byte completion floor.
_VALID_README = "# VulnHunter Results\n\n" + ("finding detail. " * 20)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestGetEngine:
    @pytest.mark.parametrize("name,cls", [
        ("claude-code", ClaudeCodeEngine),
        ("hermes", HermesEngine),
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
        assert ENGINE_NAMES == ("claude-code", "hermes")

    @pytest.mark.parametrize("name", ["copilot", "codex"])
    def test_unshipped_engine_raises(self, name: str) -> None:
        cfg = SimpleNamespace(scan=SimpleNamespace(engine=name))
        with pytest.raises(ValueError, match="unknown scan engine"):
            get_engine(cfg)

    def test_engine_error_is_shared_symbol(self) -> None:
        # EngineError's home is engines/__init__; the hermes re-export must
        # be the very same class so `except EngineError` catches all engines.
        assert HermesEngineError is EngineError


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
engine_extra_args = ["--accept-hooks", "--reasoning=high"]
"""
            )
        )
        cfg = load_config(path)
        assert cfg.scan.engine == "hermes"
        assert cfg.scan.engine_command == "/opt/hermes/bin/hermes"
        assert cfg.scan.engine_provider == "anthropic"
        assert cfg.scan.engine_timeout_seconds == 3600
        assert cfg.scan.engine_extra_args == ["--accept-hooks", "--reasoning=high"]

    def test_extra_args_string_is_shlex_split(self, tmp_path: Path) -> None:
        # A bare string is accepted for convenience and shlex-split, so a
        # future engine's value with commas/parens survives intact.
        from agent.config import load_config

        path = tmp_path / "cfg.toml"
        path.write_text(
            self._toml(
                """
[scan]
engine = "hermes"
engine_extra_args = "--flag 'value,with(parens)'"
"""
            )
        )
        cfg = load_config(path)
        assert cfg.scan.engine_extra_args == ["--flag", "value,with(parens)"]

    def test_invalid_engine_rejected(self, tmp_path: Path) -> None:
        from agent.config import load_config

        path = tmp_path / "cfg.toml"
        path.write_text(self._toml('[scan]\nengine = "nope"\n'))
        with pytest.raises(ValueError, match=r"\[scan\] engine"):
            load_config(path)


# ---------------------------------------------------------------------------
# Fakes / helpers shared across the subprocess engines
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


def _find_results_dir(clone_dir: Path) -> Path | None:
    if not clone_dir.is_dir():
        return None
    for entry in clone_dir.iterdir():
        if entry.is_dir() and "_VULNHUNT_RESULTS_" in entry.name:
            return entry
    return None


def _exec_writing_readme(returncode: int = 0, stdout: bytes = b"ok", stderr: bytes = b""):
    """Fake create_subprocess_exec that simulates a *completed* scan.

    The engine pre-creates the results dir before launching, so the fake
    finds it (via cwd) and drops a valid README.md — mirroring what a real
    engine does on success. This is what makes the contents-based contract
    return the dir.
    """
    async def fake_exec(*cmd, **kw):
        clone_dir = Path(kw["cwd"])
        results = _find_results_dir(clone_dir)
        if results is not None:
            (results / "README.md").write_text(_VALID_README)
        return _FakeProc(returncode, stdout, stderr)

    return fake_exec


def _exec_leaving_empty(returncode: int = 0, stdout: bytes = b"", stderr: bytes = b"boom"):
    """Fake exec that leaves the pre-created results dir EMPTY (crash/OOM)."""
    async def fake_exec(*cmd, **kw):
        return _FakeProc(returncode, stdout, stderr)

    return fake_exec


def _capturing_exec(captured: list, returncode: int = 0):
    async def fake_exec(*cmd, **kw):
        captured.append((cmd, kw))
        clone_dir = Path(kw["cwd"])
        results = _find_results_dir(clone_dir)
        if results is not None:
            (results / "README.md").write_text(_VALID_README)
        return _FakeProc(returncode)

    return fake_exec


def _spec(
    tmp_path: Path,
    engine_name: str = "hermes",
    *,
    read_only: bool = True,
    enable_bash: bool = False,
    **scan_overrides,
) -> ScanSpec:
    scan_fields = dict(
        engine=engine_name,
        engine_command=f"/fake/{engine_name}",
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
        read_only=read_only,
        enable_bash=enable_bash,
    )


# Per-engine wiring: the engine class and how to point its skill lookup at a
# temp SKILL.md. Subprocess launch lives in the shared base, so all exec
# patching targets ``agent.engines._subprocess`` regardless of engine.
_SUBPROC = _subprocess_mod
_ENGINE_TABLE = [
    ("hermes", HermesEngine, "agent.engines.hermes._HERMES_SKILL_CANDIDATES", True),
]


def _install_skill(monkeypatch, tmp_path: Path, attr: str, as_tuple: bool) -> Path:
    skill = tmp_path / "SKILL.md"
    skill.write_text("# vulnhunt\n")
    monkeypatch.setattr(attr, (skill,) if as_tuple else skill)
    return skill


# ---------------------------------------------------------------------------
# Shared subprocess-engine contract (Hermes now; reusable by future engines)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name,cls,skill_attr,as_tuple", _ENGINE_TABLE)
class TestSubprocessEngineContract:
    async def test_missing_skill_raises(
        self, tmp_path, monkeypatch, name, cls, skill_attr, as_tuple
    ):
        missing = tmp_path / "nope" / "SKILL.md"
        monkeypatch.setattr(skill_attr, (missing,) if as_tuple else missing)
        spec = _spec(tmp_path, name)
        with pytest.raises(EngineError, match=f"install.sh --target {name}"):
            await cls().run_scan(spec)

    async def test_missing_binary_raises(
        self, tmp_path, monkeypatch, name, cls, skill_attr, as_tuple
    ):
        _install_skill(monkeypatch, tmp_path, skill_attr, as_tuple)
        monkeypatch.setattr("agent.engines._subprocess.shutil.which", lambda n: None)
        spec = _spec(tmp_path, name, engine_command="")
        spec.clone_dir.mkdir(parents=True)
        with pytest.raises(EngineError, match="binary not found"):
            await cls().run_scan(spec)

    async def test_complete_results_dir_returned(
        self, tmp_path, monkeypatch, name, cls, skill_attr, as_tuple
    ):
        _install_skill(monkeypatch, tmp_path, skill_attr, as_tuple)
        monkeypatch.setattr(_SUBPROC.asyncio, "create_subprocess_exec", _exec_writing_readme(0))
        spec = _spec(tmp_path, name)
        spec.clone_dir.mkdir(parents=True)
        results = await cls().run_scan(spec)
        assert results is not None
        assert "_VULNHUNT_RESULTS_" in results.name
        assert (results / "README.md").is_file()

    async def test_zero_exit_empty_results_is_failure(
        self, tmp_path, monkeypatch, name, cls, skill_attr, as_tuple
    ):
        """The core fix: exit 0 but an empty results dir is NOT a clean scan.

        A crashed/OOM-killed engine that returns 0 while writing nothing
        must raise, not report the empty pre-created dir as success.
        """
        _install_skill(monkeypatch, tmp_path, skill_attr, as_tuple)
        monkeypatch.setattr(_SUBPROC.asyncio, "create_subprocess_exec", _exec_leaving_empty(0))
        spec = _spec(tmp_path, name)
        spec.clone_dir.mkdir(parents=True)
        with pytest.raises(EngineError, match="did not complete"):
            await cls().run_scan(spec)

    async def test_nonzero_exit_empty_results_raises(
        self, tmp_path, monkeypatch, name, cls, skill_attr, as_tuple
    ):
        _install_skill(monkeypatch, tmp_path, skill_attr, as_tuple)
        monkeypatch.setattr(_SUBPROC.asyncio, "create_subprocess_exec", _exec_leaving_empty(3))
        spec = _spec(tmp_path, name)
        spec.clone_dir.mkdir(parents=True)
        with pytest.raises(EngineError, match="exited 3"):
            await cls().run_scan(spec)

    async def test_nonzero_exit_even_with_results_raises(
        self, tmp_path, monkeypatch, name, cls, skill_attr, as_tuple
    ):
        """A non-zero exit is a failure even if a README got written."""
        _install_skill(monkeypatch, tmp_path, skill_attr, as_tuple)
        monkeypatch.setattr(_SUBPROC.asyncio, "create_subprocess_exec", _exec_writing_readme(1))
        spec = _spec(tmp_path, name)
        spec.clone_dir.mkdir(parents=True)
        with pytest.raises(EngineError, match="exited 1"):
            await cls().run_scan(spec)

    async def test_timeout_kills_process(
        self, tmp_path, monkeypatch, name, cls, skill_attr, as_tuple
    ):
        proc_holder: dict = {}

        async def fake_exec(*cmd, **kw):
            proc = _FakeProc(0)

            async def communicate():
                await asyncio.sleep(999)

            proc.communicate = communicate
            proc_holder["proc"] = proc
            return proc

        _install_skill(monkeypatch, tmp_path, skill_attr, as_tuple)
        monkeypatch.setattr(_SUBPROC.asyncio, "create_subprocess_exec", fake_exec)
        # A tiny positive timeout fires; 0/negative means "no timeout" (below).
        spec = _spec(tmp_path, name, engine_timeout_seconds=0.01)
        spec.clone_dir.mkdir(parents=True)
        with pytest.raises(EngineError, match="engine_timeout_seconds"):
            await cls().run_scan(spec)
        assert proc_holder["proc"].killed

    async def test_extra_args_appended(
        self, tmp_path, monkeypatch, name, cls, skill_attr, as_tuple
    ):
        _install_skill(monkeypatch, tmp_path, skill_attr, as_tuple)
        captured: list = []
        monkeypatch.setattr(_SUBPROC.asyncio, "create_subprocess_exec", _capturing_exec(captured))
        spec = _spec(tmp_path, name, engine_extra_args=["--flag", "value,with(parens)"])
        spec.clone_dir.mkdir(parents=True)
        await cls().run_scan(spec)
        cmd = list(captured[0][0])
        # The exact whitespace/parens of the arg survive as a single token.
        assert "--flag" in cmd
        assert "value,with(parens)" in cmd


class TestTimeoutDisabled:
    """engine_timeout_seconds <= 0 means 'no timeout', not 'instant timeout'."""

    async def test_zero_timeout_waits_indefinitely(self, tmp_path, monkeypatch):
        captured_timeouts: list = []
        real_wait_for = asyncio.wait_for

        async def spy_wait_for(aw, timeout):
            captured_timeouts.append(timeout)
            return await real_wait_for(aw, timeout)

        skill = tmp_path / "SKILL.md"
        skill.write_text("# vulnhunt\n")
        monkeypatch.setattr("agent.engines.hermes._HERMES_SKILL_CANDIDATES", (skill,))
        monkeypatch.setattr(_SUBPROC.asyncio, "create_subprocess_exec", _exec_writing_readme(0))
        monkeypatch.setattr("agent.engines._subprocess.asyncio.wait_for", spy_wait_for)
        spec = _spec(tmp_path, "hermes", engine_timeout_seconds=0)
        spec.clone_dir.mkdir(parents=True)
        await HermesEngine().run_scan(spec)
        # None => asyncio.wait_for waits forever (no cap).
        assert captured_timeouts == [None]


# ---------------------------------------------------------------------------
# Engine-specific command construction
# ---------------------------------------------------------------------------


class TestHermesCommand:
    async def test_command_construction_read_only(self, tmp_path, monkeypatch):
        skill = tmp_path / "SKILL.md"
        skill.write_text("# vulnhunt\n")
        monkeypatch.setattr("agent.engines.hermes._HERMES_SKILL_CANDIDATES", (skill,))
        captured: list = []
        monkeypatch.setattr(_SUBPROC.asyncio, "create_subprocess_exec", _capturing_exec(captured))
        spec = _spec(tmp_path, "hermes")
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
        assert results is not None and "_VULNHUNT_RESULTS_" in results.name

    async def test_command_construction_bash_and_provider(self, tmp_path, monkeypatch):
        skill = tmp_path / "SKILL.md"
        skill.write_text("# vulnhunt\n")
        monkeypatch.setattr("agent.engines.hermes._HERMES_SKILL_CANDIDATES", (skill,))
        captured: list = []
        monkeypatch.setattr(_SUBPROC.asyncio, "create_subprocess_exec", _capturing_exec(captured))
        spec = _spec(
            tmp_path,
            "hermes",
            read_only=False,
            enable_bash=True,
            engine_provider="anthropic",
            engine_extra_args=["--reasoning=high"],
        )
        spec.clone_dir.mkdir(parents=True)
        await HermesEngine().run_scan(spec)

        cmd = captured[0][0]
        assert cmd[cmd.index("-t") + 1] == "file,terminal,delegation"
        assert cmd[cmd.index("--provider") + 1] == "anthropic"
        assert "--reasoning=high" in cmd
