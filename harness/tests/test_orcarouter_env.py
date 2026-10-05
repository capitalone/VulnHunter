"""Tests for the harness OrcaRouter env bridge.

The harness drives the ``claude`` CLI directly. When OrcaRouter is
configured, the bridge injects the inference origin and an API key into the
subprocess environment; otherwise it must be a no-op so existing behavior is
unchanged. The harness acquires no credentials itself.
"""

import importlib

import pytest

import local_harness.orcarouter_env as bridge


ORCA_ENV_KEYS = (
    "ORCA_BASE_URL", "ORCA_API_BASE_URL", "ORCA_AUTH_BASE_URL",
    "ORCA_API_KEY", "ORCAROUTER_API_KEY",
)


@pytest.fixture(autouse=True)
def _clean_orca_env(monkeypatch):
    for key in ORCA_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


def test_noop_when_orcarouter_not_configured():
    assert bridge.orcarouter_env() == {}
    assert bridge.claude_env() is None


def test_injects_api_origin_and_key(monkeypatch):
    monkeypatch.setenv("ORCA_API_KEY", "sk-orca-HARNESS000000000000000")
    monkeypatch.setenv("ORCA_API_BASE_URL", "https://api.orcarouter.ai/v1")
    env = bridge.orcarouter_env()
    assert env["ANTHROPIC_BASE_URL"] == "https://api.orcarouter.ai"
    assert env["ANTHROPIC_API_KEY"] == "sk-orca-HARNESS000000000000000"
    # Never the /v1 form — the CLI appends the version segment itself.
    assert not env["ANTHROPIC_BASE_URL"].endswith("/v1")


def test_shared_base_fallback_used(monkeypatch):
    monkeypatch.setenv("ORCA_API_KEY", "sk-orca-x")
    monkeypatch.setenv("ORCA_BASE_URL", "https://orca.internal.example/v1")
    assert bridge.orcarouter_env()["ANTHROPIC_BASE_URL"] == "https://orca.internal.example"


def test_orcarouter_api_key_env_is_honored(monkeypatch):
    monkeypatch.setenv("ORCAROUTER_API_KEY", "sk-orca-fromcampaign")
    monkeypatch.setenv("ORCA_BASE_URL", "https://api.orcarouter.ai")
    assert bridge.orcarouter_env()["ANTHROPIC_API_KEY"] == "sk-orca-fromcampaign"


def test_missing_key_raises_actionable_error(monkeypatch):
    # Configured (base set) but no key available anywhere.
    monkeypatch.setenv("ORCA_BASE_URL", "https://api.orcarouter.ai")
    monkeypatch.setattr(bridge, "_api_key", lambda: "")
    with pytest.raises(RuntimeError, match="ORCA_API_KEY"):
        bridge.orcarouter_env()


def test_claude_env_merges_parent_environment(monkeypatch):
    monkeypatch.setenv("ORCA_API_KEY", "sk-orca-merge")
    monkeypatch.setenv("ORCA_BASE_URL", "https://api.orcarouter.ai")
    monkeypatch.setenv("SOME_UNRELATED_VAR", "kept")
    env = bridge.claude_env()
    assert env["SOME_UNRELATED_VAR"] == "kept"
    assert env["ANTHROPIC_API_KEY"] == "sk-orca-merge"


def test_scan_subprocess_receives_env(monkeypatch, tmp_path):
    """The scan Popen call is handed the injected env."""
    import json

    import local_harness.scan as scan

    monkeypatch.setenv("ORCA_API_KEY", "sk-orca-scan")
    monkeypatch.setenv("ORCA_BASE_URL", "https://api.orcarouter.ai")

    captured = {}

    class _FakePopen:
        def __init__(self, *a, **k):
            captured.update(k)
            self.stdout = iter([json.dumps({"type": "result"}) + "\n"])
            self.returncode = 0

        def wait(self):
            return 0

        def kill(self):
            pass

    class _NoTimer:
        def __init__(self, *a, **k):
            pass

        def start(self):
            pass

        def cancel(self):
            pass

    folder = tmp_path / "repo"
    folder.mkdir()
    monkeypatch.setattr(scan, "SKILLS_DIR", str(tmp_path / "skills"))
    (tmp_path / "skills").mkdir()
    monkeypatch.setattr(scan.subprocess, "Popen", _FakePopen)
    monkeypatch.setattr(scan.threading, "Timer", _NoTimer)

    scan.scan_folder(str(folder))
    assert captured["env"]["ANTHROPIC_BASE_URL"] == "https://api.orcarouter.ai"
    assert captured["env"]["ANTHROPIC_API_KEY"] == "sk-orca-scan"


def test_scan_subprocess_inherits_when_unconfigured(monkeypatch, tmp_path):
    """Default behavior: env is None so the subprocess inherits unchanged."""
    import json

    import local_harness.scan as scan

    captured = {}

    class _FakePopen:
        def __init__(self, *a, **k):
            captured.update(k)
            self.stdout = iter([json.dumps({"type": "result"}) + "\n"])
            self.returncode = 0

        def wait(self):
            return 0

        def kill(self):
            pass

    class _NoTimer:
        def __init__(self, *a, **k):
            pass

        def start(self):
            pass

        def cancel(self):
            pass

    folder = tmp_path / "repo"
    folder.mkdir()
    monkeypatch.setattr(scan, "SKILLS_DIR", str(tmp_path / "skills"))
    (tmp_path / "skills").mkdir()
    monkeypatch.setattr(scan.subprocess, "Popen", _FakePopen)
    monkeypatch.setattr(scan.threading, "Timer", _NoTimer)

    scan.scan_folder(str(folder))
    assert captured["env"] is None
