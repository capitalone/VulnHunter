"""Tests for local_harness.config — module-level constants."""

import importlib
import os

import pytest

import local_harness.config as config


def test_paths_are_absolute_and_nested():
    assert os.path.isabs(config.HARNESS_DIR)
    assert config.REPO_ROOT == os.path.dirname(config.HARNESS_DIR)
    assert config.BENCHMARK_DIR.endswith(os.path.join("benchmark", "ground_truth"))
    assert config.STATE_FILE.endswith("state.json")
    assert config.TALLY_FILE.endswith("tally.json")
    assert config.TALLY_REPORT.endswith("BENCHMARK_REPORT.md")


def test_retry_and_timeout_constants():
    assert config.MAX_SCAN_WORKERS == 5
    assert config.SCAN_MAX_RETRIES == 3
    assert config.SCAN_RETRY_BACKOFF_MULTIPLIER == 2.0
    assert config.JUDGE_MAX_RETRIES == 3
    assert isinstance(config.MODEL, str) and config.MODEL


@pytest.fixture
def reloaded_with():
    """Reload `config` with VULNHUNT_HARNESS_MODEL set to a chosen value.

    The two reloads have to bracket the patch correctly: the first must see the
    patched environment, the restoring one must see the *unpatched* one. Because
    monkeypatch undoes itself in fixture teardown — which runs after the test
    body — a plain `finally: reload()` inside the body would re-read the override
    and leave it baked into config.MODEL for every test that runs afterwards.
    Undoing explicitly before the restoring reload is what keeps this contained.
    """
    mp = pytest.MonkeyPatch()

    def _reload(value):
        if value is None:
            mp.delenv("VULNHUNT_HARNESS_MODEL", raising=False)
        else:
            mp.setenv("VULNHUNT_HARNESS_MODEL", value)
        importlib.reload(config)
        return config

    yield _reload

    mp.undo()
    importlib.reload(config)


def test_model_defaults_without_env_var(reloaded_with):
    assert reloaded_with(None).MODEL == "claude-opus-4-8"


def test_model_env_var_overrides_default(reloaded_with):
    assert reloaded_with("test-model-x").MODEL == "test-model-x"


@pytest.mark.parametrize("blank", ["", "   "])
def test_blank_model_env_var_is_treated_as_unset(reloaded_with, blank):
    # os.environ.get() falls back only on an *absent* key, so without the guard
    # an exported-but-empty value reaches the CLI as `claude --model ""`.
    assert reloaded_with(blank).MODEL == config.DEFAULT_MODEL


def test_model_env_var_is_stripped(reloaded_with):
    assert reloaded_with("  test-model-x  ").MODEL == "test-model-x"


@pytest.mark.skipif(
    os.environ.get("VULNHUNT_HARNESS_MODEL", "").strip() != "",
    reason="VULNHUNT_HARNESS_MODEL is set in this environment",
)
def test_model_override_does_not_leak_between_tests():
    # Regression guard for the fixture above: if the restoring reload ran while
    # the env was still patched, this would see the override, not the default.
    assert config.MODEL == config.DEFAULT_MODEL


def test_batch_and_history_paths():
    assert config.BATCH_REPO_LIST_FILE.endswith(os.path.join("batch", "REPO_LIST.txt"))
    assert config.BATCH_LOG_FILENAME == "batch_scan.log"
    assert config.HISTORY_FILE.endswith("finding_history.json")
    assert config.PHASES_DIR.endswith("phases")


def test_atomic_write_json_roundtrip(tmp_path):
    import json
    target = tmp_path / "sub" / "out.json"  # nested dir is created
    config.atomic_write_json(str(target), {"a": 1}, sort_keys=True)
    assert json.loads(target.read_text()) == {"a": 1}
    # no temp files left behind
    assert [p.name for p in target.parent.iterdir()] == ["out.json"]


def test_atomic_write_json_cleans_temp_on_error(tmp_path):
    target = tmp_path / "out.json"

    class Unserializable:
        pass

    with pytest.raises(TypeError):
        config.atomic_write_json(str(target), {"bad": Unserializable()})
    # failed write leaves neither the target nor a stray temp file
    assert not target.exists()
    assert list(tmp_path.iterdir()) == []
