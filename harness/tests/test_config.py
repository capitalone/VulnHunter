"""Tests for local_harness.config — module-level constants."""

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
