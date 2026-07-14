"""Tests for local_harness.benchmark.finding_history."""

import json

import local_harness.benchmark.finding_history as fh


def _use_tmp_history(monkeypatch, tmp_path):
    path = str(tmp_path / "finding_history.json")
    monkeypatch.setattr(fh, "HISTORY_FILE", path)
    return path


def test_load_history_missing(monkeypatch, tmp_path):
    _use_tmp_history(monkeypatch, tmp_path)
    assert fh.load_history() == {}


def test_load_history_valid(monkeypatch, tmp_path):
    path = _use_tmp_history(monkeypatch, tmp_path)
    with open(path, "w") as f:
        json.dump({"F1": {"detected": [1], "missed": []}}, f)
    assert fh.load_history() == {"F1": {"detected": [1], "missed": []}}


def test_load_history_corrupt(monkeypatch, tmp_path):
    path = _use_tmp_history(monkeypatch, tmp_path)
    with open(path, "w") as f:
        f.write("{not valid json")
    assert fh.load_history() == {}


def test_save_and_reload(monkeypatch, tmp_path):
    _use_tmp_history(monkeypatch, tmp_path)
    fh.save_history({"F2": {"detected": [], "missed": [9]}})
    assert fh.load_history()["F2"]["missed"] == [9]


def test_update_history_records_and_skips(monkeypatch, tmp_path):
    _use_tmp_history(monkeypatch, tmp_path)
    monkeypatch.setattr(fh.time, "time", lambda: 1000)
    state = {
        "judgments": {
            "F1": {"detected": True},
            "F2": {"detected": False},
            "F3": {"detected": None},  # skipped
        }
    }
    targets = {
        "t": {"findings": [
            {"finding_id": "F1"}, {"finding_id": "F2"},
            {"finding_id": "F3"}, {"finding_id": "F4"},  # F4 has no judgment -> skipped
        ]}
    }
    recorded, skipped = fh.update_history(state, targets)
    assert recorded == 2
    assert skipped == 2
    hist = fh.load_history()
    assert hist["F1"]["detected"] == [1000]
    assert hist["F2"]["missed"] == [1000]


def test_get_stable_findings(monkeypatch, tmp_path):
    path = _use_tmp_history(monkeypatch, tmp_path)
    history = {
        "STABLE": {"detected": [1, 2, 3], "missed": []},
        "FLAKY": {"detected": [1, 3], "missed": [2]},
        "TOO_FEW": {"detected": [1], "missed": []},
        "RECOVERED": {"detected": [3, 4, 5], "missed": [1]},
    }
    with open(path, "w") as f:
        json.dump(history, f)
    stable = fh.get_stable_findings(threshold=3)
    assert "STABLE" in stable
    assert "RECOVERED" in stable  # last 3 all detected
    assert "FLAKY" not in stable
    assert "TOO_FEW" not in stable
