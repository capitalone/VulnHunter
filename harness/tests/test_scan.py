"""Tests for local_harness.scan."""

import json
import os
import types

import pytest

import local_harness.scan as scan


# --- results dir helpers ---

def test_find_results_dir_missing(tmp_path):
    assert scan.find_results_dir(str(tmp_path / "nope")) is None


def test_find_results_dir_found(tmp_path):
    d = tmp_path / "repo_VULNHUNT_RESULTS_2024"
    d.mkdir()
    assert scan.find_results_dir(str(tmp_path)) == str(d)


def test_find_results_dir_none_match(tmp_path):
    (tmp_path / "src").mkdir()
    assert scan.find_results_dir(str(tmp_path)) is None


def test_find_results_dir_ignores_file(tmp_path):
    (tmp_path / "x_VULNHUNT_RESULTS_y").write_text("a file, not a dir")
    assert scan.find_results_dir(str(tmp_path)) is None


def test_has_valid_results_true(tmp_path):
    rd = tmp_path / "r_VULNHUNT_RESULTS_1"
    rd.mkdir()
    (rd / "README.md").write_text("x" * 200)
    assert scan.has_valid_results(str(tmp_path)) is True


def test_has_valid_results_readme_too_small(tmp_path):
    rd = tmp_path / "r_VULNHUNT_RESULTS_1"
    rd.mkdir()
    (rd / "README.md").write_text("tiny")
    assert scan.has_valid_results(str(tmp_path)) is False


def test_has_valid_results_no_results_dir(tmp_path):
    assert scan.has_valid_results(str(tmp_path)) is False


# --- clean helpers ---

def test_clean_incomplete_results_removes_invalid(tmp_path):
    clone = tmp_path / "clone"
    clone.mkdir()
    bad = clone / "a_VULNHUNT_RESULTS_1"
    bad.mkdir()
    (bad / "README.md").write_text("short")
    (clone / "benchmark_scan.log").write_text("log")
    removed = scan.clean_incomplete_results(str(clone))
    assert "a_VULNHUNT_RESULTS_1" in removed
    assert not bad.exists()
    assert not (clone / "benchmark_scan.log").exists()


def test_clean_incomplete_results_keeps_valid(tmp_path):
    clone = tmp_path / "clone"
    clone.mkdir()
    good = clone / "a_VULNHUNT_RESULTS_1"
    good.mkdir()
    (good / "README.md").write_text("x" * 200)
    removed = scan.clean_incomplete_results(str(clone))
    assert removed == []
    assert good.exists()


def test_clean_incomplete_results_missing_dir(tmp_path):
    assert scan.clean_incomplete_results(str(tmp_path / "nope")) == []


def test_clean_incomplete_results_skips_non_dir_entry(tmp_path):
    clone = tmp_path / "clone"
    clone.mkdir()
    (clone / "x_VULNHUNT_RESULTS_file").write_text("not a dir")
    assert scan.clean_incomplete_results(str(clone)) == []


def test_clean_prior_results_removes_all(tmp_path):
    clone = tmp_path / "clone"
    clone.mkdir()
    rd = clone / "a_VULNHUNT_RESULTS_1"
    rd.mkdir()
    (clone / "benchmark_scan.log").write_text("log")
    removed = scan.clean_prior_results(str(clone))
    assert "a_VULNHUNT_RESULTS_1" in removed
    assert "benchmark_scan.log" in removed


def test_clean_prior_results_missing_dir(tmp_path):
    assert scan.clean_prior_results(str(tmp_path / "nope")) == []


def test_clean_prior_results_symlink_to_dir_no_crash(tmp_path):
    # CANON-34: an untrusted clone can plant a symlink named
    # *_VULNHUNT_RESULTS_* pointing at a directory. os.path.isdir follows the
    # link so the old code reached shutil.rmtree(symlink) -> OSError, aborting
    # the whole scan (DoS). Cleanup must remove the link (not its target)
    # without raising.
    target = tmp_path / "real_target_dir"
    target.mkdir()
    (target / "keep.txt").write_text("do not delete me")

    clone = tmp_path / "clone"
    clone.mkdir()
    link = clone / "evil_VULNHUNT_RESULTS_1"
    os.symlink(str(target), str(link))

    removed = scan.clean_prior_results(str(clone))  # must not raise
    assert not os.path.lexists(str(link)), "planted symlink was not removed"
    assert target.is_dir() and (target / "keep.txt").exists(), \
        "symlink target must be left intact (only the link is removed)"


def test_clean_incomplete_results_symlink_to_dir_no_crash(tmp_path):
    # CANON-34 companion: same DoS applies to clean_incomplete_results.
    target = tmp_path / "real_target_dir"
    target.mkdir()
    (target / "keep.txt").write_text("do not delete me")

    clone = tmp_path / "clone"
    clone.mkdir()
    link = clone / "evil_VULNHUNT_RESULTS_1"
    os.symlink(str(target), str(link))

    scan.clean_incomplete_results(str(clone))  # must not raise
    assert not os.path.lexists(str(link)), "planted symlink was not removed"
    assert target.is_dir() and (target / "keep.txt").exists(), \
        "symlink target must be left intact (only the link is removed)"


# --- log inspection ---

def test_is_rate_limit_failure_no_file():
    assert scan.is_rate_limit_failure(None) is False
    assert scan.is_rate_limit_failure("/does/not/exist") is False


def test_is_rate_limit_failure_true(tmp_path):
    log = tmp_path / "scan.log"
    log.write_text(json.dumps({"type": "result", "api_error_status": 429}) + "\n")
    assert scan.is_rate_limit_failure(str(log)) is True


def test_is_rate_limit_failure_false(tmp_path):
    log = tmp_path / "scan.log"
    log.write_text(
        "\n"
        + json.dumps({"type": "system"}) + "\n"
        + "not json\n"
        + json.dumps({"type": "result", "api_error_status": None}) + "\n"
    )
    assert scan.is_rate_limit_failure(str(log)) is False


def test_extract_cost_no_file():
    assert scan.extract_cost_from_log(None) == {}
    assert scan.extract_cost_from_log("/nope") == {}


def test_extract_cost_from_log(tmp_path):
    log = tmp_path / "scan.log"
    event = {
        "type": "result",
        "total_cost_usd": 1.25,
        "duration_api_ms": 4200,
        "num_turns": 7,
        "modelUsage": {
            "m1": {"inputTokens": 10, "outputTokens": 20,
                   "cacheReadInputTokens": 5, "cacheCreationInputTokens": 3},
            "m2": {"inputTokens": 1, "outputTokens": 2},
        },
    }
    log.write_text("junk\n" + json.dumps(event) + "\n")
    cost = scan.extract_cost_from_log(str(log))
    assert cost["total_cost_usd"] == 1.25
    assert cost["input_tokens"] == 11
    assert cost["output_tokens"] == 22
    assert cost["cache_read_tokens"] == 5
    assert cost["num_turns"] == 7


def test_extract_cost_no_result_event(tmp_path):
    log = tmp_path / "scan.log"
    log.write_text(json.dumps({"type": "system"}) + "\n")
    assert scan.extract_cost_from_log(str(log)) == {}


def test_ts_format():
    out = scan.ts()
    assert len(out) == 8 and out.count(":") == 2


# --- scan_folder ---

def test_scan_folder_skill_not_installed(monkeypatch, tmp_path):
    monkeypatch.setattr(scan.os.path, "isdir", lambda p: False)
    result = scan.scan_folder(str(tmp_path / "repo"))
    assert result.returncode == 1
    assert result.results_dir is None


class _FakePopen:
    def __init__(self, lines, returncode=0):
        self.stdout = iter(lines)
        self.stderr = iter([])
        self.returncode = returncode
        self.killed = False

    def wait(self):
        return self.returncode

    def kill(self):
        self.killed = True


def test_scan_folder_success(monkeypatch, tmp_path):
    folder = tmp_path / "repo"
    folder.mkdir()
    # SKILLS_DIR must look installed; results dir found after scan.
    monkeypatch.setattr(scan, "SKILLS_DIR", str(tmp_path / "skills"))
    (tmp_path / "skills").mkdir()

    events = [json.dumps({"type": "system", "n": i}) for i in range(3)]
    events.append(json.dumps({"type": "result", "total_cost_usd": 0.5,
                              "modelUsage": {"m": {"inputTokens": 4, "outputTokens": 6}}}))
    lines = [e + "\n" for e in events] + ["\n", "not-json\n"]

    def fake_popen(*a, **k):
        return _FakePopen(lines, returncode=0)
    monkeypatch.setattr(scan.subprocess, "Popen", fake_popen)

    # avoid real timer thread firing
    class _NoTimer:
        def __init__(self, *a, **k):
            pass
        def start(self):
            pass
        def cancel(self):
            pass
    monkeypatch.setattr(scan.threading, "Timer", _NoTimer)

    rd = folder / "x_VULNHUNT_RESULTS_1"
    rd.mkdir()

    result = scan.scan_folder(str(folder))
    folder_path, label, returncode, event_count, elapsed, results_dir, cost = result
    assert returncode == 0
    assert event_count == 4
    assert results_dir == str(rd)
    assert cost["total_cost_usd"] == 0.5


def test_scan_folder_readonly_appends_prompt(monkeypatch, tmp_path):
    folder = tmp_path / "repo"
    folder.mkdir()
    monkeypatch.setattr(scan, "SKILLS_DIR", str(tmp_path / "skills"))
    (tmp_path / "skills").mkdir()

    captured = {}

    def fake_popen(cmd, *a, **k):
        captured["prompt"] = cmd[2]
        return _FakePopen([json.dumps({"type": "result"}) + "\n"], returncode=0)
    monkeypatch.setattr(scan.subprocess, "Popen", fake_popen)

    class _NoTimer:
        def __init__(self, *a, **k):
            pass
        def start(self):
            pass
        def cancel(self):
            pass
    monkeypatch.setattr(scan.threading, "Timer", _NoTimer)

    scan.scan_folder(str(folder), readonly=True)
    assert "read-only scan" in captured["prompt"]

    scan.scan_folder(str(folder), readonly=False)
    assert "read-only scan" not in captured["prompt"]


def test_scan_folder_timeout(monkeypatch, tmp_path):
    folder = tmp_path / "repo"
    folder.mkdir()
    monkeypatch.setattr(scan, "SKILLS_DIR", str(tmp_path / "skills"))
    (tmp_path / "skills").mkdir()

    proc_holder = {}

    def fake_popen(*a, **k):
        p = _FakePopen([json.dumps({"type": "system"}) + "\n"], returncode=-9)
        proc_holder["p"] = p
        return p
    monkeypatch.setattr(scan.subprocess, "Popen", fake_popen)

    # Timer that fires immediately on start to simulate a timeout kill.
    class _FireTimer:
        def __init__(self, interval, fn):
            self.fn = fn
        def start(self):
            self.fn()
        def cancel(self):
            pass
    monkeypatch.setattr(scan.threading, "Timer", _FireTimer)

    result = scan.scan_folder(str(folder))
    assert proc_holder["p"].killed is True
    assert result.cost_data == {}  # cost empty on timeout


def test_scan_folder_timeout_with_valid_results_not_discarded(monkeypatch, tmp_path):
    # A scan that finishes exactly as the timer fires still produced valid
    # results; scan_folder must not discard them as a timeout.
    folder = tmp_path / "repo"
    folder.mkdir()
    monkeypatch.setattr(scan, "SKILLS_DIR", str(tmp_path / "skills"))
    (tmp_path / "skills").mkdir()

    rd = folder / "x_VULNHUNT_RESULTS_1"
    rd.mkdir()
    (rd / "README.md").write_text("x" * 200)

    events = [json.dumps({"type": "result", "total_cost_usd": 0.9,
                          "modelUsage": {"m": {"inputTokens": 1, "outputTokens": 1}}}) + "\n"]

    def fake_popen(*a, **k):
        return _FakePopen(events, returncode=0)
    monkeypatch.setattr(scan.subprocess, "Popen", fake_popen)

    class _FireTimer:
        def __init__(self, interval, fn):
            self.fn = fn
        def start(self):
            self.fn()  # fire immediately -> sets timed_out True
        def cancel(self):
            pass
    monkeypatch.setattr(scan.threading, "Timer", _FireTimer)

    result = scan.scan_folder(str(folder))
    assert result.results_dir == str(rd)
    assert result.cost_data["total_cost_usd"] == 0.9  # not discarded


# --- retry wrapper ---

def test_scan_folder_with_retry_success_first_try(monkeypatch, tmp_path):
    folder = str(tmp_path / "repo")
    monkeypatch.setattr(scan, "scan_folder",
                        lambda fp, log_file=None, readonly=False: scan.ScanResult(fp, "repo", 0, 3, 1.0, "rd", {"total_cost_usd": 1}))
    monkeypatch.setattr(scan, "is_rate_limit_failure", lambda p: False)
    result = scan.scan_folder_with_retry(folder)
    assert result.returncode == 0


def test_scan_folder_with_retry_429_then_success(monkeypatch, tmp_path):
    folder = str(tmp_path / "repo")
    calls = {"n": 0}

    def fake_scan(fp, log_file=None, readonly=False):
        calls["n"] += 1
        if calls["n"] == 1:
            return scan.ScanResult(fp, "repo", 1, 0, 0.5, None, {})
        return scan.ScanResult(fp, "repo", 0, 5, 1.0, "rd", {})

    monkeypatch.setattr(scan, "scan_folder", fake_scan)
    monkeypatch.setattr(scan, "is_rate_limit_failure", lambda p: calls["n"] == 1)
    monkeypatch.setattr(scan, "clean_prior_results", lambda *a, **k: [])
    monkeypatch.setattr(scan.time, "sleep", lambda s: None)
    result = scan.scan_folder_with_retry(folder, log_filename="x.log")
    assert result.returncode == 0
    assert result.elapsed == 1.5  # elapsed summed across attempts
    assert calls["n"] == 2


def test_scan_folder_with_retry_429_exhausted(monkeypatch, tmp_path):
    folder = str(tmp_path / "repo")
    monkeypatch.setattr(scan, "scan_folder",
                        lambda fp, log_file=None, readonly=False: scan.ScanResult(fp, "repo", 1, 0, 0.5, None, {}))
    monkeypatch.setattr(scan, "is_rate_limit_failure", lambda p: True)
    monkeypatch.setattr(scan, "clean_prior_results", lambda *a, **k: ["r"])
    monkeypatch.setattr(scan.time, "sleep", lambda s: None)
    monkeypatch.setattr(scan, "SCAN_MAX_RETRIES", 2)
    result = scan.scan_folder_with_retry(folder)
    assert result.returncode == 1


# --- scan_targets ---

def test_scan_targets_collects_results(monkeypatch):
    targets = [{"clone_dir": "/c/a", "key": "a"}, {"clone_dir": "/c/b", "key": "b"}]
    monkeypatch.setattr(scan, "scan_folder_with_retry",
                        lambda cd, log_filename=None: (cd, "lbl", 0, 1, 1.0, "rd", {}))
    results = scan.scan_targets(targets, max_workers=2, status_interval=10_000)
    keys = {k for k, _ in results}
    assert keys == {"a", "b"}


def test_scan_targets_exception_path(monkeypatch):
    targets = [{"clone_dir": "/c/a", "key": "a"}]

    def boom(cd, log_filename=None):
        raise RuntimeError("kaboom")
    monkeypatch.setattr(scan, "scan_folder_with_retry", boom)
    # status_interval=0 forces the periodic status print branch.
    results = scan.scan_targets(targets, max_workers=1, status_interval=0)
    assert results[0][0] == "a"
    assert results[0][1].returncode == -1  # returncode sentinel


def test_scan_targets_default_workers(monkeypatch):
    monkeypatch.setattr(scan, "scan_folder_with_retry",
                        lambda cd, log_filename=None: (cd, "lbl", 0, 1, 1.0, "rd", {}))
    results = scan.scan_targets([{"clone_dir": "/c/a", "key": "a"}], status_interval=10_000)
    assert len(results) == 1
