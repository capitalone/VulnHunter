"""Tests for local_harness.benchmark.judge."""

import subprocess
import types

import local_harness.benchmark.judge as judge


def _proc(returncode=0, stdout="", stderr=""):
    return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


FINDINGS = [
    {"finding_id": "F1", "type": "SQLi", "description": "sqli in login"},
    {"finding_id": "F2", "type": "XSS", "description": "xss in search"},
]


def test_read_results_report_missing(tmp_path):
    assert judge.read_results_report(str(tmp_path)) is None


def test_read_results_report(tmp_path):
    (tmp_path / "README.md").write_text("hello report")
    assert judge.read_results_report(str(tmp_path)) == "hello report"


def test_is_judge_rate_limited():
    assert judge._is_judge_rate_limited(_proc(1, stderr="429 rate_limit exceeded")) is True
    assert judge._is_judge_rate_limited(_proc(1, stdout="HTTP 429 rate limit")) is True
    assert judge._is_judge_rate_limited(_proc(1, stderr="500 server error")) is False


def test_parse_judge_output_valid():
    raw = '[{"finding_id": "F1", "detected": true}]'
    out = judge._parse_judge_output(raw, FINDINGS)
    assert out[0]["finding_id"] == "F1"


def test_parse_judge_output_surrounding_text():
    raw = 'Here you go:\n[{"finding_id":"F1","detected":false}]\nThanks!'
    out = judge._parse_judge_output(raw, FINDINGS)
    assert out[0]["detected"] is False


def test_parse_judge_output_invalid():
    out = judge._parse_judge_output("not json at all", FINDINGS)
    assert len(out) == 2
    assert all(j["detected"] is None for j in out)


def test_parse_judge_output_non_list_json():
    out = judge._parse_judge_output('{"finding_id": "F1"}', FINDINGS)
    assert all(j["detected"] is None for j in out)


def test_judge_findings_batch_success(monkeypatch):
    monkeypatch.setattr(judge.subprocess, "run",
                        lambda *a, **k: _proc(0, stdout='[{"finding_id":"F1","detected":true},{"finding_id":"F2","detected":false}]'))
    out = judge.judge_findings_batch("report", FINDINGS, model="m")
    assert out[0]["detected"] is True
    assert out[1]["detected"] is False


def test_judge_findings_batch_default_model(monkeypatch):
    captured = {}

    def fake_run(cmd, **k):
        captured["cmd"] = cmd
        return _proc(0, stdout="[]")
    monkeypatch.setattr(judge.subprocess, "run", fake_run)
    judge.judge_findings_batch("report", FINDINGS)
    assert judge.MODEL in captured["cmd"]


def test_judge_findings_batch_timeout(monkeypatch):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="claude", timeout=1)
    monkeypatch.setattr(judge.subprocess, "run", boom)
    out = judge.judge_findings_batch("report", FINDINGS)
    assert all(j["reasoning"] == "judge timed out" for j in out)


def test_judge_findings_batch_nonzero_non429(monkeypatch):
    monkeypatch.setattr(judge.subprocess, "run",
                        lambda *a, **k: _proc(2, stderr="boom error"))
    out = judge.judge_findings_batch("report", FINDINGS)
    assert all("judge failed" in j["reasoning"] for j in out)


def test_judge_findings_batch_429_then_success(monkeypatch):
    calls = {"n": 0}

    def fake_run(*a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            return _proc(1, stderr="429 rate_limit")
        return _proc(0, stdout='[{"finding_id":"F1","detected":true},{"finding_id":"F2","detected":true}]')
    monkeypatch.setattr(judge.subprocess, "run", fake_run)
    monkeypatch.setattr(judge.time, "sleep", lambda s: None)
    out = judge.judge_findings_batch("report", FINDINGS)
    assert calls["n"] == 2
    assert out[0]["detected"] is True


def test_judge_findings_batch_429_exhausted(monkeypatch):
    # On the final attempt the 429 branch returns the specific
    # retries-exhausted message rather than the generic failure text.
    monkeypatch.setattr(judge.subprocess, "run",
                        lambda *a, **k: _proc(1, stderr="429 rate_limit"))
    monkeypatch.setattr(judge.time, "sleep", lambda s: None)
    monkeypatch.setattr(judge, "JUDGE_MAX_RETRIES", 1)
    out = judge.judge_findings_batch("report", FINDINGS)
    assert all("retries exhausted" in j["reasoning"] for j in out)
