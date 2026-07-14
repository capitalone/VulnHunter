"""Tests for local_harness.benchmark.tally."""

import json

import local_harness.benchmark.tally as tally


def _sample_state():
    return {
        "model": "test-model",
        "judgments": {
            "F1": {"detected": True, "type": "SQLi", "benchmark_file": "a.json",
                   "repo_name": "repo", "commit_hash": "abcdef123456",
                   "confidence": "high", "reasoning": "found", "matched_finding_id": "S1"},
            "F2": {"detected": False, "type": "XSS", "benchmark_file": "a.json",
                   "repo_name": "repo", "commit_hash": "abcdef123456",
                   "confidence": "low", "reasoning": "missed it", "matched_finding_id": None},
            "F3": {"detected": None, "type": "SQLi", "benchmark_file": "b.json",
                   "repo_name": "repo2", "commit_hash": "",
                   "confidence": None, "reasoning": "error", "matched_finding_id": None},
        },
        "scan_targets": {
            "t1": {"status": "scanned", "scan_total_cost_usd": 2.0, "scan_elapsed_s": 120,
                   "scan_input_tokens": 100, "scan_output_tokens": 50,
                   "scan_cache_read_tokens": 10, "scan_cache_creation_tokens": 5,
                   "scan_num_turns": 8},
            "t2": {"status": "scan_failed"},
        },
    }


def test_fmt_duration():
    assert tally._fmt_duration(0) == "0s"
    assert tally._fmt_duration(None) == "0s"
    assert tally._fmt_duration(45) == "45s"
    assert tally._fmt_duration(125) == "2m 5s"
    assert tally._fmt_duration(3725) == "1h 2m"


def test_generate_tally():
    t = tally.generate_tally(_sample_state())
    s = t["summary"]
    assert s["total_findings"] == 3
    assert s["detected"] == 1
    assert s["missed"] == 1
    assert s["errors"] == 1
    assert s["scan_failures"] == 1
    assert s["by_type"]["SQLi"]["total"] == 2
    assert t["cost"]["total_cost_usd"] == 2.0
    assert t["cost"]["scans_counted"] == 1
    assert t["cost"]["avg_cost_per_scan_usd"] == 2.0


def test_generate_tally_empty():
    t = tally.generate_tally({})
    assert t["summary"]["total_findings"] == 0
    assert t["summary"]["detection_rate"] == 0.0
    assert t["cost"]["avg_cost_per_scan_usd"] == 0


def test_write_tally_json(monkeypatch, tmp_path):
    out = tmp_path / "tally.json"
    monkeypatch.setattr(tally, "RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(tally, "TALLY_FILE", str(out))
    t = tally.generate_tally(_sample_state())
    tally.write_tally_json(t)
    assert json.loads(out.read_text())["summary"]["total_findings"] == 3


def test_write_tally_markdown(monkeypatch, tmp_path):
    out = tmp_path / "report.md"
    monkeypatch.setattr(tally, "RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(tally, "TALLY_REPORT", str(out))
    t = tally.generate_tally(_sample_state())
    tally.write_tally_markdown(t)
    text = out.read_text()
    assert "VulnHunter Benchmark Report" in text
    assert "Missed Findings" in text
    assert "Cost & Performance" in text
    assert "Per-Scan Breakdown" in text


def test_write_tally_markdown_no_cost(monkeypatch, tmp_path):
    out = tmp_path / "report.md"
    monkeypatch.setattr(tally, "RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(tally, "TALLY_REPORT", str(out))
    state = {"model": "m", "judgments": {
        "F1": {"detected": True, "type": "SQLi", "benchmark_file": "a.json"}},
        "scan_targets": {}}
    t = tally.generate_tally(state)
    tally.write_tally_markdown(t)
    text = out.read_text()
    assert "Cost & Performance" not in text
    assert "Missed Findings" not in text


def test_print_summary(capsys):
    t = tally.generate_tally(_sample_state())
    tally.print_summary(t)
    out = capsys.readouterr().out
    assert "BENCHMARK RESULTS" in out
    assert "COST & PERFORMANCE" in out
    assert "analyze_misses" in out


def test_print_summary_no_cost_no_miss(capsys):
    state = {"model": "m", "judgments": {
        "F1": {"detected": True, "type": "SQLi", "benchmark_file": "a.json"}},
        "scan_targets": {}}
    t = tally.generate_tally(state)
    tally.print_summary(t)
    out = capsys.readouterr().out
    assert "COST & PERFORMANCE" not in out
    assert "analyze_misses" not in out
