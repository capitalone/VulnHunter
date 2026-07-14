"""Tests for local_harness.benchmark.run."""

import json

import pytest

import local_harness.benchmark.run as run
from local_harness.scan import ScanResult


BENCH_JSON = [
    {"finding_id": "F1", "type": "SQLi", "description": "sqli",
     "source_code": "https://github.com/acme/widget/tree/abcdef1234567890"},
    {"finding_id": "F2", "type": "XSS", "description": "xss",
     "source_code": "https://github.com/acme/widget/tree/abcdef1234567890"},
    {"finding_id": "F3", "type": "IDOR", "description": "idor",
     "source_code": "https://github.com/acme/other/tree/99998888aaaabbbb"},
]


def _write_bench(monkeypatch, tmp_path):
    bdir = tmp_path / "gt"
    bdir.mkdir()
    (bdir / "widget.json").write_text(json.dumps(BENCH_JSON[:2]))
    (bdir / "other.json").write_text(json.dumps(BENCH_JSON[2:]))
    monkeypatch.setattr(run, "BENCHMARK_DIR", str(bdir))
    monkeypatch.setattr(run, "CLONE_BASE_DIR", str(tmp_path / "repos"))
    return bdir


def test_load_all_benchmarks(monkeypatch, tmp_path):
    _write_bench(monkeypatch, tmp_path)
    benches = run.load_all_benchmarks()
    assert len(benches) == 2
    # sorted alphabetically: other.json, widget.json
    names = [n for n, _ in benches]
    assert names == ["other.json", "widget.json"]
    _, widget_findings = benches[1]
    assert widget_findings[0]["_repo_name"] == "widget"
    assert widget_findings[0]["_commit_hash"] == "abcdef1234567890"


def test_deduplicate_targets(monkeypatch, tmp_path):
    _write_bench(monkeypatch, tmp_path)
    benches = run.load_all_benchmarks()
    targets = run.deduplicate_targets(benches)
    assert len(targets) == 2  # widget (2 findings), other (1 finding)
    widget_key = run.target_dir_name("widget", "abcdef1234567890")
    assert len(targets[widget_key]["findings"]) == 2


def test_load_and_save_state(monkeypatch, tmp_path):
    state_file = tmp_path / "state.json"
    monkeypatch.setattr(run, "STATE_FILE", str(state_file))
    monkeypatch.setattr(run, "MODEL", "m")
    # missing -> defaults
    st = run.load_state()
    assert st["scan_targets"] == {} and st["judgments"] == {}
    st["judgments"]["F1"] = {"detected": True}
    run.save_state(st)
    assert run.load_state()["judgments"]["F1"]["detected"] is True


def test_load_state_corrupt_starts_fresh(monkeypatch, tmp_path):
    state_file = tmp_path / "state.json"
    state_file.write_text("{ this is not json")
    monkeypatch.setattr(run, "STATE_FILE", str(state_file))
    monkeypatch.setattr(run, "MODEL", "m")
    st = run.load_state()
    assert st == {"scan_targets": {}, "judgments": {}, "model": "m"}


def test_filter_targets_by_findings():
    targets = {
        "t1": {"key": "t1", "findings": [{"finding_id": "F1"}, {"finding_id": "F2"}]},
        "t2": {"key": "t2", "findings": [{"finding_id": "F3"}]},
    }
    filtered = run.filter_targets_by_findings(targets, {"F2"})
    assert set(filtered) == {"t1"}
    assert len(filtered["t1"]["findings"]) == 1


def test_phase_clone(monkeypatch, tmp_path):
    monkeypatch.setattr(run, "STATE_FILE", str(tmp_path / "state.json"))
    calls = {"n": 0}

    def fake_clone(url, commit, target):
        calls["n"] += 1
        if calls["n"] == 1:
            return (target, None)  # success
        return (target, "clone error")  # failure

    monkeypatch.setattr(run, "clone_at_commit", fake_clone)
    targets = {
        "t1": {"key": "t1", "repo_url": "u1", "commit_hash": "c1", "clone_dir": "/c/t1"},
        "t2": {"key": "t2", "repo_url": "u2", "commit_hash": "c2", "clone_dir": "/c/t2"},
    }
    state = {"scan_targets": {}, "judgments": {}}
    run.phase_clone(targets, state)
    assert state["scan_targets"]["t1"]["status"] == "cloned"
    assert state["scan_targets"]["t2"]["status"] == "clone_failed"


def test_phase_clone_skips_already_cloned(monkeypatch, tmp_path):
    monkeypatch.setattr(run, "STATE_FILE", str(tmp_path / "state.json"))
    clone_dir = tmp_path / "existing"
    clone_dir.mkdir()

    def fail(*a, **k):
        raise AssertionError("should not clone")
    monkeypatch.setattr(run, "clone_at_commit", fail)
    targets = {"t1": {"key": "t1", "repo_url": "u", "commit_hash": "c",
                      "clone_dir": str(clone_dir)}}
    state = {"scan_targets": {"t1": {"status": "cloned"}}, "judgments": {}}
    run.phase_clone(targets, state)  # must not raise


def test_phase_scan_all_skipped(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(run, "STATE_FILE", str(tmp_path / "state.json"))
    rd = tmp_path / "rd"
    rd.mkdir()
    targets = {"t1": {"key": "t1", "clone_dir": str(tmp_path), "findings": []}}
    state = {"scan_targets": {"t1": {"status": "scanned", "results_dir": str(rd)}},
             "judgments": {}}
    run.phase_scan(targets, state)
    assert "already scanned" in capsys.readouterr().out


def test_phase_scan_runs(monkeypatch, tmp_path):
    monkeypatch.setattr(run, "STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setattr(run, "clean_prior_results", lambda cd: [])
    monkeypatch.setattr(run, "has_valid_results", lambda cd: False)

    def fake_scan_targets(to_scan, max_workers=None):
        return [("t1", ScanResult("/c/t1", "t1", 0, 5, 12.0, "/c/t1/rd", {"total_cost_usd": 1.0})),
                ("t2", ScanResult("/c/t2", "t2", 1, 0, 3.0, None, {}))]
    monkeypatch.setattr(run, "scan_targets", fake_scan_targets)

    targets = {
        "t1": {"key": "t1", "clone_dir": "/c/t1", "findings": [{"finding_id": "F1"}]},
        "t2": {"key": "t2", "clone_dir": "/c/t2", "findings": [{"finding_id": "F2"}]},
    }
    state = {"scan_targets": {"t1": {"status": "cloned"}, "t2": {"status": "cloned"}},
             "judgments": {"F1": {}, "F2": {}}}
    run.phase_scan(targets, state, force_rescan=True)
    assert state["scan_targets"]["t1"]["status"] == "scanned"
    assert state["scan_targets"]["t2"]["status"] == "scan_failed"


def test_phase_scan_adopts_existing_results(monkeypatch, tmp_path):
    monkeypatch.setattr(run, "STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setattr(run, "has_valid_results", lambda cd: True)
    monkeypatch.setattr(run, "find_results_dir", lambda cd: "/c/t1/rd")

    def fail_scan(*a, **k):
        raise AssertionError("should not scan")
    monkeypatch.setattr(run, "scan_targets", fail_scan)
    targets = {"t1": {"key": "t1", "clone_dir": "/c/t1", "findings": []}}
    state = {"scan_targets": {"t1": {"status": "cloned"}}, "judgments": {}}
    run.phase_scan(targets, state)
    assert state["scan_targets"]["t1"]["results_dir"] == "/c/t1/rd"


def test_phase_judge(monkeypatch, tmp_path):
    monkeypatch.setattr(run, "STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setattr(run, "read_results_report", lambda rd: "the report")
    monkeypatch.setattr(run, "judge_findings_batch",
                        lambda report, findings: [
                            {"finding_id": "F1", "detected": True, "confidence": "high",
                             "reasoning": "yes", "matched_finding_id": "S1"}])
    targets = {"t1": {"key": "t1", "repo_name": "repo", "commit_hash": "c",
                      "findings": [{"finding_id": "F1", "type": "SQLi",
                                    "benchmark_file": "a.json"}]}}
    state = {"scan_targets": {"t1": {"status": "scanned", "results_dir": "/rd"}},
             "judgments": {}}
    run.phase_judge(targets, state)
    assert state["judgments"]["F1"]["detected"] is True


def test_phase_judge_scan_unavailable(monkeypatch, tmp_path):
    monkeypatch.setattr(run, "STATE_FILE", str(tmp_path / "state.json"))
    targets = {"t1": {"key": "t1", "repo_name": "repo", "commit_hash": "c",
                      "findings": [{"finding_id": "F1", "type": "SQLi",
                                    "benchmark_file": "a.json"}]}}
    state = {"scan_targets": {"t1": {"status": "scan_failed"}}, "judgments": {}}
    run.phase_judge(targets, state)
    assert state["judgments"]["F1"]["detected"] is None
    assert "scan not available" in state["judgments"]["F1"]["reasoning"]


def test_phase_judge_no_report(monkeypatch, tmp_path):
    monkeypatch.setattr(run, "STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setattr(run, "read_results_report", lambda rd: None)
    targets = {"t1": {"key": "t1", "repo_name": "repo", "commit_hash": "c",
                      "findings": [{"finding_id": "F1", "type": "SQLi",
                                    "benchmark_file": "a.json"}]}}
    state = {"scan_targets": {"t1": {"status": "scanned", "results_dir": "/rd"}},
             "judgments": {}}
    run.phase_judge(targets, state)
    assert "no README.md" in state["judgments"]["F1"]["reasoning"]


def test_phase_judge_skips_existing(monkeypatch, tmp_path):
    monkeypatch.setattr(run, "STATE_FILE", str(tmp_path / "state.json"))

    def fail(*a, **k):
        raise AssertionError("should not judge")
    monkeypatch.setattr(run, "judge_findings_batch", fail)
    targets = {"t1": {"key": "t1", "repo_name": "repo", "commit_hash": "c",
                      "findings": [{"finding_id": "F1", "type": "SQLi",
                                    "benchmark_file": "a.json"}]}}
    state = {"scan_targets": {"t1": {"status": "scanned", "results_dir": "/rd"}},
             "judgments": {"F1": {"detected": True}}}
    run.phase_judge(targets, state)  # F1 already judged, no rejudge


def test_phase_tally(monkeypatch, tmp_path):
    monkeypatch.setattr(run, "extract_cost_from_log", lambda p: {"total_cost_usd": 3.0})
    written = {}
    monkeypatch.setattr(run, "generate_tally", lambda st: {"t": 1})
    monkeypatch.setattr(run, "write_tally_json", lambda t: written.setdefault("json", t))
    monkeypatch.setattr(run, "write_tally_markdown", lambda t: written.setdefault("md", t))
    monkeypatch.setattr(run, "print_summary", lambda t: None)
    monkeypatch.setattr(run, "save_state", lambda st: None)
    state = {"scan_targets": {"t1": {"clone_dir": str(tmp_path)}}}
    run.phase_tally(state)
    # cost backfilled
    assert state["scan_targets"]["t1"]["scan_total_cost_usd"] == 3.0
    assert written["json"] == {"t": 1}


def _setup_main(monkeypatch, tmp_path):
    _write_bench(monkeypatch, tmp_path)
    monkeypatch.setattr(run, "STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setattr(run, "MODEL", "m")
    monkeypatch.setattr(run, "phase_clone", lambda t, s: None)
    monkeypatch.setattr(run, "phase_scan", lambda t, s, force_rescan=False, max_workers=5: None)
    monkeypatch.setattr(run, "phase_judge", lambda t, s, force_rejudge=False: None)
    monkeypatch.setattr(run, "phase_tally", lambda s: None)
    monkeypatch.setattr(run, "update_history", lambda s, t: (1, 0))


def test_main_full(monkeypatch, tmp_path):
    _setup_main(monkeypatch, tmp_path)
    monkeypatch.setattr(run.sys, "argv", ["run"])
    run.main()


def test_main_tally_only(monkeypatch, tmp_path):
    _setup_main(monkeypatch, tmp_path)
    called = {}
    monkeypatch.setattr(run, "phase_tally", lambda s: called.setdefault("tally", True))
    monkeypatch.setattr(run.sys, "argv", ["run", "--tally-only"])
    run.main()
    assert called["tally"]


def test_main_scan_only(monkeypatch, tmp_path):
    _setup_main(monkeypatch, tmp_path)
    monkeypatch.setattr(run, "save_state", lambda s: None)
    monkeypatch.setattr(run.sys, "argv", ["run", "--scan-only"])
    run.main()


def test_main_repos_filter_no_match(monkeypatch, tmp_path):
    _setup_main(monkeypatch, tmp_path)
    monkeypatch.setattr(run.sys, "argv", ["run", "--repos", "zzzznope"])
    with pytest.raises(SystemExit):
        run.main()


def test_main_findings_filter(monkeypatch, tmp_path):
    _setup_main(monkeypatch, tmp_path)
    monkeypatch.setattr(run.sys, "argv", ["run", "--findings", "F1"])
    run.main()


def test_main_findings_unknown(monkeypatch, tmp_path):
    _setup_main(monkeypatch, tmp_path)
    monkeypatch.setattr(run.sys, "argv", ["run", "--findings", "NOPE999"])
    with pytest.raises(SystemExit):
        run.main()


def test_main_skip_stable_all_stable(monkeypatch, tmp_path):
    _setup_main(monkeypatch, tmp_path)
    monkeypatch.setattr(run, "get_stable_findings", lambda threshold=3: {"F1", "F2", "F3"})
    monkeypatch.setattr(run.sys, "argv", ["run", "--skip-stable"])
    run.main()  # returns early, "nothing to run"


def test_main_no_benchmarks(monkeypatch, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setattr(run, "BENCHMARK_DIR", str(empty))
    monkeypatch.setattr(run.sys, "argv", ["run"])
    with pytest.raises(SystemExit):
        run.main()
