"""Tests for local_harness.benchmark.analyze_misses."""

import json
import subprocess
import types

import pytest

import local_harness.benchmark.analyze_misses as am


def _proc(returncode=0, stdout="", stderr=""):
    return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def test_extract_identifiers():
    desc = ("The endpoint /api/users/{id} in handler getUser calls "
            "queryDatabase() in src/db/users.py without validation")
    ids = am.extract_identifiers(desc)
    assert any(i.endswith("users.py") for i in ids)
    assert "/api/users/{id}" in ids
    assert "getUser" in ids or "queryDatabase" in ids


def test_extract_identifiers_route():
    ids = am.extract_identifiers("POST /login handles auth")
    assert "/login" in ids


def test_extract_identifiers_ignores_prose_and_versions():
    # "e.g." and version strings must not be mistaken for file paths.
    ids = am.extract_identifiers("See e.g. the bug in version 1.2.3 of the app")
    assert "e.g." not in ids
    assert "1.2.3" not in ids


def test_extract_identifiers_keeps_bare_code_filename():
    ids = am.extract_identifiers("the bug is in users.py somewhere")
    assert "users.py" in ids


def test_search_word_boundary(tmp_path):
    # a plain identifier must match on a word boundary, not as a substring
    f = tmp_path / "code.py"
    f.write_text("value = getUserProfile()\nvalue2 = getUser()\n")
    matches = am.search_file_for_identifiers(str(f), ["getUser"], context_lines=0)
    assert matches[0]["line"] == 2  # skips getUserProfile on line 1


def test_search_file_for_identifiers_missing(tmp_path):
    assert am.search_file_for_identifiers(str(tmp_path / "nope"), ["x"]) == []


def test_search_file_for_identifiers(tmp_path):
    f = tmp_path / "code.py"
    f.write_text("line one\ndef getUser():\n    pass\nother\n")
    matches = am.search_file_for_identifiers(str(f), ["getUser"], context_lines=1)
    assert matches[0]["identifier"] == "getUser"
    assert matches[0]["line"] == 2


def test_infer_class_from_filename():
    assert am._infer_class_from_filename("sg-1_inj_results.md") == "inj"
    assert am._infer_class_from_filename("sg-1_nav_results.md") == "nav"
    assert am._infer_class_from_filename("sg-1_log_results.md") == "log"
    assert am._infer_class_from_filename("sink_driven_results.md") == "inj"
    assert am._infer_class_from_filename("mystery.md") == "nav"


def test_type_to_class():
    assert am._type_to_class("SQLi") == "inj"
    assert am._type_to_class("IDOR") == "nav"
    assert am._type_to_class("RaceCondition") == "log"
    assert am._type_to_class("Unknown") == "nav"


def test_locate_loss_phase_no_identifiers(tmp_path):
    phase, ev = am.locate_loss_phase(str(tmp_path), {"description": "!!!", "type": "SQLi"})
    assert phase == "unknown"


def test_locate_loss_phase_phase2b_reject(tmp_path):
    rd = tmp_path / "rd"
    rd.mkdir()
    (rd / "phase2b_output.md").write_text(
        "Candidate in src/app.py getUser was REJECTED as false positive\n")
    finding = {"description": "getUser in src/app.py", "type": "SQLi"}
    phase, ev = am.locate_loss_phase(str(rd), finding)
    assert phase == "phase2b"


def test_locate_loss_phase_phase2_non_candidate(tmp_path):
    rd = tmp_path / "rd"
    rd.mkdir()
    (rd / "phase2b_output.md").write_text("nothing relevant here\n")
    results = rd / "results"
    results.mkdir()
    (results / "sg-1_inj_results.md").write_text(
        "Traced getUser in src/app.py -> disposition SAFE\n")
    finding = {"description": "getUser in src/app.py", "type": "SQLi"}
    phase, ev = am.locate_loss_phase(str(rd), finding)
    assert phase == "phase2_inj"


def test_locate_loss_phase_phase1_missing(tmp_path):
    rd = tmp_path / "rd"
    rd.mkdir()
    finding = {"description": "getUser in src/app.py", "type": "SQLi"}
    phase, ev = am.locate_loss_phase(str(rd), finding)
    assert phase == "phase1"


def test_locate_loss_phase_dispatch_loss(tmp_path):
    rd = tmp_path / "rd"
    rd.mkdir()
    (rd / "phase1_output.md").write_text("Enumerated getUser in src/app.py endpoint\n")
    finding = {"description": "getUser in src/app.py", "type": "IDOR"}
    phase, ev = am.locate_loss_phase(str(rd), finding)
    assert phase == "phase2_nav"  # IDOR -> nav
    assert "enumerated in phase1" in ev.lower()


def test_build_diagnostic_prompt(monkeypatch, tmp_path):
    monkeypatch.setattr(am, "BENCHMARK_DIR", str(tmp_path))
    monkeypatch.setattr(am, "REPO_ROOT", str(tmp_path))
    (tmp_path / "myrepo.json").write_text("[]")
    finding = {"finding_id": "F1", "type": "SQLi", "description": "d", "repo_name": "myrepo"}
    prompt = am.build_diagnostic_prompt(finding, "phase1", "evidence", "/rd", "/repo")
    assert "F1" in prompt
    assert "myrepo.json" in prompt


def test_parse_diagnostic_output_valid():
    raw = 'text {"root_cause": "x", "prompt_file": "p"} trailer'
    out = am._parse_diagnostic_output(raw)
    assert out["root_cause"] == "x"


def test_parse_diagnostic_output_invalid():
    out = am._parse_diagnostic_output("no json here")
    assert out["root_cause"].startswith("failed to parse")


def test_invoke_diagnostic_success(monkeypatch):
    monkeypatch.setattr(am.subprocess, "run",
                        lambda *a, **k: _proc(0, stdout='{"root_cause":"rc"}'))
    finding = {"finding_id": "F1", "type": "SQLi", "description": "d", "repo_name": "r"}
    out = am.invoke_diagnostic(finding, "phase1", "ev", "/rd", "/repo")
    assert out["root_cause"] == "rc"


def test_invoke_diagnostic_timeout(monkeypatch):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="claude", timeout=1)
    monkeypatch.setattr(am.subprocess, "run", boom)
    finding = {"finding_id": "F1", "type": "SQLi", "description": "d", "repo_name": "r"}
    out = am.invoke_diagnostic(finding, "phase1", "ev", "/rd", "/repo")
    assert out["root_cause"] == "diagnostic timed out"


def test_invoke_diagnostic_nonzero(monkeypatch):
    monkeypatch.setattr(am.subprocess, "run",
                        lambda *a, **k: _proc(3, stderr="boom"))
    finding = {"finding_id": "F1", "type": "SQLi", "description": "d", "repo_name": "r"}
    out = am.invoke_diagnostic(finding, "phase1", "ev", "/rd", "/repo")
    assert "diagnostic failed" in out["root_cause"]


def test_write_analysis_json_and_report(monkeypatch, tmp_path):
    monkeypatch.setattr(am, "RESULTS_DIR", str(tmp_path))
    json_out = tmp_path / "miss.json"
    md_out = tmp_path / "miss.md"
    monkeypatch.setattr(am, "ANALYSIS_JSON", str(json_out))
    monkeypatch.setattr(am, "ANALYSIS_REPORT", str(md_out))
    analyses = [{
        "finding_id": "F1", "type": "SQLi", "repo_name": "repo",
        "loss_phase": "phase1", "evidence": "ev",
        "diagnostic": {"root_cause": "rc", "prompt_file": "p",
                       "section_to_change": "s", "suggested_change": "c",
                       "change_type": "add", "false_positive_risk": "low",
                       "risk_explanation": "none"},
    }]
    am.write_analysis_json(analyses)
    am.write_analysis_report(analyses)
    assert json.loads(json_out.read_text())[0]["finding_id"] == "F1"
    assert "False Negative Analysis" in md_out.read_text()


def test_get_finding_description(monkeypatch, tmp_path):
    monkeypatch.setattr(am, "BENCHMARK_DIR", str(tmp_path))
    (tmp_path / "r.json").write_text(json.dumps(
        [{"finding_id": "F1", "description": "the desc"}]))
    assert am._get_finding_description("F1", {}) == "the desc"
    assert am._get_finding_description("MISSING", {}) == ""


def _state_file(tmp_path, judgments, scan_targets=None):
    sf = tmp_path / "state.json"
    sf.write_text(json.dumps({"judgments": judgments,
                              "scan_targets": scan_targets or {}}))
    return str(sf)


def test_main_state_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(am.sys, "argv", ["am", "--state-file", str(tmp_path / "nope.json")])
    with pytest.raises(SystemExit):
        am.main()


def test_main_no_misses(monkeypatch, tmp_path):
    sf = _state_file(tmp_path, {"F1": {"detected": True}})
    monkeypatch.setattr(am.sys, "argv", ["am", "--state-file", sf])
    with pytest.raises(SystemExit):
        am.main()


def test_main_specific_finding_not_a_miss(monkeypatch, tmp_path):
    sf = _state_file(tmp_path, {"F1": {"detected": True}})
    monkeypatch.setattr(am.sys, "argv", ["am", "--state-file", sf, "--finding", "F1"])
    with pytest.raises(SystemExit):
        am.main()


def test_main_analyzes_miss(monkeypatch, tmp_path):
    rd = tmp_path / "rd"
    rd.mkdir()
    sf = _state_file(
        tmp_path,
        {"F1": {"detected": False, "type": "SQLi", "repo_name": "repo",
                "scan_target": "t1"}},
        {"t1": {"results_dir": str(rd)}},
    )
    monkeypatch.setattr(am, "RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(am, "ANALYSIS_JSON", str(tmp_path / "a.json"))
    monkeypatch.setattr(am, "ANALYSIS_REPORT", str(tmp_path / "a.md"))
    monkeypatch.setattr(am, "_get_finding_description", lambda fid, st: "desc")
    monkeypatch.setattr(am, "locate_loss_phase", lambda rd_, m: ("phase1", "ev"))
    monkeypatch.setattr(am, "invoke_diagnostic",
                        lambda *a, **k: {"root_cause": "rc", "false_positive_risk": "low"})
    monkeypatch.setattr(am.sys, "argv", ["am", "--state-file", sf, "--verbose"])
    am.main()
    assert json.loads((tmp_path / "a.json").read_text())[0]["finding_id"] == "F1"


def test_main_miss_no_results_dir(monkeypatch, tmp_path):
    sf = _state_file(
        tmp_path,
        {"F1": {"detected": False, "type": "SQLi", "repo_name": "repo",
                "scan_target": "t1"}},
        {"t1": {"results_dir": None}},
    )
    monkeypatch.setattr(am, "ANALYSIS_JSON", str(tmp_path / "a.json"))
    monkeypatch.setattr(am, "ANALYSIS_REPORT", str(tmp_path / "a.md"))
    monkeypatch.setattr(am, "RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(am, "_get_finding_description", lambda fid, st: "desc")
    monkeypatch.setattr(am.sys, "argv", ["am", "--state-file", sf])
    am.main()
    data = json.loads((tmp_path / "a.json").read_text())
    assert data[0]["loss_phase"] == "no_results"
