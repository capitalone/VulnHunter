"""Coverage tests for sweep-root-causes.py and validate-verification.py."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"


def _load(name: str, mod: str):
    spec = importlib.util.spec_from_file_location(mod, SCRIPTS / name)
    m = importlib.util.module_from_spec(spec)
    sys.modules[mod] = m
    spec.loader.exec_module(m)
    return m


@pytest.fixture(scope="module")
def sweep():
    return _load("sweep-root-causes.py", "sweep")


@pytest.fixture(scope="module")
def vv():
    return _load("validate-verification.py", "vv")


# =============================================================================
# sweep-root-causes.py
# =============================================================================

def test_sweep_cwe_int_valid(sweep):
    assert sweep._cwe_int("CWE-89") == 89


def test_sweep_cwe_int_invalid(sweep):
    assert sweep._cwe_int("CWE-xyz") is None
    assert sweep._cwe_int("") is None
    assert sweep._cwe_int(None) is None


def test_sweep_unquote_matching(sweep):
    assert sweep._unquote('"x"') == "x"
    assert sweep._unquote("'x'") == "x"
    assert sweep._unquote("no-quotes") == "no-quotes"


def test_sweep_strip_inline_comment(sweep):
    assert sweep._strip_inline_comment("value  # comment") == "value"
    assert sweep._strip_inline_comment("no-comment") == "no-comment"
    assert sweep._strip_inline_comment("") == ""


def test_sweep_load_patterns_from_file(sweep, tmp_path):
    md = tmp_path / "sweep-patterns.md"
    md.write_text(
        "# Sweep patterns\n\n"
        "```yaml\n"
        "class: injection\n"
        "cwes: [89]\n"
        "patterns:\n"
        "  - 'execute\\('\n"
        "  - \"query\\(.*%\"\n"
        "```\n\n"
        "```yaml\n"
        "class: crypto\n"
        "cwes: [327]\n"
        "patterns:\n"
        "  - 'md5'  # weak hash\n"
        "```\n",
        encoding="utf-8",
    )
    got = sweep._load_patterns(md)
    assert "injection" in got
    assert "execute\\(" in got["injection"]
    assert "query\\(.*%" in got["injection"]
    assert "md5" in got["crypto"]


def test_sweep_load_graph_valid(sweep, tmp_path):
    g = tmp_path / "graph.json"
    g.write_text('{"nodes": {}, "edges": []}', encoding="utf-8")
    assert sweep._load_graph(g) == {"nodes": {}, "edges": []}


def test_sweep_load_graph_missing(sweep, tmp_path):
    assert sweep._load_graph(tmp_path / "nope.json") is None


def test_sweep_load_graph_malformed(sweep, tmp_path):
    g = tmp_path / "graph.json"
    g.write_text("not-json{", encoding="utf-8")
    assert sweep._load_graph(g) is None


def test_sweep_load_results(sweep, tmp_path):
    r1 = tmp_path / "a_result.json"
    r1.write_text(json.dumps({"vuln_id": "VULN-1", "status": "VERIFIED_FULL"}), encoding="utf-8")
    r2 = tmp_path / "b_result.json"
    r2.write_text(json.dumps({"vuln_id": "VULN-2", "status": "FAILED"}), encoding="utf-8")  # skipped
    r3 = tmp_path / "c_result.json"
    r3.write_text("{bad", encoding="utf-8")  # skipped
    findings = sweep._load_results(tmp_path)
    assert len(findings) == 1
    assert findings[0]["vuln_id"] == "VULN-1"


def test_sweep_load_results_missing_dir(sweep, tmp_path):
    assert sweep._load_results(tmp_path / "nope") == []


def test_sweep_pass1_empty_inputs(sweep):
    assert sweep.pass1_symbol({}, "", []) == []
    assert sweep.pass1_symbol({"nodes": {}}, "", []) == []


def test_sweep_pass1_finds_siblings(sweep):
    graph = {
        "nodes": {
            "n1": {"name": "sink", "qualified_name": "src/x.py:sink", "file": "src/x.py"},
            "n2": {"name": "caller_a", "file": "src/a.py"},
            "n3": {"name": "caller_b", "file": "src/b.py"},
        },
        "edges": [
            {"from": "n2", "to": "n1", "kind": "calls"},
            {"from": "n3", "to": "n1", "kind": "calls"},
        ],
    }
    routed = ["src/a.py:caller_a"]
    siblings = sweep.pass1_symbol(graph, "src/x.py:sink", routed)
    assert siblings == ["src/b.py:caller_b"]


def test_sweep_pass1_sink_not_found(sweep):
    graph = {"nodes": {"n1": {"name": "other"}}, "edges": []}
    assert sweep.pass1_symbol(graph, "src/x.py:unknown", []) == []


def test_sweep_pass1_grep_backend_finds_siblings(sweep, tmp_path):
    """M3 (synthesized review S8): under grep backend the graph carries no
    call edges, so the edge hand-walk returned [] and silently missed every
    sibling defect. pass1_symbol must delegate to grep_callers_of so a
    grep-backed run still finds callers of the sink."""
    (tmp_path / "a.py").write_text("def caller_a():\n    return login('u')\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("def caller_b():\n    return login('v')\n", encoding="utf-8")
    graph = {"backend": "grep", "nodes": {}, "edges": []}
    siblings = sweep.pass1_symbol(graph, "auth.py:login", [], repo_root=tmp_path)
    assert siblings != [], "grep-backed sweep found no siblings (hand-walk fail-open)"
    assert any("caller_a" in s for s in siblings)
    assert any("caller_b" in s for s in siblings)


def test_sweep_pass1_grep_backend_respects_routed(sweep, tmp_path):
    """Routed callers must be excluded even on the grep path."""
    (tmp_path / "a.py").write_text("def caller_a():\n    return login('u')\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("def caller_b():\n    return login('v')\n", encoding="utf-8")
    graph = {"backend": "grep", "nodes": {}, "edges": []}
    siblings = sweep.pass1_symbol(graph, "auth.py:login", ["a.py:caller_a"], repo_root=tmp_path)
    assert not any("caller_a" in s for s in siblings)
    assert any("caller_b" in s for s in siblings)


# --- S4 (12-seg review): sweep downgrade + fail-closed --------------------

def _ast_graph_with_unrouted_sibling(tmp_path):
    """Graph where sink_fn has a caller (caller_bad) in a DIFFERENT file than
    the fix touched — an unmitigated Path-B sibling."""
    graph = tmp_path / "g.json"
    graph.write_text(json.dumps({
        "schema_version": "1", "graphify_version": "t", "generated_at": "2026-07-07T00:00:00Z",
        "backend": "ast", "confidence": "high", "content_hash": "sha256:0", "root_dir": str(tmp_path),
        "nodes": {
            "auth.py:sink_fn": {"kind": "function", "name": "sink_fn", "file": "auth.py",
                                "line": 1, "qualified_name": "auth.py:sink_fn", "language": "python"},
            "other.py:caller_bad": {"kind": "function", "name": "caller_bad", "file": "other.py",
                                    "line": 5, "qualified_name": "other.py:caller_bad", "language": "python"},
        },
        "edges": [{"from": "other.py:caller_bad", "to": "auth.py:sink_fn", "kind": "calls"}],
    }), encoding="utf-8")
    triage = tmp_path / "triage"; triage.mkdir(exist_ok=True)
    (triage / "VULN-1.json").write_text(json.dumps({
        "vuln_id": "VULN-1", "confidence": "high", "sink_symbol": "auth.py:sink_fn",
        "callers_of_sink": ["other.py:caller_bad"], "generated_at": "2026-07-07T00:00:00Z",
    }), encoding="utf-8")
    patterns = tmp_path / "p.md"
    patterns.write_text("```\nclass: injection\ncwes: [89]\npatterns: []\n```\n", encoding="utf-8")
    return graph, triage, patterns


def _write_result(tmp_path, files_modified):
    results = tmp_path / "results"; results.mkdir(exist_ok=True)
    (results / "VULN-1_result.json").write_text(json.dumps({
        "vuln_id": "VULN-1", "status": "VERIFIED", "cwe": "CWE-89", "file_path": "auth.py",
        "completeness_tier": "FULL", "callers_routed_through_fix": [],
        "files_modified": files_modified,
    }), encoding="utf-8")
    return results


def test_sweep_marks_revised_when_unmitigated_sibling_remains(sweep, tmp_path):
    """S4 CRITICAL: a found sibling whose file is NOT in files_modified is an
    unmitigated Path-B sibling and must force sweep_revised=true (FULL->
    MITIGATION). Previously mitigated stayed 0 'set by executor' (now deleted),
    so the downgrade never happened and the sibling shipped as FULL."""
    graph, triage, patterns = _ast_graph_with_unrouted_sibling(tmp_path)
    results = _write_result(tmp_path, files_modified=["auth.py"])  # sibling is in other.py
    out = tmp_path / "sweep.json"
    rc = sweep.main(["sweep", "--repo-root", str(tmp_path), "--graph", str(graph),
                     "--patterns", str(patterns), "--results-dir", str(results),
                     "--triage-dir", str(triage), "--out", str(out)])
    assert rc == 0
    row = json.loads(out.read_text())["rows"][0]
    assert row["remaining"] >= 1, f"unmitigated sibling not counted: {row}"
    assert row["sweep_revised"] is True, f"FULL not flagged for downgrade: {row}"


def test_sweep_mitigates_sibling_in_files_modified(sweep, tmp_path):
    """A sibling whose file IS in files_modified is amended into the same PR
    (Path A) — counted as mitigated; with no other siblings, no downgrade."""
    graph, triage, patterns = _ast_graph_with_unrouted_sibling(tmp_path)
    results = _write_result(tmp_path, files_modified=["auth.py", "other.py"])  # sibling amended
    out = tmp_path / "sweep.json"
    rc = sweep.main(["sweep", "--repo-root", str(tmp_path), "--graph", str(graph),
                     "--patterns", str(patterns), "--results-dir", str(results),
                     "--triage-dir", str(triage), "--out", str(out)])
    assert rc == 0
    row = json.loads(out.read_text())["rows"][0]
    assert row["mitigated"] >= 1, f"Path-A sibling not counted as mitigated: {row}"
    assert row["remaining"] == 0 and row["sweep_revised"] is False, f"spurious downgrade: {row}"


def test_sweep_fails_closed_on_missing_graph(sweep, tmp_path):
    """S4: a missing/malformed graph was treated as an empty run (exit 0), so
    pass-1 anchoring silently degraded with no signal. Must fail closed:
    sweep_incomplete + non-zero exit."""
    _, _, patterns = _ast_graph_with_unrouted_sibling(tmp_path)
    results = _write_result(tmp_path, files_modified=["auth.py"])
    out = tmp_path / "sweep.json"
    rc = sweep.main(["sweep", "--repo-root", str(tmp_path), "--graph", str(tmp_path / "nonexistent.json"),
                     "--patterns", str(patterns), "--results-dir", str(results), "--out", str(out)])
    assert rc != 0, "missing graph did not fail closed"
    assert json.loads(out.read_text()).get("sweep_incomplete") is True


def test_sweep_pass2_pattern_hits(sweep, tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text(
        "cursor.execute('SELECT * FROM t')\n",
        encoding="utf-8",
    )
    hits = sweep.pass2_pattern(tmp_path, [r"execute\("], exclude_files=set())
    assert hits
    assert hits[0][0] == "src/a.py"


def test_sweep_pass2_skips_excluded(sweep, tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("execute(", encoding="utf-8")
    (tmp_path / "src" / "b.py").write_text("execute(", encoding="utf-8")
    hits = sweep.pass2_pattern(tmp_path, [r"execute\("], exclude_files={"src/a.py"})
    assert all(rel != "src/a.py" for rel, _, _ in hits)


def test_sweep_pass2_skips_directories(sweep, tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "hook.py").write_text("execute(", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "mod.js").write_text("execute(", encoding="utf-8")
    (tmp_path / "app.py").write_text("execute(", encoding="utf-8")
    hits = sweep.pass2_pattern(tmp_path, [r"execute\("], exclude_files=set())
    assert len(hits) == 1
    assert hits[0][0] == "app.py"


def test_sweep_pass2_skips_unknown_suffix(sweep, tmp_path):
    (tmp_path / "README.md").write_text("execute(", encoding="utf-8")
    (tmp_path / "app.py").write_text("execute(", encoding="utf-8")
    hits = sweep.pass2_pattern(tmp_path, [r"execute\("], exclude_files=set())
    assert len(hits) == 1


def test_sweep_pass2_handles_invalid_regex(sweep, tmp_path):
    (tmp_path / "app.py").write_text("execute(", encoding="utf-8")
    hits = sweep.pass2_pattern(tmp_path, ["[invalid("], exclude_files=set())
    assert hits == []


def test_sweep_end_to_end(sweep, tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("cursor.execute('%s' % val)\n", encoding="utf-8")

    graph_p = tmp_path / "graph.json"
    graph_p.write_text('{"nodes": {}, "edges": [], "backend": "ast"}', encoding="utf-8")

    patterns_p = tmp_path / "sweep-patterns.md"
    patterns_p.write_text(
        "```yaml\n"
        "class: injection\n"
        "cwes: [89]\n"
        "patterns:\n"
        "  - 'execute\\(.*%'\n"
        "```\n",
        encoding="utf-8",
    )

    results_dir = tmp_path / "manifests"
    results_dir.mkdir()
    (results_dir / "g_result.json").write_text(json.dumps({
        "vuln_id": "VULN-1",
        "cwe": "CWE-89",
        "status": "VERIFIED_FULL",
        "sink_symbol": "src/a.py:execute",
        "callers_routed_through_fix": [],
    }), encoding="utf-8")

    ns = type("N", (), {})()
    ns.repo_root = str(tmp_path)
    ns.results_dir = str(results_dir)
    ns.graph = str(graph_p)
    ns.patterns = str(patterns_p)

    result = sweep.sweep(ns)
    assert result["fallback_only"] is False
    assert len(result["rows"]) == 1
    row = result["rows"][0]
    assert row["root_cause"] == "VULN-1"
    assert row["found"] >= 1


def test_sweep_grep_fallback_marks_annotation(sweep, tmp_path):
    (tmp_path / "src.py").write_text("md5(x)\n", encoding="utf-8")
    graph_p = tmp_path / "graph.json"
    graph_p.write_text('{"backend": "grep"}', encoding="utf-8")
    patterns_p = tmp_path / "p.md"
    patterns_p.write_text(
        "```yaml\nclass: crypto\npatterns:\n  - 'md5'\n```\n", encoding="utf-8",
    )
    results = tmp_path / "res"
    results.mkdir()
    (results / "r_result.json").write_text(json.dumps({
        "vuln_id": "VULN-2", "cwe": "CWE-327", "status": "VERIFIED_MITIGATION",
    }), encoding="utf-8")

    ns = type("N", (), {})()
    ns.repo_root = str(tmp_path)
    ns.results_dir = str(results)
    ns.graph = str(graph_p)
    ns.patterns = str(patterns_p)
    result = sweep.sweep(ns)
    assert result["fallback_only"] is True
    row = result["rows"][0]
    assert row["captured_annotation"] == "(regex-only)"


def test_sweep_main_writes_out(sweep, tmp_path, capsys):
    graph_p = tmp_path / "g.json"
    graph_p.write_text('{"nodes":{},"edges":[]}', encoding="utf-8")
    patterns_p = tmp_path / "p.md"
    patterns_p.write_text("no fenced blocks\n", encoding="utf-8")
    results = tmp_path / "r"
    results.mkdir()
    out = tmp_path / "out.json"
    rc = sweep.main([
        "sweep",
        "--repo-root", str(tmp_path),
        "--results-dir", str(results),
        "--graph", str(graph_p),
        "--patterns", str(patterns_p),
        "--out", str(out),
    ])
    assert rc == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert "rows" in payload


def test_sweep_pass2_survives_permission_denied_dir(sweep, tmp_path):
    """Regression: sweep's file walker previously used rglob without
    permission guards. Same class of bug that hit language-detect and
    graph.build. Fixed by routing through config.safe_walk_files.
    """
    import os
    (tmp_path / "app.py").write_text("cursor.execute('SELECT %s' % x)\n", encoding="utf-8")
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "hidden.py").write_text("x = 1\n", encoding="utf-8")
    try:
        os.chmod(locked, 0o000)
        # Must not raise
        hits = sweep.pass2_pattern(tmp_path, [r"execute\("], exclude_files=set())
    finally:
        os.chmod(locked, 0o755)
    assert any(rel == "app.py" for rel, _, _ in hits)


# =============================================================================
# validate-verification.py
# =============================================================================

_VALID_TABLE = """\
Some PR body preamble.

| # | VULN-NNN | Stated vector closed? | Test exercises real attack? | Default fail-closed? | Residual risk documented? | All call sites covered? | Sweep complete? | Verdict |
|---|----------|-----------------------|-----------------------------|----------------------|---------------------------|-------------------------|-----------------|---------|
| 1 | VULN-42  | yes (src/a.py:3)      | yes (tests/t.py:5)          | yes (src/a.py:3)     | n/a                       | yes (src/b.py:call)     | yes (src/a.py:3)| PASS    |

Trailer.
"""


def test_vv_parse_table_finds_it(vv):
    parsed = vv._parse_table(_VALID_TABLE)
    assert parsed is not None
    header, rows = parsed
    assert len(header) == 9
    assert len(rows) == 1


def test_vv_parse_table_missing(vv):
    assert vv._parse_table("body with no table\n") is None


def test_vv_cell_kind_variants(vv):
    assert vv._cell_kind("yes (file:1)") == "yes"
    assert vv._cell_kind("no") == "no"
    assert vv._cell_kind("n/a") == "n/a"
    assert vv._cell_kind("n / a") == "n/a"
    assert vv._cell_kind("maybe") == "unknown"


def test_vv_extract_citations(vv):
    cites = vv._extract_citations("yes (a.py:3) and yes (b.py:12)")
    assert cites == [("a.py", 3), ("b.py", 12)]


def test_vv_extract_citations_none(vv):
    assert vv._extract_citations("yes without citation") == []


def test_vv_check_citation_exists_true(vv, tmp_path):
    fp = tmp_path / "a.py"
    fp.write_text("line1\nline2\nline3\n", encoding="utf-8")
    assert vv._check_citation_exists(tmp_path, "a.py", 2) is True


def test_vv_check_citation_line_out_of_range(vv, tmp_path):
    fp = tmp_path / "a.py"
    fp.write_text("only one\n", encoding="utf-8")
    assert vv._check_citation_exists(tmp_path, "a.py", 42) is False


def test_vv_check_citation_missing_file(vv, tmp_path):
    assert vv._check_citation_exists(tmp_path, "nope.py", 1) is False


def test_vv_load_sidecar(vv, tmp_path):
    sc = tmp_path / "VULN-1.json"
    sc.write_text(json.dumps({"confidence": "high"}), encoding="utf-8")
    got = vv._load_sidecar_for_vuln(tmp_path, "VULN-1")
    assert got["confidence"] == "high"


def test_vv_load_sidecar_missing(vv, tmp_path):
    assert vv._load_sidecar_for_vuln(tmp_path, "VULN-999") is None


def test_vv_load_sidecar_malformed(vv, tmp_path):
    sc = tmp_path / "VULN-1.json"
    sc.write_text("not-json{", encoding="utf-8")
    assert vv._load_sidecar_for_vuln(tmp_path, "VULN-1") is None


def test_vv_load_result_missing(vv, tmp_path):
    assert vv._load_result(None) is None
    assert vv._load_result(tmp_path / "nope.json") is None


def test_vv_load_result_valid(vv, tmp_path):
    fp = tmp_path / "r.json"
    fp.write_text('{"x": 1}', encoding="utf-8")
    assert vv._load_result(fp) == {"x": 1}


def test_vv_parse_col7_callers_basic(vv):
    callers, trunc = vv._parse_column7_callers("yes (a.py:sym1) (b.py:sym2)")
    assert callers == ["a.py:sym1", "b.py:sym2"]
    assert trunc is None


def test_vv_parse_col7_truncated(vv):
    text = "yes (a.py:s1) (b.py:s2) ... 15 more via callers_of()"
    callers, trunc = vv._parse_column7_callers(text)
    assert trunc == 15


def test_vv_tokenize_caller(vv):
    basename, sym = vv._tokenize_caller("src/deep/path/mod.py:CaseSensitive")
    assert basename == "mod.py"
    assert sym == "casesensitive"


def test_vv_validate_valid_body(vv, tmp_path):
    body = tmp_path / "pr.md"
    body.write_text(_VALID_TABLE, encoding="utf-8")

    worktree = tmp_path / "wt"
    worktree.mkdir()
    (worktree / "src").mkdir()
    (worktree / "src" / "a.py").write_text("\n" * 10, encoding="utf-8")
    (worktree / "src" / "b.py").write_text("\n" * 10, encoding="utf-8")
    (worktree / "tests").mkdir()
    (worktree / "tests" / "t.py").write_text("\n" * 10, encoding="utf-8")

    # Column 7 says 'yes (src/b.py:call)' — post blocker-#3 fix the
    # validator fails closed on a 'yes' coverage cell it cannot verify, so
    # a valid body must supply a backing sidecar + result.
    sidecars = tmp_path / "sidecars"
    sidecars.mkdir()
    (sidecars / "VULN-42.json").write_text(
        json.dumps({"callers_of_sink": ["src/b.py:call"], "confidence": "high"}),
        encoding="utf-8",
    )
    result = tmp_path / "result.json"
    result.write_text(
        json.dumps({"callers_routed_through_fix": ["src/b.py:call"]}), encoding="utf-8"
    )

    rc = vv.validate(body, worktree, sidecars, result)
    assert rc == 0


def test_vv_validate_column7_fails_closed_without_sidecar(vv, tmp_path, capsys):
    """peer re-review blocker #3 regression guard: a 'yes' column-7
    coverage cell must be REJECTED when no sidecar can verify it, rather
    than silently passing."""
    body = tmp_path / "pr.md"
    body.write_text(_VALID_TABLE, encoding="utf-8")
    worktree = tmp_path / "wt"
    worktree.mkdir()
    (worktree / "src").mkdir()
    (worktree / "src" / "a.py").write_text("\n" * 10, encoding="utf-8")
    (worktree / "src" / "b.py").write_text("\n" * 10, encoding="utf-8")
    (worktree / "tests").mkdir()
    (worktree / "tests" / "t.py").write_text("\n" * 10, encoding="utf-8")

    rc = vv.validate(body, worktree, None, None)
    assert rc == 1
    assert "no triage sidecar available" in capsys.readouterr().err


def test_vv_validate_missing_body_file(vv, tmp_path, capsys):
    rc = vv.validate(tmp_path / "missing.md", tmp_path, None, None)
    assert rc == 2
    assert "<io>" in capsys.readouterr().err


def test_vv_validate_no_table(vv, tmp_path, capsys):
    body = tmp_path / "pr.md"
    body.write_text("body with no table\n", encoding="utf-8")
    rc = vv.validate(body, tmp_path, None, None)
    assert rc == 1


def test_vv_validate_missing_citation(vv, tmp_path, capsys):
    """Column 3 says yes but no (file:line)."""
    body = tmp_path / "pr.md"
    table = _VALID_TABLE.replace("yes (src/a.py:3)      | yes (tests/t.py:5)", "yes                   | yes (tests/t.py:5)")
    body.write_text(table, encoding="utf-8")
    worktree = tmp_path / "wt"
    worktree.mkdir()
    (worktree / "src").mkdir()
    (worktree / "src" / "a.py").write_text("\n" * 5, encoding="utf-8")
    (worktree / "src" / "b.py").write_text("\n" * 5, encoding="utf-8")
    (worktree / "tests").mkdir()
    (worktree / "tests" / "t.py").write_text("\n" * 10, encoding="utf-8")
    rc = vv.validate(body, worktree, None, None)
    assert rc == 1
    assert "missing file:line citation" in capsys.readouterr().err


def test_vv_column7_high_confidence_strict_match(vv, tmp_path, capsys):
    body = tmp_path / "pr.md"
    body.write_text(_VALID_TABLE, encoding="utf-8")
    wt = tmp_path / "wt"
    wt.mkdir()
    (wt / "src").mkdir()
    (wt / "src" / "a.py").write_text("\n" * 10, encoding="utf-8")
    (wt / "src" / "b.py").write_text("\n" * 10, encoding="utf-8")
    (wt / "tests").mkdir()
    (wt / "tests" / "t.py").write_text("\n" * 10, encoding="utf-8")

    sidecars = tmp_path / "graph_context"
    sidecars.mkdir()
    (sidecars / "VULN-42.json").write_text(json.dumps({
        "confidence": "high",
        "callers_of_sink": ["src/z.py:some_other_caller"],  # not in routed → fail
    }), encoding="utf-8")

    result = tmp_path / "r.json"
    result.write_text(json.dumps({
        "callers_routed_through_fix": ["src/b.py:call"],
    }), encoding="utf-8")

    rc = vv.validate(body, wt, sidecars, result)
    assert rc == 1
    err = capsys.readouterr().err
    assert "strict match failed" in err


def test_vv_column7_empty_callers_does_not_vacuously_pass(vv, tmp_path, capsys):
    """S3 (12-seg review): a 'yes' coverage cell with an empty callers_of_sink
    made the strict-match check vacuously pass (bare yes + {callers_of_sink: []}
    → rc 0). An unsubstantiated coverage claim must fail unless the sink is
    explicitly annotated as having no callers."""
    body = tmp_path / "pr.md"
    body.write_text(_VALID_TABLE, encoding="utf-8")
    wt = tmp_path / "wt"
    (wt / "src").mkdir(parents=True, exist_ok=True)
    (wt / "src" / "a.py").write_text("\n" * 10, encoding="utf-8")
    (wt / "src" / "b.py").write_text("\n" * 10, encoding="utf-8")
    (wt / "tests").mkdir(exist_ok=True)
    (wt / "tests" / "t.py").write_text("\n" * 10, encoding="utf-8")

    sidecars = tmp_path / "graph_context"
    sidecars.mkdir(exist_ok=True)
    (sidecars / "VULN-42.json").write_text(json.dumps({
        "confidence": "high",
        "callers_of_sink": [],   # empty — nothing to verify coverage against
    }), encoding="utf-8")
    result = tmp_path / "r.json"
    result.write_text(json.dumps({"callers_routed_through_fix": ["src/b.py:call"]}), encoding="utf-8")

    rc = vv.validate(body, wt, sidecars, result)
    assert rc == 1, "bare 'yes' with empty callers_of_sink vacuously passed"
    err = capsys.readouterr().err
    assert "no callers" in err.lower() or "unsubstantiated" in err.lower()


def test_vv_column7_low_confidence_needs_annotation(vv, tmp_path, capsys):
    body = tmp_path / "pr.md"
    body.write_text(_VALID_TABLE, encoding="utf-8")
    wt = tmp_path / "wt"
    wt.mkdir()
    (wt / "src").mkdir()
    (wt / "src" / "a.py").write_text("\n" * 10, encoding="utf-8")
    (wt / "src" / "b.py").write_text("\n" * 10, encoding="utf-8")
    (wt / "tests").mkdir()
    (wt / "tests" / "t.py").write_text("\n" * 10, encoding="utf-8")

    sidecars = tmp_path / "graph_context"
    sidecars.mkdir()
    (sidecars / "VULN-42.json").write_text(json.dumps({
        "confidence": "low",
        "callers_of_sink": ["src/b.py:call"],
    }), encoding="utf-8")
    result = tmp_path / "r.json"
    result.write_text(json.dumps({
        "callers_routed_through_fix": ["src/b.py:call"],
    }), encoding="utf-8")

    rc = vv.validate(body, wt, sidecars, result)
    assert rc == 1
    err = capsys.readouterr().err
    assert "(grep_fallback)" in err


def test_vv_main_smoke(vv, tmp_path):
    body = tmp_path / "pr.md"
    body.write_text(_VALID_TABLE, encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("\n" * 10, encoding="utf-8")
    (tmp_path / "src" / "b.py").write_text("\n" * 10, encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "t.py").write_text("\n" * 10, encoding="utf-8")
    sidecars = tmp_path / "sidecars"
    sidecars.mkdir()
    (sidecars / "VULN-42.json").write_text(
        json.dumps({"callers_of_sink": ["src/b.py:call"], "confidence": "high"}),
        encoding="utf-8",
    )
    result = tmp_path / "result.json"
    result.write_text(
        json.dumps({"callers_routed_through_fix": ["src/b.py:call"]}), encoding="utf-8"
    )
    rc = vv.main([
        "vv", str(body), "--worktree", str(tmp_path),
        "--sidecars-dir", str(sidecars), "--result", str(result),
    ])
    assert rc == 0


# ---- peer re-review majors M3 (sweep column-8) + M4 (authz regex) ----


def test_sweep_ok_helper(sweep):
    assert sweep._sweep_ok(0, 0) == "yes (n/a)"   # no siblings
    assert sweep._sweep_ok(3, 0) == "yes"          # all mitigated
    assert sweep._sweep_ok(3, 2) == "no"           # siblings remain


def test_sweep_row_emits_sweep_ok(sweep, tmp_path):
    """M3: render_verification_table reads a per-row `sweep_ok`; the sweep
    output must emit it (previously it emitted found/remaining but no
    sweep_ok, so column 8 always rendered 'n/a')."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    (results_dir / "g_result.json").write_text(
        json.dumps({"vuln_id": "VULN-001", "cwe": "CWE-89", "file_path": "a.py",
                    "status": "VERIFIED_FULL", "callers_routed_through_fix": []}),
        encoding="utf-8",
    )
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("print('x')\n", encoding="utf-8")
    graph = tmp_path / "graph.json"
    graph.write_text(json.dumps({"nodes": {}, "edges": [], "backend": "grep"}), encoding="utf-8")
    ns = type("N", (), {})()
    ns.repo_root = str(repo); ns.results_dir = str(results_dir)
    ns.graph = str(graph); ns.patterns = str(REPO_ROOT / "references" / "sweep-patterns.md")
    data = sweep.sweep(ns)
    assert data["rows"], "sweep produced no rows"
    for row in data["rows"]:
        assert "sweep_ok" in row, "sweep row missing sweep_ok (M3)"
        assert row["sweep_ok"] in ("yes", "no", "yes (n/a)")


def test_sweep_authz_regex_spares_protected_routes(sweep):
    """M4: the authz route pattern must NOT flag routes that already carry a
    *_required guard, and must still flag unguarded routes."""
    pats = sweep._load_patterns(REPO_ROOT / "references" / "sweep-patterns.md")
    route_pat = pats["authz"][0]
    import re
    protected = '@app.route("/x")\n@login_required\ndef view():\n    pass\n'
    unprotected = '@app.route("/y")\ndef open_view():\n    pass\n'
    deep_guard = '@app.route("/z")\n@cache.cached()\n@admin_required\ndef z():\n    pass\n'
    assert re.search(route_pat, protected) is None      # guarded → not flagged
    assert re.search(route_pat, unprotected) is not None  # unguarded → flagged
    assert re.search(route_pat, deep_guard) is None       # guard deeper in stack → not flagged


def test_pass2_pattern_skips_oversized_files(sweep, tmp_path):
    """M4b: pass2_pattern must skip files larger than MAX_SWEEP_FILE_BYTES so
    a multi-MB generated file isn't re-read + scanned per finding."""
    repo = tmp_path / "repo"
    repo.mkdir()
    big = repo / "generated.py"
    big.write_text("x = 1  # is_admin or user\n" + ("# pad\n" * 5), encoding="utf-8")
    # Force it over the cap without writing megabytes to disk.
    import os
    orig = sweep.MAX_SWEEP_FILE_BYTES
    try:
        sweep.MAX_SWEEP_FILE_BYTES = 10  # tiny cap → the file is "oversized"
        hits = sweep.pass2_pattern(repo, [r"is_admin\s*or\s+\w+"], exclude_files=set())
        assert hits == [], "oversized file should be skipped"
        sweep.MAX_SWEEP_FILE_BYTES = 10_000_000  # generous → now scanned
        hits2 = sweep.pass2_pattern(repo, [r"is_admin\s*or\s+\w+"], exclude_files=set())
        assert any("generated.py" in h[0] for h in hits2)
    finally:
        sweep.MAX_SWEEP_FILE_BYTES = orig
