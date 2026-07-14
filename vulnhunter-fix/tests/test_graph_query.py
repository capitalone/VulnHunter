"""Unit tests for the vulnhunter_fix.graph public API.

Covers REQ-GRA-002 (stable wrapper), REQ-GRA-005 (content-hash cache),
REQ-GRA-007 (six inherited primitives), REQ-GRA-008 (three security-purpose
additions), REQ-GRA-020 (confidence-aware matching). Exercises both the
AST-preferred path and the grep fallback.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from vulnhunter_fix.graph import GRAPHIFY_VERSION_RANGE, GraphQuery, build_or_load, load_graph
from vulnhunter_fix.graph.build import _content_hash, build_graph
from vulnhunter_fix.graph.config import (
    CLOUD_LLM_ENV_VARS,
    cache_dir_for_repo,
    check_backend_isolation,
    graph_path_for_repo,
    language_for_path,
)
from vulnhunter_fix.graph.fallback import _enclosing_symbol, build_fallback_graph, grep_callers_of
from vulnhunter_fix.graph.schema import SCHEMA_VERSION, Edge, GraphDocument, Node


PY_FIXTURE = REPO_ROOT / "tests" / "graph_fixtures" / "python"
GO_FIXTURE = REPO_ROOT / "tests" / "graph_fixtures" / "go"


# ---- config ----------------------------------------------------------------


def test_graphify_version_range_is_pinned():
    assert GRAPHIFY_VERSION_RANGE == ">=0.8.14,<0.9.0"


def test_language_for_path():
    assert language_for_path("x.py") == "python"
    assert language_for_path("x.go") == "go"
    assert language_for_path("x.java") == "java"
    assert language_for_path("x.tsx") == "typescript"
    assert language_for_path("x.unknown") is None


def test_cache_and_graph_paths():
    assert cache_dir_for_repo("/w", "repo") == Path("/w/repo/cache")
    assert graph_path_for_repo("/w", "repo") == Path("/w/repo/cache/graph.json")


def test_backend_isolation_clean(monkeypatch):
    for var in CLOUD_LLM_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    assert check_backend_isolation() == []


def test_backend_isolation_detects_leak(monkeypatch):
    for var in CLOUD_LLM_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake")
    leaked = check_backend_isolation()
    assert "ANTHROPIC_API_KEY" in leaked


# ---- schema round-trip -----------------------------------------------------


def test_schema_roundtrip_preserves_fields():
    original = GraphDocument(
        schema_version=SCHEMA_VERSION,
        graphify_version="0.8.51",
        generated_at="2026-07-01T00:00:00+00:00",
        backend="ast",
        confidence="high",
        content_hash="sha256:abc",
        root_dir="/tmp/repo",
        nodes={
            "src/a.py:foo": Node(
                id="src/a.py:foo",
                kind="function",
                name="foo",
                file="src/a.py",
                line=10,
                qualified_name="src/a.py:foo",
                language="python",
            )
        },
        edges=[Edge(src="src/a.py:foo", dst="src/b.py:bar", kind="calls")],
    )
    d = original.to_dict()
    restored = GraphDocument.from_dict(d)

    assert restored.schema_version == original.schema_version
    assert restored.backend == "ast"
    assert restored.confidence == "high"
    assert "src/a.py:foo" in restored.nodes
    assert restored.nodes["src/a.py:foo"].name == "foo"
    assert restored.edges[0].src == "src/a.py:foo"
    assert restored.edges[0].kind == "calls"


def test_schema_from_dict_accepts_legacy_edge_keys():
    data = {
        "schema_version": "1",
        "graphify_version": None,
        "generated_at": "",
        "backend": "grep",
        "confidence": "low",
        "content_hash": "",
        "root_dir": "",
        "nodes": {"a:x": {"kind": "function", "name": "x", "file": "a", "line": 1,
                          "qualified_name": "a:x", "language": "python"}},
        "edges": [{"src": "a:x", "dst": "b:y", "kind": "calls"}],
    }
    doc = GraphDocument.from_dict(data)
    assert doc.edges[0].src == "a:x"


# ---- content hash ----------------------------------------------------------


def test_content_hash_is_stable_across_runs():
    h1 = _content_hash(PY_FIXTURE.resolve())
    h2 = _content_hash(PY_FIXTURE.resolve())
    assert h1 == h2
    assert h1.startswith("sha256:")


def test_content_hash_changes_with_content(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    h1 = _content_hash(tmp_path)
    (tmp_path / "a.py").write_text("x = 2\n")
    h2 = _content_hash(tmp_path)
    assert h1 != h2


def test_content_hash_is_order_independent(tmp_path, monkeypatch):
    """M1 (synthesized review S1): _content_hash consumed iter_source_files in
    rglob (filesystem) order, so two identical repos could hash differently on
    different filesystems -> spurious cache invalidation, defeating REQ-GRA-005.
    The hash must not depend on file iteration order."""
    import vulnhunter_fix.graph.build as buildmod
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.py").write_text("y = 2\n")
    a, b = tmp_path / "a.py", tmp_path / "b.py"
    monkeypatch.setattr(buildmod, "iter_source_files", lambda root: iter([a, b]))
    h1 = buildmod._content_hash(tmp_path)
    monkeypatch.setattr(buildmod, "iter_source_files", lambda root: iter([b, a]))
    h2 = buildmod._content_hash(tmp_path)
    assert h1 == h2, "content hash depends on file order (nondeterministic cache key)"


# ---- build / load / cache --------------------------------------------------


def test_build_graph_produces_valid_document():
    doc = build_graph(PY_FIXTURE)
    assert doc.schema_version == SCHEMA_VERSION
    assert doc.backend in ("ast", "grep")
    assert doc.confidence in ("high", "low")
    assert doc.content_hash.startswith("sha256:")
    assert doc.root_dir  # non-empty


def test_build_or_load_caches_and_reuses(tmp_path):
    cache = tmp_path / "graph.json"
    doc1 = build_or_load(PY_FIXTURE, cache)
    assert cache.exists()
    doc2 = build_or_load(PY_FIXTURE, cache)
    # Second call must return same content_hash (cache hit)
    assert doc1.content_hash == doc2.content_hash


def test_build_or_load_rebuilds_on_content_change(tmp_path):
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "a.py").write_text("def foo(): return 1\n")
    cache = tmp_path / "graph.json"
    doc1 = build_or_load(src_dir, cache)
    (src_dir / "a.py").write_text("def foo(): return 2\ndef bar(): return 3\n")
    doc2 = build_or_load(src_dir, cache)
    assert doc1.content_hash != doc2.content_hash


def test_build_or_load_ignores_invalid_cache(tmp_path):
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "a.py").write_text("x = 1\n")
    cache = tmp_path / "graph.json"
    cache.write_text("{malformed json}")
    doc = build_or_load(src_dir, cache)
    assert doc.content_hash.startswith("sha256:")


def test_normalizer_skips_non_code_nodes():
    """S2 (12-seg review, MEDIUM): graphify can emit non-code nodes (a docstring
    /comment/rationale). The normalizer passed unknown kinds through verbatim,
    polluting god_nodes/counts and risking prose in graph.json. Non-code kinds
    must be skipped; code nodes kept."""
    from vulnhunter_fix.graph.build import _iter_normalized_graphify_entities
    raw = {"nodes": [
        {"id": "a_foo", "label": "foo()", "source_file": "a.py",
         "source_location": "L1", "kind": "function", "name": "foo"},
        {"id": "a_doc", "label": "module docstring", "source_file": "a.py",
         "source_location": "L1", "kind": "docstring", "name": "<docstring>"},
        {"id": "a_cmt", "label": "comment", "source_file": "a.py",
         "source_location": "L2", "kind": "comment", "name": "<comment>"},
    ]}
    nodes = list(_iter_normalized_graphify_entities(raw, REPO_ROOT))
    names = {n.name for n in nodes}
    assert "foo" in names, "code node was dropped"
    assert not any(n.kind in ("docstring", "comment") for n in nodes), (
        f"non-code node leaked into graph: {[(n.name, n.kind) for n in nodes]}"
    )


def test_load_graph_reads_from_cache(tmp_path):
    cache = tmp_path / "graph.json"
    build_or_load(PY_FIXTURE, cache)
    doc = load_graph(cache)
    assert doc.schema_version == SCHEMA_VERSION


# ---- fallback grep ---------------------------------------------------------


def test_build_fallback_graph_finds_python_functions():
    doc = build_fallback_graph(PY_FIXTURE, content_hash="sha256:test")
    assert doc.backend == "grep"
    assert doc.confidence == "low"
    names = {n.name for n in doc.nodes.values()}
    assert "authenticate" in names
    assert "check_password" in names


def test_build_fallback_graph_finds_go_functions():
    doc = build_fallback_graph(GO_FIXTURE, content_hash="sha256:test")
    names = {n.name for n in doc.nodes.values()}
    assert "Authenticate" in names
    assert "CheckPassword" in names


def test_grep_callers_of_returns_file_symbol():
    callers = grep_callers_of(PY_FIXTURE, "authenticate")
    assert callers, "expected at least one caller of authenticate"
    for c in callers:
        assert ":" in c
        file_part, _, sym_part = c.rpartition(":")
        assert file_part.endswith(".py")
        assert sym_part and not sym_part.isdigit()


def test_grep_callers_of_case_insensitive():
    callers = grep_callers_of(PY_FIXTURE, "AUTHENTICATE")
    assert callers, "expected case-insensitive match to still find authenticate callers"


def test_enclosing_symbol_walks_backward():
    file = PY_FIXTURE / "sample_auth.py"
    text = file.read_text()
    # `authenticate` calls `get_user_by_id` — the enclosing symbol at that line is `authenticate`.
    call_line = None
    for i, line in enumerate(text.splitlines(), start=1):
        if "get_user_by_id(username)" in line:
            call_line = i
            break
    assert call_line, "fixture must call get_user_by_id"
    assert _enclosing_symbol(file, call_line) == "authenticate"


# ---- GraphQuery primitives -------------------------------------------------


@pytest.fixture
def sample_doc():
    return GraphDocument(
        schema_version=SCHEMA_VERSION,
        graphify_version="0.8.51",
        generated_at="",
        backend="ast",
        confidence="high",
        content_hash="",
        root_dir=str(REPO_ROOT),
        nodes={
            "a.py:foo": Node(id="a.py:foo", kind="function", name="foo", file="a.py",
                             line=1, qualified_name="a.py:foo", language="python"),
            "a.py:bar": Node(id="a.py:bar", kind="function", name="bar", file="a.py",
                             line=5, qualified_name="a.py:bar", language="python"),
            "b.py:baz": Node(id="b.py:baz", kind="function", name="baz", file="b.py",
                             line=1, qualified_name="b.py:baz", language="python"),
            "b.py:qux": Node(id="b.py:qux", kind="function", name="qux", file="b.py",
                             line=5, qualified_name="b.py:qux", language="python"),
        },
        edges=[
            Edge(src="a.py:foo", dst="a.py:bar", kind="calls"),
            Edge(src="a.py:bar", dst="b.py:baz", kind="calls"),
            Edge(src="b.py:qux", dst="a.py:foo", kind="calls"),
        ],
    )


def test_query_status_exposes_backend(sample_doc):
    q = GraphQuery(sample_doc)
    s = q.status()
    assert s["backend"] == "ast"
    assert s["confidence"] == "high"
    assert s["node_count"] == 4
    assert s["edge_count"] == 3


def test_query_context_for_file(sample_doc):
    q = GraphQuery(sample_doc)
    ctx = q.context_for_file("a.py")
    assert ctx["confidence"] == "high"
    assert set(ctx["nodes"]) == {"foo", "bar"}


def test_query_blast_radius_reachable_from_target(sample_doc):
    q = GraphQuery(sample_doc)
    result = q.blast_radius("b.py")
    # b.py:baz is called by a.py:bar → walking back from b.py reaches a.py
    assert "a.py" in result["reachable_files"]


def test_query_blast_radius_accepts_file_symbol_form(sample_doc):
    """Allow-path guard (peer review major): build_graph.py passes a
    `file:symbol` sink (a finding's location) into blast_radius, which keys
    on bare file paths — previously it never matched and every sidecar's
    blast_radius came back empty. The file:symbol / file:line form must
    resolve to the same result as the bare file path."""
    q = GraphQuery(sample_doc)
    bare = q.blast_radius("b.py")["reachable_files"]
    by_symbol = q.blast_radius("b.py:baz")["reachable_files"]
    by_line = q.blast_radius("b.py:12")["reachable_files"]
    assert by_symbol == bare
    assert by_line == bare
    assert "a.py" in by_symbol   # non-empty — the bug produced []


def test_query_god_nodes_ranks_by_degree(sample_doc):
    q = GraphQuery(sample_doc)
    ranked = q.god_nodes(top_n=2)
    assert len(ranked) == 2
    # a.py:foo has in=1 (qux→foo) and out=1 (foo→bar) = degree 2. Same for bar.
    ids = {n["id"] for n in ranked}
    assert "a.py:foo" in ids or "a.py:bar" in ids


def test_query_changed_impact(sample_doc):
    q = GraphQuery(sample_doc)
    impact = q.changed_impact(["b.py"])
    assert "b.py" in impact["files_changed"]
    assert isinstance(impact["impacted_files"], list)


def test_query_co_changes_returns_structural_neighbors(sample_doc):
    q = GraphQuery(sample_doc)
    neighbors = q.co_changes("b.py", cutoff=5)
    assert isinstance(neighbors, list)


def test_query_callers_of_by_qualified_name(sample_doc):
    q = GraphQuery(sample_doc)
    callers = q.callers_of("a.py:foo")
    assert "b.py:qux" in callers


def test_query_callers_of_matches_qualified_name_when_node_id_differs():
    """S2 (12-seg review, CRITICAL): real graphify node ids are module-qualified
    (e.g. `auth.mod:check_password`) and differ from the `file:symbol` form a
    finding carries. _match_symbol only matched raw id / file:line, so
    callers_of('sample_auth.py:check_password') returned [] while stamped
    confidence:high — a fix-masking false negative that feeds 'no vulnerable
    callers' → superset → FULL. Must also match node.qualified_name."""
    doc = GraphDocument(
        schema_version=SCHEMA_VERSION, graphify_version="0.8.51", generated_at="",
        backend="ast", confidence="high", content_hash="", root_dir=str(REPO_ROOT),
        nodes={
            # node id != qualified_name (the real-graphify shape)
            "auth.mod:check_password": Node(
                id="auth.mod:check_password", kind="function", name="check_password",
                file="sample_auth.py", line=5, qualified_name="sample_auth.py:check_password",
                language="python"),
            "auth.mod:authenticate": Node(
                id="auth.mod:authenticate", kind="function", name="authenticate",
                file="sample_auth.py", line=1, qualified_name="sample_auth.py:authenticate",
                language="python"),
        },
        edges=[Edge(src="auth.mod:authenticate", dst="auth.mod:check_password", kind="calls")],
    )
    q = GraphQuery(doc)
    # The finding carries the file:symbol form, which is NOT a node id but IS a qualified_name.
    callers = q.callers_of("sample_auth.py:check_password")
    assert "sample_auth.py:authenticate" in callers, (
        f"file:symbol sink resolved to no callers (fix-masking false negative): {callers}"
    )


def test_query_callers_of_by_bare_name(sample_doc):
    q = GraphQuery(sample_doc)
    callers = q.callers_of("foo")
    assert "b.py:qux" in callers


def test_query_callers_of_by_line_form(sample_doc):
    """F10 (segment-review S1a): a file:line sink (what build_graph derives
    from a finding location) used to return [] because file:line is not a node
    id. It must resolve to the enclosing symbol (closest preceding def) and
    return real callers. b.py:2 → baz (line 1); bar calls baz."""
    q = GraphQuery(sample_doc)
    callers = q.callers_of("b.py:2")
    assert "a.py:bar" in callers, f"file:line sink resolved to no callers: {callers}"
    # Equivalent to resolving the symbol directly.
    assert set(callers) == set(q.callers_of("b.py:baz"))


def test_query_callees_of(sample_doc):
    q = GraphQuery(sample_doc)
    callees = q.callees_of("a.py:foo")
    assert "a.py:bar" in callees


def test_query_reachable_from_true(sample_doc):
    q = GraphQuery(sample_doc)
    # a.py file has foo which calls bar which calls baz — b.py:baz IS reachable
    assert q.reachable_from("a.py", 1, "b.py:baz") is True


def test_query_reachable_from_honors_input_line(sample_doc):
    """F9 (segment-review S1a): reachable_from used to ignore input_line and
    build its entry set from ALL nodes in the file → false positives. In b.py,
    qux (line 5) reaches foo but baz (line 1) reaches nothing. Line precision
    must distinguish them; the old file-level behavior returned True for both."""
    q = GraphQuery(sample_doc)
    # line 6 → qux (line 5 <= 6); qux → foo → reachable
    assert q.reachable_from("b.py", 6, "a.py:foo") is True
    # line 2 → baz (line 1 <= 2 < 5); baz reaches nothing → NOT reachable.
    # File-level (buggy) behavior would find qux in the file and return True.
    assert q.reachable_from("b.py", 2, "a.py:foo") is False


def test_query_reachable_from_false(sample_doc):
    q = GraphQuery(sample_doc)
    # Line-precise: b.py line 1 → baz, which has no callees → cannot reach bar.
    # (Pre-F9 this returned True via file-level entry set including qux.)
    assert q.reachable_from("b.py", 1, "a.py:bar") is False
    # Truly unreachable: start from a file that isn't in the doc
    assert q.reachable_from("nonexistent.py", 1, "a.py:foo") is False


def test_query_reachable_from_unknown_symbol(sample_doc):
    q = GraphQuery(sample_doc)
    assert q.reachable_from("a.py", 1, "nonexistent") is False


def test_query_callers_of_returns_empty_for_unknown(sample_doc):
    q = GraphQuery(sample_doc)
    assert q.callers_of("nonexistent") == []


def test_query_under_grep_backend_uses_fallback(monkeypatch):
    grep_doc = GraphDocument(
        schema_version=SCHEMA_VERSION,
        graphify_version=None,
        generated_at="",
        backend="grep",
        confidence="low",
        content_hash="",
        root_dir=str(PY_FIXTURE),
        nodes={},
        edges=[],
    )
    q = GraphQuery(grep_doc, source_root=PY_FIXTURE)
    # Under grep backend, callees_of returns empty and reachable_from returns False.
    assert q.callees_of("authenticate") == []
    assert q.reachable_from("sample_auth.py", 1, "authenticate") is False
    # callers_of delegates to grep_callers_of which does find real callers in the fixture
    callers = q.callers_of("authenticate")
    assert isinstance(callers, list)
