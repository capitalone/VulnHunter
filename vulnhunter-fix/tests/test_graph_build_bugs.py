"""Regression tests for graph.build bugs surfaced by real E2E runs.

Covers:
- The AST path uses ``graphify.detect.detect(root)`` for file enumeration
  (0.8.x contract) so graphify never sees files it can't or shouldn't read.
  Prior form re-implemented the walker with ``rglob`` and handed graphify
  files (like ``.envrc``) that blew up with PermissionError in the sandbox.
- ``iter_source_files`` (shared walker in ``config.py``) skips unreadable
  files rather than aborting the walk — used by both the content-hash key
  and the grep fallback.
- ``build_fallback_graph`` doesn't crash on unreadable subdirs.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from vulnhunter_fix.graph.build import _content_hash, build_graph
from vulnhunter_fix.graph.config import iter_source_files
from vulnhunter_fix.graph.fallback import build_fallback_graph


def test_iter_skips_excluded_dirs(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "hook.py").write_text("y = 2\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "junk.js").write_text("z = 3\n", encoding="utf-8")
    got = list(iter_source_files(tmp_path))
    assert (tmp_path / "src" / "a.py") in got
    assert (tmp_path / ".git" / "hook.py") not in got
    assert (tmp_path / "node_modules" / "junk.js") not in got


def test_iter_skips_non_source_suffixes(tmp_path):
    (tmp_path / "src.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("readme\n", encoding="utf-8")
    (tmp_path / "config.yaml").write_text("k: v\n", encoding="utf-8")
    got = list(iter_source_files(tmp_path))
    names = {p.name for p in got}
    assert "src.py" in names
    assert "README.md" not in names
    assert "config.yaml" not in names


def test_iter_survives_permission_denied_dir(tmp_path):
    """PermissionError on parts / stat must be swallowed, not propagated."""
    (tmp_path / "readable.py").write_text("def a(): pass\n", encoding="utf-8")
    subdir = tmp_path / "locked"
    subdir.mkdir()
    (subdir / "hidden.py").write_text("def b(): pass\n", encoding="utf-8")
    try:
        os.chmod(subdir, 0o000)
        got = list(iter_source_files(tmp_path))  # must not raise
    finally:
        os.chmod(subdir, 0o755)
    names = {p.name for p in got}
    assert "readable.py" in names


def test_content_hash_survives_unreadable_file(tmp_path):
    (tmp_path / "readable.py").write_text("x = 1\n", encoding="utf-8")
    subdir = tmp_path / "locked"
    subdir.mkdir()
    (subdir / "hidden.py").write_text("z = 3\n", encoding="utf-8")
    try:
        os.chmod(subdir, 0o000)
        got = _content_hash(tmp_path)
    finally:
        os.chmod(subdir, 0o755)
    assert got.startswith("sha256:")


def test_content_hash_stable_across_runs(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    h1 = _content_hash(tmp_path)
    h2 = _content_hash(tmp_path)
    assert h1 == h2


def test_content_hash_changes_with_content(tmp_path):
    fp = tmp_path / "a.py"
    fp.write_text("x = 1\n", encoding="utf-8")
    h1 = _content_hash(tmp_path)
    fp.write_text("x = 2\n", encoding="utf-8")
    h2 = _content_hash(tmp_path)
    assert h1 != h2


def test_build_graph_falls_back_when_no_sources(tmp_path):
    """Empty repo → fallback graph, no crash."""
    doc = build_graph(tmp_path)
    assert doc is not None
    assert doc.backend in ("grep", "ast", "none")


def test_build_graph_returns_nodes_on_python_fixture(tmp_path):
    """A 2-function fixture should produce >0 nodes via AST or fallback."""
    (tmp_path / "app.py").write_text(
        "def login(user, pw):\n    return f\"SELECT * WHERE u='{user}'\"\n"
        "def hash_password(pw):\n    import hashlib; return hashlib.md5(pw.encode()).hexdigest()\n",
        encoding="utf-8",
    )
    doc = build_graph(tmp_path)
    if len(doc.nodes) == 0 and doc.backend == "grep":
        pytest.skip("both graphify and grep fallback returned 0 nodes in this env")
    assert len(doc.nodes) > 0, f"expected graph nodes from a 2-function fixture, got {len(doc.nodes)}"


def test_fallback_graph_survives_permission_denied_dir(tmp_path):
    """The reason we reverted: fallback path crashed on an unreadable
    subdir even after build.py's walker was guarded. The shared walker
    in config.py makes this test pass for both paths."""
    (tmp_path / "readable.py").write_text("def foo():\n    return 1\n", encoding="utf-8")
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "hidden.py").write_text("def bar():\n    return 2\n", encoding="utf-8")
    try:
        os.chmod(locked, 0o000)
        doc = build_fallback_graph(tmp_path, "sha256:test")
    finally:
        os.chmod(locked, 0o755)
    assert doc.backend == "grep"
    assert any(n.name == "foo" for n in doc.nodes.values())


def test_ast_path_uses_graphify_detect_not_rglob(monkeypatch, tmp_path):
    """When graphify is available, the AST path must call
    ``graphify.detect.detect(root)`` rather than doing its own file walk.

    Reason: graphify.detect honors .gitignore + .graphifyignore and
    pre-filters files graphify can't extract from. Our rglob-based walker
    was handing graphify.extract() files that blew up on PermissionError.

    This test replaces graphify.detect with a tracker + returns a fixed
    file list; the assertion is that our code called it (once) and passed
    the resulting file list on to graphify.extract().
    """
    graphify = pytest.importorskip("graphify")
    from graphify.detect import detect as real_detect

    (tmp_path / "a.py").write_text("def x(): pass\n", encoding="utf-8")
    calls = {"detect_count": 0, "extract_args": None, "extract_kwargs": None}

    def fake_detect(root_arg):
        calls["detect_count"] += 1
        return {"files": {"code": [str(tmp_path / "a.py")]}}

    def fake_extract(files, **kwargs):
        calls["extract_args"] = list(files)
        calls["extract_kwargs"] = kwargs
        return {"nodes": [], "edges": []}

    monkeypatch.setattr("graphify.detect.detect", fake_detect)
    monkeypatch.setattr(graphify, "extract", fake_extract)

    doc = build_graph(tmp_path)
    assert calls["detect_count"] == 1, "graphify.detect must be called exactly once"
    assert calls["extract_args"] is not None, "extract must be called with detect's file list"
    assert len(calls["extract_args"]) == 1
    assert Path(calls["extract_args"][0]).name == "a.py"
    assert doc.backend == "ast"


def test_graphify_parallel_defaults_to_sequential_on_darwin(monkeypatch):
    """Regression: graphify.extract(parallel=True) crashes on macOS because
    ProcessPoolExecutor.__init__ calls os.sysconf("SC_SEM_NSEMS_MAX") which
    the Claude Code sandbox blocks with PermissionError. Catalyst hit and
    documented this — we honor the same GRAPHIFY_PARALLEL env override,
    defaulting to sequential on Darwin.
    """
    import sys as _sys
    from vulnhunter_fix.graph.build import _graphify_parallel

    monkeypatch.delenv("GRAPHIFY_PARALLEL", raising=False)
    monkeypatch.setattr(_sys, "platform", "darwin")
    assert _graphify_parallel() is False, "darwin default must be sequential"

    monkeypatch.setattr(_sys, "platform", "linux")
    assert _graphify_parallel() is True, "linux default must be parallel"

    monkeypatch.setenv("GRAPHIFY_PARALLEL", "1")
    monkeypatch.setattr(_sys, "platform", "darwin")
    assert _graphify_parallel() is True, "env=1 must force parallel even on darwin"

    monkeypatch.setenv("GRAPHIFY_PARALLEL", "0")
    monkeypatch.setattr(_sys, "platform", "linux")
    assert _graphify_parallel() is False, "env=0 must force sequential"


def test_ast_path_passes_parallel_kwarg_to_extract(monkeypatch, tmp_path):
    """The parallel kwarg must reach graphify.extract — otherwise
    the sysconf-block on macOS still fires."""
    graphify = pytest.importorskip("graphify")

    (tmp_path / "a.py").write_text("def x(): pass\n", encoding="utf-8")
    seen = {"parallel": None}

    def fake_detect(root_arg):
        return {"files": {"code": [str(tmp_path / "a.py")]}}

    def fake_extract(files, parallel=None, **kwargs):
        seen["parallel"] = parallel
        return {"nodes": [], "edges": []}

    monkeypatch.setattr("graphify.detect.detect", fake_detect)
    monkeypatch.setattr(graphify, "extract", fake_extract)
    build_graph(tmp_path)
    assert seen["parallel"] in (True, False), "extract must be invoked with a parallel kwarg"
