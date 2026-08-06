# LSP Backend for `vulnhunter-fix` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement an opt-in LSP backend (`VULNFIX_GRAPH_BACKEND=lsp`) in `vulnhunter-fix` using `multilspy` (or local JSON-RPC language servers like `pyright`) with graceful fallback to the AST/Grep baseline, per-symbol caching, and schema validation support.

**Architecture:** A `GraphBackend` protocol defines the graph query interface. `LSPGraphQuery` implements this interface using lazy edge resolution and eager node caching via LSP stdio JSON-RPC. `build_graph.py` orchestrates per-finding backend selection, populates `reachable_from_entry`, and handles fallback/downgrade behavior.

**Tech Stack:** Python 3.11+, setuptools, `multilspy` (optional dependency), `jsonschema`, `pytest`.

## Global Constraints

- Python baseline: 3.11+.
- Opt-in env var: `VULNFIX_GRAPH_BACKEND` (values: `auto`, `lsp`, `ast`, `grep`).
- Cloud LLM isolation: LSP uses local binaries (`pyright`), no network calls.
- Fallback & Downgrade: any LSP query timeout or error falls back to baseline `GraphQuery` and downgrades sidecar provenance.

---

### Task 1: Schema Fix for `triage-schema.json`

**Files:**
- Modify: `vulnhunter-fix/references/triage-schema.json:20-40`
- Test: `vulnhunter-fix/tests/test_triage_schema.py`

**Interfaces:**
- Consumes: JSON Schema 2020-12 definition
- Produces: Updated schema accepting `graph_backend: "lsp"` with `confidence: "high"`

- [ ] **Step 1: Write failing schema contract test**

```python
import json
import pytest
from jsonschema import validate

def test_triage_schema_accepts_lsp_high_confidence():
    with open("vulnhunter-fix/references/triage-schema.json") as f:
        schema = json.load(f)
    
    sample_sidecar = {
        "finding_id": "VULN-001",
        "cwe": "CWE-89",
        "confidence": "high",
        "graph_backend": "lsp",
        "callers": [],
        "blast_radius": []
    }
    # Should validate without raising jsonschema.ValidationError
    validate(instance=sample_sidecar, schema=schema)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest vulnhunter-fix/tests/test_triage_schema.py -v`
Expected: FAIL with ValidationError (`"lsp" is not one of ["ast", "grep", "none"]` or `const: "ast"` failure).

- [ ] **Step 3: Update `triage-schema.json`**

In `vulnhunter-fix/references/triage-schema.json`, update `graph_backend` enum to include `"lsp"`, and update the conditional `confidence == "high"` branch to accept `enum: ["ast", "lsp"]`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest vulnhunter-fix/tests/test_triage_schema.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add vulnhunter-fix/references/triage-schema.json vulnhunter-fix/tests/test_triage_schema.py
git commit -m "fix(schema): allow graph_backend lsp with high confidence in triage-schema"
```

---

### Task 2: Define `GraphBackend` Protocol & Mock Language Server Test Infrastructure

**Files:**
- Create: `vulnhunter-fix/vulnhunter_fix/graph/protocol.py`
- Create: `vulnhunter-fix/tests/mock_lsp_server.py`
- Modify: `vulnhunter-fix/vulnhunter_fix/graph/__init__.py`

**Interfaces:**
- Consumes: `GraphDocument`, `GraphQuery`
- Produces: `GraphBackend` structural typing protocol with `callers_of`, `callees_of`, `reachable_from`, `blast_radius`, `status`

- [ ] **Step 1: Write test for `GraphBackend` protocol compliance**

```python
from vulnhunter_fix.graph.protocol import GraphBackend
from vulnhunter_fix.graph.query import GraphQuery
from vulnhunter_fix.graph.build import build_graph_doc

def test_graph_query_implements_protocol():
    doc = build_graph_doc([])
    query = GraphQuery(doc)
    assert isinstance(query, GraphBackend)
```

- [ ] **Step 2: Run test to verify failure**

Run: `pytest vulnhunter-fix/tests/test_graph_protocol.py -v`
Expected: FAIL with `ImportError: cannot import name GraphBackend`.

- [ ] **Step 3: Implement `GraphBackend` Protocol and `mock_lsp_server.py`**

In `vulnhunter_fix/graph/protocol.py`:
```python
from typing import Protocol, List, Dict, Any, Optional, Tuple, runtime_checkable

@runtime_checkable
class GraphBackend(Protocol):
    def callers_of(self, symbol_or_node_id: str, max_depth: int = 5) -> List[Dict[str, Any]]: ...
    def callees_of(self, symbol_or_node_id: str, max_depth: int = 5) -> List[Dict[str, Any]]: ...
    def reachable_from(self, entry_node_id: str, sink_node_id: str, max_depth: int = 10) -> Optional[List[str]]: ...
    def blast_radius(self, symbol_or_node_id: str, max_depth: int = 3) -> Dict[str, Any]: ...
    def status(self) -> Dict[str, Any]: ...
```

In `tests/mock_lsp_server.py`, build a helper that spawns a subprocess responding to JSON-RPC over stdio (`initialize`, `textDocument/definition`, `textDocument/prepareCallHierarchy`, `callHierarchy/incomingCalls`).

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest vulnhunter-fix/tests/test_graph_protocol.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add vulnhunter-fix/vulnhunter_fix/graph/protocol.py vulnhunter-fix/tests/mock_lsp_server.py vulnhunter-fix/tests/test_graph_protocol.py
git commit -m "feat(graph): add GraphBackend protocol and mock LSP server test helper"
```

---

### Task 3: Implement `LSPGraphQuery` and Lazy LSP Session Manager

**Files:**
- Create: `vulnhunter-fix/vulnhunter_fix/graph/lsp_backend.py`
- Create: `vulnhunter-fix/tests/test_lsp_backend.py`

**Interfaces:**
- Consumes: JSON-RPC stdio process or `multilspy` session
- Produces: `LSPGraphQuery` class satisfying `GraphBackend` and `select_backend(root, language)` session manager

- [ ] **Step 1: Write test for `LSPGraphQuery` callers and reachability**

```python
import pytest
from tests.mock_lsp_server import start_mock_lsp_server
from vulnhunter_fix.graph.lsp_backend import LSPGraphQuery

def test_lsp_graph_query_callers():
    server_proc = start_mock_lsp_server()
    lsp_query = LSPGraphQuery(server_proc, repo_root="/tmp/test-repo", language="python")
    callers = lsp_query.callers_of("auth_sink")
    assert len(callers) > 0
    assert lsp_query.status()["backend"] == "lsp"
```

- [ ] **Step 2: Run test to verify failure**

Run: `pytest vulnhunter-fix/tests/test_lsp_backend.py -v`
Expected: FAIL with `ImportError: cannot import name LSPGraphQuery`.

- [ ] **Step 3: Implement `LSPGraphQuery`**

Implement `lsp_backend.py` with:
- JSON-RPC over stdio client (`LSPClient`).
- Eager `workspace/symbol` caching.
- Lazy `prepareCallHierarchy` + `incomingCalls` resolution.
- Per-query caching for successes, no caching for errors/timeouts (30s timeout).
- `select_backend(repo_root, language)` lazy manager.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest vulnhunter-fix/tests/test_lsp_backend.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add vulnhunter-fix/vulnhunter_fix/graph/lsp_backend.py vulnhunter-fix/tests/test_lsp_backend.py
git commit -m "feat(graph): implement LSPGraphQuery and session manager"
```

---

### Task 4: Integrate LSP Backend & `reachable_from_entry` into `build_graph.py`

**Files:**
- Modify: `vulnhunter-fix/scripts/build_graph.py:50-180`
- Test: `vulnhunter-fix/tests/test_build_graph_lsp.py`

**Interfaces:**
- Consumes: `VULNFIX_GRAPH_BACKEND` env var, `GraphBackend`, `select_backend`
- Produces: Sidecar JSON output with `graph_backend: "lsp"`, `confidence: "high"`, and `reachable_from_entry` populated

- [ ] **Step 1: Write integration test for `build_graph.py` with LSP backend and entry points**

```python
import json
import subprocess
import os

def test_build_graph_script_lsp_mode(tmp_path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "main.py").write_text("def sink(): pass\ndef entry(): sink()\n")
    
    sidecar_in = tmp_path / "finding.json"
    sidecar_in.write_text(json.dumps([{
        "id": "VULN-1",
        "location": "main.py:1",
        "entry_point": "main.py:2"
    }]))
    
    out_dir = tmp_path / "out"
    env = os.environ.copy()
    env["VULNFIX_GRAPH_BACKEND"] = "lsp"
    
    # Run build_graph.py
    res = subprocess.run([
        "python", "vulnhunter-fix/scripts/build_graph.py",
        "--repo-root", str(repo_dir),
        "--work-dir", str(out_dir),
        "--sidecar-in", str(sidecar_in)
    ], env=env, capture_output=True, text=True)
    assert res.returncode == 0
```

- [ ] **Step 2: Run test to verify failure/missing behavior**

Run: `pytest vulnhunter-fix/tests/test_build_graph_lsp.py -v`
Expected: FAIL or fallback to `grep` backend without `reachable_from_entry` processing.

- [ ] **Step 3: Update `build_graph.py`**

In `scripts/build_graph.py`:
- Parse `VULNFIX_GRAPH_BACKEND` env var (default `auto`).
- When `VULNFIX_GRAPH_BACKEND == "lsp"`, attempt `select_backend` for finding's language.
- Parse `entry_point` format `<file>:<line>` and call `reachable_from` to populate `reachable_from_entry`.
- Fall back to baseline `GraphQuery` and downgrade provenance (`confidence: "low"` / `graph_backend: "grep"`) on LSP failure or query error.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest vulnhunter-fix/tests/test_build_graph_lsp.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add vulnhunter-fix/scripts/build_graph.py vulnhunter-fix/tests/test_build_graph_lsp.py
git commit -m "feat(scripts): wire LSP graph backend and entry_point reachability into build_graph.py"
```

---

### Task 5: End-to-End Verification & Real Substrate Comparison Test

**Files:**
- Modify: `vulnhunter-fix/tests/test_lsp_backend.py` (add Pyright live test marked `lsp_live`)

- [ ] **Step 1: Run full pytest suite across `vulnhunter-fix`**

Run: `cd vulnhunter-fix && python -m pytest -v`
Expected: All tests PASS.

- [ ] **Step 2: Test live execution on `/tmp/test-fastapi`**

Run:
```bash
VULNFIX_GRAPH_BACKEND=lsp python vulnhunter-fix/scripts/build_graph.py \
  --repo-root /tmp/test-fastapi \
  --work-dir /Users/praveenp/gitea/test/withLSP
```
Verify output json reports `backend: "lsp"` (or graceful fallback if Pyright is not installed).

- [ ] **Step 3: Commit final plan & test artifacts**

```bash
git add docs/superpowers/plans/2026-07-18-lsp-backend-plan.md
git commit -m "docs: add implementation plan for LSP backend in vulnhunter-fix"
```
