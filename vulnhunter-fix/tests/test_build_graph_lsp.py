import json
import os
import subprocess
import pytest
from pathlib import Path

def test_build_graph_lsp_and_entry_point(tmp_path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "main.py").write_text("def sink(): pass\ndef entry(): sink()\n")
    
    sidecar_in = tmp_path / "findings.json"
    sidecar_in.write_text(json.dumps([{
        "id": "VULN-001",
        "location": "main.py:sink",
        "entry_point": "main.py:entry"
    }]))
    
    out_dir = tmp_path / "out"
    env = os.environ.copy()
    env["VULNFIX_GRAPH_BACKEND"] = "lsp"
    
    res = subprocess.run([
        "python3", "scripts/build_graph.py",
        "--repo-root", str(repo_dir),
        "--work-dir", str(out_dir),
        "--findings", str(sidecar_in)
    ], env=env, capture_output=True, text=True, cwd=str(Path(__file__).parent.parent))
    
    assert res.returncode in (0, 3)
    sidecar_file = out_dir / "graph_context" / "VULN-001.json"
    assert sidecar_file.exists()
    
    sidecar = json.loads(sidecar_file.read_text())
    assert "graph_backend" in sidecar
    assert "reachable_from_entry" in sidecar
