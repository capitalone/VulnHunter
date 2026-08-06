import os
import sys
import subprocess
import pytest
from pathlib import Path
from vulnhunter_fix.graph.lsp_backend import LSPGraphQuery, select_backend

def test_lsp_graph_query_with_mock_server():
    server_script = str(Path(__file__).parent / "mock_lsp_server.py")
    proc = subprocess.Popen(
        [sys.executable, server_script],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0
    )
    
    try:
        query = LSPGraphQuery(proc, repo_root="/tmp/test-repo", language="python")
        callers = query.callers_of("auth_sink")
        assert len(callers) == 1
        assert callers[0]["symbol"] == "login_entry"
        assert query.status()["backend"] == "lsp"
        
        reachable = query.reachable_from("src/main.py:login_entry", 5, "src/auth.py:auth_sink")
        assert reachable is True
    finally:
        if proc.stdin:
            proc.stdin.close()
        if proc.stdout:
            proc.stdout.close()
        if proc.stderr:
            proc.stderr.close()
        proc.terminate()
        proc.wait()
