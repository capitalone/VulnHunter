import pytest
from pathlib import Path
from vulnhunter_fix.graph.protocol import GraphBackend
from vulnhunter_fix.graph.query import GraphQuery
from vulnhunter_fix.graph.fallback import build_fallback_graph

def test_graph_query_implements_protocol(tmp_path: Path):
    doc = build_fallback_graph(tmp_path, content_hash="hash")
    query = GraphQuery(doc)
    assert isinstance(query, GraphBackend)
