"""Public graph schema — the shape VF code sees, decoupled from graphify.

`graph.json` on disk is a dict with:

    {
      "schema_version": "1",
      "graphify_version": "0.8.51",
      "generated_at": "ISO8601 UTC",
      "backend": "ast" | "grep",
      "confidence": "high" | "low",
      "content_hash": "sha256:...",
      "root_dir": "/abs/path",
      "nodes": {                # keyed by stable node id
          "<id>": {
              "kind": "function" | "class" | "module" | "file",
              "name": "authenticate",
              "file": "src/auth/login.py",
              "line": 42,
              "qualified_name": "src/auth/login.py:authenticate",
              "language": "python"
          },
          ...
      },
      "edges": [
          {"from": "<id>", "to": "<id>", "kind": "calls" | "imports" | "depends_on" | "defines"},
          ...
      ]
    }

Wrapping upstream graphify output into this stable schema is the point of
REQ-GRA-002: if graphify's on-disk shape changes, only `build.py` needs a
patch — every caller of `query.py` is insulated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


SCHEMA_VERSION = "1"

NodeKind = Literal["function", "class", "module", "file"]
EdgeKind = Literal["calls", "imports", "depends_on", "defines"]
Backend = Literal["ast", "grep", "none"]
Confidence = Literal["high", "low"]


@dataclass(frozen=True)
class Node:
    id: str
    kind: str
    name: str
    file: str
    line: int
    qualified_name: str
    language: str


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    kind: str


@dataclass
class GraphDocument:
    schema_version: str
    graphify_version: str | None
    generated_at: str
    backend: str
    confidence: str
    content_hash: str
    root_dir: str
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "graphify_version": self.graphify_version,
            "generated_at": self.generated_at,
            "backend": self.backend,
            "confidence": self.confidence,
            "content_hash": self.content_hash,
            "root_dir": self.root_dir,
            "nodes": {
                nid: {
                    "kind": n.kind,
                    "name": n.name,
                    "file": n.file,
                    "line": n.line,
                    "qualified_name": n.qualified_name,
                    "language": n.language,
                }
                for nid, n in self.nodes.items()
            },
            "edges": [{"from": e.src, "to": e.dst, "kind": e.kind} for e in self.edges],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "GraphDocument":
        nodes = {
            nid: Node(
                id=nid,
                kind=nd["kind"],
                name=nd["name"],
                file=nd["file"],
                line=nd.get("line", 0),
                qualified_name=nd.get("qualified_name", f"{nd['file']}:{nd['name']}"),
                language=nd.get("language", ""),
            )
            for nid, nd in (data.get("nodes") or {}).items()
        }
        edges = [
            Edge(src=e.get("from") or e["src"], dst=e.get("to") or e["dst"], kind=e["kind"])
            for e in (data.get("edges") or [])
        ]
        return cls(
            schema_version=data.get("schema_version", SCHEMA_VERSION),
            graphify_version=data.get("graphify_version"),
            generated_at=data.get("generated_at", ""),
            backend=data.get("backend", "ast"),
            confidence=data.get("confidence", "high"),
            content_hash=data.get("content_hash", ""),
            root_dir=data.get("root_dir", ""),
            nodes=nodes,
            edges=edges,
        )
