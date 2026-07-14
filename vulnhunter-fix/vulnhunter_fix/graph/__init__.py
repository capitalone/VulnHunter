"""VulnHunter-Fix graph substrate.

Wraps the `graphify` PyPI package (distribution name `graphifyy`) into a
stable public API that VulnHunter-Fix code uses. The wrapper isolates VF
from upstream graphify schema drift (REQ-GRA-002) and exposes an
AST-only backend (REQ-GRA-003) with a grep fallback (REQ-GRA-006).

Public surface:
    from vulnhunter_fix.graph import build_or_load, GraphQuery, load_graph
"""

from __future__ import annotations

from .build import build_or_load, build_graph
from .query import GraphQuery, load_graph
from .config import GRAPHIFY_VERSION_RANGE

__all__ = [
    "build_or_load",
    "build_graph",
    "GraphQuery",
    "load_graph",
    "GRAPHIFY_VERSION_RANGE",
]
