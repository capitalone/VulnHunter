"""Graph builder — wraps graphify AST extraction into the VF schema.

REQ-GRA-002 / REQ-GRA-003 / REQ-GRA-005 / REQ-GRA-006:
- Uses graphify (dist name graphifyy) for extraction.
- AST-only backend (never invokes cloud LLMs).
- Content-hash cache keying (not TTL).
- On any failure, degrades to fallback.py grep mode with confidence=low.

Usage:
    doc = build_or_load(root_dir="/abs/path/repo", cache_path="/abs/.work/repo/cache/graph.json")

The wrapper insulates callers from the graphify import path (`import
graphify`, though the PyPI dist is `graphifyy`). Callers should only see
`GraphDocument` and use `query.GraphQuery`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from .config import check_backend_isolation, iter_source_files, language_for_path
from .fallback import build_fallback_graph
from .schema import Backend, Confidence, Edge, GraphDocument, Node, SCHEMA_VERSION


log = logging.getLogger(__name__)


def _graphify_parallel() -> bool:
    """Decide whether graphify.extract() may spawn a ProcessPoolExecutor.

    Sequential is the safer default on macOS because
    ``concurrent.futures.ProcessPoolExecutor.__init__`` calls
    ``os.sysconf("SC_SEM_NSEMS_MAX")`` which the macOS Claude Code sandbox
    blocks with ``PermissionError: Operation not permitted``. That aborts
    the entire extract and forces a grep fallback for the wrong reason
    (nothing was wrong with the source — the parallel harness just
    couldn't initialize). Catalyst hit and documented this same case;
    we honor the same ``GRAPHIFY_PARALLEL`` env override.

    Set ``GRAPHIFY_PARALLEL=1`` (or ``true``) to force parallel;
    ``GRAPHIFY_PARALLEL=0`` (or ``false``) to force sequential. Unset:
    defaults to sequential on Darwin, parallel elsewhere.
    """
    override = os.environ.get("GRAPHIFY_PARALLEL", "").strip().lower()
    if override in ("1", "true", "yes"):
        return True
    if override in ("0", "false", "no"):
        return False
    return sys.platform != "darwin"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _content_hash(root: Path) -> str:
    """Stable content hash over source files (REQ-GRA-005).

    Uses the shared ``iter_source_files`` walker (defined in ``config.py``)
    so this stays in sync with the fallback path. Per-file OSError is
    swallowed — a file we can't read shouldn't invalidate the whole cache.
    Files are hashed in sorted order so the key is independent of filesystem
    walk order — two identical repos must produce the same hash (REQ-GRA-005;
    unsorted rglob order caused spurious cache invalidation, synth review S1).
    """
    h = hashlib.sha256()
    for p in sorted(iter_source_files(root)):
        try:
            h.update(str(p.relative_to(root)).encode("utf-8"))
            h.update(b"\0")
            h.update(p.read_bytes())
            h.update(b"\0")
        except OSError:
            continue
    return "sha256:" + h.hexdigest()


def _load_cache_if_valid(cache_path: Path, expected_hash: str) -> GraphDocument | None:
    if not cache_path.exists():
        return None
    try:
        data = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if data.get("content_hash") != expected_hash:
        return None
    if data.get("schema_version") != SCHEMA_VERSION:
        return None
    return GraphDocument.from_dict(data)


def _save_cache(cache_path: Path, doc: GraphDocument) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(doc.to_dict(), indent=2), encoding="utf-8")


def _try_graphify_build(root: Path, content_hash: str) -> GraphDocument | None:
    """Attempt a graphify AST-only build. Returns None on any failure (REQ-GRA-006)."""
    isolation_violations = check_backend_isolation()
    if isolation_violations:
        log.warning(
            "graph.build: backend isolation not guaranteed; cloud LLM env vars set: %s. "
            "Falling back to grep mode. Unset variables and re-run for AST mode.",
            ", ".join(isolation_violations),
        )
        return None

    try:
        import graphify  # type: ignore
        from graphify.detect import detect as graphify_detect  # type: ignore
    except ImportError:
        log.warning("graph.build: graphify import failed; using grep fallback.")
        return None

    # Use graphify's own file enumerator — it honors .gitignore / .graphifyignore
    # and pre-filters files it can't or shouldn't extract from (secrets, binaries,
    # unreadable paths). Doing our own rglob() here hands graphify files it will
    # reject and gets us PermissionError on sandbox-blocked entries.
    try:
        detected = graphify_detect(root)
    except Exception as exc:  # pragma: no cover - graphify runtime error
        log.warning("graph.build: graphify.detect raised %r; falling back.", exc)
        return None

    code_files = [Path(f) for f in (detected.get("files") or {}).get("code", []) or []]
    if not code_files:
        log.warning(
            "graph.build: graphify.detect found no code files under %s "
            "(skipped=%d); falling back.",
            root, len(detected.get("skipped_sensitive") or []),
        )
        return None

    try:
        raw_nodes = graphify.extract(code_files, parallel=_graphify_parallel())
    except TypeError:
        # Older graphify variants without a ``parallel`` kwarg — fall back
        # to the positional form. Second TypeError layer defends against a
        # variant that expects a stringified path list.
        try:
            raw_nodes = graphify.extract(code_files)
        except TypeError:
            try:
                raw_nodes = graphify.extract([str(p) for p in code_files])
            except Exception as exc:  # pragma: no cover - graphify runtime error
                log.warning("graph.build: graphify.extract(str-list) raised %r; falling back.", exc)
                return None
        except Exception as exc:  # pragma: no cover - graphify runtime error
            log.warning("graph.build: graphify.extract raised %r; falling back.", exc)
            return None
    except Exception as exc:  # pragma: no cover - graphify runtime error
        log.warning("graph.build: graphify.extract raised %r; falling back.", exc)
        return None

    version = getattr(graphify, "__version__", None) or "unknown"
    nodes: dict[str, Node] = {}
    edges: list[Edge] = []
    for entry in _iter_normalized_graphify_entities(raw_nodes, root):
        nodes[entry.id] = entry
    for edge in _iter_normalized_graphify_edges(raw_nodes):
        edges.append(edge)

    return GraphDocument(
        schema_version=SCHEMA_VERSION,
        graphify_version=str(version),
        generated_at=_now(),
        backend="ast",
        confidence="high",
        content_hash=content_hash,
        root_dir=str(root),
        nodes=nodes,
        edges=edges,
    )


_RELATION_MAP = {
    "contains": "defines",
    "defines": "defines",
    "calls": "calls",
    "imports": "imports",
    "depends_on": "depends_on",
    "references": "calls",
    "uses": "calls",
}

# Node kinds graphify may emit that are NOT code/structure — skipped during
# normalization so they don't pollute god_nodes/counts or leak prose into
# graph.json (12-seg review S2 MEDIUM).
_NON_CODE_NODE_KINDS = frozenset({
    "docstring", "comment", "string", "rationale", "literal", "annotation",
})


def _parse_source_location(loc) -> int:
    """Graphify writes 'L42' — extract the integer."""
    if isinstance(loc, int):
        return loc
    if not isinstance(loc, str):
        return 0
    s = loc.lstrip("Ll")
    try:
        return int(s.split(":", 1)[0])
    except (ValueError, TypeError):
        return 0


def _iter_normalized_graphify_edges(raw):
    """Yield VF Edge objects from graphify's raw output."""
    if isinstance(raw, dict):
        source = raw.get("edges") or []
    elif hasattr(raw, "edges"):
        source = getattr(raw, "edges") or []
    else:
        return
    for item in source:
        if not isinstance(item, dict):
            continue
        src = item.get("source") or item.get("from") or item.get("src")
        dst = item.get("target") or item.get("to") or item.get("dst")
        if not src or not dst:
            continue
        relation = str(item.get("relation") or item.get("kind") or "calls").lower()
        kind = _RELATION_MAP.get(relation, relation)
        yield Edge(src=str(src), dst=str(dst), kind=kind)


def _iter_normalized_graphify_entities(raw, root: Path):
    """Normalize whatever graphify.extract() returns into VF Node objects.

    graphify 0.8.x returns a dict with ``nodes`` and ``edges`` keys. Each
    node looks like::

        {"id": "app_foo", "label": "foo()", "source_file": "/abs/app.py",
         "source_location": "L1", "file_type": "code", "_origin": "ast"}

    Older shapes (dicts with ``entities``, or objects with an ``.entities``
    attribute, or bare iterables of ``{file, name, ...}``) are tolerated
    for forward-compat.
    """
    if isinstance(raw, dict):
        source = raw.get("nodes") or raw.get("entities") or []
    elif hasattr(raw, "nodes"):
        source = getattr(raw, "nodes") or []
    elif hasattr(raw, "entities"):
        source = getattr(raw, "entities") or []
    else:
        source = raw if hasattr(raw, "__iter__") else []

    for item in source:
        if not isinstance(item, dict):
            continue

        # Graphify 0.8.x schema first, then fall back to legacy shapes.
        node_id = item.get("id")
        label = item.get("label") or ""
        raw_file = item.get("source_file") or item.get("file") or item.get("path")
        raw_line = item.get("source_location") or item.get("line") or item.get("lineno") or 0
        raw_name = item.get("name") or item.get("symbol") or label.rstrip("()")
        raw_kind = item.get("kind") or item.get("file_type") or "function"

        # Skip non-code node kinds graphify may emit (docstring / comment /
        # rationale / literal). They pollute god_nodes + node counts and can
        # leak prose into graph.json (12-seg review S2 MEDIUM). Only
        # structural/callable nodes belong in the graph.
        if str(raw_kind).lower() in _NON_CODE_NODE_KINDS:
            continue

        if not raw_file:
            continue
        name = str(raw_name).strip()
        if not name:
            continue

        try:
            rel_file = str(Path(raw_file).resolve().relative_to(root.resolve()))
        except (OSError, ValueError):
            rel_file = str(raw_file)

        # If label ends with "()", it's a function; if the id is the module
        # itself (no underscore separator or label is a filename), it's a
        # module node.
        if raw_kind == "code" or raw_kind == "file":
            if label.endswith("()"):
                kind = "function"
            elif label.endswith(".py") or label.endswith(".go") or label.endswith(".ts") or label.endswith(".tsx") or label.endswith(".java"):
                kind = "module"
            else:
                kind = "function"
        else:
            kind = str(raw_kind)

        line = _parse_source_location(raw_line)
        language = item.get("language") or language_for_path(rel_file) or "unknown"

        final_id = str(node_id) if node_id else f"{rel_file}:{name}"
        qualified = f"{rel_file}:{name}"

        yield Node(
            id=final_id,
            kind=kind,
            name=name,
            file=rel_file,
            line=line,
            qualified_name=qualified,
            language=language,
        )


def build_graph(root_dir: str | Path) -> GraphDocument:
    """Build a fresh graph (no cache read). Prefers graphify; falls back on failure."""
    root = Path(root_dir).resolve()
    content_hash = _content_hash(root)
    doc = _try_graphify_build(root, content_hash)
    if doc is not None:
        return doc
    return build_fallback_graph(root, content_hash)


def build_or_load(root_dir: str | Path, cache_path: str | Path) -> GraphDocument:
    """Load the cached graph if content-hash matches, else rebuild and cache."""
    root = Path(root_dir).resolve()
    cache = Path(cache_path)
    content_hash = _content_hash(root)
    cached = _load_cache_if_valid(cache, content_hash)
    if cached is not None:
        return cached
    doc = build_graph(root)
    try:
        _save_cache(cache, doc)
    except OSError as exc:
        log.warning("graph.build: cache save failed: %s", exc)
    return doc
