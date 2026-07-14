"""Graph query API — the primitives VF phases (Plan, Implement, Verify, Sweep) call.

Six primitives forked from Catalyst's graph_query.py (REQ-GRA-007):
    blast_radius(file)
    god_nodes(top_n)
    context_for_file(file)
    changed_impact(files_changed)
    co_changes(file)
    status()

Three security-purpose additions (REQ-GRA-008):
    callers_of(symbol)
    callees_of(symbol)
    reachable_from(input_file, input_line, sink_symbol)

The query layer is pure-stdlib: it operates on the JSON `GraphDocument`
loaded from cache. Callers must respect the returned confidence field
(REQ-GRA-020: strict vs. token match in validate-verification.py depends
on it).
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Iterable

from .fallback import grep_callers_of
from .schema import GraphDocument


def load_graph(cache_path: str | Path) -> GraphDocument:
    path = Path(cache_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    return GraphDocument.from_dict(data)


class GraphQuery:
    """Read-only view over a GraphDocument with the VF query primitives."""

    def __init__(self, doc: GraphDocument, source_root: str | Path | None = None) -> None:
        self._doc = doc
        self._source_root = Path(source_root).resolve() if source_root else Path(doc.root_dir).resolve()
        self._by_file: dict[str, list[str]] = defaultdict(list)
        for nid, node in doc.nodes.items():
            self._by_file[node.file].append(nid)
        self._out_edges: dict[str, list[tuple[str, str]]] = defaultdict(list)
        self._in_edges: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for edge in doc.edges:
            self._out_edges[edge.src].append((edge.dst, edge.kind))
            self._in_edges[edge.dst].append((edge.src, edge.kind))

    # ---- inherited primitives (REQ-GRA-007) ----

    def status(self) -> dict:
        return {
            "backend": self._doc.backend,
            "confidence": self._doc.confidence,
            "graphify_version": self._doc.graphify_version,
            "schema_version": self._doc.schema_version,
            "content_hash": self._doc.content_hash,
            "node_count": len(self._doc.nodes),
            "edge_count": len(self._doc.edges),
        }

    def context_for_file(self, file: str) -> dict:
        node_ids = self._by_file.get(file, [])
        return {
            "confidence": self._doc.confidence,
            "file": file,
            "nodes": [self._doc.nodes[nid].name for nid in node_ids],
            "imports": [dst for nid in node_ids for dst, kind in self._out_edges.get(nid, []) if kind == "imports"],
            "importers": [src for nid in node_ids for src, kind in self._in_edges.get(nid, []) if kind == "imports"],
        }

    def _resolve_file_key(self, ref: str) -> str:
        """Accept a bare file path OR a `file:symbol`/`file:line` reference
        and return the key `_by_file` is indexed by (a bare file path).

        callers_of() already accepts the qualified form via _match_symbol;
        blast_radius keys on _by_file, so a `file:symbol` sink (what
        build_graph.py derives from a finding's location) never matched and
        every sidecar's blast_radius came back empty (peer review major).
        """
        if ref in self._by_file:
            return ref
        head = ref.rpartition(":")[0]
        if head and head in self._by_file:
            return head
        return ref

    def blast_radius(self, file: str, max_depth: int = 3) -> dict:
        file = self._resolve_file_key(file)
        seen: set[str] = set()
        frontier: deque[tuple[str, int]] = deque()
        for nid in self._by_file.get(file, []):
            frontier.append((nid, 0))
        result_files: set[str] = set()
        while frontier:
            nid, depth = frontier.popleft()
            if nid in seen or depth > max_depth:
                continue
            seen.add(nid)
            node = self._doc.nodes.get(nid)
            if node:
                result_files.add(node.file)
            for src, _kind in self._in_edges.get(nid, []):
                frontier.append((src, depth + 1))
        result_files.discard(file)
        return {"confidence": self._doc.confidence, "file": file, "reachable_files": sorted(result_files)}

    def god_nodes(self, top_n: int = 10) -> list[dict]:
        degrees = Counter()
        for nid in self._doc.nodes:
            degrees[nid] = len(self._out_edges.get(nid, [])) + len(self._in_edges.get(nid, []))
        ranked = degrees.most_common(top_n)
        return [
            {
                "id": nid,
                "name": self._doc.nodes[nid].name,
                "file": self._doc.nodes[nid].file,
                "degree": deg,
            }
            for nid, deg in ranked
            if nid in self._doc.nodes
        ]

    def changed_impact(self, files_changed: Iterable[str]) -> dict:
        impacted: set[str] = set()
        for f in files_changed:
            impacted.update(self.blast_radius(f)["reachable_files"])
        return {
            "confidence": self._doc.confidence,
            "files_changed": sorted(set(files_changed)),
            "impacted_files": sorted(impacted),
        }

    def co_changes(self, file: str, cutoff: int = 5) -> list[str]:
        """Placeholder: without git-history integration, return blast-radius top hits.

        Catalyst's co_changes reads git log; VF's fork keeps the API surface
        stable and returns structural neighbors as a proxy. Upgrade to
        history-aware in a later polish milestone (deferred).
        """
        return self.blast_radius(file)["reachable_files"][:cutoff]

    # ---- security-purpose additions (REQ-GRA-008) ----

    def callers_of(self, symbol: str) -> list[str]:
        """Return `file:symbol` entries that call the given symbol.

        `symbol` accepts either a bare name ("authenticate") or a qualified
        `file:symbol`. Under `backend == "ast"` this reads from the graph's
        call edges; under `backend == "grep"` it delegates to
        `fallback.grep_callers_of` and returns low-confidence results.
        """
        if self._doc.backend == "grep":
            return grep_callers_of(self._source_root, symbol.split(":", 1)[-1])

        target_ids = self._match_symbol(symbol)
        results: set[str] = set()
        for tid in target_ids:
            for src, kind in self._in_edges.get(tid, []):
                if kind != "calls":
                    continue
                src_node = self._doc.nodes.get(src)
                if src_node:
                    results.add(f"{src_node.file}:{src_node.name}")
        return sorted(results)

    def callees_of(self, symbol: str) -> list[str]:
        if self._doc.backend == "grep":
            return []
        target_ids = self._match_symbol(symbol)
        results: set[str] = set()
        for tid in target_ids:
            for dst, kind in self._out_edges.get(tid, []):
                if kind != "calls":
                    continue
                dst_node = self._doc.nodes.get(dst)
                if dst_node:
                    results.add(f"{dst_node.file}:{dst_node.name}")
        return sorted(results)

    def reachable_from(self, input_file: str, input_line: int, sink_symbol: str) -> bool:
        """Best-effort reachability from an entry point to a sink symbol.

        Under grep backend we cannot resolve control flow — return False
        with confidence low. Callers must check `status().confidence` and
        decline to gate on this result under low confidence.
        """
        if self._doc.backend == "grep":
            return False
        sink_ids = set(self._match_symbol(sink_symbol))
        if not sink_ids:
            return False
        # Honor input_line: start from the symbol enclosing the tainted line,
        # not every symbol in the file. Ignoring input_line made reachability
        # file-level → false positives (segment-review S1a, F9). Fall back
        # to file-level only when the line can't be resolved to a symbol.
        enclosing = self._symbol_at_line(input_file, input_line)
        if enclosing is not None:
            entry_ids = [enclosing]
        else:
            entry_ids = [nid for nid in self._by_file.get(input_file, [])]
        seen: set[str] = set()
        frontier: deque[str] = deque(entry_ids)
        while frontier:
            nid = frontier.popleft()
            if nid in seen:
                continue
            seen.add(nid)
            if nid in sink_ids:
                return True
            for dst, kind in self._out_edges.get(nid, []):
                if kind == "calls":
                    frontier.append(dst)
        return False

    # ---- internals ----

    def _symbol_at_line(self, file: str, line: int) -> str | None:
        """Resolve a `file:line` location to the enclosing symbol's node id.

        Nodes carry only a definition (start) line, not a range, so we use the
        standard enclosing-symbol heuristic: the symbol in `file` whose def
        line most closely precedes `line`. Used so a `file:line` sink (what
        build_graph derives from a finding's raw location) resolves to a real
        symbol instead of returning empty (segment-review S1a, F9/F10).
        """
        best: str | None = None
        best_line = -1
        for nid in self._by_file.get(file, []):
            node = self._doc.nodes.get(nid)
            if node and node.line <= line and node.line > best_line:
                best = nid
                best_line = node.line
        return best

    def _match_symbol(self, symbol: str) -> list[str]:
        if ":" in symbol:
            if symbol in self._doc.nodes:
                return [symbol]
            # Match on qualified_name: real graphify node ids are
            # module-qualified (e.g. `auth.mod:check_password`) and differ
            # from the `file:symbol` form a finding carries — the raw-id-only
            # match returned [] and masked the fix (12-seg review S2, CRITICAL).
            by_qual = [nid for nid, node in self._doc.nodes.items()
                       if node.qualified_name == symbol]
            if by_qual:
                return by_qual
            # `file:line` form (line is all digits) — resolve to the enclosing
            # symbol rather than returning [] for a non-node-id.
            file, _, tail = symbol.rpartition(":")
            if file and tail.isdigit():
                nid = self._symbol_at_line(file, int(tail))
                return [nid] if nid else []
            # `file:symbol` where qualified_name didn't match verbatim — fall
            # back to the bare symbol name scoped to that file (path-form drift
            # between the finding location and the graph's file field).
            if file and tail:
                scoped = [nid for nid, node in self._doc.nodes.items()
                          if node.name == tail and node.file == file]
                if scoped:
                    return scoped
            return []
        return [nid for nid, node in self._doc.nodes.items() if node.name == symbol]
