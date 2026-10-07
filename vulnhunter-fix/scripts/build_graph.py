#!/usr/bin/env python3
"""Build a graph for a repository and (optionally) per-finding sidecars.

Wraps ``vulnhunter_fix.graph.build_or_load`` and
``vulnhunter_fix.graph.query.GraphQuery`` into a phase-callable CLI. Consumed
by ``prompts/plan.md`` after finding selection and by any downstream phase
that needs a graph but can't assume one exists yet.

Outputs:
- ``<work-dir>/cache/graph.json``  — the graph document (REQ-GRA-005).
- ``<work-dir>/graph_context/<VULN>.json``  — per-finding sidecar
  (REQ-GRA-015, REQ-CWE-008 schema). Only when ``--findings`` is passed.

Usage:
    build_graph.py --repo-root <path> --work-dir <path> [--findings <path>]

Exit codes:
    0 — graph built (or loaded from cache), sidecars written if requested.
    2 — I/O or usage error.
    3 — graph build fell through to grep fallback AND sidecar mode was
        requested (caller may still proceed; sidecars will carry
        ``confidence: "low"``).
"""
from __future__ import annotations

import _skill_bootstrap  # noqa: F401  — adds bundled .venv site-packages to sys.path

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vulnhunter_fix.graph.build import build_or_load
from vulnhunter_fix.graph.query import GraphQuery
from vulnhunter_fix.graph.lsp_backend import select_backend
from vulnhunter_fix.graph.config import language_for_path


VULN_ID_RE = re.compile(r"VULN-\d+", re.IGNORECASE)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sink_symbol_from_finding(finding: dict) -> str | None:
    """Derive the ``file:symbol`` sink from a finding's location.

    Findings typically carry a ``location`` like ``src/auth/login.py:42``
    or ``src/auth/login.py:authenticate``. We prefer the symbol form; if
    only a line is given, we return the ``file:line`` form and let the
    graph query fall back to a line-anchored search.
    """
    loc = finding.get("location") or finding.get("sink") or ""
    if not loc:
        # Fall back to files[0]:root_cause-first-symbol if present.
        files = finding.get("files") or []
        if not files:
            return None
        loc = files[0]
    return str(loc).strip()


def _build_sidecar(
    query: GraphQuery,
    finding: dict,
    doc_backend: str,
    doc_version: str | None,
    repo_root: Path | None = None,
    opt_backend: str = "auto"
) -> dict:
    """Emit one triage-schema.json-compatible sidecar for a single finding."""
    vuln_id = finding.get("id") or finding.get("vuln_id") or ""
    m = VULN_ID_RE.search(str(vuln_id))
    if not m:
        raise ValueError(f"finding missing VULN-N id: {finding!r}")
    vuln_id = m.group(0).upper()

    sink_symbol = _sink_symbol_from_finding(finding)
    active_query: GraphQuery | Any = query
    active_backend = doc_backend

    if opt_backend == "lsp" and repo_root and sink_symbol:
        file_path = sink_symbol.split(":")[0]
        lang = language_for_path(repo_root / file_path) or "python"
        lsp_q = select_backend(str(repo_root), lang)
        if lsp_q:
            active_query = lsp_q
            active_backend = "lsp"

    callers: list[str] = []
    blast_radius: list[str] = []
    reachable_from_entry: bool | None = None

    if sink_symbol:
        try:
            raw_callers = active_query.callers_of(sink_symbol) or []
            if isinstance(raw_callers, list):
                callers = []
                for c in raw_callers:
                    if isinstance(c, dict):
                        file_part = c.get("file") or ""
                        sym_part = c.get("symbol") or ""
                        callers.append(f"{file_part}:{sym_part}" if file_part and sym_part else str(c))
                    elif c:
                        callers.append(str(c))
        except Exception:
            if active_backend == "lsp":
                active_backend = "grep"
                active_query = query
            callers = []

        try:
            br = active_query.blast_radius(sink_symbol) or {}
            blast_radius = list(br.get("reachable_files") or br.get("affected_files") or [])
        except Exception:
            blast_radius = []

        entry_point = finding.get("entry_point")
        if entry_point and isinstance(entry_point, str):
            try:
                parts = entry_point.split(":")
                file_part = parts[0]
                line_part = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
                reachable_from_entry = bool(active_query.reachable_from(file_part, line_part, sink_symbol))
            except Exception:
                reachable_from_entry = None

    confidence = "high" if active_backend in ("ast", "lsp") else "low"
    graph_backend = active_backend if active_backend in ("ast", "grep", "lsp", "none") else "grep"

    sidecar = {
        "vuln_id": vuln_id,
        "confidence": confidence,
        "sink_symbol": sink_symbol,
        "callers_of_sink": callers,
        "blast_radius": blast_radius,
        "reachable_from_entry": reachable_from_entry,
        "graph_backend": graph_backend,
        "generated_at": _now(),
        "graphifyy_version": doc_version if confidence == "high" and active_backend == "ast" else None,
    }
    return sidecar


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Build graph + optional per-finding sidecars (REQ-GRA-002..020).")
    ap.add_argument("--repo-root", required=True, help="Absolute path to the target repo checkout.")
    ap.add_argument("--work-dir", required=True,
                    help="Where to write cache/graph.json and graph_context/. "
                         "In-place mode: <repo>/.vulnhunter-fix/. Fork mode: .work/<repo>/.")
    ap.add_argument("--findings", default=None,
                    help="Path to findings.json (single object or {\"findings\": [...]}). "
                         "When set, emits one sidecar per finding under graph_context/.")
    args = ap.parse_args(argv[1:])

    repo_root = Path(args.repo_root).resolve()
    work_dir = Path(args.work_dir).resolve()
    if not repo_root.is_dir():
        print(f"error: --repo-root is not a directory: {repo_root}", file=sys.stderr)
        return 2

    cache_dir = work_dir / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    graph_path = cache_dir / "graph.json"

    doc = build_or_load(str(repo_root), graph_path)
    print(json.dumps({
        "graph": str(graph_path),
        "backend": doc.backend,
        "confidence": doc.confidence,
        "nodes": len(doc.nodes),
        "edges": len(doc.edges),
    }, indent=2))

    if args.findings is None:
        return 0

    findings_path = Path(args.findings)
    if not findings_path.is_file():
        print(f"error: --findings path not readable: {findings_path}", file=sys.stderr)
        return 2

    try:
        payload = json.loads(findings_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"error: findings JSON parse failed: {exc}", file=sys.stderr)
        return 2

    if isinstance(payload, dict) and isinstance(payload.get("findings"), list):
        findings = payload["findings"]
    elif isinstance(payload, list):
        findings = payload
    elif isinstance(payload, dict) and payload.get("id"):
        findings = [payload]
    else:
        print("error: findings payload must be a list, a {findings: [...]} object, "
              "or a single finding with an 'id' field.", file=sys.stderr)
        return 2

    sidecar_dir = work_dir / "graph_context"
    sidecar_dir.mkdir(parents=True, exist_ok=True)

    opt_backend = os.environ.get("VULNFIX_GRAPH_BACKEND", "auto").lower()
    query = GraphQuery(doc)
    written: list[str] = []
    errors: list[str] = []
    for finding in findings:
        try:
            sidecar = _build_sidecar(
                query, finding, doc.backend, doc.graphify_version,
                repo_root=repo_root, opt_backend=opt_backend
            )
        except ValueError as exc:
            errors.append(str(exc))
            continue
        sidecar_path = sidecar_dir / f"{sidecar['vuln_id']}.json"
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")
        written.append(str(sidecar_path))

    print(json.dumps({
        "sidecars_written": len(written),
        "sidecars_dir": str(sidecar_dir),
        "errors": errors,
    }, indent=2))

    if doc.backend != "ast" and written:
        # Not a hard fail — sidecars are still valid — but signal it so
        # callers can decide whether to warn the operator.
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
