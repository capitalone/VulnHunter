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
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from vulnhunter_fix.graph.build import build_or_load
from vulnhunter_fix.graph.query import GraphQuery


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


def _build_sidecar(query: GraphQuery, finding: dict, doc_backend: str, doc_version: str | None) -> dict:
    """Emit one triage-schema.json-compatible sidecar for a single finding."""
    vuln_id = finding.get("id") or finding.get("vuln_id") or ""
    m = VULN_ID_RE.search(str(vuln_id))
    if not m:
        raise ValueError(f"finding missing VULN-N id: {finding!r}")
    vuln_id = m.group(0).upper()

    sink_symbol = _sink_symbol_from_finding(finding)
    callers: list[str] = []
    blast_radius: list[str] = []
    if sink_symbol:
        try:
            callers = [c for c in query.callers_of(sink_symbol) or [] if c]
        except Exception:
            callers = []
        try:
            # blast_radius returns {"confidence", "file", "reachable_files": [...]}.
            # list(<dict>) yields the *keys*, not the reachable files — the sidecar
            # then held the three literal key strings instead of file paths.
            br = query.blast_radius(sink_symbol) or {}
            blast_radius = list(br.get("reachable_files") or [])
        except Exception:
            blast_radius = []

    confidence = "high" if doc_backend == "ast" else "low"
    graph_backend = doc_backend if doc_backend in ("ast", "grep", "none") else "grep"

    sidecar = {
        "vuln_id": vuln_id,
        "confidence": confidence,
        "sink_symbol": sink_symbol,
        "callers_of_sink": callers,
        "blast_radius": blast_radius,
        "reachable_from_entry": None,
        "graph_backend": graph_backend,
        "generated_at": _now(),
        "graphifyy_version": doc_version if confidence == "high" else None,
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

    query = GraphQuery(doc)
    written: list[str] = []
    errors: list[str] = []
    for finding in findings:
        try:
            sidecar = _build_sidecar(query, finding, doc.backend, doc.graphify_version)
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
