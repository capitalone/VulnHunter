#!/usr/bin/env python3
"""Root-cause sweep (Phase 3c).

Implements REQ-SWP-001 through REQ-SWP-009. Two-pass algorithm:
    Pass 1 — Symbol pass (graph-anchored via callers_of).
    Pass 2 — Pattern pass (regex fallback per CWE class).

Emits a JSON sweep summary consumed by `vulnhunter_fix.delivery.render_verification_table`
and the ## Sweep Summary template section.

Usage:
    sweep-root-causes.py --repo-root <path> --results-dir <path>
                         --graph <path> --patterns <path> --out <path>
                         [--triage-dir <path>]

SCH-5: `sink_symbol` is a graph fact that lives on `triage-schema.json`
(the sidecar written by Phase 1/2), not on `result-schema.json` (worker
outcome). Sweep loads the triage sidecar for each finding and reads
`sink_symbol` from there; falls back to any `sink_symbol` on the result
(older worker outputs) and finally to a `file_path:cwe` placeholder
that never matches — so pass-1 anchoring is only correct when the
sidecar exists.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


CWE_CLASS_ROUTING = {
    287: "authz", 290: "authz", 306: "authz", 639: "authz",
    862: "authz", 863: "authz", 915: "authz",
    22: "injection", 78: "injection", 79: "injection", 89: "injection",
    94: "injection", 352: "injection", 434: "injection", 502: "injection",
    601: "injection", 611: "injection", 918: "injection",
    295: "crypto", 326: "crypto", 327: "crypto", 328: "crypto",
    330: "crypto", 345: "crypto", 347: "crypto",
    117: "resource", 200: "resource", 362: "resource", 400: "resource",
    532: "resource",
}


def _cwe_int(cwe: str) -> int | None:
    m = re.match(r"CWE-(\d+)$", cwe or "")
    return int(m.group(1)) if m else None


def _unquote(val: str) -> str:
    if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
        return val[1:-1]
    return val


def _strip_inline_comment(val: str) -> str:
    """Strip a trailing YAML `  # ...` comment.

    Uses two-space + hash as the delimiter to avoid mis-parsing `#` chars
    inside regex character classes. This matches the convention used in
    references/sweep-patterns.md and approved-*-{algorithms,key-sources}.yaml.
    """
    if not val:
        return val
    m = re.search(r"\s{2,}#\s", val)
    if m:
        return val[: m.start()].rstrip()
    return val


def _load_patterns(path: Path) -> dict[str, list[str]]:
    """Parse fenced YAML-ish blocks in sweep-patterns.md.

    Each block is delimited by triple-backticks and contains:
        class: <name>
        cwes: [...]
        patterns:
          - '<regex>'  # optional inline comment
    """
    text = path.read_text(encoding="utf-8")
    result: dict[str, list[str]] = {}
    in_fence = False
    current_class: str | None = None
    in_patterns = False
    for raw in text.splitlines():
        if raw.strip().startswith("```"):
            in_fence = not in_fence
            if not in_fence:
                current_class = None
                in_patterns = False
            continue
        if not in_fence:
            continue
        stripped = raw.strip()
        if stripped.startswith("class:"):
            current_class = stripped.split(":", 1)[1].strip()
            result.setdefault(current_class, [])
            in_patterns = False
            continue
        if stripped == "patterns:":
            in_patterns = True
            continue
        if in_patterns and stripped.startswith("- "):
            val = _unquote(_strip_inline_comment(stripped[2:].strip()))
            if val and current_class:
                result[current_class].append(val)
    return result


def _load_graph(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _load_results(results_dir: Path) -> list[dict]:
    findings: list[dict] = []
    if not results_dir.is_dir():
        return findings
    for p in results_dir.glob("*_result.json"):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict) and data.get("status") in (
            "VERIFIED", "VERIFIED_FULL", "VERIFIED_MITIGATION", "VERIFIED_WORKAROUND"
        ):
            findings.append(data)
    return findings


def _load_triage_sidecar(triage_dir: Path | None, vuln_id: str) -> dict:
    """SCH-5: sink_symbol lives on triage-schema.json.

    Sidecars are conventionally written to `<work-dir>/triage/<VULN>.json`
    by Phase 1/2. Return {} if not present so the caller falls back
    gracefully.
    """
    if not triage_dir or not vuln_id:
        return {}
    path = triage_dir / f"{vuln_id}.json"
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def pass1_symbol(graph: dict, sink_symbol: str, routed: list[str],
                 repo_root: "Path | None" = None) -> list[str]:
    """Return callers of sink_symbol not present in routed list (siblings).

    Under a grep-backed graph there are no call edges to walk, so the AST
    hand-walk below would return [] and silently miss every sibling defect
    (synthesized review S8, M3). Delegate those to grep_callers_of — the same
    fallback GraphQuery.callers_of uses — so grep-backed runs still anchor
    pass 1 on real callers.
    """
    if not graph or not sink_symbol:
        return []
    routed_set = set(routed or ())
    if graph.get("backend") == "grep":
        if not repo_root:
            return []
        try:
            from vulnhunter_fix.graph.fallback import grep_callers_of
        except Exception:
            return []
        bare = sink_symbol.split(":")[-1]
        callers = grep_callers_of(Path(repo_root), bare)
        return sorted({c for c in callers if c and c not in routed_set})
    # AST path: hand-walk in-edges to the sink (tolerates from/to and src/dst).
    edges = graph.get("edges", [])
    sinks = [nid for nid, node in (graph.get("nodes") or {}).items()
             if node.get("qualified_name") == sink_symbol or node.get("name") == sink_symbol.split(":")[-1]]
    if not sinks:
        return []
    siblings: list[str] = []
    for e in edges:
        dst = e.get("to") or e.get("dst")
        if dst in sinks and e.get("kind") == "calls":
            src = e.get("from") or e.get("src")
            src_node = (graph.get("nodes") or {}).get(src)
            if src_node:
                ptr = f"{src_node.get('file')}:{src_node.get('name')}"
                if ptr not in routed_set:
                    siblings.append(ptr)
    return sorted(set(siblings))


def _sweep_ok(found: int, remaining: int) -> str:
    """Verification-table column-8 cell (REQ-GRA-013).

    yes (n/a) — the finding had no captured siblings;
    yes       — siblings existed and all were mitigated (remaining == 0);
    no        — siblings remain unmitigated.
    """
    if found == 0:
        return "yes (n/a)"
    return "yes" if remaining == 0 else "no"


# Per-file byte cap for the Pass-2 regex scan. pass2_pattern re-reads the
# repo once per finding; without a cap a single multi-MB generated/vendored
# file (missed by the dir excludes) is re-read and regex-scanned per finding
# on large repos (peer review major). 1 MB comfortably covers hand-written
# source; anything larger is almost certainly generated/minified.
MAX_SWEEP_FILE_BYTES = 1_000_000


def pass2_pattern(repo_root: Path, patterns: list[str], exclude_files: set[str]) -> list[tuple[str, int, str]]:
    """Return (file, line, pattern) triples matching pattern set, skipping exclude_files.

    Uses the shared permission-guarded walker from
    ``vulnhunter_fix.graph.config`` so sandbox-denied entries (``.envrc``
    etc.) skip cleanly. Suffix filter is applied here since sweep's
    file-shape rules are broader than the graph's.
    """
    from vulnhunter_fix.graph.config import safe_walk_files

    hits: list[tuple[str, int, str]] = []
    sweep_suffixes = {".py", ".go", ".java", ".ts", ".tsx", ".js", ".jsx", ".yaml", ".yml", ".tf", ".json"}
    sweep_excluded_dirs = {".git", ".venv", "node_modules", "__pycache__", "build", "dist", "vendor"}
    for path in safe_walk_files(repo_root, excluded_dir_parts=sweep_excluded_dirs):
        try:
            if path.suffix not in sweep_suffixes:
                continue
        except OSError:
            continue
        try:
            rel = str(path.relative_to(repo_root))
        except (OSError, ValueError):
            continue
        if rel in exclude_files:
            continue
        try:
            if path.stat().st_size > MAX_SWEEP_FILE_BYTES:
                continue  # skip oversized (generated/minified/vendored) files
        except OSError:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for pat in patterns:
            try:
                for m in re.finditer(pat, text):
                    line_no = text[:m.start()].count("\n") + 1
                    hits.append((rel, line_no, pat))
            except re.error:
                continue
    return hits


def sweep(args) -> dict:
    repo_root = Path(args.repo_root).resolve()
    graph = _load_graph(Path(args.graph))
    # A None graph means the --graph file is missing or unparseable. Pass-1
    # anchoring is impossible without it, so the sweep is INCOMPLETE and must
    # fail closed rather than silently degrade to regex-only (12-seg review S4).
    graph_ok = graph is not None
    patterns_by_class = _load_patterns(Path(args.patterns))
    findings = _load_results(Path(args.results_dir))
    triage_dir = Path(args.triage_dir) if getattr(args, "triage_dir", None) else None

    fallback_only = (graph or {}).get("backend") == "grep"
    rows: list[dict] = []

    for finding in findings:
        cwe_int = _cwe_int(finding.get("cwe", ""))
        cwe_class = CWE_CLASS_ROUTING.get(cwe_int) if cwe_int else "config"
        # SCH-5: sink_symbol is authoritative on triage sidecar. Load
        # it there first; fall back to any sink_symbol carried on the
        # result (older worker outputs); finally the placeholder that
        # never matches (preserves current-behavior on missing sidecar).
        triage = _load_triage_sidecar(triage_dir, finding.get("vuln_id", ""))
        sink = (
            triage.get("sink_symbol")
            or finding.get("sink_symbol")
            or f"{finding.get('file_path', '')}:{finding.get('cwe', '')}"
        )
        routed = finding.get("callers_routed_through_fix", [])
        files_modified = set(finding.get("files_modified") or [])

        # Always run Pass-1: pass1_symbol handles both AST and grep backends
        # (grep delegates to grep_callers_of). Previously gated behind
        # `if not fallback_only`, which skipped anchoring on grep graphs
        # entirely — regex-only with no anchor (12-seg review S4 HIGH).
        siblings_pass1 = pass1_symbol(graph or {}, sink, routed, repo_root=repo_root)

        pass1_files = {s.split(":", 1)[0] for s in siblings_pass1}
        patterns = patterns_by_class.get(cwe_class, [])
        pass2_hits = pass2_pattern(repo_root, patterns, exclude_files=pass1_files)

        found = len(siblings_pass1) + len(pass2_hits)
        # A sibling is MITIGATED (Path A) when its file is already in this
        # fix's files_modified — it gets amended into the same PR. Others
        # (Path B) REMAIN and force the FULL->MITIGATION downgrade. This is
        # the mechanical downgrade decision that was prose-only ("set by
        # executor" — the executor no longer exists) (12-seg review S4).
        mitigated = (
            sum(1 for s in siblings_pass1 if s.split(":", 1)[0] in files_modified)
            + sum(1 for f, _ln, _p in pass2_hits if f in files_modified)
        )
        remaining = found - mitigated
        sweep_revised = remaining > 0

        row = {
            "root_cause": finding.get("vuln_id"),
            "cwe": finding.get("cwe"),
            "cwe_class": cwe_class,
            "pattern": "graph+regex" if not fallback_only else "regex-only",
            "found": found,
            "captured": found,
            "captured_annotation": "(regex-only)" if fallback_only else "",
            "pass1_siblings": siblings_pass1,
            "pass2_hits": [f"{f}:{ln}" for f, ln, _ in pass2_hits],
            "mitigated": mitigated,
            "remaining": remaining,
            # REQ-SWP-006: an unmitigated Path-B sibling downgrades a
            # previously-FULL fix to MITIGATION. Emitted mechanically here so
            # the delivery/verify flow can apply it without a human step.
            "sweep_revised": sweep_revised,
            "revised_tier": "MITIGATION" if sweep_revised else None,
            # Verification-table column 8 cell (REQ-GRA-013).
            "sweep_ok": _sweep_ok(found, remaining),
        }
        rows.append(row)

    return {
        "generated_by": "sweep-root-causes.py",
        "fallback_only": fallback_only,
        "graph_ok": graph_ok,
        "sweep_incomplete": not graph_ok,
        "rows": rows,
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Root-cause sweep (REQ-SWP-001..009).")
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--results-dir", required=True)
    ap.add_argument("--graph", required=True)
    ap.add_argument("--patterns", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--triage-dir", default=None,
                    help="Directory of triage sidecars (SCH-5); required for reliable Pass-1 anchoring.")
    args = ap.parse_args(argv[1:])

    result = sweep(args)
    Path(args.out).write_text(json.dumps(result, indent=2), encoding="utf-8")
    # Fail closed when the graph was unavailable — pass-1 anchoring could not
    # run, so a "no siblings" result is not trustworthy (12-seg review S4).
    if result.get("sweep_incomplete"):
        print(json.dumps({
            "status": "sweep_incomplete",
            "reason": "graph missing or unparseable — Pass-1 anchoring impossible; "
                      "sweep result is not trustworthy",
            "out": args.out,
        }), file=sys.stderr)
        return 3
    print(json.dumps({"status": "ok", "rows": len(result["rows"]), "out": args.out}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
