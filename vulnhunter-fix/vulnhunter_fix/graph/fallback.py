"""Grep-based fallback for the graph query API.

Used when graphify is unavailable at runtime OR the build step failed
(REQ-GRA-006). Every query returns a `GraphDocument` shape with
`backend="grep"` and `confidence="low"`, so downstream callers can tell
they're operating on structurally-shallow data (validator matching relaxes
to token-based per REQ-GRA-020).

The fallback covers only the subset of primitives needed to keep the
verification table from crashing on grep-only data.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .schema import Backend, Confidence, Edge, GraphDocument, Node, SCHEMA_VERSION
from .config import iter_source_files, language_for_path


CALL_PATTERN_LANG = {
    "python": re.compile(r"^\s*def\s+(\w+)\s*\("),
    "go": re.compile(r"^\s*func\s+(?:\([^)]*\)\s+)?(\w+)\s*\("),
    "java": re.compile(r"^\s*(?:public|private|protected|static)?\s*[\w<>,\s]+\s+(\w+)\s*\("),
    "typescript": re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\("),
    "javascript": re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\("),
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def build_fallback_graph(root: Path, content_hash: str) -> GraphDocument:
    """Grep-and-glob a minimal graph document without touching graphify.

    File enumeration goes through ``config.iter_source_files`` — single
    source of truth, with all permission guards centralized there.
    """
    nodes: dict[str, Node] = {}
    for path in iter_source_files(root):
        try:
            rel = str(path.relative_to(root))
        except (OSError, ValueError):
            continue
        language = language_for_path(path) or "unknown"
        pat = CALL_PATTERN_LANG.get(language)
        if not pat:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            m = pat.match(line)
            if not m:
                continue
            symbol = m.group(1)
            node_id = f"{rel}:{symbol}"
            nodes[node_id] = Node(
                id=node_id,
                kind="function",
                name=symbol,
                file=rel,
                line=lineno,
                qualified_name=node_id,
                language=language,
            )

    return GraphDocument(
        schema_version=SCHEMA_VERSION,
        graphify_version=None,
        generated_at=_now(),
        backend="grep",
        confidence="low",
        content_hash=content_hash,
        root_dir=str(root),
        nodes=nodes,
        edges=[],  # grep fallback does not resolve call edges
    )


_ENCLOSING_FN_RE = re.compile(
    r"^\s*(?:def|func|fn|function|public|private|protected|static|async)"
    r"[\w<>\[\],\s\*&]*?\s(\w+)\s*\(",
)


def _enclosing_symbol(file_path: Path, line_no: int) -> str | None:
    """Best-effort: walk backward from `line_no` to find the enclosing function name.

    Language-agnostic — matches `def`, `func`, `fn`, `function`, plus Java-style
    method declarations. Returns the symbol name or None if not detectable.
    """
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    lines = text.splitlines()
    for i in range(min(line_no - 1, len(lines) - 1), -1, -1):
        m = _ENCLOSING_FN_RE.match(lines[i])
        if m:
            return m.group(1)
    return None


def grep_callers_of(root: Path, symbol_name: str) -> list[str]:
    """Return best-effort `file:symbol` callers by regex-matching invocations.

    Confidence "low" per REQ-GRA-006. Case-insensitive symbol comparison per
    REQ-GRA-020 fallback semantics — grep runs with `-i`, and the returned
    symbols are normalized to whatever spelling appears in the source.
    """
    root_abs = root.resolve()
    pattern = rf"\b{re.escape(symbol_name)}\s*\("
    grep = shutil.which("grep")
    if grep is None:
        return []
    try:
        # Inputs: `symbol_name` is a symbol name from AST or scan output,
        # here re.escape'd before being embedded into the regex; `root_abs`
        # is a resolved Path. argv is a list, no shell interpretation.
        proc = subprocess.run(  # nosec B603
            [grep, "-rIin", "--include=*.py", "--include=*.go", "--include=*.java",
             "--include=*.ts", "--include=*.tsx", "--include=*.js", "-E", pattern, str(root_abs)],
            capture_output=True, text=True, check=False, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    hits: list[str] = []
    for line in proc.stdout.splitlines():
        parts = line.split(":", 2)
        if len(parts) < 3:
            continue
        abs_path = Path(parts[0])
        try:
            file_rel = str(abs_path.relative_to(root_abs))
        except ValueError:
            file_rel = parts[0]
        try:
            line_no = int(parts[1])
        except ValueError:
            continue
        symbol = _enclosing_symbol(abs_path, line_no)
        if symbol:
            hits.append(f"{file_rel}:{symbol}")
    return sorted(set(hits))
