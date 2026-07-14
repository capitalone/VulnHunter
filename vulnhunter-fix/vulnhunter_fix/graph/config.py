"""Graph substrate configuration.

Centralizes version pins, cloud-LLM environment-variable guards, paths,
and the shared source-file walker used by the grep fallback and the
content-hash cache key.
Consumed by build.py, fallback.py, query.py, and scripts/preflight.py.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Iterable, Iterator


log = logging.getLogger(__name__)


GRAPHIFY_MIN_VERSION = "0.8.14"
GRAPHIFY_MAX_VERSION_EXCLUSIVE = "0.9.0"
GRAPHIFY_VERSION_RANGE = f">={GRAPHIFY_MIN_VERSION},<{GRAPHIFY_MAX_VERSION_EXCLUSIVE}"

CLOUD_LLM_ENV_VARS = (
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
    "DEEPSEEK_API_KEY",
    "MOONSHOT_API_KEY",
)

CACHE_SUBDIR = "cache"
GRAPH_FILE_NAME = "graph.json"

SUPPORTED_LANGUAGE_SUFFIXES = {
    ".py": "python",
    ".go": "go",
    ".java": "java",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".rs": "rust",
    ".rb": "ruby",
}

# Directories skipped by the shared file walker. Not exhaustive — graphify's
# own `.graphifyignore` + `.gitignore` handling is more thorough and should
# be preferred when available (see build.py::_try_graphify_build). The
# fallback walker has to make its own decisions.
_EXCLUDED_DIR_PARTS = frozenset(
    {".git", ".venv", "node_modules", "__pycache__", "build", "dist", "vendor", "target"}
)


def cache_dir_for_repo(work_root: str | Path, repo_name: str) -> Path:
    return Path(work_root) / repo_name / CACHE_SUBDIR


def graph_path_for_repo(work_root: str | Path, repo_name: str) -> Path:
    return cache_dir_for_repo(work_root, repo_name) / GRAPH_FILE_NAME


def check_backend_isolation(env: dict[str, str] | None = None) -> list[str]:
    """Return the list of set cloud-LLM env vars (REQ-GRA-004).

    Empty list means AST-only isolation is guaranteed.
    """
    env = env if env is not None else os.environ
    return [name for name in CLOUD_LLM_ENV_VARS if env.get(name)]


def language_for_path(path: str | Path) -> str | None:
    return SUPPORTED_LANGUAGE_SUFFIXES.get(Path(path).suffix.lower())


def iter_source_files(root: Path) -> Iterator[Path]:
    """Yield readable source files under ``root``, skipping vendored dirs.

    Single source of truth for the fallback-path file walker AND the
    content-hash key. Filters to files with a supported language suffix
    (``language_for_path``). Every ``stat()`` / ``parts`` / relative-path
    access is guarded so sandbox / permission-denied entries (macOS
    Claude Code sandbox blocks reads of ``.envrc``, submodule ``.git``
    internals, etc.) skip cleanly rather than aborting the walk.

    When graphify is available, prefer ``graphify.detect.detect(root)`` —
    it respects ``.gitignore`` and ``.graphifyignore`` and returns a
    curated list. This walker is the "graphify unavailable" fallback.
    """
    for path in safe_walk_files(root):
        if language_for_path(path):
            yield path


def safe_walk_files(
    root: Path,
    *,
    excluded_dir_parts: Iterable[str] | None = None,
) -> Iterator[Path]:
    """Yield every readable file under ``root``, permission-guarded.

    Lower-level than ``iter_source_files``: does NOT filter by suffix, so
    callers with their own file-shape rules (language detection, sweep
    pattern matching, parse-results directory scans) can layer their own
    filter on top without re-implementing the sandbox-hardening.

    Guards every ``stat()`` / ``.parts`` access individually so
    sandbox / permission-denied entries (macOS Claude Code sandbox blocks
    reads of ``.envrc``, submodule ``.git`` internals, etc.) skip cleanly
    rather than aborting the whole walk.

    ``excluded_dir_parts`` defaults to :data:`_EXCLUDED_DIR_PARTS`. Pass
    an empty iterable to disable directory exclusion.
    """
    excluded = frozenset(excluded_dir_parts) if excluded_dir_parts is not None else _EXCLUDED_DIR_PARTS
    try:
        candidates = root.rglob("*")
    except OSError as exc:
        log.warning("safe_walk_files: rglob failed on %s: %s", root, exc)
        return
    for path in candidates:
        try:
            if not path.is_file():
                continue
        except OSError:
            continue
        try:
            if excluded and any(part in excluded for part in path.parts):
                continue
        except OSError:
            continue
        yield path
