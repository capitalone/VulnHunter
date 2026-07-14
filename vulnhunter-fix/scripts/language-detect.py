#!/usr/bin/env python3
"""Detect a target repo's primary programming language.

Consumed by Phase 2 (Plan) per REQ-CWE-005 — the plan orchestrator uses
the result to inject the matching adapter section from
`references/repo-type-adapters.md` into the worker prompt.

Detection is heuristic:
1. Check for well-known manifest files (go.mod, Pipfile, pom.xml, ...).
2. Fall back to file-suffix majority-vote across source files.

Usage:
    language-detect.py <repo-root>

Prints a JSON object on stdout:
    {"language": "go|java|python|typescript|javascript|rust|ruby|null",
     "confidence": "high|medium|low",
     "signals": ["...", "..."]}
"""

from __future__ import annotations

import _skill_bootstrap  # noqa: F401  — adds bundled .venv site-packages to sys.path

import json
import sys
from collections import Counter
from pathlib import Path

from vulnhunter_fix.graph.config import safe_walk_files


MANIFEST_MAP = {
    "go.mod": ("go", "high"),
    "Pipfile": ("python", "high"),
    "pyproject.toml": ("python", "high"),
    "setup.py": ("python", "medium"),
    "requirements.txt": ("python", "medium"),
    "pom.xml": ("java", "high"),
    "build.gradle": ("java", "high"),
    "build.gradle.kts": ("java", "high"),
    "package.json": ("javascript", "medium"),
    "tsconfig.json": ("typescript", "high"),
    "Cargo.toml": ("rust", "high"),
    "Gemfile": ("ruby", "high"),
}

SUFFIX_MAP = {
    ".go": "go",
    ".py": "python",
    ".java": "java",
    # Kotlin is JVM-family with no dedicated adapter; route it to the java
    # adapter rather than emitting an out-of-enum "kotlin" that no worker
    # handles → silent misroute (12-seg review S8).
    ".kt": "java",
    ".kts": "java",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".rs": "rust",
    ".rb": "ruby",
}

SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__", "build", "dist", "vendor", "target"}


def _manifest_present(root: Path, name: str) -> bool:
    """Guarded ``is_file`` so a sandbox-denied manifest doesn't crash detection."""
    try:
        return (root / name).is_file()
    except OSError:
        return False


def detect(root: Path) -> dict:
    signals: list[str] = []
    manifest_hits: dict[str, str] = {}
    for name, (lang, conf) in MANIFEST_MAP.items():
        if _manifest_present(root, name):
            manifest_hits[lang] = conf
            signals.append(f"manifest:{name}→{lang}")

    if manifest_hits:
        high_conf_langs = [l for l, c in manifest_hits.items() if c == "high"]
        if high_conf_langs:
            # tsconfig.json + package.json both present → prefer typescript
            if "typescript" in manifest_hits:
                return {"language": "typescript", "confidence": "high", "signals": signals}
            if len(high_conf_langs) == 1:
                return {"language": high_conf_langs[0], "confidence": "high", "signals": signals}
            # Multiple high-confidence languages — polyglot repo; pick by suffix vote
        else:
            single = list(manifest_hits)[0]
            return {"language": single, "confidence": "medium", "signals": signals}

    counter: Counter[str] = Counter()
    # Uses the shared permission-guarded walker from
    # vulnhunter_fix.graph.config so a sandbox-denied .envrc / secret file
    # doesn't crash language detection. Suffix filter is applied here.
    for path in safe_walk_files(root, excluded_dir_parts=SKIP_DIRS):
        try:
            suffix = path.suffix.lower()
        except OSError:
            continue
        lang = SUFFIX_MAP.get(suffix)
        if lang:
            counter[lang] += 1

    if not counter:
        return {"language": None, "confidence": "low", "signals": signals + ["no source files found"]}

    winner, count = counter.most_common(1)[0]
    total = sum(counter.values())
    confidence = "high" if count / total >= 0.7 else "medium"
    signals.append(f"suffix-vote: {winner}={count}/{total} ({', '.join(f'{k}={v}' for k, v in counter.most_common(4))})")
    return {"language": winner, "confidence": confidence, "signals": signals}


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: language-detect.py <repo-root>", file=sys.stderr)
        return 64
    root = Path(argv[1])
    if not root.is_dir():
        print(f"error: not a directory: {root}", file=sys.stderr)
        return 2
    result = detect(root)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
