#!/usr/bin/env python3
"""Worker-preamble sync lint.

Enforces byte-coherence between reference blocks in
`prompts/worker_agent_common.md` and their canonical source in
`prompts/implement.md`. Workers spawn as Task subagents and never
file-read `implement.md`, so shared invariants (exploit path template,
result JSON template, Step A-I procedure) must be duplicated. This
lint makes drift a hard CI failure.

Convention: mark blocks with HTML comment sentinels.

    <!-- SYNC:implement.md:exploit-path:start -->
    ... byte-identical content ...
    <!-- SYNC:implement.md:exploit-path:end -->

The source file must have matching sentinels with the same block name.
Content between the sentinels (excluding the sentinel lines themselves)
is compared byte-for-byte.

Exit codes: 0 clean, 1 drift, 2 syntax error.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
CONSUMER = REPO_ROOT / "prompts" / "worker_agent_common.md"

# Sentinel regex — captures source-file name and block name.
START_RE = re.compile(r"<!--\s*SYNC:([^:\s]+):([^:\s]+):start\s*-->")
END_RE = re.compile(r"<!--\s*SYNC:([^:\s]+):([^:\s]+):end\s*-->")


def _extract_blocks(path: Path) -> dict[tuple[str, str], str] | None:
    """Return {(source_file, block_name): content_between_sentinels}.

    Returns None if sentinels are malformed (unbalanced, nested, etc.).
    """
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    blocks: dict[tuple[str, str], str] = {}
    open_key: tuple[str, str] | None = None
    open_start: int = -1
    for i, line in enumerate(lines):
        m_start = START_RE.search(line)
        m_end = END_RE.search(line)
        if m_start and m_end:
            print(
                f"error: {path}:{i+1} has both start and end on one line",
                file=sys.stderr,
            )
            return None
        if m_start:
            if open_key is not None:
                print(
                    f"error: {path}:{i+1} nested SYNC block (previous {open_key} still open)",
                    file=sys.stderr,
                )
                return None
            open_key = (m_start.group(1), m_start.group(2))
            open_start = i + 1
        elif m_end:
            if open_key is None:
                print(
                    f"error: {path}:{i+1} SYNC end with no matching start",
                    file=sys.stderr,
                )
                return None
            key = (m_end.group(1), m_end.group(2))
            if key != open_key:
                print(
                    f"error: {path}:{i+1} SYNC end {key} doesn't match open {open_key}",
                    file=sys.stderr,
                )
                return None
            blocks[open_key] = "".join(lines[open_start:i])
            open_key = None
    if open_key is not None:
        print(f"error: {path} SYNC block {open_key} unterminated", file=sys.stderr)
        return None
    return blocks


def main() -> int:
    if not CONSUMER.exists():
        print(f"error: consumer file not found: {CONSUMER}", file=sys.stderr)
        return 2
    consumer_blocks = _extract_blocks(CONSUMER)
    if consumer_blocks is None:
        return 2
    if not consumer_blocks:
        # Baseline: no SYNC markers yet. Not an error — the script is a
        # no-op until markers are added.
        return 0

    drift = []
    for (source_name, block_name), consumer_content in consumer_blocks.items():
        source_path = REPO_ROOT / "prompts" / source_name
        if not source_path.exists():
            drift.append(f"  source file missing: {source_path}")
            continue
        source_blocks = _extract_blocks(source_path)
        if source_blocks is None:
            drift.append(f"  source file has malformed SYNC markers: {source_path}")
            continue
        source_content = source_blocks.get((source_name, block_name))
        if source_content is None:
            drift.append(
                f"  block {block_name!r} referenced by {CONSUMER.name} "
                f"but not defined in {source_path.name}"
            )
            continue
        if source_content != consumer_content:
            drift.append(
                f"  block {block_name!r} drift between {source_path.name} "
                f"and {CONSUMER.name}"
            )

    if drift:
        print("Worker-preamble sync drift detected:", file=sys.stderr)
        for line in drift:
            print(line, file=sys.stderr)
        print(
            "\nFix: byte-copy the source block into the consumer block, "
            "or update the source. See scripts/worker-preamble-sync-lint.py "
            "docstring.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
