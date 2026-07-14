"""Tests for scripts/worker-preamble-sync-lint.py.

Verifies:
1. Baseline pass on the current repo (SYNC markers are byte-coherent).
2. Simulated drift is caught with a non-zero exit.

Locks in the mechanism peer review 5 recommended: architecturally-
required duplication needs mechanical enforcement, not review discipline.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SYNC_LINT = REPO_ROOT / "scripts" / "worker-preamble-sync-lint.py"


def test_sync_lint_passes_on_head():
    """The current tree has SYNC markers that byte-match their source."""
    proc = subprocess.run(  # nosec B603
        [sys.executable, str(SYNC_LINT)],
        capture_output=True, text=True, timeout=10,
    )
    assert proc.returncode == 0, (
        f"sync-lint failed on HEAD:\nstderr:\n{proc.stderr}"
    )


def test_sync_lint_catches_drift(tmp_path, monkeypatch):
    """Copy prompts/ to a scratch dir, mutate one SYNC block, expect drift."""
    # Copy the two files the lint reads
    scratch_prompts = tmp_path / "prompts"
    scratch_prompts.mkdir()
    for name in ("worker_agent_common.md", "implement.md"):
        shutil.copy(REPO_ROOT / "prompts" / name, scratch_prompts / name)

    # Mutate the worker preamble's SYNC block to introduce drift
    common = scratch_prompts / "worker_agent_common.md"
    text = common.read_text(encoding="utf-8")
    marker = "<!-- SYNC:implement.md:exploit-path:start -->"
    idx = text.find(marker)
    assert idx != -1, "test fixture: expected SYNC marker missing"
    end_marker = "<!-- SYNC:implement.md:exploit-path:end -->"
    end_idx = text.find(end_marker, idx)
    assert end_idx != -1, "test fixture: expected SYNC end marker missing"
    # Rewrite the content between markers with a divergent string
    mutated = (
        text[: idx + len(marker)]
        + "\n- DRIFTED CONTENT — this should trip the sync-lint\n"
        + text[end_idx:]
    )
    common.write_text(mutated, encoding="utf-8")

    # Run sync-lint with a monkey-patched REPO_ROOT pointing at scratch.
    # Simplest way: run the script in an env where CONSUMER's parent
    # chain resolves to our tmp_path. We do that by copying the script
    # into scratch and running it there so its `Path(__file__).parent.parent`
    # resolves to tmp_path.
    scratch_scripts = tmp_path / "scripts"
    scratch_scripts.mkdir()
    shutil.copy(SYNC_LINT, scratch_scripts / "worker-preamble-sync-lint.py")

    proc = subprocess.run(  # nosec B603
        [sys.executable, str(scratch_scripts / "worker-preamble-sync-lint.py")],
        capture_output=True, text=True, timeout=10,
    )
    assert proc.returncode != 0, (
        "sync-lint failed to detect drift; exit was 0.\n"
        f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
    )
    assert "drift" in proc.stderr.lower(), (
        f"sync-lint exited non-zero but stderr doesn't mention drift: {proc.stderr}"
    )
