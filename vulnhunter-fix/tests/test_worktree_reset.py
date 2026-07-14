"""TS-15b — worktree reset semantics (REQ-GAT-009 / REQ-GAT-010).

Verifies:
1. `worktree-reset.py` hard-resets and cleans a dirty worktree.
2. Protected paths (manifest, graph_context, result_history) survive.
3. Each reset appends a JSON line to retry_log.jsonl.
4. On the third reset for a single VULN, the executor MUST route the
   finding to NEEDS_MANUAL_REVIEW (executor wiring; skeleton pending).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
RESET_SCRIPT = REPO_ROOT / "scripts" / "worktree-reset.py"


def _init_repo(repo: Path) -> tuple[Path, str]:
    """Init a git repo at `repo`, add a baseline commit, return (path, baseline_sha).

    Inherits PATH from the parent environment so `git` resolves on CI where the
    shell doesn't set PATH inside subprocess. `GIT_TEMPLATE_DIR=""` is overlaid
    to skip the hook-template copy that some sandbox profiles reject.
    """
    env = {**os.environ, "GIT_TEMPLATE_DIR": ""}
    subprocess.run(["git", "init", "-q", str(repo)], check=True, env=env)
    (repo / "src.py").write_text("x = 1\n")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, env=env)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=T",
         "commit", "-q", "-m", "init"],
        check=True, env=env,
    )
    sha = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True, env=env,
    ).strip()
    return repo, sha


def _add_worktree(repo: Path, wt: Path, sha: str) -> Path:
    """Create a LINKED worktree of `repo` at `wt` (detached at sha). This is
    the production shape — reset only ever targets linked worktrees under
    .vulnhunter-fix/worktrees/, never the main checkout (S11)."""
    env = {**os.environ, "GIT_TEMPLATE_DIR": ""}
    subprocess.run(
        ["git", "-C", str(repo), "worktree", "add", "--detach", str(wt), sha],
        check=True, capture_output=True, env=env,
    )
    return wt


def test_reset_refuses_main_worktree(tmp_path):
    """S11 (12-seg review): reset only checked is_dir(); `git -C <path>` walks
    up to the enclosing .git, so pointing it at the MAIN checkout reset the
    primary repo (destroying committed + uncommitted work) and still returned
    ok. The main worktree must be refused."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _, sha = _init_repo(repo)
    (repo / "uncommitted.py").write_text("precious work\n")  # would be destroyed
    (repo / "src.py").write_text("x = 999\n")               # uncommitted edit

    result = subprocess.run(
        [sys.executable, str(RESET_SCRIPT),
         "--worktree", str(repo), "--branch-baseline", sha,
         "--vuln-id", "VULN-1", "--retry-number", "1", "--reason", "test",
         "--repo-work-root", str(tmp_path)],
        capture_output=True, text=True,
    )
    assert result.returncode != 0, "reset did not refuse the main worktree"
    # The precious work must survive — reset must not have run.
    assert (repo / "uncommitted.py").exists()
    assert (repo / "src.py").read_text() == "x = 999\n"


def test_reset_refuses_subdir_of_repo(tmp_path):
    """S11: a non-worktree-root subdir must be refused (else git walks up and
    resets the enclosing repo)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _, sha = _init_repo(repo)
    subdir = repo / "src"
    subdir.mkdir()
    result = subprocess.run(
        [sys.executable, str(RESET_SCRIPT),
         "--worktree", str(subdir), "--branch-baseline", sha,
         "--vuln-id", "VULN-1", "--retry-number", "1", "--reason", "test",
         "--repo-work-root", str(tmp_path)],
        capture_output=True, text=True,
    )
    assert result.returncode != 0, "reset did not refuse a non-worktree-root subdir"


def test_reset_restores_baseline(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _, sha = _init_repo(repo)
    wt = _add_worktree(repo, tmp_path / "wt", sha)
    # Dirty the worktree
    (wt / "src.py").write_text("x = 999\n")
    (wt / "aborted.py").write_text("garbage\n")
    (wt / "manifest.json").write_text('{"kept":true}\n')

    log_root = tmp_path / "workroot"
    log_root.mkdir()
    result = subprocess.run(
        [sys.executable, str(RESET_SCRIPT),
         "--worktree", str(wt), "--branch-baseline", sha,
         "--vuln-id", "VULN-1", "--retry-number", "1",
         "--reason", "test",
         "--repo-work-root", str(log_root)],
        capture_output=True, text=True, check=True,
    )
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"

    # Baseline content restored
    assert (wt / "src.py").read_text() == "x = 1\n"
    # Untracked file cleaned
    assert not (wt / "aborted.py").exists()
    # Protected file survives
    assert (wt / "manifest.json").read_text() == '{"kept":true}\n'


def test_reset_appends_log(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _, sha = _init_repo(repo)
    wt = _add_worktree(repo, tmp_path / "wt", sha)
    log_root = tmp_path / "workroot"
    log_root.mkdir()
    for i in range(1, 3):
        subprocess.run(
            [sys.executable, str(RESET_SCRIPT),
             "--worktree", str(wt), "--branch-baseline", sha,
             "--vuln-id", "VULN-42", "--retry-number", str(i),
             "--reason", f"attempt {i}",
             "--repo-work-root", str(log_root)],
            check=True, capture_output=True,
        )

    log = log_root / "retry_log.jsonl"
    assert log.exists()
    entries = [json.loads(line) for line in log.read_text().splitlines() if line.strip()]
    assert len(entries) == 2
    assert entries[0]["vuln_id"] == "VULN-42"
    assert entries[0]["retry"] == 1


@pytest.mark.skip(reason="harness pending task-61 (Phase 4 pre-retry reset wiring)")
def test_third_reset_routes_to_needs_manual_review():
    """After three resets for one VULN, the finding MUST route to
    NEEDS_MANUAL_REVIEW and no further resets fire (REQ-GAT-009 last
    paragraph)."""
