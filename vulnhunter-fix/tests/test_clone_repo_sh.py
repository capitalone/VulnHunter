"""Regression test for scripts/clone_repo.sh's fork-privacy guarantee.

Exercises the real script as a subprocess (mocked gh/git on PATH), same
approach as test_detect_mode_sh.py, so we test the canonical bash
implementation rather than a Python re-derivation of it.

Covers the bug from issue #45: a rejected `gh repo edit --visibility
private` must abort the helper, not fall through to cloning and
reporting false private-fork success.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "clone_repo.sh"

GH_MOCK = """#!/bin/bash
case "$*" in
  'repo fork '*) exit 0;;
  'repo edit '*--visibility*)
    if [ "$MOCK_VISIBILITY_EXIT" = "0" ]; then exit 0; fi
    echo 'mock: visibility edit rejected' >&2
    exit 1;;
  'repo edit '*--enable-issues) exit 0;;
  *) echo "unexpected gh operation: $*" >&2; exit 99;;
esac
"""

GIT_MOCK = """#!/bin/bash
case "$*" in
  '-c init.templateDir= clone --template= --depth 1 '*)
    for last; do :; done
    mkdir -p "$last";;
  *) echo "unexpected git operation: $*" >&2; exit 99;;
esac
"""


def _mock_bin_dir(tmp_path: Path) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, content in (("gh", GH_MOCK), ("git", GIT_MOCK)):
        path = bin_dir / name
        path.write_text(content)
        path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return bin_dir


def _run(tmp_path: Path, visibility_edit_exit: int) -> subprocess.CompletedProcess[str]:
    bin_dir = _mock_bin_dir(tmp_path)
    target_dir = tmp_path / f"clone-{visibility_edit_exit}"
    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:/usr/bin:/bin"
    env["VULNFIX_SKILL_DIR"] = str(tmp_path / "empty-skill")
    (tmp_path / "empty-skill").mkdir()
    env["MOCK_VISIBILITY_EXIT"] = str(visibility_edit_exit)
    return subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "https://github.com/example-org/example-repo",
            str(target_dir),
            "--fork",
            "--fork-org",
            "example-fork-org",
        ],
        capture_output=True,
        text=True,
        env=env,
    )


def test_rejected_visibility_edit_does_not_report_private_success(tmp_path):
    result = _run(tmp_path, visibility_edit_exit=1)

    assert result.returncode != 0, (
        "a rejected visibility edit must abort the helper, not exit 0: "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert '"status": "ok"' not in result.stdout
    assert '"visibility": "private"' not in result.stdout


def test_accepted_visibility_edit_still_reports_private_success(tmp_path):
    result = _run(tmp_path, visibility_edit_exit=0)

    assert result.returncode == 0, result.stderr
    assert '"status": "ok"' in result.stdout
    assert '"visibility": "private"' in result.stdout
