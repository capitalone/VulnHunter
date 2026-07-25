"""Prepare a disposable worktree and execute one argument-array command."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys


def main() -> int:
    if len(sys.argv) < 2:
        print("expected a command argument array", file=sys.stderr)
        return 64
    source = Path("/source")
    work = Path("/work")
    if not source.is_dir() or not work.is_dir():
        print("sandbox mounts are unavailable", file=sys.stderr)
        return 64
    for child in source.iterdir():
        destination = work / child.name
        if child.is_dir():
            shutil.copytree(child, destination, symlinks=False)
        elif child.is_file():
            shutil.copy2(child, destination, follow_symlinks=False)
    environment = {
        "HOME": "/tmp/home",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TMPDIR": "/tmp",
    }
    Path(environment["HOME"]).mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        sys.argv[1:],
        cwd=work,
        env=environment,
        shell=False,
        check=False,
    )
    return int(completed.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
