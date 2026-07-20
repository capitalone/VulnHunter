"""Sys.path + interpreter bootstrap for the installed skill layout.

When VulnHunter-Fix is installed via ``install.sh``, its runtime
dependencies (``jsonschema``, ``graphifyy``) live in a bundled venv at
``<skill-root>/.venv/``. That venv is created with **Python 3.11** (see
``install.sh``'s ``find_python311``) and its native extensions are
compiled for cpython-3.11 specifically.

If the caller invokes a script with a different Python (e.g., ``python3
scripts/foo.py`` where ``python3`` is 3.13), pure-Python packages would
still resolve but native modules like ``rpds.rpds`` (a transitive
dep of ``jsonschema``) fail with ``ModuleNotFoundError`` because their
``.abi3.so`` was built for cpython-3.11.

To keep the installed skill working regardless of how the user's
``python3`` resolves, this module transparently re-executes the current
script under the bundled venv's Python if it detects a mismatch. In
dev flow (no bundled venv present) it's a no-op.

Side effects:
- ``os.execv`` replaces the process — anything imported before this
  module is discarded. Callers must import this FIRST, before any of
  the deps that trigger the mismatch.
- Only fires when a Python binary exists inside the bundled venv
  (``.venv/bin/python3`` on POSIX, ``.venv/Scripts/python.exe`` on Windows).
"""
from __future__ import annotations

import glob
import os
import sys


_HERE = os.path.dirname(os.path.abspath(__file__))
_SKILL_ROOT = os.path.dirname(_HERE)
_VENV_PY = (
    os.path.join(_SKILL_ROOT, ".venv", "Scripts", "python.exe")
    if os.name == "nt"
    else os.path.join(_SKILL_ROOT, ".venv", "bin", "python3")
)


def _same_interpreter(a: str, b: str) -> bool:
    """Robustly compare two Python executables through symlinks."""
    try:
        return os.path.realpath(a) == os.path.realpath(b)
    except OSError:
        return False


# 1. Re-exec under the bundled Python if we're not already running there.
#    Skip entirely in dev flow (no bundled venv). Also skip if a re-exec
#    already happened once — guard via env var to prevent an accidental loop.
if (
    os.path.isfile(_VENV_PY)
    and not _same_interpreter(sys.executable, _VENV_PY)
    and os.environ.get("VULNFIX_SKILL_REEXEC") != "1"
):
    # Pass the flag so the child process doesn't loop if realpath comparison
    # somehow disagrees between runs (e.g., filesystem-level symlink quirks).
    os.environ["VULNFIX_SKILL_REEXEC"] = "1"
    os.execv(_VENV_PY, [_VENV_PY, *sys.argv])


def _prepend_once(path: str) -> None:
    if os.path.isdir(path) and path not in sys.path:
        sys.path.insert(0, path)


# 2. Under the bundled Python OR in dev flow: put the matching-minor's
#    site-packages at index 0 (defensive; usually already present).
_matching = (
    os.path.join(_SKILL_ROOT, ".venv", "Lib", "site-packages")
    if os.name == "nt"
    else os.path.join(
        _SKILL_ROOT,
        ".venv",
        "lib",
        f"python{sys.version_info.major}.{sys.version_info.minor}",
        "site-packages",
    )
)
_prepend_once(_matching)

# 3. Skill root itself, so ``import vulnhunter_fix.delivery`` and
#    ``import vulnhunter_fix.graph.*`` resolve without needing PYTHONPATH.
_prepend_once(_SKILL_ROOT)

