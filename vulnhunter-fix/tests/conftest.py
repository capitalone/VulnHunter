"""Shared pytest helpers.

Subprocess coverage: tests that invoke the skill's CLI scripts via
``subprocess.run([sys.executable, str(SCRIPT), ...])`` would otherwise
contribute zero coverage. Setting ``COVERAGE_PROCESS_START`` here
causes the auto-installed ``coverage.pth`` hook in the venv to call
``coverage.process_startup()`` in each subprocess, and the
``parallel = true`` setting in pyproject.toml's ``[tool.coverage.run]``
keeps those per-process data files from clobbering the parent run.

Additionally, remediation-rigor tests import ``vulnhunter_fix.delivery``
and ``vulnhunter_fix.graph``. We add the repo root to ``sys.path`` so
the imports resolve during test runs (the package is installed in
editable mode via ``[dev-packages]``, but sys.path is defensive).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]

os.environ.setdefault(
    "COVERAGE_PROCESS_START",
    str(REPO_ROOT / "pyproject.toml"),
)

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# The bundled-venv bootstrap lives at scripts/_skill_bootstrap.py. When
# tests load a hyphenated CLI script via importlib.util.spec_from_file_location
# the module's own directory is NOT auto-added to sys.path, so its top-level
# ``import _skill_bootstrap`` fails. Add scripts/ explicitly here so the
# bootstrap resolves under pytest regardless of load style.
_SCRIPTS_DIR = str(REPO_ROOT / "scripts")
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)
