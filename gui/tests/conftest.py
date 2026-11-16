"""Make the repo root importable so tests can use ``gui.*`` and ``llm_connector.*``.

Run the tests from anywhere: ``python -m pytest gui/tests -q``.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
