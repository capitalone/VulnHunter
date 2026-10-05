"""Shared pytest fixtures for the harness test suite.

Keeps OrcaRouter provider configuration out of the test process so a
credential present in the developer/CI environment can never change a
test's outcome (the harness env bridge keys off ``ORCA_*``).
"""

from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _clean_orcarouter_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith(("ORCA_", "ORCAROUTER_")):
            monkeypatch.delenv(key, raising=False)
