"""Resolve the commit-level identity of this build.

The build step (``scripts/write-build-version.sh``) writes
``agent/_build_version.py`` with a ``BUILD_VERSION`` constant of the
form ``<short-sha>-<clean|dirty>``. This module reads that constant
at import; if the module is missing (running from a raw checkout with
no build step), returns ``"unknown"``.

Callers use this for the ``Skill version`` field on clean-scan issues
and any other place a build identity is useful. Since the agent and
the ``/vulnhunt`` skill live in the same repo, one hash identifies
both.
"""

from __future__ import annotations

from functools import cache


@cache
def resolve() -> str:
    """Return the build's commit-level identity or ``"unknown"``."""
    try:
        from ._build_version import BUILD_VERSION  # type: ignore[import-not-found]
    except ImportError:
        return "unknown"
    value = str(BUILD_VERSION).strip()
    return value or "unknown"
