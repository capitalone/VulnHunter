"""Producer-side writer for ``<results_dir>/scan_manifest.json``.

Serializes the agent's aggregate in-memory state (findings extracted
from the scan README, session cost from the SDK, issues-stage
outcomes) into the JSON contract defined by ``scan_manifest.schema.json``.
A downstream scan-worker reads and re-validates the same file — one
authoritative schema, two sides.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from dataclasses import asdict
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

from ._stream_events import SessionTotals
from .issues import PostSummary
from .issues_extract import Finding

logger = logging.getLogger(__name__)


# Stderr prefix so CloudWatch metric filters can distinguish schema
# violations from other agent crashes without regex-matching prose.
MANIFEST_VALIDATION_FAILURE_PREFIX = "MANIFEST_VALIDATION_FAILURE:"

_SCHEMA_FILENAME = "scan_manifest.schema.json"
_MANIFEST_FILENAME = "scan_manifest.json"
_TMP_SUFFIX = ".tmp"

# Exit codes that MUST NOT produce a manifest. Publish-failed (2, per HLD §9
# and AGENT-MANIFEST-002) is the only such code: on that path the scan-worker
# fails the SCAN row (SCAN-AGENT-006) and retains the SQS message, inspecting
# publish state directly — writing a manifest would be a phantom "success"
# marker for a run that never closed the loop. All other results-bearing exits
# (0/1/3/4/5) write per AGENT-MANIFEST-001.
_NO_MANIFEST_EXIT_CODES = frozenset({2})


# @spec AGENT-MANIFEST-001, AGENT-MANIFEST-002, AGENT-MANIFEST-003,
# @spec AGENT-MANIFEST-004, AGENT-MANIFEST-005, AGENT-MANIFEST-006,
# @spec AGENT-MANIFEST-007, AGENT-MANIFEST-008, AGENT-MANIFEST-009,
# @spec AGENT-MANIFEST-010, AGENT-MANIFEST-011
def write_manifest(
    results_dir: Path,
    scan_id: str,
    agent_exit_code: int,
    totals: SessionTotals,
    findings: list[Finding],
    post_summary: PostSummary,
) -> None:
    """Serialize scan state to ``<results_dir>/scan_manifest.json``.

    Pre-write validation against ``scan_manifest.schema.json`` guards
    the invariant that any file the wrapper sees on disk parses
    against the vendored schema. Atomic commit via ``os.replace`` so
    a mid-write crash leaves no half-written manifest for the
    wrapper to consume.

    Callers must invoke this before process exit (AGENT-MANIFEST-011) at
    every path where a results directory exists, so the wrapper sees the
    manifest instead of stalling on ``manifest_absent``.

    Raises:
        ValidationError: if the assembled manifest fails schema
            validation. Also emits ``MANIFEST_VALIDATION_FAILURE:``
            on stderr so CloudWatch can bucket the failure.
        OSError: if the results directory doesn't exist, the tmp
            file can't be written, or the rename fails.
    """
    if agent_exit_code in _NO_MANIFEST_EXIT_CODES:
        return

    manifest = {
        "schema_version": "1",
        "scan_id": scan_id,
        "agent_exit_code": agent_exit_code,
        "cost_usd": totals.cost_usd,
        "findings": [asdict(f) for f in findings],
        "posted": [asdict(p) for p in post_summary.posted],
        "skipped": [asdict(s) for s in post_summary.skipped],
        "failed": [asdict(f) for f in post_summary.failed],
    }

    schema = _load_schema()
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(manifest), key=lambda e: e.path)
    if errors:
        detail = "; ".join(f"{list(e.absolute_path)}: {e.message}" for e in errors)
        print(
            f"{MANIFEST_VALIDATION_FAILURE_PREFIX} {detail}",
            file=sys.stderr,
            flush=True,
        )
        raise ValidationError(f"scan_manifest is not valid: {detail}")

    final_path = results_dir / _MANIFEST_FILENAME
    tmp_path = results_dir / (_MANIFEST_FILENAME + _TMP_SUFFIX)
    tmp_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp_path, final_path)


def _load_schema() -> dict:
    """Load ``scan_manifest.schema.json`` from the repo root.

    Mirrors ``agent/verify_runner.py::_schema_root()`` — walks up from
    this module's directory to the parent (repo root in both editable
    install and the Docker image at ``/app``).
    """
    schema_path = Path(__file__).resolve().parent.parent / _SCHEMA_FILENAME
    return json.loads(schema_path.read_text(encoding="utf-8"))
