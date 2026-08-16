"""Reference engine: the existing Claude Agent SDK path, unchanged.

``run_vulnhunt`` in ``agent/runner.py`` remains the single implementation;
this class only adapts it to the ScanEngine protocol so the CLI can treat
every engine uniformly.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from agent import runner as _runner
from agent.engines import ScanSpec

if TYPE_CHECKING:
    from agent._stream_events import SessionTotals
    from agent.audit import AuditWriter

logger = logging.getLogger(__name__)


class ClaudeCodeEngine:
    name = "claude-code"

    async def run_scan(
        self,
        spec: ScanSpec,
        *,
        audit_writer: "AuditWriter | None" = None,
        totals_out: "SessionTotals | None" = None,
    ) -> Path | None:
        backoffs = spec.backoffs or _runner._SCAN_RETRY_BACKOFFS
        return await _runner.run_vulnhunt(
            spec.clone_dir,
            spec.config,
            model_override=spec.model,
            scan_id=spec.scan_id,
            read_only=spec.read_only,
            enable_bash=spec.enable_bash,
            backoffs=backoffs,
            audit_writer=audit_writer,
            totals_out=totals_out,
        )
