"""Shared base for the subprocess-driven scan engines (hermes/copilot/codex).

Each of those engines drives /vulnhunt by shelling out to an agent CLI and
judging success by the VulnHunter results contract. The orchestration is
identical across all three — skill check, binary check, prior-results
guard, results-dir staging, git context, audit start, prompt/command
build, subprocess launch with timeout, and the completion contract — so it
lives here once. A concrete engine supplies only what actually differs:

  - ``name``                class attribute, the ``[scan] engine`` value;
  - ``_binary_name``        PATH lookup name (``"hermes"`` etc.);
  - ``_skill_paths()``      candidate SKILL.md locations to verify install;
  - ``_install_target``     the ``install.sh --target X`` name for errors;
  - ``_binary_hint``        engine-specific "binary not found" remedy text;
  - ``_build_command()``    the argv for the subprocess;
  - ``_build_kickoff()``    the kickoff prompt.

Success contract (the load-bearing invariant): the engine pre-creates the
results directory, so ``_find_results_dir`` will always *find* it. Success
is therefore judged by ``_results_dir_is_complete`` — the dir must hold the
skill's ``README.md`` report — never by the directory merely existing. A
crashed / OOM-killed / non-zero-exiting engine leaves an empty shell behind
and is correctly reported as a failure, not a clean "found nothing".
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import time
from pathlib import Path
from typing import TYPE_CHECKING

from agent import audit as _audit
from agent import runner as _runner
from agent.engines import EngineError, ScanSpec

if TYPE_CHECKING:
    from agent._stream_events import SessionTotals
    from agent.audit import AuditWriter

logger = logging.getLogger(__name__)


class SubprocessEngine:
    """Template base for CLI-driven engines. Subclasses fill the hooks."""

    name: str = ""
    _binary_name: str = ""
    _install_target: str = ""
    _binary_hint: str = ""

    # --- hooks a subclass must / may override -----------------------------

    def _skill_paths(self) -> tuple[Path, ...]:
        """SKILL.md locations to accept as "installed" (first hit wins)."""
        raise NotImplementedError  # pragma: no cover

    def _build_command(self, spec: ScanSpec, binary: str, prompt: str) -> list[str]:
        """Full argv for the subprocess (binary already resolved)."""
        raise NotImplementedError  # pragma: no cover

    def _build_kickoff(
        self, spec: ScanSpec, *, results_dir: Path, git_ctx: dict[str, str]
    ) -> str:
        """The kickoff prompt handed to the engine."""
        raise NotImplementedError  # pragma: no cover

    def _log_launch(self, cmd: list[str]) -> None:
        """Emit a launch log line. Overridable (e.g. experimental warnings)."""
        logger.info("%s engine: %s … <prompt>", self.name, cmd[0])

    # --- shared machinery -------------------------------------------------

    def _resolve_binary(self, spec: ScanSpec) -> str:
        configured = spec.config.scan.engine_command
        binary = configured or shutil.which(self._binary_name)
        if not binary:
            raise EngineError(
                f"{self._binary_name} binary not found on PATH — {self._binary_hint} "
                "or set [scan] engine_command in the agent TOML"
            )
        return binary

    def _check_skill_installed(self) -> None:
        paths = self._skill_paths()
        if not any(p.is_file() for p in paths):
            shown = paths[0]
            raise EngineError(
                f"vulnhunt skill not found at {shown}. "
                f"Run ./install.sh --target {self._install_target} from the "
                "vulnhunter repo first."
            )

    async def run_scan(
        self,
        spec: ScanSpec,
        *,
        audit_writer: "AuditWriter | None" = None,
        totals_out: "SessionTotals | None" = None,  # noqa: ARG002 (SDK-only)
    ) -> Path | None:
        self._check_skill_installed()
        binary = self._resolve_binary(spec)  # fail fast before any pre-staging
        clone_dir = spec.clone_dir
        model = spec.model

        # Same pre-staging contract as the SDK path: compute + create the
        # results dir, refuse to shadow prior results, resolve git context,
        # and hand the skill every value it must not recompute.
        _runner._check_no_prior_results(clone_dir)
        results_dir = _runner._compute_results_dir(clone_dir, model)
        results_dir.mkdir(exist_ok=False)
        git_ctx = _runner._git_context(clone_dir)
        repo_slug = _runner._repo_slug_from_url(git_ctx["repo_url"], clone_dir.name)
        report_id = _audit.report_id_from(results_dir)
        wall_start = time.time()

        if audit_writer is not None:
            audit_writer.emit_audit(
                _audit.build_scan_started(
                    app_id=spec.config.audit.app_id,
                    actor=spec.config.audit.actor,
                    repo_slug=repo_slug,
                    report_id=report_id,
                    model_version=model,
                    target_sha=git_ctx["head_sha"],
                )
            )

        prompt = self._build_kickoff(spec, results_dir=results_dir, git_ctx=git_ctx)
        cmd = self._build_command(spec, binary, prompt)
        self._log_launch(cmd)

        # engine_timeout_seconds <= 0 means "no timeout" (wait indefinitely),
        # not "time out instantly". asyncio.wait_for(timeout=None) waits
        # forever; a positive value caps the run.
        raw_timeout = spec.config.scan.engine_timeout_seconds
        timeout = raw_timeout if raw_timeout and raw_timeout > 0 else None
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(clone_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            raise EngineError(
                f"{self.name} exceeded engine_timeout_seconds={raw_timeout}"
            ) from None

        out_text = stdout.decode("utf-8", errors="replace").strip()
        err_text = stderr.decode("utf-8", errors="replace").strip()
        logger.info("%s engine exit=%s final=%r", self.name, proc.returncode, out_text[:200])
        if err_text:
            logger.debug("%s engine stderr: %s", self.name, err_text[-2000:])

        found = _runner._find_results_dir(clone_dir)
        # Contents-based success: the results dir the engine pre-created
        # always *exists*, so judge on whether it actually holds a report.
        # An empty results dir (crash / OOM / early exit) is a failure even
        # when the process returned 0, and any non-zero exit is a failure.
        complete = _runner._results_dir_is_complete(found)
        error: Exception | None = None
        if proc.returncode != 0 or not complete:
            tail = (out_text + "\n" + err_text)[-800:]
            if not complete:
                reason = (
                    "no results directory produced"
                    if found is None
                    else f"results directory {found.name} has no README.md report"
                )
                error = EngineError(
                    f"{self.name} exited {proc.returncode} but {reason} — "
                    f"the scan did not complete. Output tail:\n{tail}"
                )
            else:
                error = EngineError(
                    f"{self.name} exited {proc.returncode} with a results dir. "
                    f"Output tail:\n{tail}"
                )

        # Only a complete results dir is reported to the audit trail and
        # returned as the scan's output; a failure records no results dir.
        reported = found if complete else None
        _runner._emit_scan_completed_safely(
            audit_writer,
            config=spec.config,
            repo_slug=repo_slug,
            report_id=report_id,
            model=model,
            target_sha=git_ctx["head_sha"],
            results_dir=reported,
            session_result=None,
            error=error,
            wall_start=wall_start,
        )
        if error is not None:
            raise error
        return reported
