"""Hermes CLI engine: drive /vulnhunt via a headless ``hermes chat`` run.

The vulnhunt skill must be installed for Hermes first
(``./install.sh --target hermes`` → ``~/.hermes/skills/vulnhunt``).
This engine pre-stages the same metadata the Claude SDK path provides
(results dir, branch label, repo URL, model tag, shell availability),
launches one headless session, and judges success by the results
directory — Hermes' ``-Q`` contract (stdout = final message, stderr =
session id) is used only for logging/diagnostics.

Subagent fan-out happens inside Hermes (``delegate_task``), so no
process-level fan-out is needed here.
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
from agent.engines import ScanSpec

if TYPE_CHECKING:
    from agent._stream_events import SessionTotals
    from agent.audit import AuditWriter

logger = logging.getLogger(__name__)

_HERMES_SKILL_CANDIDATES = (
    Path.home() / ".hermes" / "skills" / "vulnhunt" / "SKILL.md",
)

# Toolsets mirroring the Claude path's tool policy: no terminal for
# read-only scans (the engine pre-creates the results dir); terminal is
# added only with --enable-bash, exactly like ``Bash`` on the SDK path.
_TOOLSETS_READ_ONLY = "file,delegation"
_TOOLSETS_BASH = "file,terminal,delegation"

# Vocabulary the hermes skill's adaptation overlay maps to Hermes tools
# (search_files / read_file / write_file / patch). Rendered into the
# "Bash is NOT available — use X only" line.
_EFFECTIVE_TOOLS = ["Read", "Write", "Edit", "Glob", "Grep"]

# Hermes runs every top-level delegate_task in the background; a headless
# single-query session exits when the orchestrator concludes, killing
# in-flight children. The kickoff must teach the wait protocol explicitly.
_DELEGATION_PROTOCOL = (
    "\n\nDelegation protocol (important): every top-level delegate_task runs "
    "in the background — the call returns immediately with status "
    "\"dispatched\" and the child's result is only delivered while your turn "
    "is alive. After dispatching any subagent, do NOT conclude or error out "
    "while children are running; keep the turn alive by periodically calling "
    "delegate_task with action=\"list\" until every child shows completed, "
    "then verify that phase's output files exist before continuing."
)


class EngineError(RuntimeError):
    """Engine-level failure (binary missing, timeout, non-zero exit)."""


class HermesEngine:
    name = "hermes"

    def _binary(self, spec: ScanSpec) -> str:
        configured = spec.config.scan.engine_command
        binary = configured or shutil.which("hermes")
        if not binary:
            raise EngineError(
                "hermes binary not found on PATH — install Hermes "
                "(https://github.com/weav/hermes-agent) or set "
                "[scan] engine_command in the agent TOML"
            )
        return binary

    def _check_skill_installed(self) -> None:
        if not any(p.is_file() for p in _HERMES_SKILL_CANDIDATES):
            raise EngineError(
                "vulnhunt skill not found at ~/.hermes/skills/vulnhunt/SKILL.md. "
                "Run ./install.sh --target hermes from the vulnhunter repo first."
            )

    def _build_command(self, spec: ScanSpec, prompt: str) -> list[str]:
        scan = spec.config.scan
        cmd = [
            self._binary(spec),
            "chat",
            "-Q",
            "-s",
            "vulnhunt",
            "-t",
            _TOOLSETS_BASH if spec.enable_bash else _TOOLSETS_READ_ONLY,
        ]
        if scan.engine_provider:
            cmd += ["--provider", scan.engine_provider]
        if spec.model:
            cmd += ["-m", spec.model]
        cmd += list(scan.engine_extra_args)
        cmd += ["-q", prompt]
        return cmd

    async def run_scan(
        self,
        spec: ScanSpec,
        *,
        audit_writer: "AuditWriter | None" = None,
        totals_out: "SessionTotals | None" = None,  # noqa: ARG002 (SDK-only)
    ) -> Path | None:
        self._check_skill_installed()
        self._binary(spec)  # fail fast before any pre-staging
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

        prompt = _runner._build_vulnhunt_prompt(
            clone_dir,
            model,
            read_only=spec.read_only,
            results_dir=results_dir,
            branch_label=git_ctx["branch_label"],
            repo_url=git_ctx["repo_url"],
            enable_bash=spec.enable_bash,
            effective_tools=list(_EFFECTIVE_TOOLS),
        )
        prompt = prompt + _DELEGATION_PROTOCOL
        cmd = self._build_command(spec, prompt)
        logger.info("hermes engine: %s", " ".join(cmd[:8]) + " … -q <prompt>")

        timeout = spec.config.scan.engine_timeout_seconds
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
                f"hermes chat exceeded engine_timeout_seconds={timeout}"
            ) from None

        out_text = stdout.decode("utf-8", errors="replace").strip()
        err_text = stderr.decode("utf-8", errors="replace").strip()
        logger.info("hermes engine exit=%s final=%r", proc.returncode, out_text[:200])
        if err_text:
            logger.debug("hermes engine stderr: %s", err_text[-2000:])

        found = _runner._find_results_dir(clone_dir)
        error: Exception | None = None
        if proc.returncode != 0 and found is None:
            tail = (out_text + "\n" + err_text)[-800:]
            error = EngineError(
                f"hermes chat exited {proc.returncode} with no results dir. "
                f"Output tail:\n{tail}"
            )

        _runner._emit_scan_completed_safely(
            audit_writer,
            config=spec.config,
            repo_slug=repo_slug,
            report_id=report_id,
            model=model,
            target_sha=git_ctx["head_sha"],
            results_dir=found,
            session_result=None,
            error=error,
            wall_start=wall_start,
        )
        if error is not None:
            raise error
        return found
