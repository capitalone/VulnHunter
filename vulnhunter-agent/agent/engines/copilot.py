"""GitHub Copilot CLI engine (EXPERIMENTAL).

Drives /vulnhunt through a non-interactive ``copilot`` run against the
skill bundle installed at ``~/.copilot/skills/vulnhunt``
(``./install.sh --target copilot``). Copilot has no skill/slash-command
registry, so the kickoff prompt points the agent at the bundle's
SKILL.md explicitly.

Status: the Copilot CLI's headless flag surface (non-interactive prompt
flag, permission flags) could not be verified against a live binary when
this engine was authored. ``_build_command`` uses ``-p`` for the prompt
plus any flags configured via ``[scan] engine_extra_args`` (e.g.
``--allow-tool`` patterns). Verify with ``copilot -h`` /
``copilot help permissions`` on your install before relying on it.
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
from agent.engines.hermes import EngineError

if TYPE_CHECKING:
    from agent._stream_events import SessionTotals
    from agent.audit import AuditWriter

logger = logging.getLogger(__name__)

_COPILOT_SKILL = Path.home() / ".copilot" / "skills" / "vulnhunt" / "SKILL.md"

_EFFECTIVE_TOOLS = ["Read", "Write", "Edit", "Glob", "Grep"]


class CopilotCliEngine:
    name = "copilot"

    def _binary(self, spec: ScanSpec) -> str:
        configured = spec.config.scan.engine_command
        binary = configured or shutil.which("copilot")
        if not binary:
            raise EngineError(
                "copilot binary not found on PATH — install GitHub Copilot CLI "
                "or set [scan] engine_command in the agent TOML"
            )
        return binary

    def _check_skill_installed(self) -> None:
        if not _COPILOT_SKILL.is_file():
            raise EngineError(
                "vulnhunt skill not found at ~/.copilot/skills/vulnhunt/SKILL.md. "
                "Run ./install.sh --target copilot from the vulnhunter repo first."
            )

    def _build_command(self, spec: ScanSpec, prompt: str) -> list[str]:
        cmd = [self._binary(spec), "-p", prompt]
        cmd += list(spec.config.scan.engine_extra_args)
        return cmd

    def _build_kickoff(self, spec: ScanSpec, *, results_dir: Path, git_ctx: dict[str, str]) -> str:
        shell_line = (
            "The shell tool is AVAILABLE for exploit-test execution "
            "(--enable-bash was passed)."
            if spec.enable_bash
            else "The shell tool is NOT available for this read-only scan — use "
            "your file search/read/write tools only; write exploit tests but do "
            "not run them."
        )
        tag = _runner._model_tag(spec.model)
        return (
            f"{_runner._VULNHUNT_PROMPT_PREAMBLE}\n\n"
            f"Read {_COPILOT_SKILL} and execute the /vulnhunt workflow it defines "
            f"on {spec.clone_dir}. Follow the SKILL.md and its phase files "
            f"exactly; add the directory containing the SKILL.md to your session "
            f"so the phases/ files are readable.\n\n"
            f"Use the model tag `{tag}` for this scan. Name the results "
            f"directory and any other artifacts with that exact tag.\n\n"
            "Pre-resolved scan metadata (use these literal values — do NOT "
            "run shell commands to recompute them):\n"
            f"- VULNHUNT_DIR: {results_dir}\n"
            f"- VULNHUNT_BRANCH: {git_ctx['branch_label']}\n"
            f"- Repository URL: {git_ctx['repo_url']}\n"
            f"- {shell_line}"
        )

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
        cmd = self._build_command(spec, prompt)
        logger.warning(
            "copilot engine is EXPERIMENTAL — verify its flag surface "
            "(`copilot -h`) before production use"
        )
        logger.info("copilot engine: %s … -p <prompt>", cmd[0])

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
                f"copilot exceeded engine_timeout_seconds={timeout}"
            ) from None

        out_text = stdout.decode("utf-8", errors="replace").strip()
        err_text = stderr.decode("utf-8", errors="replace").strip()
        logger.info("copilot engine exit=%s final=%r", proc.returncode, out_text[:200])
        if err_text:
            logger.debug("copilot engine stderr: %s", err_text[-2000:])

        found = _runner._find_results_dir(clone_dir)
        error: Exception | None = None
        if proc.returncode != 0 and found is None:
            tail = (out_text + "\n" + err_text)[-800:]
            error = EngineError(
                f"copilot exited {proc.returncode} with no results dir. "
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
