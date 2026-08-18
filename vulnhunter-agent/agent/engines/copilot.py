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

from pathlib import Path

from agent import runner as _runner
from agent.engines import ScanSpec
from agent.engines._subprocess import SubprocessEngine, logger

_COPILOT_SKILL = Path.home() / ".copilot" / "skills" / "vulnhunt" / "SKILL.md"


class CopilotCliEngine(SubprocessEngine):
    name = "copilot"
    _binary_name = "copilot"
    _install_target = "copilot"
    _binary_hint = "install GitHub Copilot CLI"

    def _skill_paths(self) -> tuple[Path, ...]:
        return (_COPILOT_SKILL,)

    def _build_command(self, spec: ScanSpec, binary: str, prompt: str) -> list[str]:
        cmd = [binary, "-p", prompt]
        cmd += list(spec.config.scan.engine_extra_args)
        return cmd

    def _build_kickoff(
        self, spec: ScanSpec, *, results_dir: Path, git_ctx: dict[str, str]
    ) -> str:
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

    def _log_launch(self, cmd: list[str]) -> None:
        logger.warning(
            "copilot engine is EXPERIMENTAL — verify its flag surface "
            "(`copilot -h`) before production use"
        )
        logger.info("copilot engine: %s … -p <prompt>", cmd[0])
