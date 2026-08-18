"""OpenAI Codex CLI engine.

Drives /vulnhunt through a headless ``codex exec`` run against the skill
bundle installed at ``~/.codex/skills/vulnhunt``
(``./install.sh --target codex``). Codex has no slash-command registry or
subagent tool, so the kickoff prompt points the agent at the bundle's
SKILL.md explicitly and the codex-rendered skill itself carries the
sequential-execution instructions.

Sandbox: always ``workspace-write`` — even read-only scans must write the
results directory; the read-only contract is enforced by the prompt
(exploit tests written, not run), mirroring the Claude path's acceptEdits
policy. Flags verified against codex-cli 0.147.0.
"""

from __future__ import annotations

from pathlib import Path

from agent import runner as _runner
from agent.engines import ScanSpec
from agent.engines._subprocess import SubprocessEngine, logger

_CODEX_SKILL = Path.home() / ".codex" / "skills" / "vulnhunt" / "SKILL.md"


class CodexEngine(SubprocessEngine):
    name = "codex"
    _binary_name = "codex"
    _install_target = "codex"
    _binary_hint = "install the Codex CLI"

    def _skill_paths(self) -> tuple[Path, ...]:
        return (_CODEX_SKILL,)

    def _build_command(self, spec: ScanSpec, binary: str, prompt: str) -> list[str]:
        cmd = [
            binary,
            "exec",
            "-C",
            str(spec.clone_dir),
            "-s",
            "workspace-write",
        ]
        if spec.model:
            cmd += ["-m", spec.model]
        cmd += list(spec.config.scan.engine_extra_args)
        cmd += [prompt]
        return cmd

    def _build_kickoff(
        self, spec: ScanSpec, *, results_dir: Path, git_ctx: dict[str, str]
    ) -> str:
        shell_line = (
            "The sandboxed shell is AVAILABLE for exploit-test execution "
            "(--enable-bash was passed)."
            if spec.enable_bash
            else "This is a read-only scan: use shell searches and file reads for "
            "analysis; write exploit tests but do NOT run them."
        )
        tag = _runner._model_tag(spec.model)
        return (
            f"{_runner._VULNHUNT_PROMPT_PREAMBLE}\n\n"
            f"Read {_CODEX_SKILL} and execute the /vulnhunt workflow it defines "
            f"on {spec.clone_dir}. Follow the SKILL.md and its phase files "
            f"exactly (phase files are under ~/.codex/skills/vulnhunt/phases/).\n\n"
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
        logger.info("codex engine: %s … exec <prompt>", cmd[0])
