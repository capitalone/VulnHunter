"""Hermes CLI engine: drive /vulnhunt via a headless ``hermes chat`` run.

The vulnhunt skill must be installed for Hermes first
(``./install.sh --target hermes`` → ``~/.hermes/skills/vulnhunt``).
This engine pre-stages the same metadata the Claude SDK path provides
(results dir, branch label, repo URL, model tag, shell availability),
launches one headless session, and judges success by the results
directory's contents — Hermes' ``-Q`` contract (stdout = final message,
stderr = session id) is used only for logging/diagnostics.

Subagent fan-out happens inside Hermes (``delegate_task``), so no
process-level fan-out is needed here; the kickoff teaches the async-
delegation wait protocol instead.
"""

from __future__ import annotations

from pathlib import Path

from agent import runner as _runner
from agent.engines import EngineError, ScanSpec
from agent.engines._subprocess import SubprocessEngine, logger

# Re-exported for backwards compatibility: callers and tests historically
# imported EngineError from this module. Its home is now engines/__init__.
__all__ = ["EngineError", "HermesEngine"]

_HERMES_SKILL = Path.home() / ".hermes" / "skills" / "vulnhunt" / "SKILL.md"
# A tuple so additional fallback locations can be added without touching the
# base-class lookup (any-of semantics); tests monkeypatch this to a temp path.
_HERMES_SKILL_CANDIDATES = (_HERMES_SKILL,)

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


class HermesEngine(SubprocessEngine):
    name = "hermes"
    _binary_name = "hermes"
    _install_target = "hermes"
    _binary_hint = (
        "install Hermes (https://github.com/weav/hermes-agent)"
    )

    def _skill_paths(self) -> tuple[Path, ...]:
        return _HERMES_SKILL_CANDIDATES

    def _build_command(self, spec: ScanSpec, binary: str, prompt: str) -> list[str]:
        scan = spec.config.scan
        cmd = [
            binary,
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

    def _build_kickoff(
        self, spec: ScanSpec, *, results_dir: Path, git_ctx: dict[str, str]
    ) -> str:
        prompt = _runner._build_vulnhunt_prompt(
            spec.clone_dir,
            spec.model,
            read_only=spec.read_only,
            results_dir=results_dir,
            branch_label=git_ctx["branch_label"],
            repo_url=git_ctx["repo_url"],
            enable_bash=spec.enable_bash,
            effective_tools=list(_EFFECTIVE_TOOLS),
        )
        return prompt + _DELEGATION_PROTOCOL

    def _log_launch(self, cmd: list[str]) -> None:
        logger.info("hermes engine: %s", " ".join(cmd[:8]) + " … -q <prompt>")
