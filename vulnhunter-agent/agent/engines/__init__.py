"""Pluggable scan engines for the vulnhunter-agent runtime.

An *engine* is the agent harness that actually drives the /vulnhunt skill
against a clone: currently the Claude Agent SDK (reference) or the Hermes
CLI. The protocol remains open to future engine modules. All engines share
one contract:

  - success is judged by the VulnHunter results contract — a
    ``*_VULNHUNT_RESULTS_*`` directory that actually contains the skill's
    ``README.md`` report — never by stdout text, which differs per
    harness, and never by the directory's mere existence (the subprocess
    engines pre-create it, so an engine that crashes before writing must
    still be judged a failure);
  - the kickoff prompt carries the same "Pre-resolved scan metadata"
    block the skill's Mandatory First Actions expect (results dir, branch
    label, repo URL, model tag, shell availability), so the skill runs
    identically regardless of engine;
  - downstream stages (manifest, publish, issues, audit, verify) are
    engine-agnostic and consume only the results contract.

Select via ``[scan] engine = "claude-code" | "hermes"`` in the agent TOML
(default ``claude-code`` — the existing SDK path, unchanged).

CLI-backed engines subclass ``SubprocessEngine``
(``agent/engines/_subprocess.py``); each concrete engine only declares its
binary name, skill path, argv, and kickoff prompt. Adding another harness
therefore does not require duplicating process, audit, timeout, or results
contract handling.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from agent._stream_events import SessionTotals
    from agent.audit import AuditWriter
    from agent.config import AgentConfig

ENGINE_NAMES = ("claude-code", "hermes")


class EngineError(RuntimeError):
    """Engine-level failure (binary missing, timeout, non-zero/empty result).

    Lives here — next to ``ScanSpec`` / ``ScanEngine`` — rather than in any
    one engine module, so importing a single engine doesn't drag in an
    unrelated one purely for the exception type.
    """


@dataclass(frozen=True)
class ScanSpec:
    """Everything an engine needs to run one scan."""

    clone_dir: Path
    config: "AgentConfig"
    model: str
    scan_id: str = ""
    read_only: bool = True
    enable_bash: bool = False
    backoffs: tuple[float, ...] = ()


@runtime_checkable
class ScanEngine(Protocol):
    """The engine contract implemented by every harness adapter."""

    name: str

    async def run_scan(
        self,
        spec: ScanSpec,
        *,
        audit_writer: "AuditWriter | None" = None,
        totals_out: "SessionTotals | None" = None,
    ) -> Path | None:
        """Run /vulnhunt against ``spec.clone_dir``; return the results dir.

        Raises on pre-flight failures (missing skill, prior results,
        engine binary absent, engine timeout) and on a run that finishes
        without a complete results directory. A None return means the
        engine finished cleanly but produced no results directory.
        """
        ...  # pragma: no cover


def get_engine(config: "AgentConfig") -> ScanEngine:
    """Instantiate the engine selected by ``[scan] engine``."""
    # Local imports keep module import cheap and avoid cycles: the engine
    # modules import runner helpers, runner imports config, config imports
    # this package — so the concrete engines must not load at package import.
    name = config.scan.engine
    if name == "claude-code":
        from agent.engines.claude_code import ClaudeCodeEngine

        return ClaudeCodeEngine()
    if name == "hermes":
        from agent.engines.hermes import HermesEngine

        return HermesEngine()

    raise ValueError(
        f"unknown scan engine {name!r} (supported: {', '.join(ENGINE_NAMES)}); "
        "set [scan] engine in the agent TOML"
    )


__all__ = [
    "ENGINE_NAMES",
    "EngineError",
    "ScanEngine",
    "ScanSpec",
    "get_engine",
]
