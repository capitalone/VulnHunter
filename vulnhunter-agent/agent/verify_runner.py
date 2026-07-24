"""SDK driver for ``/vulnhunt-fix-verify`` skill invocations.

Smaller and more focused than ``agent/runner.py``: verify is a
single-shot read-only call with no pre-flight clone-dir check, no
running-cost tracking across continuations, no Bash. We build a
kickoff prompt from the orchestrator's already-staged inputs
(target repo clone, downloaded report, comments file, output dir),
stream the session, and classify the output afterwards.

Event rendering and per-turn-usage/totals accounting are shared
with ``agent/runner.py`` via ``agent/_stream_events.py``. Verify
mode is missing scan-mode's cold-start retry loop (verify runs
are short enough that an in-process restart costs more than a
fresh subprocess invocation would), but otherwise the two paths
emit the same shape of stream and end-of-session rollup.

Public surface:

- ``build_kickoff_prompt`` — pure-function prompt builder.
- ``run_verify_session`` — async coroutine that drives the SDK and
  returns a ``VerifySessionResult``.
- ``classify_output`` — pure-function output-dir classifier
  (disposition / empty / schema-invalid). Called internally by
  ``run_verify_session`` after the SDK stream completes; exposed
  for the orchestrator's tests.
- ``VerifySessionResult``, ``OutputKind`` — return types.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    ResultMessage,
    SystemMessage,
    TaskNotificationMessage,
    TaskStartedMessage,
    TaskUpdatedMessage,
    UserMessage,
)
from jsonschema import Draft202012Validator

from .build_settings import build_claude_settings
from .config import AgentConfig
from ._stream_events import (
    SessionTotals,
    _agent_name_from_started,
    _log_assistant_message,
    _log_per_turn_usage,
    _log_result,
    _log_system_message,
    _log_task_started,
    _log_task_status,
    _log_user_message,
    accumulate_result,
    get_verbosity,
    log_session_totals,
)

logger = logging.getLogger(__name__)


# Read-only tool envelope. Mirrors the skill's documented allow-list
# (Read/Write/Edit/Glob/Grep/Agent) — no Bash, no network. Caller
# can't extend; we want verify mode to be a tight envelope.
_VERIFY_ALLOWED_TOOLS: tuple[str, ...] = (
    "Read",
    "Write",
    "Edit",
    "Glob",
    "Grep",
    "Agent",
)


# Schema files live at the repo root next to the rest of the
# vendored contracts. Resolved by walking up from this module's
# directory — works in both editable install and Docker image.
def _schema_root() -> Path:
    here = Path(__file__).resolve()
    # agent/verify_runner.py → walk to repo root.
    return here.parent.parent


class OutputKind(str, Enum):
    DISPOSITION = "disposition"
    EMPTY = "empty"            # disposition file missing (infra failure)
    SCHEMA_INVALID = "schema_invalid"


@dataclass(frozen=True)
class VerifySessionResult:
    """Outcome of a single verify-skill session.

    The session produces a ``verify_disposition.json`` (verdict) which
    is validated against its schema before being handed back. The
    clone-request stop-signal mechanism was retired in favor of an
    agent-side Haiku pre-flight that resolves cross-repo references
    before the skill ever runs (see ``agent/verify_refs.py``); the
    skill no longer has a way to halt mid-run asking for more sources.
    """

    kind: OutputKind
    output_path: Path | None      # path to the disposition file
    parsed: dict[str, Any] | None  # parsed + validated disposition payload
    error_detail: str = ""        # populated when kind == SCHEMA_INVALID or EMPTY


def build_kickoff_prompt(
    *,
    repo: Path,
    report: Path,
    fixed_ids: list[str],
    out: Path,
    comments: Path,
    additional_repos: list[Path] | None = None,
) -> str:
    """Build the slash-command prompt for one verify session.

    All paths must be absolute; the skill rejects relative paths in
    its phase-0 argument-shape check. ``fixed_ids`` is rendered as a
    comma-separated list. ``additional_repos`` is omitted from the
    prompt entirely when empty (the skill treats absence as "no
    additional roots").
    """
    if not fixed_ids:
        raise ValueError("fixed_ids must be a non-empty list of VULN-NNN strings")
    fixed_value = ",".join(fixed_ids)
    lines = [
        "/vulnhunt-fix-verify",
        "",
        "Arguments:",
        f"  repo:     {repo}",
        f"  report:   {report}",
        f"  fixed:    {fixed_value}",
        f"  out:      {out}",
        f"  comments: {comments}",
    ]
    if additional_repos:
        lines.append(
            "  additional_repos: " + ",".join(str(p) for p in additional_repos)
        )
    lines.append("")
    return "\n".join(lines)


def classify_output(out_dir: Path) -> VerifySessionResult:
    """Inspect ``out_dir`` for the verify skill's disposition and validate it.

    The skill writes exactly one output file — ``verify_disposition.json``.
    Absence collapses to ``OutputKind.EMPTY``; presence with malformed
    JSON or a schema-violating payload collapses to
    ``OutputKind.SCHEMA_INVALID``. The orchestrator treats both as
    infrastructure failures (no GitHub mutation).
    """
    disposition = out_dir / "verify_disposition.json"
    if disposition.is_file():
        return _load_and_validate(
            disposition,
            schema_filename="verify_disposition.schema.json",
            success_kind=OutputKind.DISPOSITION,
        )
    return VerifySessionResult(
        kind=OutputKind.EMPTY,
        output_path=None,
        parsed=None,
        error_detail=(
            f"verify_disposition.json did not appear in {out_dir}"
        ),
    )


def _load_and_validate(
    path: Path,
    *,
    schema_filename: str,
    success_kind: OutputKind,
) -> VerifySessionResult:
    """Parse ``path`` as JSON and validate against ``schema_filename``.

    Schema files are sourced from the repo root (next to the
    scan_manifest schema). Validation errors collapse to
    ``OutputKind.SCHEMA_INVALID`` so the orchestrator handles the
    failure uniformly.
    """
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return VerifySessionResult(
            kind=OutputKind.SCHEMA_INVALID,
            output_path=path,
            parsed=None,
            error_detail=f"Could not parse {path}: {exc}",
        )
    schema_path = _schema_root() / schema_filename
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except OSError as exc:
        return VerifySessionResult(
            kind=OutputKind.SCHEMA_INVALID,
            output_path=path,
            parsed=None,
            error_detail=f"Could not load schema {schema_path}: {exc}",
        )
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(payload), key=lambda e: e.path)
    if errors:
        detail = "; ".join(
            f"{'/'.join(str(p) for p in err.path) or '<root>'}: {err.message}"
            for err in errors[:5]
        )
        return VerifySessionResult(
            kind=OutputKind.SCHEMA_INVALID,
            output_path=path,
            parsed=None,
            error_detail=(
                f"{path.name} failed {schema_filename} validation: {detail}"
            ),
        )
    return VerifySessionResult(
        kind=success_kind,
        output_path=path,
        parsed=payload,
        error_detail="",
    )


# ---- SDK session driver ----------------------------------------------------


async def run_verify_session(
    *,
    config: AgentConfig,
    auth_token: str,
    cwd: Path,
    out_dir: Path,
    prompt: str,
    log_path: Path,
    model_override: str | None = None,
) -> VerifySessionResult:
    """Drive one verify-skill SDK session and classify its output.

    The caller has already staged ``cwd`` (the run's scratch dir),
    created ``out_dir``, and written the kickoff prompt's referenced
    files (``repo/``, ``report/``, ``comments.md``).

    Logs every SDK event to ``log_path`` (append-mode) so a per-run
    forensics trail survives even if the orchestrator crashes
    mid-run.
    """
    model = model_override or config.anthropic.model
    scan_id = out_dir.parent.name  # one level up from out/iter-N — readable run id

    settings_json = build_claude_settings(
        config, auth_token, model=model, scan_id=scan_id
    )
    options = ClaudeAgentOptions(
        # Locked allow-list — verify mode is always read-only; no
        # CLI flag widens this set. The skill is responsible for
        # reading/writing only under cwd / out_dir.
        tools=list(_VERIFY_ALLOWED_TOOLS),
        allowed_tools=list(_VERIFY_ALLOWED_TOOLS),
        permission_mode=config.scan.permission_mode,
        settings=settings_json,
        model=model,
        cwd=str(cwd),
        # Same skill discovery path as scan mode — the SDK reads
        # ~/.claude/skills/vulnhunt-fix-verify/SKILL.md.
        #
        # CANON-19: ``cwd`` is the untrusted cloned repo. "project"/"local"
        # would load that repo's .claude/settings(.local).json (hooks,
        # permissions) and its skills, executing attacker-controlled config on
        # the host. Restrict to "user" only — the trusted vulnhunt-fix-verify
        # skill lives in the user dir, so verify functionality is unaffected.
        setting_sources=["user"],
        skills="all",
    )

    log_path.parent.mkdir(parents=True, exist_ok=True)
    totals = SessionTotals()
    start = time.time()
    log_per_turn_usage = config.logging.per_turn_usage
    last_turn_ts: dict[str | None, float] = {None: start}
    agent_names_by_tool_use_id: dict[str, str] = {}
    agent_names_by_task_id: dict[str, str] = {}
    message_count = 0
    with log_path.open("a", encoding="utf-8") as log_fh:
        log_fh.write(f"\n--- verify session begin: model={model} ---\n")
        log_fh.write(f"prompt:\n{prompt}\n")
        log_fh.write("--- events ---\n")
        try:
            async with ClaudeSDKClient(options) as client:
                await client.query(prompt)
                async for event in client.receive_response():
                    message_count += 1
                    # File log: terse one-line summary survives crashes.
                    log_fh.write(
                        f"{type(event).__name__}: {_event_summary(event)}\n"
                    )
                    # Stdout/structured log: routed through the shared
                    # verbosity-tiered helpers so verify-mode -v/-vv
                    # behave the same as scan-mode.
                    _dispatch_event(
                        event,
                        totals=totals,
                        last_turn_ts=last_turn_ts,
                        run_start=start,
                        agent_names_by_tool_use_id=agent_names_by_tool_use_id,
                        agent_names_by_task_id=agent_names_by_task_id,
                        log_per_turn_usage=log_per_turn_usage,
                        message_count=message_count,
                    )
        except Exception as exc:
            log_fh.write(f"!!! SDK exception: {exc!r}\n")
            logger.exception("Verify SDK session failed")
            return VerifySessionResult(
                kind=OutputKind.EMPTY,
                output_path=None,
                parsed=None,
                error_detail=f"SDK session raised: {exc!r}",
            )
        log_fh.write("--- verify session end ---\n")

    elapsed = time.time() - start
    logger.info(
        "Verify session finished in %.1fs (%d messages)",
        elapsed,
        message_count,
    )
    log_session_totals(totals, "Verify")
    return classify_output(out_dir)


def _dispatch_event(
    event: object,
    *,
    totals: SessionTotals,
    last_turn_ts: dict[str | None, float],
    run_start: float,
    agent_names_by_tool_use_id: dict[str, str],
    agent_names_by_task_id: dict[str, str],
    log_per_turn_usage: bool,
    message_count: int,
) -> None:
    """Route one SDK event to the shared print/log helpers.

    Verify mode doesn't need the cold-start rate-limit detection,
    continuation logic, or auth-failure counters from
    ``runner._run_scan_session`` — verify sessions are short enough
    that a fresh subprocess retry is cheaper than an in-process
    restart, and the wrapper handles that at a higher level. We just
    need parity on the stream-rendering side.
    """
    elapsed = time.time() - run_start
    msg_type = type(event).__name__
    header_extra = ""
    if isinstance(event, AssistantMessage):
        msg_model = getattr(event, "model", None)
        if msg_model:
            header_extra = f" model={msg_model}"
    if get_verbosity() >= 2:
        logger.info(
            "[%6.1fs] message #%d: %s%s",
            elapsed,
            message_count,
            msg_type,
            header_extra,
        )

    # Same dispatch order as runner._run_scan_session: Task* are
    # SystemMessage subtypes, so they must be tested first.
    if isinstance(event, TaskStartedMessage):
        name = _agent_name_from_started(event)
        tool_use_id = getattr(event, "tool_use_id", None)
        if name:
            if tool_use_id:
                agent_names_by_tool_use_id[tool_use_id] = name
            agent_names_by_task_id[event.task_id] = name
        if tool_use_id and tool_use_id not in last_turn_ts:
            last_turn_ts[tool_use_id] = time.time()
        _log_task_started(event)
    elif isinstance(event, (TaskUpdatedMessage, TaskNotificationMessage)):
        _log_task_status(
            event, agent_name=agent_names_by_task_id.get(event.task_id)
        )
    elif isinstance(event, AssistantMessage):
        if log_per_turn_usage:
            _log_per_turn_usage(
                event,
                last_turn_ts,
                run_start,
                agent_names_by_tool_use_id,
            )
        _log_assistant_message(event)
    elif isinstance(event, UserMessage):
        _log_user_message(event)
    elif isinstance(event, SystemMessage):
        _log_system_message(event)
    elif isinstance(event, ResultMessage):
        _log_result(event)
        accumulate_result(totals, event)


def _event_summary(event: object) -> str:
    """One-line summary of an SDK event for the run log.

    Keeps the log human-skimmable without spilling full message
    contents. The full text lives in the SDK's own debug traces if
    the caller cranks up logging.
    """
    cls = type(event).__name__
    if isinstance(event, (AssistantMessage, UserMessage, SystemMessage)):
        return f"{cls}"
    if isinstance(event, ResultMessage):
        return (
            f"{cls} is_error={getattr(event, 'is_error', None)} "
            f"cost=${getattr(event, 'total_cost_usd', 0.0):.4f}"
        )
    if isinstance(
        event,
        (TaskStartedMessage, TaskUpdatedMessage, TaskNotificationMessage),
    ):
        return f"{cls} task_id={getattr(event, 'task_id', '?')}"
    return cls
