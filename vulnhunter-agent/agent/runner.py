"""SDK runner: launch /vulnhunt against a clone via the Claude Agent SDK.

The skill itself must already be installed at ~/.claude/skills/vulnhunt
(run install.sh from the repo root). We don't reinstall it here.
"""

from __future__ import annotations

import datetime as _dt
import logging
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    ResultMessage,
    SystemMessage,
    TERMINAL_TASK_STATUSES,
    TaskNotificationMessage,
    TaskStartedMessage,
    TaskUpdatedMessage,
    UserMessage,
)
from tenacity import (
    AsyncRetrying,
    RetryCallState,
    retry_if_exception_type,
    stop_after_attempt,
    wait_chain,
    wait_fixed,
    wait_none,
)

from . import audit as _audit
from . import audit_extract as _audit_extract
from .auth import make_token_manager
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
    _render_block,
    _result_brief,
    _tool_brief,
    _truncate,
    accumulate_result,
    get_verbosity,
    log_session_totals,
    set_verbosity,
)
from ._transient import classify as _classify_transient
from ._url import redact as _redact

logger = logging.getLogger(__name__)


# Resolve git's absolute path once at module load rather than relying on
# PATH-time resolution at every subprocess call (Bandit B607). ``None``
# when git is not installed — every ``_run_git`` call then returns "" so
# callers take their basename / "unknown" fallback without a surprise
# OSError. The agent itself doesn't require git for the scan loop; only
# the metadata pre-stage and the harness's clone/publish helpers do.
_GIT_EXECUTABLE: str | None = shutil.which("git")


_VULNHUNT_PROMPT_PREAMBLE = (
    "\n\nIMPORTANT: This is running in non-interactive headless mode. "
    "Do NOT ask for approval or confirmation. Execute immediately."
)

# Appended when read_only=True. Matches the harness's --read-only
# semantics (harness/scan.py): the model still has Bash/Edit/Write
# available, but the prompt asks it to skip dependency installation
# and any code execution. This is the default — runs that need to
# install deps or execute code (e.g. exploit_test verification) must
# explicitly pass read_only=False.
_READONLY_PROMPT_SUFFIX = (
    " Perform a read-only scan, skip instructions related to "
    "getting dependencies and executing code."
)


_MODEL_FAMILIES = ("opus", "sonnet", "haiku", "gpt", "o3", "o1")
_LONG_CONTEXT_RE = re.compile(r"\[1m\]|_1m\b", re.IGNORECASE)


def _model_tag(model: str) -> str:
    """Derive the short MODEL tag the /vulnhunt skill expects in directory names.

    The skill instructs Claude to self-identify (``opus47``, ``sonnet46``, ...)
    but models often misremember their version. We compute the tag from the
    configured model name and pass it explicitly so the skill doesn't depend
    on the model knowing what it is.

    The 1-million-context variant suffix (``[1m]`` or ``_1m``) is preserved
    as ``_1m`` on the resulting tag, matching the skill's documented form.

    Examples:
        claude-opus-4-8         -> opus48
        claude-opus-4-8[1m]     -> opus48_1m
        claude-4.6-opus         -> opus46
        claude-sonnet-5         -> sonnet5
        claude-haiku-4-5        -> haiku45
    """
    lowered = model.lower().replace("claude-", "")
    long_context = bool(_LONG_CONTEXT_RE.search(lowered))
    # Strip the long-context marker before extracting digits so its '1' and
    # 'm' don't pollute the version detection.
    cleaned = _LONG_CONTEXT_RE.sub("", lowered)
    family = next((f for f in _MODEL_FAMILIES if f in cleaned), "model")
    digits = re.findall(r"\d", cleaned)
    version = "".join(digits[:2])
    base = f"{family}{version}" if version else family
    return f"{base}_1m" if long_context else base


def _build_vulnhunt_prompt(
    clone_path: Path,
    model: str,
    *,
    read_only: bool = True,
    results_dir: Path | None = None,
    branch_label: str = "unknown",
    repo_url: str | None = None,
    enable_bash: bool = False,
    effective_tools: list[str] | None = None,
) -> str:
    """Compose the /vulnhunt prompt without using str.format on the path.

    A plain f-string is safer than .format(...) because the cloned repo
    name is filesystem-derived; if it ever contained ``{`` or ``}`` chars
    the .format call would raise. The model tag is also injected so the
    skill doesn't have to ask the model to self-identify.

    When ``results_dir`` / ``branch_label`` / ``repo_url`` are supplied,
    a "Pre-resolved scan metadata" block is appended. Every value the
    skill previously gathered via shell commands (``pwd``, ``date``,
    ``mkdir``, ``git rev-parse``, ``git remote get-url``) is supplied
    here so the model can run with ``Bash`` removed from its tool
    allow-list. ``enable_bash`` toggles a one-line clarifier the skill
    uses to gate code-execution instructions.

    ``effective_tools`` is the post-policy SDK tool allow-list (already
    has ``Bash`` stripped or re-added per ``enable_bash``). It's used to
    render the "use X/Y/Z only" line accurately — without it we'd hard-
    code a tool list and lie to the model when a TOML adds or removes
    tools. ``Agent`` is omitted from the rendered list (it's the
    subagent dispatcher, not a read/write surface the model picks
    between for content access).
    """
    tag = _model_tag(model)
    preamble = _VULNHUNT_PROMPT_PREAMBLE
    if read_only:
        preamble += _READONLY_PROMPT_SUFFIX
    base = (
        f"/vulnhunt {clone_path}{preamble}\n\n"
        f"Use the model tag `{tag}` for this scan. Name the results "
        f"directory and any other artifacts with that exact tag — do not "
        f"introspect your own model identity."
    )
    if results_dir is None and repo_url is None and branch_label == "unknown":
        # No pre-staging requested (test paths). Preserve the historical
        # prompt shape exactly so existing snapshot/assertion tests keep
        # passing without modification.
        return base
    resolved_repo_url = repo_url if repo_url is not None else clone_path.name
    resolved_dir = (
        str(results_dir) if results_dir is not None else "<unset>"
    )
    if enable_bash:
        bash_line = (
            "Bash is AVAILABLE for exploit-test execution "
            "(--enable-bash was passed)."
        )
    else:
        # Render the actual non-Bash tools the model has, so the prompt
        # doesn't claim Grep/Edit are available when the TOML allow-list
        # doesn't include them. Falls back to a vaguer phrasing when no
        # tool list was threaded through (test paths that bypass
        # ``run_vulnhunt``).
        if effective_tools is None:
            tool_phrase = "the non-Bash tools in your allow-list"
        else:
            tool_names = [t for t in effective_tools if t not in ("Bash", "Agent")]
            tool_phrase = (
                "/".join(tool_names) if tool_names
                else "the non-Bash tools in your allow-list"
            )
        bash_line = f"Bash is NOT available — use {tool_phrase} only."
    return (
        f"{base}\n\n"
        "Pre-resolved scan metadata (use these literal values — do NOT "
        "run shell commands to recompute them):\n"
        f"- VULNHUNT_DIR: {resolved_dir}\n"
        f"- VULNHUNT_BRANCH: {branch_label}\n"
        f"- Repository URL: {resolved_repo_url}\n"
        f"- {bash_line}"
    )


def _vulnhunt_skill_path() -> Path | None:
    """Locate the vulnhunt skill installation. Container path first, then $HOME."""
    candidates = [
        Path("/home/appuser/.claude/skills/vulnhunt"),
        Path.home() / ".claude" / "skills" / "vulnhunt",
    ]
    for path in candidates:
        if (path / "SKILL.md").is_file():
            return path
    return None


def _find_results_dir(clone_dir: Path) -> Path | None:
    """Return the most recently modified ``*_VULNHUNT_RESULTS_*`` dir.

    Multiple results dirs can coexist if a previous run was kept (the
    user chose not to ``--re-clone``). We pick the newest by mtime so a
    fresh scan's results always win over older leftovers.
    """
    if not clone_dir.is_dir():
        return None
    candidates = [
        entry
        for entry in clone_dir.iterdir()
        if entry.is_dir() and "_VULNHUNT_RESULTS_" in entry.name
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


class PriorResultsError(RuntimeError):
    """Raised when an existing ``*_VULNHUNT_RESULTS_*`` dir would shadow this scan.

    The skill must not read its own prior output during a re-scan; surface
    the conflict to the caller (typically ``__main__.py``) rather than
    overwriting silently.
    """


def _git_context(clone_dir: Path) -> dict[str, str]:
    """Resolve branch label and origin URL for ``clone_dir`` via local git.

    Returns a dict with three keys:

    - ``branch_label``: ``"<branch> [<short-sha>]"`` on success, ``"unknown"``
      otherwise. Format matches what phase4_report.md's README header
      previously asked the model to assemble.
    - ``repo_url``: normalized HTTPS URL (``https://github.com/<org>/<repo>``).
      SSH form ``git@host:org/repo.git`` is rewritten, embedded basic-auth
      userinfo (``user:token@``) is stripped, and the trailing ``.git`` is
      removed. Falls back to ``clone_dir.parent.name`` when ``origin``
      cannot be resolved — matches phase4_report.md's documented fallback.
    - ``head_sha``: full HEAD commit SHA at scan time. Empty string when
      not derivable (missing git binary, corrupt clone). Consumed by the
      audit stream's ``target_sha`` field.

    All lookups are best-effort: a corrupted clone, missing git binary,
    or absent ``origin`` remote yields the fallback rather than raising.
    The skill receives literal values via the kickoff prompt and never
    runs git itself.
    """
    branch_label = _git_branch_label(clone_dir)
    repo_url = _git_repo_url(clone_dir)
    head_sha = _run_git(clone_dir, "rev-parse", "HEAD")
    return {
        "branch_label": branch_label,
        "repo_url": repo_url,
        "head_sha": head_sha,
    }


def _git_branch_label(clone_dir: Path) -> str:
    branch = _run_git(clone_dir, "rev-parse", "--abbrev-ref", "HEAD")
    sha = _run_git(clone_dir, "rev-parse", "--short", "HEAD")
    if not branch or not sha:
        return "unknown"
    return f"{branch} [{sha}]"


def _git_repo_url(clone_dir: Path) -> str:
    raw = _run_git(clone_dir, "remote", "get-url", "origin")
    if not raw:
        return clone_dir.name
    return _normalize_repo_url(raw) or clone_dir.name


def _normalize_repo_url(raw: str) -> str:
    """Convert SSH/HTTPS git origin URL to canonical ``https://host/org/repo``.

    Strips embedded basic-auth (``https://user:token@host/...``) and the
    trailing ``.git`` suffix; rewrites SSH ``git@host:org/repo`` to
    ``https://host/org/repo``. An empty input maps to ``""``. Any other
    input that doesn't match the SSH or userinfo patterns falls through
    unchanged (minus a trailing ``.git`` if present) — ``git remote
    get-url origin`` is the only producer in practice and never returns
    free-form garbage, so this is fine. The caller (``_git_repo_url``)
    treats any non-empty return as authoritative.
    """
    url = raw.strip()
    if not url:
        return ""
    # SSH form: git@github.com:org/repo[.git]
    ssh_match = re.match(r"^git@([^:]+):(.+)$", url)
    if ssh_match:
        host, path = ssh_match.groups()
        url = f"https://{host}/{path}"
    # Strip basic-auth userinfo from HTTPS form.
    url = re.sub(r"^(https?://)[^/@]+@", r"\1", url)
    # Strip trailing .git
    if url.endswith(".git"):
        url = url[: -len(".git")]
    return url


def _repo_slug_from_url(url: str, fallback_basename: str) -> str:
    """Extract ``org/repo`` from a normalized git URL.

    - ``https://github.com/org/repo`` → ``org/repo``
    - Deeper paths take the last two segments.
    - No path segments → ``unknown/{fallback_basename}``.

    Matches the audit schema's documented ``owner/repo`` shape.
    """
    parsed = urlparse(url)
    parts = [p for p in parsed.path.split("/") if p] if parsed.path else []
    if len(parts) >= 2:
        return f"{parts[-2]}/{parts[-1]}"
    if len(parts) == 1:
        return f"unknown/{parts[0]}"
    if "/" in url:
        segs = [p for p in url.split("/") if p]
        if len(segs) >= 2:
            return f"{segs[-2]}/{segs[-1]}"
    return f"unknown/{fallback_basename or url or 'repo'}"


def _run_git(clone_dir: Path, *args: str) -> str:
    """Run ``git <args>`` in ``clone_dir`` and return stdout or "" on failure.

    Logs a warning on subprocess errors (matches ``__main__._short_sha``'s
    pattern) so an unexpected git failure doesn't go silent, but always
    returns a string — callers fall back to ``"unknown"`` or the directory
    basename rather than failing the scan over metadata.

    Uses the absolute path resolved at module load via
    ``shutil.which("git")``. If git isn't on PATH at import time, every
    call returns ``""`` and the caller takes its fallback path — no
    surprise PATH-time resolution at call sites (Bandit B607).
    """
    if _GIT_EXECUTABLE is None:
        logger.warning("git not on PATH; skipping git %s", " ".join(args))
        return ""
    try:
        # nosec B603 — args are statically constructed in this module
        # (`["rev-parse", "--abbrev-ref", "HEAD"]`, `["remote", "get-url",
        # "origin"]`); ``clone_dir`` is a Path the agent owns. No
        # untrusted input enters the argv list. Executable path is
        # resolved at module load (kills B607).
        out = subprocess.run(  # nosec B603
            [_GIT_EXECUTABLE, *args],
            cwd=str(clone_dir),
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("git %s failed: %s", " ".join(args), exc)
        return ""
    if out.returncode != 0:
        # Quiet at INFO — many of our fallback paths (not-a-git-repo, no
        # origin remote) hit this and are expected, not error-worthy.
        logger.info(
            "git %s returned %d: %s",
            " ".join(args),
            out.returncode,
            out.stderr.strip(),
        )
        return ""
    return out.stdout.strip()


def _compute_results_dir(clone_dir: Path, model: str) -> Path:
    """Build the absolute path to a fresh ``*_VULNHUNT_RESULTS_*`` directory.

    Name format: ``{clone-basename}_VULNHUNT_RESULTS_{tag}_{YYYY-MM-DD-HHMMSS}``.
    The timestamp is captured in UTC so dirs are sortable and don't drift
    with the host TZ. The caller is responsible for creating the directory
    (we hand back the path so tests can predict it).
    """
    tag = _model_tag(model)
    ts = _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%d-%H%M%S")
    return clone_dir / f"{clone_dir.name}_VULNHUNT_RESULTS_{tag}_{ts}"


def _check_no_prior_results(clone_dir: Path) -> None:
    """Refuse to start when an existing ``*_VULNHUNT_RESULTS_*`` dir is
    present in ``clone_dir``.

    The skill must not read its own prior output during a re-scan. With
    Python pre-creating the dir up-front, the old SKILL.md ``ls`` check is
    gone; this helper carries forward the same safety guarantee.
    """
    if not clone_dir.is_dir():
        return
    priors = [
        entry.name
        for entry in clone_dir.iterdir()
        if entry.is_dir() and "_VULNHUNT_RESULTS_" in entry.name
    ]
    if priors:
        raise PriorResultsError(
            f"Existing VulnHunter results directory/directories in "
            f"{clone_dir}: {sorted(priors)}. Move or remove them before "
            "re-scanning — the skill must not read its own prior output."
        )


_MAX_CONSECUTIVE_AUTH_FAILURES = 3
# Cold-start rate-limit threshold: after this many consecutive transient
# (429 / 5xx) SystemMessages with no AssistantMessage in between, we
# treat the run as "couldn't even start" and raise RateLimitError so the
# outer retry loop can back off and try again. Single transient signals
# are absorbed silently — the SDK does internal retries before
# surfacing them.
_MAX_CONSECUTIVE_RATE_LIMITS = 3
# Backoff schedule for the outer scan-retry loop on cold-start transient
# errors. Mirrors harness/scan.py's pattern (60s → 2× → cap at 300s)
# so the agent-level retry behaves the same as the subprocess-level
# retry the harness already provides.
_SCAN_RETRY_BACKOFFS: tuple[float, ...] = (60.0, 120.0, 300.0)
# A continuation is "stalled" when NO task lifecycle event
# (TaskStartedMessage or terminal TaskNotificationMessage) arrives
# during it. Continuations that show any task activity reset this
# counter to zero. Heavy rate-limiting produces many continuations
# but they remain productive (new dispatches and/or completions
# in between waits), so this gates abort on actual progress rather
# than raw iteration count. In practice re-prompt round-trips average
# ~3s (not ~30s as originally estimated), so 10 stalls ≈ 30s — far
# too short when a 429 backoff can reach 37s per retry with up to 10
# retries (~2 min total). Raised to 60 to give stalled agents ~3 min
# of breathing room to recover from rate-limit backoff before being
# declared orphaned.
_MAX_STALLED_CONTINUATIONS = 60
_CONTINUATION_PROMPT = (
    "Continue the /vulnhunt workflow. Background subagents may still be "
    "running — do not stop until every dispatched task has completed and "
    "you have advanced through Phase 2b, Phase 3, Phase 3d, and the final "
    "report. Verify each phase's output files exist before moving on. "
    "Do not respond with a goodbye message until the report is written."
)


class AuthRejectedError(RuntimeError):
    """The Bedrock proxy rejected the bearer token; retrying won't help."""


class RateLimitError(RuntimeError):
    """API returned 429 / 5xx / overload before any AssistantMessage arrived.

    Cold-start condition — restarting the SDK session after a backoff is
    safe (no work is discarded). Mid-stream rate-limits do NOT raise this:
    a restart would discard meaningful progress, and the harness's
    subprocess-level retry handles that case.
    """


@dataclass
class _SessionResult:
    """Output of one ``_run_scan_session`` invocation.

    Threading these back out of the session lets ``run_vulnhunt`` populate
    ``scan_completed`` audit events with per-session cost / duration /
    turn totals without keeping a mutable ``totals`` handle across the
    function boundary.
    """

    results_dir: Path | None
    cost_usd: float
    duration_s: float
    num_turns: int


async def run_vulnhunt(
    clone_dir: Path,
    config: AgentConfig,
    *,
    model_override: str | None = None,
    scan_id: str = "",
    read_only: bool = True,
    enable_bash: bool = False,
    backoffs: tuple[float, ...] = _SCAN_RETRY_BACKOFFS,
    audit_writer: "_audit.AuditWriter | None" = None,
    totals_out: SessionTotals | None = None,
) -> Path | None:
    """Run /vulnhunt inside clone_dir and return the results directory it produced.

    The SDK session is wrapped in a ``tenacity.AsyncRetrying`` keyed on
    ``RateLimitError`` — a *cold-start* transient (429 / 5xx before the
    orchestrator produced any AssistantMessage) restarts cleanly because
    no work is lost. Mid-stream transients are logged but do NOT trigger
    a restart: the harness's subprocess-level retry handles those (and
    a restart from scratch on minute 14 of a long scan would waste more
    than the retry saves).

    ``backoffs`` defaults to ``_SCAN_RETRY_BACKOFFS``; tests inject
    ``()`` (no retry) or ``(0.0, 0.0, 0.0)`` (zero-delay) to keep runs
    fast. The token is refreshed inside the retry block, so a backoff
    long enough to rotate the bearer doesn't carry a stale credential
    into the retry attempt.

    ``enable_bash=True`` adds ``"Bash"`` to the SDK tool allow-list for
    this run. The default is False; the skill prompts assume Bash is
    absent and use Read/Grep/Glob/Write/Edit for all read-only work.
    Bash is supplied only when the caller passes ``--enable-bash`` on
    the CLI (and matched ``--no-read-only``) — there is no config-file
    knob, so a stray TOML can't accidentally re-enable arbitrary code
    execution.

    Raises ``PriorResultsError`` if the clone already contains a
    ``*_VULNHUNT_RESULTS_*`` directory — the skill must not read its
    own prior output during a re-scan.
    """
    token_manager = make_token_manager(config)
    auth_token = token_manager.get_valid_token()
    if auth_token:
        # Token prefix/suffix are useful for confirming propagation but reveal
        # JWT header bytes, so keep them out of INFO output. Set --log-level
        # DEBUG when you actually need to verify what the SDK received.
        prefix = auth_token[:8]
        suffix = auth_token[-4:] if len(auth_token) > 12 else ""
        logger.debug(
            "Token forwarded to SDK: %s...%s (len=%d)", prefix, suffix, len(auth_token)
        )

    model = model_override or config.anthropic.model

    # Pre-compute report_id + repo_slug up front so ``scan_started`` can
    # fire even if the pre-flight steps below (skill discovery, prior-
    # results check, mkdir, git context) raise. Design promises the
    # audit trail covers pre-scan failures — we emit scan_started
    # early, wrap the setup in try/except, and emit a matching
    # scan_completed with a failure note before re-raising.
    #
    # Wall-clock anchor also lives out here for the same reason: on a
    # pre-flight failure or cold-start-retry exhaustion the duration
    # in scan_completed still reflects the operator-visible elapsed
    # time, not a partial per-attempt figure.
    wall_start = time.time()
    results_dir = _compute_results_dir(clone_dir, model)
    report_id = _audit.report_id_from(results_dir)
    # git_context is best-effort — missing git or a corrupt clone returns
    # placeholders rather than raising, so this is safe to call before
    # mkdir/prior-results verification.
    git_ctx = _git_context(clone_dir)
    repo_slug = _repo_slug_from_url(git_ctx["repo_url"], clone_dir.name)

    if audit_writer is not None:
        audit_writer.emit_audit(
            _audit.build_scan_started(
                app_id=config.audit.app_id,
                actor=config.audit.actor,
                repo_slug=repo_slug,
                report_id=report_id,
                model_version=model,
                target_sha=git_ctx["head_sha"],
            )
        )

    skill_path = _vulnhunt_skill_path()
    if skill_path is None:
        exc = RuntimeError(
            "vulnhunt skill not found at /home/appuser/.claude/skills/vulnhunt or "
            "$HOME/.claude/skills/vulnhunt. Install the skill (run install.sh) "
            "or rebuild the container so it gets baked in."
        )
        _emit_scan_completed_safely(
            audit_writer,
            config=config,
            repo_slug=repo_slug,
            report_id=report_id,
            model=model,
            target_sha=git_ctx["head_sha"],
            results_dir=results_dir,
            session_result=None,
            error=exc,
            wall_start=wall_start,
        )
        raise exc
    logger.info("vulnhunt skill present at %s", skill_path)

    # Pre-stage everything the skill's old "Mandatory First Actions" Bash
    # block used to gather. Computing in Python lets us drop Bash from the
    # tool allow-list entirely for read-only scans.
    try:
        _check_no_prior_results(clone_dir)
        # exist_ok=False catches the (essentially impossible) case of two
        # scans starting in the same second — _compute_results_dir's
        # timestamp has second-level precision, so a collision means a
        # genuine concurrency bug. parents= is omitted: clone_dir must
        # already exist (we'd have failed _check_no_prior_results or the
        # clone step otherwise).
        results_dir.mkdir(exist_ok=False)
    except Exception as pre_exc:  # noqa: BLE001
        _emit_scan_completed_safely(
            audit_writer,
            config=config,
            repo_slug=repo_slug,
            report_id=report_id,
            model=model,
            target_sha=git_ctx["head_sha"],
            results_dir=results_dir,
            session_result=None,
            error=pre_exc,
            wall_start=wall_start,
        )
        raise
    logger.info(
        "Pre-resolved scan metadata: results=%s branch=%s repo=%s bash=%s",
        results_dir,
        git_ctx["branch_label"],
        git_ctx["repo_url"],
        enable_bash,
    )

    # Effective tool list: strip Bash unconditionally, then re-add iff the
    # caller explicitly opted in. This is the policy the user asked for —
    # config can't accidentally enable Bash; only the CLI flag does.
    effective_tools = [t for t in config.scan.allowed_tools if t != "Bash"]
    if enable_bash:
        effective_tools.append("Bash")
        if read_only:
            # Logically inconsistent; __main__.py enforces the pairing, but
            # programmatic callers might still mismatch. Warn loudly.
            logger.warning(
                "enable_bash=True with read_only=True — Bash is in the "
                "allow-list but the prompt tells the model not to execute "
                "code. This is almost certainly a misconfiguration."
            )

    prompt = _build_vulnhunt_prompt(
        clone_dir,
        model,
        read_only=read_only,
        results_dir=results_dir,
        branch_label=git_ctx["branch_label"],
        repo_url=git_ctx["repo_url"],
        enable_bash=enable_bash,
        effective_tools=effective_tools,
    )
    retrying = _build_scan_retrying(backoffs=backoffs)

    session_result: _SessionResult | None = None
    scan_error: Exception | None = None
    try:
        async for attempt in retrying:
            with attempt:
                # Per-attempt: refresh token and rebuild settings/options so
                # the next retry doesn't carry a stale bearer (the JWT may
                # have rotated during the backoff sleep).
                auth_token = token_manager.get_valid_token()
                settings_json = build_claude_settings(
                    config, auth_token, model=model, scan_id=scan_id
                )
                options = ClaudeAgentOptions(
                    # `tools` is the *visibility* allow-list (what the model sees in
                    # its tool menu). Without it, the SDK defaults to the
                    # `claude_code` preset which exposes ~26 tools (NotebookEdit,
                    # WebFetch, Cron*, EnterWorktree, etc.) that the orchestrator
                    # has no business calling. `allowed_tools` only controls
                    # permission auto-approval — it doesn't hide anything from the
                    # model. Setting both to the same list gives us a strict
                    # allow-list with no permission prompts in headless mode.
                    tools=list(effective_tools),
                    allowed_tools=list(effective_tools),
                    permission_mode=config.scan.permission_mode,
                    settings=settings_json,
                    model=model,
                    cwd=str(clone_dir),
                    # The SDK discovers skills from filesystem ``setting_sources``. With
                    # "user" the SDK reads ~/.claude/skills/<name>/SKILL.md (note the
                    # uppercase filename — the SDK's case-sensitive lookup is why this
                    # only worked on the case-insensitive macOS host before the rename).
                    # ``skills="all"`` enables every discovered skill.
                    setting_sources=["user", "project", "local"],
                    skills="all",
                )
                session_result = await _run_scan_session(
                    options=options,
                    prompt=prompt,
                    clone_dir=clone_dir,
                    config=config,
                    model=model,
                )
                # _run_scan_session returns a session-only result; the
                # scan-specific ``results_dir`` discovery happens here so
                # the session helper stays reusable (see verify_runner).
                if session_result is not None:
                    session_result.results_dir = _find_results_dir(clone_dir)
    except RateLimitError as exc:
        # Tenacity raised the final cold-start failure (reraise=True). The
        # before_sleep hook already logged each intermediate retry, but
        # there's no per-attempt log on the FINAL one — add an ERROR
        # trace so operators see "exhausted N retries" framing.
        logger.error(
            "Scan exhausted %d cold-start retry/retries; surfacing transient "
            "error: %s",
            len(backoffs),
            exc,
        )
        scan_error = exc
    except Exception as exc:  # noqa: BLE001
        # BaseException would swallow KeyboardInterrupt / SystemExit /
        # CancelledError until the audit emit finishes — an operator
        # hitting Ctrl-C on a hung scan would appear to hang. Exception
        # covers everything the retry loop can legitimately raise
        # (RateLimitError above, AuthRejectedError, RuntimeError from
        # the SDK, etc.); terminal signals propagate immediately.
        scan_error = exc

    # Defensive: AsyncRetrying always either populates session_result
    # (success path) or raises (failure path), but a programmer error
    # could exit the retrying context without either. Treat that as a
    # failure so the audit event correctly shows scan_completed with
    # a failure note rather than a spurious success shape.
    if scan_error is None and session_result is None:
        scan_error = RuntimeError(
            "scan retry loop exited without a session result"
        )

    if audit_writer is not None:
        try:
            _emit_scan_completed(
                audit_writer,
                config=config,
                repo_slug=repo_slug,
                report_id=report_id,
                model=model,
                target_sha=git_ctx["head_sha"],
                results_dir=results_dir,
                session_result=session_result,
                error=scan_error,
                wall_start=wall_start,
            )
        except _audit.AuditWriteError:
            # strict-mode audit failure. Prefer to surface it when the
            # scan itself succeeded (audit is the primary signal there);
            # when the scan already failed, the scan_error is the root
            # cause and the audit write failure becomes secondary noise.
            if scan_error is None:
                raise
            logger.error(
                "Audit strict-mode write failed for scan_completed; "
                "preserving underlying scan error"
            )
        except Exception:  # noqa: BLE001
            # Non-strict writer failures are already logged internally;
            # a bug in the emit-builder itself falls through here so we
            # don't let it mask the scan's real error.
            logger.exception("Failed to emit scan_completed audit event")

    if scan_error is not None:
        raise scan_error
    # session_result is guaranteed non-None here — the defensive block
    # above turned any None-without-error case into a scan_error.
    assert session_result is not None  # nosec B101 — narrowing for type-checkers
    if totals_out is not None:
        # Expose session totals to callers that need them post-scan
        # (e.g. __main__ threading cost_usd into the manifest writer).
        # Kept as an out-param so the primary return type (results_dir)
        # doesn't change for the ~20 test callers already in tree.
        totals_out.cost_usd = session_result.cost_usd
        totals_out.num_turns = session_result.num_turns
    return session_result.results_dir


def _emit_scan_completed(
    audit_writer: "_audit.AuditWriter",
    *,
    config: AgentConfig,
    repo_slug: str,
    report_id: str,
    model: str,
    target_sha: str,
    results_dir: Path,
    session_result: _SessionResult | None,
    error: Exception | None,
    wall_start: float,
) -> None:
    """Emit ``scan_completed`` for both success and failure paths.

    ``findings_count`` uses a filesystem count (poc/ + exploit_tests/ VULN
    files) rather than the Haiku extractor, so this stays cheap and
    doesn't tie the audit path to an LLM round-trip. The /vulnhunt
    skill only creates ``poc/VULN-NNN_*`` and ``exploit_tests/*`` files
    for **confirmed** findings — code-smells and other non-confirmed
    categories don't produce these artifacts — so the disk count
    matches the confirmed count by construction. Downstream consumers
    who need per-finding detail read the findings stream, where every
    confirmed finding is a discrete event.

    ``scan_duration_seconds`` is wall-clock from run entry, computed
    from ``wall_start``. This includes retry-loop backoff sleeps —
    operators experienced them, so the metric should reflect them.
    """
    if session_result is not None:
        cost_usd = session_result.cost_usd
        results_final = session_result.results_dir or results_dir
    else:
        cost_usd = None
        results_final = results_dir
    # Wall-clock — always populated, even on cold-start-retry
    # exhaustion where session_result is None.
    duration_s: int | None = int(time.time() - wall_start)
    findings_count: int | None
    try:
        findings_count = _audit_extract.count_findings_from_disk(results_final)
    except OSError as exc:
        logger.warning("Could not count findings for scan_completed: %s", exc)
        findings_count = None
    notes = ""
    if error is not None:
        # error class + short message is enough for downstream diagnosis;
        # full tracebacks would exceed typical ingest field limits and echo
        # internal details.
        notes = f"failed: {type(error).__name__}: {error}"
        # On failure we didn't finish extracting; suppress the count so
        # downstream doesn't misread a partial number as "N findings".
        findings_count = None

    audit_writer.emit_audit(
        _audit.build_scan_completed(
            app_id=config.audit.app_id,
            actor=config.audit.actor,
            repo_slug=repo_slug,
            report_id=report_id,
            model_version=model,
            target_sha=target_sha,
            findings_count=findings_count,
            scan_cost_usd=cost_usd,
            scan_duration_seconds=duration_s,
            notes=notes,
        )
    )


def _emit_scan_completed_safely(
    audit_writer: "_audit.AuditWriter | None",
    **kwargs: Any,
) -> None:
    """Best-effort wrapper for pre-flight failure paths.

    Called from the pre-flight try/except branches in ``run_vulnhunt``
    where an exception is about to be re-raised. A no-op when
    ``audit_writer`` is None (audit disabled); non-strict writer errors
    are logged and swallowed since the caller is about to propagate a
    more important exception; strict-mode ``AuditWriteError`` is
    swallowed too so the original pre-flight error remains visible.
    """
    if audit_writer is None:
        return
    try:
        _emit_scan_completed(audit_writer, **kwargs)
    except _audit.AuditWriteError:
        logger.error(
            "Audit strict-mode write failed for pre-flight scan_completed; "
            "preserving underlying pre-flight error"
        )
    except Exception:  # noqa: BLE001
        logger.exception(
            "Failed to emit pre-flight scan_completed audit event"
        )


def _build_scan_retrying(*, backoffs: tuple[float, ...]) -> AsyncRetrying:
    """Build an ``AsyncRetrying`` for the scan-stage cold-start retry.

    Retries only on ``RateLimitError`` — every other exception
    (``AuthRejectedError``, programmer errors, etc.) propagates
    immediately. ``reraise=True`` surfaces the final ``RateLimitError``
    instead of wrapping in ``RetryError`` when retries are exhausted.
    """
    if backoffs:
        wait = wait_chain(*[wait_fixed(b) for b in backoffs])
    else:
        wait = wait_none()
    return AsyncRetrying(
        retry=retry_if_exception_type(RateLimitError),
        wait=wait,
        stop=stop_after_attempt(1 + len(backoffs)),
        before_sleep=_log_scan_retry,
        reraise=True,
    )


def _log_scan_retry(retry_state: RetryCallState) -> None:
    """Tenacity ``before_sleep`` hook — surfaces each cold-start retry.

    Not gated on ``config.logging.retries``: a scan restart is rare and
    load-bearing for understanding "why did this take twice as long as
    expected", so it's always logged at WARN.
    """
    delay = (
        retry_state.next_action.sleep
        if retry_state.next_action is not None
        else 0.0
    )
    exc = (
        retry_state.outcome.exception()
        if retry_state.outcome is not None
        else None
    )
    max_attempts = getattr(
        retry_state.retry_object.stop, "max_attempt_number", None
    )
    logger.warning(
        "Scan cold-start transient on attempt %d/%s; sleeping %.0fs "
        "before retry: %s",
        retry_state.attempt_number,
        max_attempts if max_attempts else "?",
        delay,
        exc,
    )


async def _run_scan_session(
    *,
    options: ClaudeAgentOptions,
    prompt: str,
    clone_dir: Path,
    config: AgentConfig,
    model: str,
) -> _SessionResult:
    """One /vulnhunt SDK session. May raise RateLimitError on cold-start 429.

    All per-attempt state (totals, agent registries, pending tasks) is
    initialized here so retries from ``run_vulnhunt`` start clean.
    """
    logger.info("Starting Claude SDK: model=%s cwd=%s", model, clone_dir)
    start = time.time()
    message_count = 0
    consecutive_auth_failures = 0
    # Cold-start transient detector: counts consecutive 429/5xx
    # SystemMessages BEFORE the first AssistantMessage arrives. Reset to
    # zero once the orchestrator produces any prose, so mid-stream
    # blips don't trigger a restart of a partially-progressed scan.
    consecutive_rate_limits = 0
    saw_assistant = False
    # Per-cycle aggregates. See SessionTotals docstring for per-field
    # accumulation semantics (running-max cost vs sum for duration/turns).
    totals = SessionTotals()
    # Tasks that have started but not yet reached a terminal status. The
    # SDK 0.2.x Agent tool dispatches subagents asynchronously, so a
    # ResultMessage can arrive while subagents are still running. We use
    # this set to decide whether to re-prompt the orchestrator instead of
    # exiting prematurely.
    pending_tasks: set[str] = set()
    continuations = 0
    # Count of consecutive continuations during which ZERO task lifecycle
    # events arrived (neither TaskStartedMessage nor terminal
    # TaskNotificationMessage). Reset to 0 the instant any task starts or
    # finishes; bumps each time a continuation cycle closes with no
    # lifecycle activity. Tripping ``_MAX_STALLED_CONTINUATIONS`` is the
    # real "tasks are orphaned" signal — distinct from heavy rate-
    # limiting, which produces many continuations but still shows task
    # activity (new dispatches and/or completions in between waits).
    stalled_continuations = 0
    # Reset each iteration of the outer while loop; incremented inside
    # the inner receive_response() loop on every TaskStartedMessage and
    # every terminal TaskNotificationMessage. Read at the bottom of each
    # iteration to decide whether to bump or reset
    # ``stalled_continuations``.
    task_lifecycle_events = 0

    # Per-agent wall-clock anchors for `config.logging.per_turn_usage`.
    # Keyed by parent_tool_use_id (None = root orchestrator). Seeded with
    # ``start`` for the root and updated to ``time.time()`` when a
    # TaskStartedMessage arrives for a subagent, so the first Δ on a
    # subagent's first turn reflects "time since the subagent was
    # dispatched", not "time since the run began". Updated again on each
    # AssistantMessage so subsequent Δs are inter-turn gaps for that
    # specific agent — useful for spotting which subagent in a parallel
    # fan-out is slow, but it's a wall-clock measurement, not the model's
    # raw compute time.
    last_turn_ts: dict[str | None, float] = {None: start}
    # Friendly-name registry for subagents. Populated from TaskStartedMessage
    # so we can resolve a turn's `parent_tool_use_id` back to the human label
    # the orchestrator dispatched it under (e.g. "INJ partition 1") instead
    # of the opaque tool_use_id. ``task_id`` mirrors the same label so the
    # task-lifecycle logs can include it on the trailing status events.
    agent_names_by_tool_use_id: dict[str, str] = {}
    agent_names_by_task_id: dict[str, str] = {}
    log_per_turn_usage = config.logging.per_turn_usage
    # Set when a terminal ResultMessage with a transient-error indicator
    # arrives and we've made no progress — raised right after the inner
    # message loop exits so the caller's retry loop can back off.
    pending_rate_limit: RateLimitError | None = None

    async with ClaudeSDKClient(options) as client:
        logger.info("Claude SDK client connected; sending /vulnhunt query")
        await client.query(prompt)

        while True:
            saw_result = False
            # Reset the per-continuation activity counter. Incremented
            # below on every TaskStartedMessage and every terminal
            # TaskNotificationMessage; read at the bottom to update
            # ``stalled_continuations``.
            task_lifecycle_events = 0
            async for message in client.receive_response():
                message_count += 1
                elapsed = time.time() - start
                msg_type = type(message).__name__
                # Show the model on the header line for assistant messages so
                # multi-model runs (subagents on different models, fallback
                # model in effect, etc.) are obvious without reading the
                # content blocks. Header itself is noise at low verbosity —
                # suppress unless the user asked for -vv.
                header_extra = ""
                if isinstance(message, AssistantMessage):
                    msg_model = getattr(message, "model", None)
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

                # Order matters: the Task* classes are SystemMessage subtypes,
                # so test for them first.
                if isinstance(message, TaskStartedMessage):
                    name = _agent_name_from_started(message)
                    tool_use_id = getattr(message, "tool_use_id", None)
                    if name:
                        if tool_use_id:
                            agent_names_by_tool_use_id[tool_use_id] = name
                        agent_names_by_task_id[message.task_id] = name
                    # Anchor "first turn Δ" at dispatch time. Without this
                    # seed, the first AssistantMessage from the subagent
                    # would compute Δ against ``start`` (run launch), which
                    # is misleading for subagents dispatched mid-run.
                    if tool_use_id and tool_use_id not in last_turn_ts:
                        last_turn_ts[tool_use_id] = time.time()
                    _log_task_started(message)
                    pending_tasks.add(message.task_id)
                    task_lifecycle_events += 1
                elif isinstance(message, (TaskUpdatedMessage, TaskNotificationMessage)):
                    _log_task_status(
                        message, agent_name=agent_names_by_task_id.get(message.task_id)
                    )
                    status = getattr(message, "status", None)
                    if status in TERMINAL_TASK_STATUSES:
                        pending_tasks.discard(message.task_id)
                        task_lifecycle_events += 1
                elif isinstance(message, AssistantMessage):
                    # First AssistantMessage = the orchestrator started
                    # producing output. From this point a cold-start retry
                    # is no longer safe (we'd discard real progress), so
                    # mid-stream transients log and continue.
                    saw_assistant = True
                    consecutive_rate_limits = 0
                    if log_per_turn_usage:
                        _log_per_turn_usage(
                            message,
                            last_turn_ts,
                            start,
                            agent_names_by_tool_use_id,
                        )
                    _log_assistant_message(message)
                    consecutive_auth_failures = 0
                elif isinstance(message, UserMessage):
                    _log_user_message(message)
                elif isinstance(message, SystemMessage):
                    _log_system_message(message)
                    if _is_auth_failure(message):
                        consecutive_auth_failures += 1
                        if consecutive_auth_failures >= _MAX_CONSECUTIVE_AUTH_FAILURES:
                            raise AuthRejectedError(
                                f"Bedrock proxy rejected the bearer token "
                                f"{consecutive_auth_failures} consecutive times "
                                "(error_status=401 authentication_failed). The OAuth "
                                "client likely lacks Bedrock access — check the "
                                "JWT's aud/scope claims against a known-working client."
                            )
                    else:
                        consecutive_auth_failures = 0
                    if _is_rate_limit_system_message(message):
                        if saw_assistant:
                            # Mid-stream transient: SDK has internal retries;
                            # we surface it loudly so a harness-level retry
                            # can decide whether to restart the whole run.
                            # The "%d completed turn(s)" value uses
                            # totals["result_messages"] (one per finished
                            # turn/continuation cycle), so "0" means the
                            # first turn was still in flight when the
                            # signal arrived — not that no AssistantMessage
                            # has been emitted (saw_assistant is True here
                            # by construction).
                            logger.warning(
                                "Mid-stream transient API signal (429/5xx) "
                                "after %d completed turn(s); not restarting "
                                "session.",
                                totals.result_messages,
                            )
                        else:
                            consecutive_rate_limits += 1
                            if (
                                consecutive_rate_limits
                                >= _MAX_CONSECUTIVE_RATE_LIMITS
                            ):
                                raise RateLimitError(
                                    f"API returned transient error "
                                    f"{consecutive_rate_limits} consecutive "
                                    "times before the orchestrator produced "
                                    "any AssistantMessage — cold-start "
                                    "rate-limit; restart with backoff."
                                )
                elif isinstance(message, ResultMessage):
                    _log_result(message)
                    # cost is running-max (cumulative-within-session), the
                    # rest are per-cycle and sum. See SessionTotals docs.
                    accumulate_result(totals, message)
                    saw_result = True
                    # Terminal ResultMessage with transient-error data and
                    # no assistant output = cold-start failure. Don't raise
                    # mid-iteration (let the loop finish normal cleanup
                    # first), then raise after the for-loop exits.
                    if _is_rate_limit_result(message) and not saw_assistant:
                        pending_rate_limit = RateLimitError(
                            "API returned transient error in terminal "
                            "ResultMessage before any AssistantMessage — "
                            "cold-start rate-limit; restart with backoff."
                        )
                    break

            if pending_rate_limit is not None:
                raise pending_rate_limit
            if not saw_result:
                # receive_response() ended without a ResultMessage — treat
                # as terminal (the SDK closed the stream).
                break
            if not pending_tasks:
                break
            # Progress accounting: a continuation cycle with at least one
            # task lifecycle event (start or terminal) is evidence of
            # forward progress and zeros the stall counter. Cycles with
            # zero lifecycle events bump it; ``_MAX_STALLED_CONTINUATIONS``
            # consecutive zero-progress cycles is the real "tasks are
            # orphaned" signal.
            if task_lifecycle_events > 0:
                stalled_continuations = 0
            else:
                stalled_continuations += 1
            if stalled_continuations >= _MAX_STALLED_CONTINUATIONS:
                logger.warning(
                    "No task completed for %d consecutive continuations; "
                    "%d task(s) appear orphaned: %s",
                    stalled_continuations,
                    len(pending_tasks),
                    sorted(pending_tasks),
                )
                break
            continuations += 1
            logger.info(
                "ResultMessage received but %d task(s) still pending; "
                "re-prompting (continuation %d, stall %d/%d). Pending: %s",
                len(pending_tasks),
                continuations,
                stalled_continuations,
                _MAX_STALLED_CONTINUATIONS,
                sorted(pending_tasks),
            )
            await client.query(_CONTINUATION_PROMPT)

    elapsed = time.time() - start
    logger.info(
        "Run finished in %.1fs (%d messages, %d continuations, %d task(s) still pending)",
        elapsed,
        message_count,
        continuations,
        len(pending_tasks),
    )
    # Cumulative totals across every ResultMessage we saw — the SDK scopes
    # each ResultMessage to one turn, so a per-message cost line under-reports
    # any run that needed continuations.
    log_session_totals(totals, "Scan")
    # _run_scan_session returns a session-only result; the scan-specific
    # ``results_dir`` discovery happens in ``run_vulnhunt`` so this helper
    # stays reusable across scan and verify paths.
    return _SessionResult(
        results_dir=None,
        cost_usd=totals.cost_usd,
        duration_s=elapsed,
        num_turns=totals.num_turns,
    )


_PREVIEW_MAX = 300


# Verbosity helpers and the SDK event-rendering surface live in
# ``agent/_stream_events.py``; we re-import them at module top so
# existing ``from agent.runner import _log_*`` imports keep working.


def _is_auth_failure(message: SystemMessage) -> bool:
    data = getattr(message, "data", None)
    if not isinstance(data, dict):
        return False
    return (
        data.get("error_status") == 401
        or str(data.get("error", "")).lower() == "authentication_failed"
    )


def _is_rate_limit_system_message(message: SystemMessage) -> bool:
    """True if a SystemMessage signals an API 429 / 5xx / overload.

    Typed-first via the shared ``_transient.classify`` helper: when
    ``data.error_status`` (or ``data.api_error_status``) is an int,
    that status is authoritative — a non-transient typed status (400,
    401, 404, ...) returns False even if ``data.error`` text contains
    transient-looking phrases. Mirrors
    ``_llm.py::_looks_transient_at_boundary``'s short-circuit
    semantics; closes the Bug-1-shape asymmetry the PR-#11 reviewer
    flagged in the follow-up.
    """
    data = getattr(message, "data", None)
    if not isinstance(data, dict):
        return False
    status = data.get("error_status")
    if not isinstance(status, int):
        status = data.get("api_error_status")
    return _classify_transient(status, str(data.get("error", "")))


def _is_rate_limit_result(message: ResultMessage) -> bool:
    """True if a terminal ResultMessage indicates the run died on 429 / 5xx.

    The SDK marks transient API failures by setting ``is_error=True``
    and populating ``api_error_status``. Typed-first classification
    via ``_transient.classify``: a typed non-transient
    ``api_error_status`` (e.g. 400) short-circuits to False even if
    ``errors`` text contains transient-looking phrases — same shape as
    ``_is_rate_limit_system_message`` above.
    """
    if not getattr(message, "is_error", False):
        return False
    status = getattr(message, "api_error_status", None)
    errors = getattr(message, "errors", None)
    return _classify_transient(status, "" if errors is None else str(errors))
