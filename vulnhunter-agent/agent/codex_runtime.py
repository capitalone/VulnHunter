"""Hardened ``codex exec`` adapter for OpenAI-compatible VulnHunter scans.

The Codex process runs from a disposable workspace rather than the target
checkout.  The target is therefore readable but not writable, while the
pre-created VulnHunter results directory is added as the sole durable writable
root.  User config, rules, plugins, apps, web search, shell network access, and
credential inheritance into model-launched commands are disabled explicitly.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ._transient import is_transient_text
from .config import AgentConfig

logger = logging.getLogger(__name__)

_PROVIDER_ID = "vulnhunter_compatible"
_API_KEY_ENV = "VULNHUNT_CODEX_API_KEY"
_SKILL_DEST = Path(".agents/skills/vulnhunt-codex")
_SHELL_PATH = "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin"
_STDERR_LIMIT = 200_000
_STREAM_LIMIT = 16 * 1024 * 1024


class CodexExecutionError(RuntimeError):
    """A Codex launch, protocol, authentication, or model failure."""

    def __init__(
        self,
        message: str,
        *,
        transient: bool = False,
        auth_rejected: bool = False,
        initial_request: bool = False,
    ) -> None:
        super().__init__(message)
        self.transient = transient
        self.auth_rejected = auth_rejected
        self.initial_request = initial_request


@dataclass(frozen=True)
class CodexUsage:
    input_tokens: int = 0
    cached_input_tokens: int = 0
    output_tokens: int = 0
    reasoning_output_tokens: int = 0
    turns: int = 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass(frozen=True)
class CodexResult:
    text: str
    usage: CodexUsage
    thread_id: str = ""


def _toml_string(value: str) -> str:
    """Render a string accepted by Codex's TOML ``-c`` parser."""

    return json.dumps(value, ensure_ascii=False)


def _config(key: str, value: str | int | bool) -> list[str]:
    if isinstance(value, str):
        rendered = _toml_string(value)
    elif isinstance(value, bool):
        rendered = "true" if value else "false"
    else:
        rendered = str(value)
    return ["-c", f"{key}={rendered}"]


def build_codex_command(
    config: AgentConfig,
    *,
    executable: str,
    model: str,
    work_dir: Path,
    output_file: Path,
    writable_roots: tuple[Path, ...] = (),
    api_key_present: bool,
) -> list[str]:
    """Build an argv-only, one-run Codex configuration.

    No credential is placed in argv.  A non-empty key is supplied to the
    custom provider through ``VULNHUNT_CODEX_API_KEY`` by :func:`run_codex`.
    """

    sandbox = "workspace-write" if writable_roots else "read-only"
    args = [
        executable,
        "exec",
        "--strict-config",
        "--ignore-user-config",
        "--ignore-rules",
        "--ephemeral",
        "--skip-git-repo-check",
        "--sandbox",
        sandbox,
        "--json",
        "--disable",
        "plugins",
        "--disable",
        "apps",
        "--disable",
        "remote_plugin",
        "--disable",
        "plugin_sharing",
        "--model",
        model,
        "-C",
        str(work_dir),
        "--output-last-message",
        str(output_file),
    ]
    for root in writable_roots:
        args.extend(["--add-dir", str(root)])

    overrides: list[tuple[str, str | int | bool]] = [
        ("model_provider", _PROVIDER_ID),
        (f"model_providers.{_PROVIDER_ID}.name", "VulnHunter compatible endpoint"),
        (f"model_providers.{_PROVIDER_ID}.base_url", config.openai.base_url),
        (f"model_providers.{_PROVIDER_ID}.wire_api", "responses"),
        (
            f"model_providers.{_PROVIDER_ID}.stream_idle_timeout_ms",
            config.openai.request_timeout_seconds * 1000,
        ),
        ("model_reasoning_effort", config.openai.reasoning_effort),
        ("approval_policy", "never"),
        ("web_search", "disabled"),
        ("allow_login_shell", False),
        ("sandbox_workspace_write.network_access", False),
        ("sandbox_workspace_write.exclude_slash_tmp", True),
        ("sandbox_workspace_write.exclude_tmpdir_env_var", True),
        ("shell_environment_policy.inherit", "none"),
        ("shell_environment_policy.ignore_default_excludes", False),
        ("features.skill_mcp_dependency_install", False),
        ("check_for_update_on_startup", False),
        ("analytics.enabled", False),
        ("feedback.enabled", False),
    ]
    if api_key_present:
        overrides.insert(
            4,
            (f"model_providers.{_PROVIDER_ID}.env_key", _API_KEY_ENV),
        )
    for key, value in overrides:
        args.extend(_config(key, value))

    # An inline TOML table is clearer than several nested set overrides and
    # ensures commands retain only a deterministic tool PATH, never the API key.
    args.extend(
        [
            "-c",
            f'shell_environment_policy.set={{ PATH = {_toml_string(_SHELL_PATH)} }}',
            "-",
        ]
    )
    return args


def _resolve_executable(value: str) -> str:
    expanded = os.path.expanduser(value)
    if os.sep in expanded or (os.altsep and os.altsep in expanded):
        path = Path(expanded).resolve()
        if not path.is_file() or not os.access(path, os.X_OK):
            raise CodexExecutionError(
                f"Codex executable is missing or not executable: {path}"
            )
        return str(path)
    resolved = shutil.which(expanded)
    if resolved is None:
        raise CodexExecutionError(
            f"Codex executable '{value}' was not found on PATH"
        )
    return resolved


def _event_error(event: dict[str, Any]) -> str:
    raw = event.get("error")
    if isinstance(raw, dict):
        message = raw.get("message")
        if isinstance(message, str):
            return message
        return json.dumps(raw, ensure_ascii=False)
    message = event.get("message")
    return message if isinstance(message, str) else str(raw or "Codex error")


class _EventAccumulator:
    def __init__(self) -> None:
        self.thread_id = ""
        self.final_text = ""
        self.errors: list[str] = []
        self.turn_failed = False
        self.item_count = 0
        self.invalid_lines: list[str] = []
        self.input_tokens = 0
        self.cached_input_tokens = 0
        self.output_tokens = 0
        self.reasoning_output_tokens = 0
        self.turns = 0

    def feed(self, line: bytes) -> None:
        text = line.decode("utf-8", errors="replace").strip()
        if not text:
            return
        try:
            event = json.loads(text)
        except json.JSONDecodeError:
            if len(self.invalid_lines) < 3:
                self.invalid_lines.append(text[:500])
            return
        if not isinstance(event, dict):
            return
        kind = event.get("type")
        if kind == "thread.started" and isinstance(event.get("thread_id"), str):
            self.thread_id = event["thread_id"]
        elif kind in ("item.started", "item.completed"):
            self.item_count += 1
            item = event.get("item")
            if (
                kind == "item.completed"
                and isinstance(item, dict)
                and item.get("type") == "agent_message"
            ):
                message = item.get("text")
                if isinstance(message, str) and message.strip():
                    self.final_text = message.strip()
        elif kind == "turn.completed":
            self.turns += 1
            usage = event.get("usage")
            if isinstance(usage, dict):
                self.input_tokens += _integer(usage.get("input_tokens"))
                self.cached_input_tokens += _integer(
                    usage.get("cached_input_tokens")
                )
                self.output_tokens += _integer(usage.get("output_tokens"))
                self.reasoning_output_tokens += _integer(
                    usage.get("reasoning_output_tokens")
                )
        elif kind == "turn.failed":
            self.turn_failed = True
            self.errors.append(_event_error(event))
        elif kind == "error":
            self.errors.append(_event_error(event))

    def result(self, fallback_text: str) -> CodexResult:
        text = fallback_text.strip() or self.final_text
        return CodexResult(
            text=text,
            usage=CodexUsage(
                input_tokens=self.input_tokens,
                cached_input_tokens=self.cached_input_tokens,
                output_tokens=self.output_tokens,
                reasoning_output_tokens=self.reasoning_output_tokens,
                turns=self.turns,
            ),
            thread_id=self.thread_id,
        )


def _integer(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


async def _consume_events(
    stream: asyncio.StreamReader,
    accumulator: _EventAccumulator,
) -> None:
    while True:
        line = await stream.readline()
        if not line:
            return
        accumulator.feed(line)


async def _consume_stderr(stream: asyncio.StreamReader) -> str:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await stream.read(8192)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        while total > _STDERR_LIMIT and chunks:
            total -= len(chunks.pop(0))
    return b"".join(chunks).decode("utf-8", errors="replace").strip()


async def _terminate_process(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    try:
        process.terminate()
    except ProcessLookupError:
        await process.wait()
        return
    try:
        await asyncio.wait_for(process.wait(), timeout=5)
    except TimeoutError:
        try:
            process.kill()
        except ProcessLookupError:
            await process.wait()
            return
        await process.wait()


def _failure_flags(text: str) -> tuple[bool, bool]:
    lowered = text.lower()
    auth_rejected = bool(
        re.search(r"\b(?:401|403)\b", text)
        or "authentication" in lowered
        or "invalid api key" in lowered
        or "unauthorized" in lowered
        or "forbidden" in lowered
    )
    return is_transient_text(text), auth_rejected


def _safe_detail(text: str, api_key: str) -> str:
    detail = text.replace(api_key, "[REDACTED]") if api_key else text
    return detail[-4000:]


async def run_codex(
    config: AgentConfig,
    *,
    api_key: str,
    model: str,
    prompt: str,
    writable_roots: tuple[Path, ...] = (),
    skill_source: Path | None = None,
) -> CodexResult:
    """Run one isolated, noninteractive Codex session and parse its JSONL."""

    executable = _resolve_executable(config.codex.executable)
    roots = tuple(root.expanduser().resolve() for root in writable_roots)
    for root in roots:
        if not root.is_dir():
            raise CodexExecutionError(f"Codex writable root does not exist: {root}")
    if skill_source is not None:
        skill_source = skill_source.expanduser().resolve()
        if not (skill_source / "SKILL.md").is_file():
            raise CodexExecutionError(
                f"Codex VulnHunter skill is missing SKILL.md: {skill_source}"
            )

    with tempfile.TemporaryDirectory(prefix="vulnhunt-codex-") as raw_work_dir:
        work_dir = Path(raw_work_dir).resolve()
        codex_home = work_dir / ".codex-home"
        codex_home.mkdir()
        if skill_source is not None:
            skill_dest = work_dir / _SKILL_DEST
            skill_dest.parent.mkdir(parents=True)
            shutil.copytree(skill_source, skill_dest)
        output_file = work_dir / "last-message.txt"
        command = build_codex_command(
            config,
            executable=executable,
            model=model,
            work_dir=work_dir,
            output_file=output_file,
            writable_roots=roots,
            api_key_present=bool(api_key),
        )
        env = os.environ.copy()
        env["CODEX_HOME"] = str(codex_home)
        if api_key:
            env[_API_KEY_ENV] = api_key
        else:
            env.pop(_API_KEY_ENV, None)

        logger.info(
            "Starting isolated Codex CLI: model=%s effort=%s writable_roots=%d",
            model,
            config.openai.reasoning_effort,
            len(roots),
        )
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                limit=_STREAM_LIMIT,
            )
        except OSError as exc:
            raise CodexExecutionError(f"Could not start Codex: {exc}") from exc

        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        accumulator = _EventAccumulator()
        stdout_task = asyncio.create_task(
            _consume_events(process.stdout, accumulator)
        )
        stderr_task = asyncio.create_task(_consume_stderr(process.stderr))
        try:
            process.stdin.write(prompt.encode("utf-8"))
            await process.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            # Config/launch failures can exit before stdin is consumed. The
            # captured JSONL/stderr below carries the actionable error.
            pass
        finally:
            process.stdin.close()

        timed_out = False
        try:
            await asyncio.wait_for(
                process.wait(), timeout=config.codex.request_timeout_seconds
            )
        except TimeoutError:
            timed_out = True
            await _terminate_process(process)
        except asyncio.CancelledError:
            await _terminate_process(process)
            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
            raise
        await stdout_task
        stderr = await stderr_task

        fallback_text = ""
        if output_file.is_file():
            fallback_text = output_file.read_text(encoding="utf-8", errors="replace")
        result = accumulator.result(fallback_text)
        initial_request = accumulator.item_count == 0

        if timed_out:
            raise CodexExecutionError(
                f"Codex timed out after {config.codex.request_timeout_seconds}s",
                transient=True,
                initial_request=initial_request,
            )
        if process.returncode != 0 or accumulator.turn_failed:
            detail_parts = accumulator.errors + ([stderr] if stderr else [])
            detail = _safe_detail("\n".join(detail_parts), api_key)
            transient, auth_rejected = _failure_flags(detail)
            raise CodexExecutionError(
                f"Codex failed with exit code {process.returncode}: {detail}",
                transient=transient,
                auth_rejected=auth_rejected,
                initial_request=initial_request,
            )
        if accumulator.invalid_lines:
            raise CodexExecutionError(
                "Codex emitted non-JSON stdout while --json was active: "
                + " | ".join(accumulator.invalid_lines)
            )
        if not result.text:
            detail = _safe_detail("\n".join(accumulator.errors + [stderr]), api_key)
            raise CodexExecutionError(
                f"Codex completed without a final agent message: {detail}",
                transient=is_transient_text(detail),
                initial_request=initial_request,
            )
        return result
