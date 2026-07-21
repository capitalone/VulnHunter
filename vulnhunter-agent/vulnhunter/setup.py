"""Interactive setup and diagnostics."""

from __future__ import annotations

import os
import json
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import httpx

from .config import DEFAULT_CONFIG_PATH, EngineConfig
from .providers import create_provider


PROVIDER_ENV_EXAMPLE = """\
# Set only the providers you use. Process environment variables take precedence.
OPENROUTER_API_KEY=
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
GEMINI_API_KEY=

# Optional model overrides
VULNHUNTER_OPENROUTER_MODEL=openrouter/auto
VULNHUNTER_ANTHROPIC_MODEL=claude-opus-4-8
VULNHUNTER_OPENAI_MODEL=gpt-5
VULNHUNTER_GEMINI_MODEL=gemini-3.5-flash

# Optional local OpenAI-compatible runtime
# VULNHUNTER_OPENAI_COMPATIBLE_URL=http://127.0.0.1:8000/v1
# VULNHUNTER_OPENAI_COMPATIBLE_MODEL=your-local-model
# VULNHUNTER_OPENAI_COMPATIBLE_API_KEY=
# VULNHUNTER_LOCAL_TOOL_MODE=json
"""


def discover_local_ollama(
    base_url: str = "http://127.0.0.1:11434",
) -> list[str]:
    try:
        response = httpx.get(f"{base_url.rstrip('/')}/api/tags", timeout=1.5)
        response.raise_for_status()
        payload = response.json()
    except (httpx.HTTPError, ValueError):
        return []
    return [
        str(row["name"])
        for row in payload.get("models", [])
        if isinstance(row, dict) and row.get("name")
    ]


def discover_openai_compatible() -> tuple[str, str] | None:
    """Probe common local OpenAI-compatible endpoints without sending source."""
    configured = os.environ.get("VULNHUNTER_OPENAI_COMPATIBLE_URL", "")
    candidates = [
        configured,
        "http://127.0.0.1:8000/v1",   # vLLM
        "http://127.0.0.1:1234/v1",   # LM Studio
        "http://127.0.0.1:8080/v1",   # llama.cpp / LocalAI
    ]
    headers: dict[str, str] = {}
    key = os.environ.get("VULNHUNTER_OPENAI_COMPATIBLE_API_KEY", "")
    if key:
        headers["Authorization"] = f"Bearer {key}"
    for base_url in dict.fromkeys(row.rstrip("/") for row in candidates if row):
        try:
            response = httpx.get(
                f"{base_url}/models", headers=headers, timeout=1.0
            )
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError):
            continue
        model = os.environ.get("VULNHUNTER_OPENAI_COMPATIBLE_MODEL", "")
        if not model:
            model = next(
                (
                    str(row["id"])
                    for row in payload.get("data", [])
                    if isinstance(row, dict) and row.get("id")
                ),
                "",
            )
        if model:
            return base_url, model
    return None


def discover_openrouter_pricing(model_id: str) -> tuple[float, float] | None:
    """Fetch and cache OpenRouter per-token metadata when the model is explicit."""
    key = os.environ.get("OPENROUTER_API_KEY", "")
    if not key or model_id == "openrouter/auto":
        return None
    cache_path = Path.home() / ".vulnhunter" / "cache" / "openrouter-models.json"
    payload: dict[str, object] | None = None
    try:
        response = httpx.get(
            "https://openrouter.ai/api/v1/models",
            headers={"Authorization": f"Bearer {key}"},
            timeout=10,
        )
        response.raise_for_status()
        payload = response.json()
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except (httpx.HTTPError, ValueError, OSError):
        if cache_path.is_file():
            try:
                cached = json.loads(cache_path.read_text(encoding="utf-8"))
                payload = cached if isinstance(cached, dict) else None
            except (ValueError, OSError):
                payload = None
    if not payload:
        return None
    data = payload.get("data", [])
    if not isinstance(data, list):
        return None
    for row in data:
        if not isinstance(row, dict) or row.get("id") != model_id:
            continue
        pricing = row.get("pricing")
        if not isinstance(pricing, dict):
            return None
        try:
            return (
                float(pricing["prompt"]) * 1_000_000,
                float(pricing["completion"]) * 1_000_000,
            )
        except (KeyError, TypeError, ValueError):
            return None
    return None


def discover_codex_cli() -> dict[str, object] | None:
    """Detect an authenticated Codex CLI and its current cached model catalog."""
    executable = shutil.which("codex")
    if not executable:
        return None
    try:
        status = subprocess.run(
            [executable, "login", "status"],
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if status.returncode != 0:
        return None
    cache = Path.home() / ".codex" / "models_cache.json"
    try:
        payload = json.loads(cache.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    rows = payload.get("models", []) if isinstance(payload, dict) else []
    available = [
        row
        for row in rows
        if isinstance(row, dict)
        and row.get("slug")
        and row.get("visibility") in {None, "list"}
    ]
    if not available:
        return None
    selected = available[0]
    efforts = [
        str(row["effort"])
        for row in selected.get("supported_reasoning_levels", [])
        if isinstance(row, dict) and row.get("effort")
    ]
    return {
        "model": str(selected["slug"]),
        "context_tokens": int(
            selected.get("context_window")
            or selected.get("max_context_window")
            or 128_000
        ),
        "reasoning_effort": "auto",
        "supported_reasoning_efforts": efforts,
        "login_status": (status.stdout or status.stderr).strip(),
    }


def generate_config(*, allow_remote: bool = True) -> tuple[str, list[str]]:
    """Return a secret-free TOML config and human-readable detections."""
    sections: list[str] = [
        "# VulnHunter provider-neutral configuration",
        "# Secrets remain in environment variables; this file stores only their names.",
        "",
    ]
    detections: list[str] = []
    models: list[tuple[str, str, str, bool, int, str]] = []
    priority = 10
    model_overrides: dict[str, dict[str, object]] = {}

    ollama_models = discover_local_ollama()
    if ollama_models:
        sections.extend(
            [
                "[providers.ollama]",
                'kind = "ollama"',
                'base_url = "http://127.0.0.1:11434"',
                "remote = false",
                "",
            ]
        )
        model_id = os.environ.get("VULNHUNTER_OLLAMA_MODEL", ollama_models[0])
        models.append(("local-ollama", "ollama", model_id, False, priority, "native"))
        detections.append(f"Ollama: {model_id}")
        priority += 10

    compatible = discover_openai_compatible()
    if compatible:
        compatible_url, compatible_model = compatible
        sections.extend(
            [
                "[providers.local-compatible]",
                'kind = "openai_compatible"',
                f'base_url = "{_toml_escape(compatible_url)}"',
                'api_key_env = "VULNHUNTER_OPENAI_COMPATIBLE_API_KEY"',
                "remote = false",
                "",
            ]
        )
        models.append(
            (
                "local-compatible",
                "local-compatible",
                compatible_model,
                False,
                priority,
                os.environ.get("VULNHUNTER_LOCAL_TOOL_MODE", "native"),
            )
        )
        detections.append(f"OpenAI-compatible local endpoint: {compatible_model}")
        priority += 10

    codex = discover_codex_cli() if allow_remote else None
    if codex:
        sections.extend(
            [
                "[providers.codex-cli]",
                'kind = "codex_cli"',
                'base_url = ""',
                "remote = true",
                "",
            ]
        )
        models.append(
            (
                "codex-cli",
                "codex-cli",
                str(codex["model"]),
                True,
                priority,
                "native",
            )
        )
        model_overrides["codex-cli"] = codex
        detections.append(
            f"Codex CLI OAuth/session: {codex['model']} ({codex['login_status']})"
        )
        priority += 10

    if allow_remote and os.environ.get("OPENROUTER_API_KEY"):
        sections.extend(
            [
                "[providers.openrouter]",
                'kind = "openrouter"',
                'base_url = "https://openrouter.ai/api/v1"',
                'api_key_env = "OPENROUTER_API_KEY"',
                "remote = true",
                "",
                "[providers.openrouter.headers]",
                '"HTTP-Referer" = "https://github.com/JJsilvera1/Multi-VulnHunter"',
                '"X-Title" = "VulnHunter"',
                "",
            ]
        )
        model_id = os.environ.get("VULNHUNTER_OPENROUTER_MODEL", "openrouter/auto")
        models.append(
            ("openrouter", "openrouter", model_id, True, priority, "native")
        )
        detections.append(f"OpenRouter credentials: {model_id}")
        openrouter_pricing = discover_openrouter_pricing(model_id)
        priority += 10
    else:
        openrouter_pricing = None

    if allow_remote and os.environ.get("ANTHROPIC_API_KEY"):
        sections.extend(
            [
                "[providers.anthropic]",
                'kind = "anthropic"',
                'base_url = "https://api.anthropic.com"',
                'api_key_env = "ANTHROPIC_API_KEY"',
                "remote = true",
                "",
            ]
        )
        model_id = os.environ.get(
            "VULNHUNTER_ANTHROPIC_MODEL", "claude-opus-4-8"
        )
        models.append(
            ("anthropic-primary", "anthropic", model_id, True, priority, "native")
        )
        detections.append(f"Anthropic credentials: {model_id}")
        priority += 10

    if allow_remote and os.environ.get("OPENAI_API_KEY"):
        sections.extend(
            [
                "[providers.openai]",
                'kind = "openai"',
                'base_url = "https://api.openai.com/v1"',
                'api_key_env = "OPENAI_API_KEY"',
                "remote = true",
                "",
            ]
        )
        model_id = os.environ.get("VULNHUNTER_OPENAI_MODEL", "gpt-5")
        models.append(("openai-primary", "openai", model_id, True, priority, "native"))
        detections.append(f"OpenAI credentials: {model_id}")
        priority += 10

    if allow_remote and os.environ.get("GEMINI_API_KEY"):
        sections.extend(
            [
                "[providers.gemini]",
                'kind = "gemini"',
                'base_url = "https://generativelanguage.googleapis.com/v1beta/openai"',
                'api_key_env = "GEMINI_API_KEY"',
                "remote = true",
                "",
            ]
        )
        model_id = os.environ.get(
            "VULNHUNTER_GEMINI_MODEL", "gemini-3.5-flash"
        )
        models.append(
            ("gemini-primary", "gemini", model_id, True, priority, "native")
        )
        detections.append(f"Gemini credentials: {model_id}")

    if not models:
        raise RuntimeError(
            "No permitted model provider detected. Allow a configured remote "
            "provider, start Ollama, or configure "
            "VULNHUNTER_OPENAI_COMPATIBLE_URL and "
            "VULNHUNTER_OPENAI_COMPATIBLE_MODEL."
        )

    for alias, provider, model, remote, row_priority, tool_mode in models:
        override = model_overrides.get(alias, {})
        sections.extend(
            [
                f"[models.{alias}]",
                f'provider = "{_toml_escape(provider)}"',
                f'model = "{_toml_escape(model)}"',
                f"remote = {str(remote).lower()}",
                f"priority = {row_priority}",
                f'tool_mode = "{tool_mode}"',
                f"context_tokens = {int(override.get('context_tokens', 128000))}",
                "max_output_tokens = 8192",
            ]
        )
        if override:
            sections.extend(
                [
                    f'reasoning_effort = "{override.get("reasoning_effort", "auto")}"',
                    "supported_reasoning_efforts = ["
                    + ", ".join(
                        f'"{_toml_escape(str(value))}"'
                        for value in override.get("supported_reasoning_efforts", [])
                    )
                    + "]",
                    'billing_label = "ChatGPT/Codex plan"',
                ]
            )
        if alias == "openrouter" and openrouter_pricing:
            sections.extend(
                [
                    f"input_cost_per_million = {openrouter_pricing[0]:.8g}",
                    f"output_cost_per_million = {openrouter_pricing[1]:.8g}",
                ]
            )
        elif alias != "codex-cli":
            sections.extend(
                [
                    "# Set input_cost_per_million and output_cost_per_million",
                    "# to enable enforceable USD budgets for remote models.",
                ]
            )
        sections.append("")
    sections.extend(
        [
            "[privacy]",
            f"remote_provider_consent = {str(allow_remote).lower()}",
            "",
            "[sandbox]",
            "# command_prefix must invoke a real OS/container sandbox before --execute.",
            "command_prefix = []",
            "",
        ]
    )
    return "\n".join(sections), detections


def write_initial_config(
    path: Path = DEFAULT_CONFIG_PATH,
    *,
    force: bool = False,
    allow_remote: bool = True,
) -> list[str]:
    if path.exists() and not force:
        raise FileExistsError(f"config already exists at {path}; use --force to replace")
    content, detections = generate_config(allow_remote=allow_remote)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return detections


def append_codex_cli_config(
    path: Path,
    config: EngineConfig,
    detection: dict[str, object],
) -> None:
    """Append the secret-free Codex CLI provider to an existing TOML config."""
    if "codex-cli" in config.providers or "codex-cli" in config.models:
        return
    priority = max((model.priority for model in config.models.values()), default=0) + 10
    efforts = ", ".join(
        f'"{_toml_escape(str(value))}"'
        for value in detection.get("supported_reasoning_efforts", [])
    )
    addition = "\n".join(
        [
            "",
            "# Authenticated Codex CLI provider; credentials remain owned by Codex.",
            "[providers.codex-cli]",
            'kind = "codex_cli"',
            'base_url = ""',
            "remote = true",
            "",
            "[models.codex-cli]",
            'provider = "codex-cli"',
            f'model = "{_toml_escape(str(detection["model"]))}"',
            "remote = true",
            f"priority = {priority}",
            'tool_mode = "native"',
            f"context_tokens = {int(detection.get('context_tokens', 128000))}",
            "max_output_tokens = 8192",
            'reasoning_effort = "auto"',
            f"supported_reasoning_efforts = [{efforts}]",
            'billing_label = "ChatGPT/Codex plan"',
            "",
        ]
    )
    original = path.read_text(encoding="utf-8")
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(original.rstrip() + "\n" + addition, encoding="utf-8")
    os.replace(temporary, path)


def write_env_example(path: Path, *, force: bool = False) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"environment file already exists at {path}; use --force")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(PROVIDER_ENV_EXAMPLE, encoding="utf-8")


async def doctor(
    config: EngineConfig, *, probe_models: bool = True
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for alias, model in sorted(
        config.models.items(), key=lambda item: item[1].priority
    ):
        provider = create_provider(config.providers[model.provider])
        ok, detail = await provider.health(model)
        probe: dict[str, object] = {}
        provider_probed_in_health = bool(
            getattr(provider, "health_includes_capability_probe", False)
        )
        if ok and probe_models and not provider_probed_in_health:
            try:
                small_model = replace(model, max_output_tokens=128)
                provider_manages_tools = bool(
                    getattr(provider, "manages_repository_tools", False)
                )
                tool = {
                    "name": "health_check",
                    "description": "Return scanner capability information.",
                    "input_schema": {
                        "type": "object",
                        "properties": {"ok": {"type": "boolean"}},
                        "required": ["ok"],
                        "additionalProperties": False,
                    },
                }
                response = await provider.complete(
                    model=small_model,
                    messages=[
                        {
                            "role": "system",
                            "content": (
                                "This is a provider capability probe. Do not use "
                                "external data."
                            ),
                        },
                        {
                            "role": "user",
                            "content": (
                                'Return only {"ok":true}.'
                                if provider_manages_tools
                                else "Call health_check with ok=true."
                                if model.tool_mode == "native"
                                else 'Return only {"ok":true}.'
                            ),
                        },
                    ],
                    tools=(
                        [tool]
                        if model.tool_mode == "native" and not provider_manages_tools
                        else []
                    ),
                    response_schema=(
                        {
                            "type": "object",
                            "properties": {
                                "ok": {"type": "boolean", "const": True}
                            },
                            "required": ["ok"],
                            "additionalProperties": False,
                        }
                        if model.tool_mode == "json" or provider_manages_tools
                        else None
                    ),
                )
                structured_ok = False
                if model.tool_mode == "json" or provider_manages_tools:
                    try:
                        structured_ok = json.loads(response.content).get("ok") is True
                    except (ValueError, AttributeError):
                        structured_ok = False
                probe = {
                    "tool_calls": (
                        "provider-managed"
                        if provider_manages_tools
                        else bool(response.tool_calls)
                        if model.tool_mode == "native"
                        else "json-emulated"
                    ),
                    "structured_output": (
                        structured_ok
                        if model.tool_mode == "json" or provider_manages_tools
                        else model.capabilities.structured_output
                    ),
                    "usage_reporting": response.usage.total_tokens > 0,
                    "context_tokens": model.context_tokens,
                }
                if (
                    model.tool_mode == "native"
                    and not provider_manages_tools
                    and not response.tool_calls
                ):
                    ok = False
                    detail = "connected, but native tool-call probe failed"
                elif (
                    model.tool_mode == "json" or provider_manages_tools
                ) and not structured_ok:
                    ok = False
                    detail = "connected, but JSON structured-output probe failed"
            except Exception as exc:  # noqa: BLE001
                ok = False
                detail = f"capability probe failed: {exc}"
        elif ok and probe_models and provider_probed_in_health:
            probe = {
                "tool_calls": "provider-managed",
                "structured_output": True,
                "usage_reporting": False,
                "context_tokens": model.context_tokens,
            }
        rows.append(
            {
                "alias": alias,
                "provider": model.provider,
                "model": model.model,
                "remote": model.remote,
                "ok": ok,
                "detail": detail,
                "capabilities": probe,
            }
        )
    return rows


def _toml_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')
