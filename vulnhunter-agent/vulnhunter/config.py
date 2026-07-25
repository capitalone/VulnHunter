"""Configuration loading for provider-neutral VulnHunter."""

from __future__ import annotations

import os
import json
import shutil
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .models import ModelCapabilities, ModelSpec, SpecialistSpec


DEFAULT_CONFIG_PATH = Path.home() / ".vulnhunter" / "config.toml"


@dataclass(frozen=True)
class ProviderConfig:
    name: str
    kind: str
    base_url: str
    api_key_env: str = ""
    credential_command: tuple[str, ...] = ()
    remote: bool = True
    headers: dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 120.0

    def api_key(self) -> str:
        return os.environ.get(self.api_key_env, "") if self.api_key_env else ""


@dataclass(frozen=True)
class SandboxConfig:
    backend: str = "docker"
    image: str = "vulnhunter-sandbox:0.3.0"
    memory: str = "2g"
    cpus: float = 2.0
    pids_limit: int = 256
    # Parsed only so one transition release can read older config files. The
    # native engine never executes this host-side prefix.
    command_prefix: tuple[str, ...] = ()

    @property
    def available(self) -> bool:
        return self.backend == "docker" and shutil.which("docker") is not None


@dataclass(frozen=True)
class EngineConfig:
    providers: dict[str, ProviderConfig]
    models: dict[str, ModelSpec]
    specialists: list[SpecialistSpec] = field(default_factory=list)
    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
    source_path: Path | None = None


def load_engine_config(
    path: str | os.PathLike[str] | None = None,
    *,
    apply_model_defaults: bool = True,
) -> EngineConfig:
    config_path = Path(path).expanduser() if path else DEFAULT_CONFIG_PATH
    if not config_path.is_file():
        raise FileNotFoundError(
            f"VulnHunter config not found at {config_path}. Run `vulnhunter init`."
        )
    with config_path.open("rb") as handle:
        raw = tomllib.load(handle)
    config = parse_engine_config(raw, source_path=config_path.resolve())
    return _apply_saved_model_defaults(config) if apply_model_defaults else config


def model_defaults_path(config_path: Path) -> Path:
    return config_path.with_name(f"{config_path.stem}.models.json")


def save_model_defaults(
    config: EngineConfig,
    selections: dict[str, str],
    context_tokens: dict[str, int] | None = None,
    input_costs: dict[str, float] | None = None,
    output_costs: dict[str, float] | None = None,
    reasoning_efforts: dict[str, str] | None = None,
) -> Path:
    if config.source_path is None:
        raise ValueError("cannot save model defaults for an in-memory config")
    unknown = sorted(set(selections) - set(config.models))
    if unknown:
        raise ValueError("unknown model aliases: " + ", ".join(unknown))
    destination = model_defaults_path(config.source_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    payload = _read_model_defaults_payload(destination)
    additions = payload.get("additional_models", [])
    if isinstance(additions, list):
        for row in additions:
            if isinstance(row, dict) and row.get("alias") in selections:
                alias = str(row["alias"])
                row["model"] = selections[alias]
                if alias in (context_tokens or {}):
                    row["context_tokens"] = (context_tokens or {})[alias]
                if alias in (input_costs or {}):
                    row["input_cost_per_million"] = (input_costs or {})[alias]
                if alias in (output_costs or {}):
                    row["output_cost_per_million"] = (output_costs or {})[alias]
                if alias in (reasoning_efforts or {}):
                    row["reasoning_effort"] = (reasoning_efforts or {})[alias]
    payload.update({"schema_version": "1", "models": selections})
    if any(
        value is not None
        for value in (context_tokens, input_costs, output_costs, reasoning_efforts)
    ):
        aliases = (
            set(context_tokens or {})
            | set(input_costs or {})
            | set(output_costs or {})
            | set(reasoning_efforts or {})
        )
        model_metadata: dict[str, dict[str, float | int | str]] = {}
        for alias in aliases:
            row: dict[str, float | int | str] = {}
            if (context_tokens or {}).get(alias, 0) > 0:
                row["context_tokens"] = (context_tokens or {})[alias]
            if alias in (input_costs or {}):
                row["input_cost_per_million"] = (input_costs or {})[alias]
            if alias in (output_costs or {}):
                row["output_cost_per_million"] = (output_costs or {})[alias]
            if alias in (reasoning_efforts or {}):
                row["reasoning_effort"] = (reasoning_efforts or {})[alias]
            model_metadata[alias] = row
        payload["model_metadata"] = model_metadata
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(temporary, destination)
    return destination


def save_additional_model(config: EngineConfig, model: ModelSpec) -> Path:
    """Persist an extra core-team model selected from a provider catalog."""
    if config.source_path is None:
        raise ValueError("cannot save a model roster for an in-memory config")
    if model.provider not in config.providers:
        raise ValueError(f"unknown provider {model.provider!r}")
    destination = model_defaults_path(config.source_path)
    payload = _read_model_defaults_payload(destination)
    additions = payload.get("additional_models", [])
    if not isinstance(additions, list):
        additions = []
    additions = [
        row
        for row in additions
        if isinstance(row, dict) and row.get("alias") != model.alias
    ]
    additions.append(
        {
            "alias": model.alias,
            "provider": model.provider,
            "model": model.model,
            "priority": model.priority,
            "context_tokens": model.context_tokens,
            "input_cost_per_million": model.input_cost_per_million,
            "output_cost_per_million": model.output_cost_per_million,
            "cache_read_cost_per_million": model.cache_read_cost_per_million,
            "cache_write_cost_per_million": model.cache_write_cost_per_million,
            "reasoning_effort": model.reasoning_effort,
            "supported_reasoning_efforts": list(model.supported_reasoning_efforts),
            "billing_label": model.billing_label,
        }
    )
    payload.update({"schema_version": "1", "additional_models": additions})
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(temporary, destination)
    return destination


def save_model_roster(config: EngineConfig, roster: list[ModelSpec]) -> Path:
    """Replace the saved active core roster with an exact ordered selection."""
    if config.source_path is None:
        raise ValueError("cannot save a model roster for an in-memory config")
    if not roster:
        raise ValueError("model roster must contain at least one model")
    if len(roster) > 3:
        raise ValueError("model roster cannot contain more than three models")

    base_aliases = set(config.models)
    selections: dict[str, str] = {}
    metadata: dict[str, dict[str, float | int | str]] = {}
    additions: list[dict[str, Any]] = []
    for model in roster:
        if model.provider not in config.providers:
            raise ValueError(f"unknown provider {model.provider!r}")
        row = {
            "context_tokens": model.context_tokens,
            "input_cost_per_million": model.input_cost_per_million,
            "output_cost_per_million": model.output_cost_per_million,
            "cache_read_cost_per_million": model.cache_read_cost_per_million,
            "cache_write_cost_per_million": model.cache_write_cost_per_million,
            "reasoning_effort": model.reasoning_effort,
        }
        metadata[model.alias] = {
            key: value for key, value in row.items() if value is not None
        }
        if model.alias in base_aliases:
            selections[model.alias] = model.model
            continue
        additions.append(
            {
                "alias": model.alias,
                "provider": model.provider,
                "model": model.model,
                "priority": model.priority,
                "context_tokens": model.context_tokens,
                "input_cost_per_million": model.input_cost_per_million,
                "output_cost_per_million": model.output_cost_per_million,
                "cache_read_cost_per_million": model.cache_read_cost_per_million,
                "cache_write_cost_per_million": model.cache_write_cost_per_million,
                "reasoning_effort": model.reasoning_effort,
                "supported_reasoning_efforts": list(
                    model.supported_reasoning_efforts
                ),
                "billing_label": model.billing_label,
            }
        )

    destination = model_defaults_path(config.source_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    payload = {
        "schema_version": "1",
        "models": selections,
        "model_metadata": metadata,
        "additional_models": additions,
        "active_model_aliases": [model.alias for model in roster],
    }
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(temporary, destination)
    return destination


def _read_model_defaults_payload(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"invalid saved model defaults at {path}: {exc}") from exc
    return payload if isinstance(payload, dict) else {}


def parse_engine_config(
    raw: dict[str, Any], *, source_path: Path | None = None
) -> EngineConfig:
    provider_rows = raw.get("providers", {})
    if (not isinstance(provider_rows, dict) or not provider_rows) and isinstance(
        raw.get("anthropic"), dict
    ):
        raw = _translate_legacy_config(raw)
        provider_rows = raw["providers"]
    if not isinstance(provider_rows, dict) or not provider_rows:
        raise ValueError("config must define at least one [providers.<name>] table")

    providers: dict[str, ProviderConfig] = {}
    for name, row in provider_rows.items():
        if not isinstance(row, dict):
            raise ValueError(f"providers.{name} must be a table")
        kind = str(row.get("kind", name)).lower()
        base_url = str(row.get("base_url", _default_base_url(kind))).rstrip("/")
        headers = row.get("headers", {})
        if not isinstance(headers, dict):
            raise ValueError(f"providers.{name}.headers must be a table")
        credential_command = row.get("credential_command", [])
        if isinstance(credential_command, str) or not isinstance(
            credential_command, list
        ):
            raise ValueError(
                f"providers.{name}.credential_command must be an argument array"
            )
        providers[name] = ProviderConfig(
            name=name,
            kind=kind,
            base_url=base_url,
            api_key_env=str(row.get("api_key_env", _default_key_env(kind))),
            credential_command=tuple(str(part) for part in credential_command),
            remote=bool(row.get("remote", kind != "ollama")),
            headers={str(k): str(v) for k, v in headers.items()},
            timeout_seconds=float(row.get("timeout_seconds", 120)),
        )

    model_rows = raw.get("models", {})
    if not isinstance(model_rows, dict) or not model_rows:
        raise ValueError("config must define at least one [models.<alias>] table")

    models: dict[str, ModelSpec] = {}
    identities: dict[tuple[str, str], str] = {}
    for alias, row in model_rows.items():
        if not isinstance(row, dict):
            raise ValueError(f"models.{alias} must be a table")
        provider_name = str(row.get("provider", ""))
        if provider_name not in providers:
            raise ValueError(
                f"models.{alias}.provider references unknown provider {provider_name!r}"
            )
        provider = providers[provider_name]
        model_id = str(row.get("model", "")).strip()
        if not model_id:
            raise ValueError(f"models.{alias}.model is required")
        tool_mode = str(row.get("tool_mode", "native")).lower()
        if tool_mode not in {"native", "json"}:
            raise ValueError(f"models.{alias}.tool_mode must be native or json")
        reasoning_effort = str(row.get("reasoning_effort", "auto")).lower()
        valid_efforts = {"auto", "none", "minimal", "low", "medium", "high", "xhigh", "max", "ultra"}
        if reasoning_effort not in valid_efforts:
            raise ValueError(
                f"models.{alias}.reasoning_effort must be one of "
                + ", ".join(sorted(valid_efforts))
            )
        spec = ModelSpec(
            alias=alias,
            provider=provider_name,
            model=model_id,
            remote=bool(row.get("remote", provider.remote)),
            priority=int(row.get("priority", 100)),
            context_tokens=int(row.get("context_tokens", 128_000)),
            max_output_tokens=int(row.get("max_output_tokens", 8_192)),
            tool_mode=tool_mode,
            reasoning_effort=reasoning_effort,
            supported_reasoning_efforts=tuple(
                str(value).lower()
                for value in row.get("supported_reasoning_efforts", [])
            ),
            billing_label=str(row.get("billing_label", "")),
            input_cost_per_million=_optional_float(
                row.get("input_cost_per_million")
            ),
            output_cost_per_million=_optional_float(
                row.get("output_cost_per_million")
            ),
            cache_read_cost_per_million=_optional_float(
                row.get("cache_read_cost_per_million")
            ),
            cache_write_cost_per_million=_optional_float(
                row.get("cache_write_cost_per_million")
            ),
            hourly_hardware_cost=_optional_float(row.get("hourly_hardware_cost")),
            capabilities=ModelCapabilities(
                native_tools=bool(row.get("native_tools", tool_mode == "native")),
                structured_output=bool(row.get("structured_output", True)),
                streaming=bool(row.get("streaming", False)),
                usage_reporting=bool(row.get("usage_reporting", True)),
            ),
        )
        if spec.identity in identities:
            raise ValueError(
                f"models.{alias} duplicates models.{identities[spec.identity]} "
                f"({provider_name}/{model_id}); team identities must be unique"
            )
        identities[spec.identity] = alias
        models[alias] = spec

    specialists: list[SpecialistSpec] = []
    specialist_rows = raw.get("specialists", {})
    if isinstance(specialist_rows, dict):
        for profile, row in specialist_rows.items():
            if not isinstance(row, dict):
                raise ValueError(f"specialists.{profile} must be a table")
            model_alias = str(row.get("model", ""))
            if model_alias not in models:
                raise ValueError(
                    f"specialists.{profile}.model references unknown model "
                    f"{model_alias!r}"
                )
            specialists.append(
                SpecialistSpec(
                    profile=profile,
                    model_alias=model_alias,
                    prompt=str(row.get("prompt", "")),
                    enabled=bool(row.get("enabled", True)),
                )
            )

    sandbox_raw = raw.get("sandbox", {})
    prefix = sandbox_raw.get("command_prefix", []) if isinstance(sandbox_raw, dict) else []
    if isinstance(prefix, str):
        raise ValueError("sandbox.command_prefix must be an array of command arguments")
    sandbox = SandboxConfig(
        backend=str(sandbox_raw.get("backend", "docker"))
        if isinstance(sandbox_raw, dict)
        else "docker",
        image=str(sandbox_raw.get("image", "vulnhunter-sandbox:0.3.0"))
        if isinstance(sandbox_raw, dict)
        else "vulnhunter-sandbox:0.3.0",
        memory=str(sandbox_raw.get("memory", "2g"))
        if isinstance(sandbox_raw, dict)
        else "2g",
        cpus=float(sandbox_raw.get("cpus", 2.0))
        if isinstance(sandbox_raw, dict)
        else 2.0,
        pids_limit=int(sandbox_raw.get("pids_limit", 256))
        if isinstance(sandbox_raw, dict)
        else 256,
        command_prefix=tuple(str(part) for part in prefix),
    )
    return EngineConfig(
        providers=providers,
        models=models,
        specialists=specialists,
        sandbox=sandbox,
        source_path=source_path,
    )


def choose_models(config: EngineConfig, count: int) -> list[ModelSpec]:
    """Select a diverse, deterministic model roster."""
    if count < 1:
        raise ValueError("model count must be at least 1")
    ordered = sorted(
        config.models.values(),
        key=lambda model: (model.priority, model.remote, model.provider, model.alias),
    )
    if count > len(ordered):
        raise ValueError(
            f"requested {count} models, but only {len(ordered)} are configured"
        )

    selected: list[ModelSpec] = []
    remaining = ordered.copy()
    # First pass maximizes provider diversity, while respecting priority order.
    seen_providers: set[str] = set()
    for model in list(remaining):
        if model.provider in seen_providers:
            continue
        selected.append(model)
        seen_providers.add(model.provider)
        remaining.remove(model)
        if len(selected) == count:
            return selected
    selected.extend(remaining[: count - len(selected)])
    return selected


def _apply_saved_model_defaults(config: EngineConfig) -> EngineConfig:
    if config.source_path is None:
        return config
    path = model_defaults_path(config.source_path)
    if not path.is_file():
        return config
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"invalid saved model defaults at {path}: {exc}") from exc
    selections = payload.get("models", {}) if isinstance(payload, dict) else {}
    if not isinstance(selections, dict):
        raise ValueError(f"invalid saved model defaults at {path}: models must be an object")
    models = dict(config.models)
    saved_metadata = payload.get("model_metadata", {}) if isinstance(payload, dict) else {}
    if not isinstance(saved_metadata, dict):
        saved_metadata = {}
    for alias, model_id in selections.items():
        if alias not in models:
            continue
        normalized = str(model_id).strip()
        if normalized:
            current = models[alias]
            models[alias] = replace(
                current,
                model=normalized,
                context_tokens=int(
                    saved_metadata.get(alias, {}).get(
                        "context_tokens", current.context_tokens
                    )
                )
                if isinstance(saved_metadata.get(alias, {}), dict)
                else current.context_tokens,
                input_cost_per_million=(
                    float(saved_metadata[alias]["input_cost_per_million"])
                    if isinstance(saved_metadata.get(alias), dict)
                    and saved_metadata[alias].get("input_cost_per_million") is not None
                    else (
                        current.input_cost_per_million
                        if normalized == current.model
                        else None
                    )
                ),
                output_cost_per_million=(
                    float(saved_metadata[alias]["output_cost_per_million"])
                    if isinstance(saved_metadata.get(alias), dict)
                    and saved_metadata[alias].get("output_cost_per_million") is not None
                    else (
                        current.output_cost_per_million
                        if normalized == current.model
                        else None
                    )
                ),
                cache_read_cost_per_million=(
                    float(saved_metadata[alias]["cache_read_cost_per_million"])
                    if isinstance(saved_metadata.get(alias), dict)
                    and saved_metadata[alias].get("cache_read_cost_per_million")
                    is not None
                    else (
                        current.cache_read_cost_per_million
                        if normalized == current.model
                        else None
                    )
                ),
                cache_write_cost_per_million=(
                    float(saved_metadata[alias]["cache_write_cost_per_million"])
                    if isinstance(saved_metadata.get(alias), dict)
                    and saved_metadata[alias].get("cache_write_cost_per_million")
                    is not None
                    else (
                        current.cache_write_cost_per_million
                        if normalized == current.model
                        else None
                    )
                ),
                reasoning_effort=str(
                    saved_metadata.get(alias, {}).get(
                        "reasoning_effort", current.reasoning_effort
                    )
                )
                if isinstance(saved_metadata.get(alias, {}), dict)
                else current.reasoning_effort,
            )
    additions = payload.get("additional_models", []) if isinstance(payload, dict) else []
    if not isinstance(additions, list):
        raise ValueError(
            f"invalid saved model defaults at {path}: additional_models must be a list"
        )
    identities = {model.identity for model in models.values()}
    for row in additions:
        if not isinstance(row, dict):
            continue
        alias = str(row.get("alias", "")).strip()
        provider_name = str(row.get("provider", "")).strip()
        model_id = str(row.get("model", "")).strip()
        if (
            not alias
            or alias in models
            or provider_name not in config.providers
            or not model_id
            or (provider_name, model_id) in identities
        ):
            continue
        template = next(
            (model for model in models.values() if model.provider == provider_name),
            None,
        )
        if template is None:
            continue
        models[alias] = replace(
            template,
            alias=alias,
            model=model_id,
            priority=int(row.get("priority", max(m.priority for m in models.values()) + 1)),
            context_tokens=int(row.get("context_tokens", template.context_tokens)),
            input_cost_per_million=(
                float(row["input_cost_per_million"])
                if row.get("input_cost_per_million") is not None
                else None
            ),
            output_cost_per_million=(
                float(row["output_cost_per_million"])
                if row.get("output_cost_per_million") is not None
                else None
            ),
            cache_read_cost_per_million=(
                float(row["cache_read_cost_per_million"])
                if row.get("cache_read_cost_per_million") is not None
                else None
            ),
            cache_write_cost_per_million=(
                float(row["cache_write_cost_per_million"])
                if row.get("cache_write_cost_per_million") is not None
                else None
            ),
            reasoning_effort=str(row.get("reasoning_effort", template.reasoning_effort)),
            supported_reasoning_efforts=tuple(
                str(value) for value in row.get(
                    "supported_reasoning_efforts", template.supported_reasoning_efforts
                )
            ),
            billing_label=str(row.get("billing_label", template.billing_label)),
        )
        identities.add((provider_name, model_id))
    active_aliases = payload.get("active_model_aliases")
    if active_aliases is not None:
        if not isinstance(active_aliases, list):
            raise ValueError(
                f"invalid saved model defaults at {path}: "
                "active_model_aliases must be a list"
            )
        active = [str(alias) for alias in active_aliases if str(alias) in models]
        if not active:
            raise ValueError(
                f"invalid saved model defaults at {path}: active roster is empty"
            )
        models = {alias: models[alias] for alias in active}
    return replace(config, models=models)


def _default_base_url(kind: str) -> str:
    return {
        "anthropic": "https://api.anthropic.com",
        "openai": "https://api.openai.com/v1",
        "openrouter": "https://openrouter.ai/api/v1",
        "gemini": "https://generativelanguage.googleapis.com/v1beta/openai",
        "ollama": "http://127.0.0.1:11434",
        "openai_compatible": "http://127.0.0.1:8000/v1",
        "codex_cli": "",
    }.get(kind, "")


def _default_key_env(kind: str) -> str:
    return {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
        "openrouter": "OPENROUTER_API_KEY",
        "gemini": "GEMINI_API_KEY",
    }.get(kind, "")


def _optional_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    return float(value)


def _translate_legacy_config(raw: dict[str, Any]) -> dict[str, Any]:
    """Translate the prior single-Anthropic scan config into Quick-mode input."""
    anthropic = raw.get("anthropic", {})
    auth_mode = str(anthropic.get("auth_mode", "api_key"))
    if auth_mode != "api_key":
        raise ValueError(
            "provider-neutral migration currently supports legacy "
            "anthropic.auth_mode=api_key only; define an explicit provider table "
            "for proxy or gateway authentication"
        )
    model = str(anthropic.get("model", "")).strip()
    if not model:
        raise ValueError("legacy anthropic.model is required")
    return {
        "providers": {
            "legacy-anthropic": {
                "kind": "anthropic",
                "base_url": "https://api.anthropic.com",
                "api_key_env": "ANTHROPIC_API_KEY",
                "remote": True,
            }
        },
        "models": {
            "legacy-anthropic": {
                "provider": "legacy-anthropic",
                "model": model,
                "priority": 10,
                "tool_mode": "native",
                "context_tokens": 200_000,
            }
        },
    }
