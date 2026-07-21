from __future__ import annotations

from dataclasses import replace
import tomllib

import pytest

from vulnhunter import setup
from vulnhunter.config import (
    choose_models,
    load_engine_config,
    parse_engine_config,
    save_additional_model,
    save_model_defaults,
)


def _raw_config() -> dict:
    return {
        "providers": {
            "local": {
                "kind": "openai_compatible",
                "base_url": "http://localhost:8000/v1",
                "remote": False,
            },
            "remote": {
                "kind": "openrouter",
                "api_key_env": "OPENROUTER_API_KEY",
            },
        },
        "models": {
            "local-a": {
                "provider": "local",
                "model": "coder-a",
                "priority": 20,
            },
            "remote-b": {
                "provider": "remote",
                "model": "vendor/model-b",
                "priority": 10,
                "input_cost_per_million": 1,
                "output_cost_per_million": 2,
            },
            "local-c": {
                "provider": "local",
                "model": "coder-c",
                "priority": 30,
            },
        },
        "specialists": {
            "crypto": {"model": "local-c", "prompt": "Audit cryptographic use."}
        },
    }


def test_parse_and_diverse_selection() -> None:
    config = parse_engine_config(_raw_config())
    selected = choose_models(config, 2)
    assert {row.provider for row in selected} == {"local", "remote"}
    assert config.specialists[0].profile == "crypto"


def test_duplicate_model_identity_rejected() -> None:
    raw = _raw_config()
    raw["models"]["duplicate"] = {
        "provider": "local",
        "model": "coder-a",
    }
    with pytest.raises(ValueError, match="duplicates"):
        parse_engine_config(raw)


def test_unrecognized_tool_mode_rejected() -> None:
    raw = _raw_config()
    raw["models"]["local-a"]["tool_mode"] = "magic"
    with pytest.raises(ValueError, match="tool_mode"):
        parse_engine_config(raw)


def test_legacy_anthropic_config_translates() -> None:
    config = parse_engine_config(
        {"anthropic": {"auth_mode": "api_key", "model": "claude-test"}}
    )
    assert config.models["legacy-anthropic"].model == "claude-test"


def test_local_only_setup_excludes_detected_remote_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "not-written")
    monkeypatch.setattr(setup, "discover_local_ollama", lambda: ["local-model"])
    monkeypatch.setattr(setup, "discover_openai_compatible", lambda: None)

    content, detections = setup.generate_config(allow_remote=False)

    assert "providers.openai" not in content
    assert "OPENAI_API_KEY" not in content
    assert "remote_provider_consent = false" in content
    assert detections == ["Ollama: local-model"]


def test_gemini_setup_and_refreshable_credential_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ("OPENROUTER_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "not-written")
    monkeypatch.setattr(setup, "discover_local_ollama", lambda: [])
    monkeypatch.setattr(setup, "discover_openai_compatible", lambda: None)
    monkeypatch.setattr(setup, "discover_codex_cli", lambda: None)

    content, detections = setup.generate_config(allow_remote=True)

    assert 'kind = "gemini"' in content
    assert "not-written" not in content
    assert detections == ["Gemini credentials: gemini-3.5-flash"]

    raw = _raw_config()
    raw["providers"]["local"]["credential_command"] = [
        "gcloud",
        "auth",
        "application-default",
        "print-access-token",
    ]
    config = parse_engine_config(raw)
    assert config.providers["local"].credential_command[0] == "gcloud"


def test_setup_adds_authenticated_codex_cli_without_copying_oauth_tokens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "OPENROUTER_API_KEY",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GEMINI_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(setup, "discover_local_ollama", lambda: [])
    monkeypatch.setattr(setup, "discover_openai_compatible", lambda: None)
    monkeypatch.setattr(
        setup,
        "discover_codex_cli",
        lambda: {
            "model": "gpt-test",
            "context_tokens": 200_000,
            "reasoning_effort": "auto",
            "supported_reasoning_efforts": ["low", "medium", "high"],
            "login_status": "Logged in using ChatGPT",
        },
    )

    content, detections = setup.generate_config(allow_remote=True)
    config = parse_engine_config(tomllib.loads(content))

    assert 'kind = "codex_cli"' in content
    assert "auth.json" not in content and "access_token" not in content
    assert config.models["codex-cli"].reasoning_effort == "auto"
    assert config.models["codex-cli"].supported_reasoning_efforts == (
        "low",
        "medium",
        "high",
    )
    assert detections == [
        "Codex CLI OAuth/session: gpt-test (Logged in using ChatGPT)"
    ]


def test_existing_config_can_append_codex_cli_without_replacement(tmp_path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        "[providers.local]\n"
        'kind = "ollama"\n\n'
        "[models.local]\n"
        'provider = "local"\n'
        'model = "coder"\n'
        "priority = 10\n",
        encoding="utf-8",
    )
    original = load_engine_config(path)

    setup.append_codex_cli_config(
        path,
        original,
        {
            "model": "gpt-test",
            "context_tokens": 200_000,
            "supported_reasoning_efforts": ["low", "high"],
        },
    )
    updated = load_engine_config(path)

    assert updated.models["local"].model == "coder"
    assert updated.models["codex-cli"].model == "gpt-test"
    assert updated.models["codex-cli"].reasoning_effort == "auto"


def test_saved_model_defaults_override_toml_without_editing_it(
    tmp_path,
) -> None:
    config_path = tmp_path / "config.toml"
    original = """\
[providers.router]
kind = "openrouter"
api_key_env = "OPENROUTER_API_KEY"

[models.router-default]
provider = "router"
model = "openrouter/auto"
remote = true
"""
    config_path.write_text(original, encoding="utf-8")
    config = load_engine_config(config_path)

    saved = save_model_defaults(
        config, {"router-default": "vendor/security-model"}
    )
    reloaded = load_engine_config(config_path)

    assert saved.is_file()
    assert reloaded.models["router-default"].model == "vendor/security-model"
    assert config_path.read_text(encoding="utf-8") == original


def test_additional_core_models_persist_in_saved_roster(tmp_path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[providers.router]\n"
        'kind = "openrouter"\n\n'
        "[models.router]\n"
        'provider = "router"\n'
        'model = "vendor/first"\n'
        "priority = 10\n",
        encoding="utf-8",
    )
    config = load_engine_config(config_path)
    extra = replace(
        config.models["router"],
        alias="router-2",
        model="vendor/second",
        priority=11,
        context_tokens=262_144,
        input_cost_per_million=0.05,
        output_cost_per_million=1.0,
    )

    save_additional_model(config, extra)
    reloaded = load_engine_config(config_path)

    assert reloaded.models["router-2"].model == "vendor/second"
    assert reloaded.models["router-2"].context_tokens == 262_144
    assert reloaded.models["router-2"].input_cost_per_million == 0.05
    assert reloaded.models["router-2"].output_cost_per_million == 1.0
    assert [model.model for model in choose_models(reloaded, 2)] == [
        "vendor/first",
        "vendor/second",
    ]
