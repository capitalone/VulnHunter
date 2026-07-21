from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from vulnhunter.config import ProviderConfig
from vulnhunter.models import ModelSpec
from vulnhunter.providers import create_provider
from vulnhunter.providers.codex_cli import CodexCLIProvider


@pytest.mark.asyncio
async def test_openrouter_headers_and_usage(monkeypatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "secret")
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["authorization"] = request.headers.get("Authorization")
        seen["referer"] = request.headers.get("HTTP-Referer")
        if request.url.path.endswith("/models"):
            return httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "id": "vendor/model",
                            "context_length": 131_072,
                            "pricing": {
                                "prompt": "0.00000005",
                                "completion": "0.000001",
                            },
                            "reasoning": {
                                "supported_efforts": ["low", "medium", "high"],
                                "default_effort": "medium",
                                "mandatory": True,
                            },
                        }
                    ]
                },
            )
        if request.url.path.endswith("/key"):
            return httpx.Response(
                200,
                json={
                    "data": {
                        "is_free_tier": False,
                        "usage_daily": 1.25,
                        "usage": 7.5,
                    }
                },
            )
        body = json.loads(request.content)
        seen["body"] = body
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {"content": '{"candidates":[]}', "tool_calls": []},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 100,
                    "completion_tokens": 20,
                    "prompt_tokens_details": {"cached_tokens": 80},
                },
            },
        )

    provider = create_provider(
        ProviderConfig(
            name="openrouter",
            kind="openrouter",
            base_url="https://openrouter.test/v1",
            api_key_env="OPENROUTER_API_KEY",
        ),
        transport=httpx.MockTransport(handler),
    )
    model = ModelSpec(
        alias="router",
        provider="openrouter",
        model="vendor/model",
        remote=True,
        reasoning_effort="high",
        input_cost_per_million=1,
        output_cost_per_million=2,
    )
    ok, detail = await provider.health(model)
    assert ok, detail
    assert await provider.list_model_metadata() == {
        "vendor/model": {
            "context_tokens": 131_072,
            "input_cost_per_million": 0.05,
            "output_cost_per_million": 1.0,
            "input_cache_supported": False,
            "supported_reasoning_efforts": ["low", "medium", "high"],
            "default_reasoning_effort": "medium",
            "reasoning_mandatory": True,
            "free": False,
        }
    }
    assert (await provider.account_status())["usage_daily"] == 1.25
    response = await provider.complete(
        model=model,
        messages=[{"role": "user", "content": "test"}],
        tools=[],
    )
    assert seen["authorization"] == "Bearer secret"
    assert seen["referer"]
    assert seen["body"]["reasoning"] == {"effort": "high"}
    assert response.usage.input_tokens == 100
    assert response.usage.cached_input_tokens == 80
    assert response.usage.requests == 1
    assert response.usage.cost_usd == pytest.approx(0.00014)
    assert response.usage.cost_source == "estimate"


@pytest.mark.asyncio
async def test_openrouter_prefers_reported_cost_and_generation_fallback(monkeypatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "secret")
    completions = 0
    generation_queries: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal completions
        if request.url.path.endswith("/generation"):
            generation_queries.append(str(request.url.params.get("id")))
            return httpx.Response(200, json={"data": {"total_cost": 0.0042}})
        completions += 1
        usage: dict[str, object] = {
            "prompt_tokens": 1000,
            "completion_tokens": 100,
            "prompt_tokens_details": {"cached_tokens": 900},
        }
        if completions == 1:
            usage["cost"] = 0.0011
        return httpx.Response(
            200,
            json={
                "id": f"gen-{completions}",
                "choices": [
                    {"message": {"content": "{}"}, "finish_reason": "stop"}
                ],
                "usage": usage,
            },
        )

    provider = create_provider(
        ProviderConfig(
            name="openrouter",
            kind="openrouter",
            base_url="https://openrouter.test/v1",
            api_key_env="OPENROUTER_API_KEY",
        ),
        transport=httpx.MockTransport(handler),
    )
    model = ModelSpec(
        alias="router",
        provider="openrouter",
        model="vendor/model",
        remote=True,
        input_cost_per_million=100,
        output_cost_per_million=100,
    )
    direct = await provider.complete(model=model, messages=[], tools=[])
    reconciled = await provider.complete(model=model, messages=[], tools=[])

    assert direct.usage.cost_usd == pytest.approx(0.0011)
    assert direct.usage.cost_source == "provider"
    assert reconciled.usage.cost_usd == pytest.approx(0.0042)
    assert reconciled.usage.cost_source == "provider"
    assert generation_queries == ["gen-2"]


@pytest.mark.asyncio
async def test_codex_cli_catalog_and_reasoning_invocation(monkeypatch, tmp_path) -> None:
    codex_home = tmp_path / ".codex"
    codex_home.mkdir()
    (codex_home / "models_cache.json").write_text(
        json.dumps(
            {
                "models": [
                    {
                        "slug": "gpt-test",
                        "visibility": "list",
                        "context_window": 200_000,
                        "default_reasoning_level": "medium",
                        "supported_reasoning_levels": [
                            {"effort": "low"},
                            {"effort": "medium"},
                            {"effort": "high"},
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("vulnhunter.providers.codex_cli.Path.home", lambda: tmp_path)
    monkeypatch.setattr("vulnhunter.providers.codex_cli.shutil.which", lambda _name: "codex")
    seen: dict[str, object] = {}

    class FakeProcess:
        returncode = 0

        def __init__(self, command):
            self.command = command

        async def communicate(self, prompt=None):
            seen["command"] = self.command
            seen["prompt"] = prompt
            output = Path(self.command[self.command.index("-o") + 1])
            output.write_text('{"ok":true}', encoding="utf-8")
            return (
                b'{"type":"turn.completed","usage":{"input_tokens":12,'
                b'"cached_input_tokens":8,"output_tokens":4}}\n',
                b"",
            )

    async def fake_subprocess(*command, **_kwargs):
        return FakeProcess(list(command))

    monkeypatch.setattr(
        "vulnhunter.providers.codex_cli.asyncio.create_subprocess_exec",
        fake_subprocess,
    )
    provider = CodexCLIProvider(
        ProviderConfig(name="codex", kind="codex_cli", base_url="")
    )
    metadata = await provider.list_model_metadata()
    assert metadata["gpt-test"]["supported_reasoning_efforts"] == [
        "low",
        "medium",
        "high",
    ]
    provider.set_repository_root(tmp_path)
    response = await provider.complete(
        model=ModelSpec(
            alias="codex",
            provider="codex",
            model="gpt-test",
            remote=True,
            reasoning_effort="high",
        ),
        messages=[{"role": "user", "content": "inspect"}],
        tools=[],
        response_schema={"type": "object"},
    )
    command = seen["command"]
    assert 'model_reasoning_effort="high"' in command
    assert "--sandbox" in command and "read-only" in command
    assert response.content == '{"ok":true}'
    assert response.usage.input_tokens == 12
    assert response.usage.cached_input_tokens == 8


@pytest.mark.asyncio
async def test_ollama_model_discovery() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": "coder:latest"}]})
        return httpx.Response(
            200,
            json={
                "message": {"content": "{}"},
                "prompt_eval_count": 4,
                "eval_count": 2,
                "done_reason": "stop",
            },
        )

    provider = create_provider(
        ProviderConfig(
            name="ollama",
            kind="ollama",
            base_url="http://ollama.test",
            remote=False,
        ),
        transport=httpx.MockTransport(handler),
    )
    model = ModelSpec(
        alias="local",
        provider="ollama",
        model="coder:latest",
        remote=False,
    )
    assert await provider.list_models() == ["coder:latest"]
    assert await provider.health(model) == (True, "ok")


@pytest.mark.asyncio
async def test_generic_endpoint_rejects_unavailable_model() -> None:
    provider = create_provider(
        ProviderConfig(
            name="local",
            kind="openai_compatible",
            base_url="http://local.test/v1",
            remote=False,
        ),
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200, json={"data": [{"id": "installed-model"}]}
            )
        ),
    )
    model = ModelSpec(
        alias="missing",
        provider="local",
        model="missing-model",
        remote=False,
    )

    ok, detail = await provider.health(model)

    assert not ok
    assert "not available" in detail


@pytest.mark.asyncio
async def test_oauth_credential_helper_is_used_and_cached(monkeypatch) -> None:
    helper_calls = 0

    def fake_run(*_args, **_kwargs):
        nonlocal helper_calls
        helper_calls += 1
        return SimpleNamespace(returncode=0, stdout="oauth-token\n", stderr="")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer oauth-token"
        return httpx.Response(200, json={"data": [{"id": "google/gemini"}]})

    monkeypatch.setattr("vulnhunter.providers.base.subprocess.run", fake_run)
    provider = create_provider(
        ProviderConfig(
            name="vertex",
            kind="openai_compatible",
            base_url="https://vertex.test/v1",
            credential_command=("gcloud", "auth", "print-access-token"),
        ),
        transport=httpx.MockTransport(handler),
    )
    model = ModelSpec(
        alias="gemini",
        provider="vertex",
        model="google/gemini",
        remote=True,
    )

    assert await provider.health(model) == (True, "ok")
    assert await provider.health(model) == (True, "ok")
    assert helper_calls == 1
