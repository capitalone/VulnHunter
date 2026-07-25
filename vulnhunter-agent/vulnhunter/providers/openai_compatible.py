"""OpenAI, OpenRouter, and generic OpenAI-compatible provider."""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import Any

import httpx

from ..config import ProviderConfig
from ..models import ModelResponse, ModelSpec, ToolCall, Usage
from .base import HTTPProvider, ProviderError, raise_for_status


class OpenAICompatibleProvider(HTTPProvider):
    def __init__(
        self,
        config: ProviderConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(config, transport=transport)

    def _headers(self) -> dict[str, str]:
        headers = super()._headers()
        key = self.credential()
        if key:
            headers["Authorization"] = f"Bearer {key}"
        if self.config.kind == "openrouter":
            headers.setdefault(
                "HTTP-Referer", "https://github.com/JJsilvera1/Multi-VulnHunter"
            )
            headers.setdefault("X-Title", "VulnHunter")
        return headers

    async def health(self, model: ModelSpec) -> tuple[bool, str]:
        try:
            models = await self.list_models()
        except Exception as exc:  # noqa: BLE001
            return False, str(exc)
        if models and model.model not in models:
            if self.config.kind == "openrouter":
                # OpenRouter aliases and routed names are not always returned
                # verbatim. Connectivity is healthy, but expose the caveat.
                return True, f"connected; configured model {model.model!r} not listed"
            return False, f"configured model {model.model!r} is not available"
        return True, "ok"

    async def list_models(self) -> list[str]:
        return list(await self.list_model_metadata())

    async def list_model_metadata(self) -> dict[str, dict[str, Any]]:
        async with self.client() as client:
            response = await client.get("/models")
        raise_for_status(response)
        payload = response.json()
        return {
            str(row["id"]): {
                "context_tokens": _context_tokens(row),
                **_pricing(row),
                **_cache_metadata(row),
                **_reasoning_metadata(row),
                "free": _is_free_model(row),
            }
            for row in payload.get("data", [])
            if isinstance(row, dict) and row.get("id")
        }

    async def account_status(self) -> dict[str, Any]:
        if self.config.kind != "openrouter" or not self.credential():
            return {}
        async with self.client() as client:
            response = await client.get("/key")
        raise_for_status(response)
        data = response.json().get("data", {})
        return data if isinstance(data, dict) else {}

    async def complete(
        self,
        *,
        model: ModelSpec,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        response_schema: dict[str, Any] | None = None,
    ) -> ModelResponse:
        if (
            self.config.kind == "openai"
            and tools
            and model.model.startswith("gpt-5.6")
            and model.reasoning_effort != "none"
        ):
            raise ProviderError(
                "OpenAI Chat Completions function tools require reasoning_effort=none; "
                "use auto/none, the Codex CLI provider, or a Responses API adapter"
            )
        payload: dict[str, Any] = {
            "model": model.model,
            "messages": messages,
            "max_tokens": model.max_output_tokens,
            "temperature": 0,
        }
        if model.reasoning_effort != "auto":
            if self.config.kind == "openrouter":
                payload["reasoning"] = {"effort": model.reasoning_effort}
            else:
                payload["reasoning_effort"] = model.reasoning_effort
        if tools and model.tool_mode == "native":
            payload["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": tool["name"],
                        "description": tool["description"],
                        "parameters": tool["input_schema"],
                    },
                }
                for tool in tools
            ]
            payload["tool_choice"] = "auto"
        if response_schema and model.capabilities.structured_output:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "vulnhunter_result",
                    "strict": True,
                    "schema": response_schema,
                },
            }
        started = time.monotonic()
        try:
            async with self.client() as client:
                response = await client.post("/chat/completions", json=payload)
        except httpx.HTTPError as exc:
            raise ProviderError(f"OpenAI-compatible request failed: {exc}") from exc
        raise_for_status(response)
        data = response.json()
        try:
            choice = data["choices"][0]
            message = choice["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderError("provider response has no choices[0].message") from exc
        calls: list[ToolCall] = []
        for raw_call in message.get("tool_calls") or []:
            function = raw_call.get("function", {})
            arguments = function.get("arguments", "{}")
            try:
                parsed = json.loads(arguments) if isinstance(arguments, str) else arguments
            except json.JSONDecodeError as exc:
                raise ProviderError(
                    f"invalid tool arguments for {function.get('name')}: {exc}"
                ) from exc
            calls.append(
                ToolCall(
                    id=str(raw_call.get("id") or uuid.uuid4()),
                    name=str(function.get("name", "")),
                    arguments=parsed if isinstance(parsed, dict) else {},
                )
            )
        usage_data = data.get("usage") or {}
        prompt_details = usage_data.get("prompt_tokens_details") or {}
        usage = Usage(
            input_tokens=int(
                usage_data.get("prompt_tokens")
                or usage_data.get("input_tokens")
                or 0
            ),
            output_tokens=int(
                usage_data.get("completion_tokens")
                or usage_data.get("output_tokens")
                or 0
            ),
            cached_input_tokens=int(prompt_details.get("cached_tokens") or 0),
            cache_write_tokens=int(prompt_details.get("cache_write_tokens") or 0),
            requests=1,
            duration_seconds=time.monotonic() - started,
        )
        reported_cost = usage_data.get("cost")
        if reported_cost is None:
            reported_cost = usage_data.get("total_cost")
        if (
            reported_cost is None
            and self.config.kind == "openrouter"
            and data.get("id")
        ):
            reported_cost = await self._openrouter_generation_cost(str(data["id"]))
        try:
            usage.cost_usd = (
                float(reported_cost)
                if reported_cost is not None
                else _cost(model, usage)
            )
            usage.cost_source = (
                "provider" if reported_cost is not None else "estimate"
            )
        except (TypeError, ValueError):
            usage.cost_usd = _cost(model, usage)
            usage.cost_source = "estimate"
        return ModelResponse(
            content=str(message.get("content") or ""),
            tool_calls=calls,
            usage=usage,
            finish_reason=str(choice.get("finish_reason") or ""),
            raw=data,
        )

    async def _openrouter_generation_cost(self, generation_id: str) -> float | None:
        """Fetch authoritative billed cost if a completion omitted usage.cost."""
        for delay in (0.0, 0.25, 0.75):
            if delay:
                await asyncio.sleep(delay)
            try:
                async with self.client() as client:
                    response = await client.get(
                        "/generation", params={"id": generation_id}
                    )
                if response.status_code in {404, 429}:
                    continue
                raise_for_status(response)
                row = response.json().get("data") or {}
                for key in ("total_cost", "usage"):
                    value = row.get(key) if isinstance(row, dict) else None
                    if value is not None:
                        return float(value)
            except (httpx.HTTPError, ProviderError, TypeError, ValueError):
                continue
        return None


def _context_tokens(row: dict[str, Any]) -> int | None:
    candidates = (
        row.get("context_length"),
        row.get("context_window"),
        row.get("max_context_length"),
        (row.get("top_provider") or {}).get("context_length")
        if isinstance(row.get("top_provider"), dict)
        else None,
    )
    for value in candidates:
        try:
            tokens = int(value)
        except (TypeError, ValueError):
            continue
        if tokens > 0:
            return tokens
    return None


def _pricing(row: dict[str, Any]) -> dict[str, float]:
    pricing = row.get("pricing")
    if not isinstance(pricing, dict):
        return {}
    result: dict[str, float] = {}
    for destination, candidates in (
        ("input_cost_per_million", ("prompt", "input")),
        ("output_cost_per_million", ("completion", "output")),
    ):
        for key in candidates:
            try:
                value = round(float(pricing.get(key)) * 1_000_000, 10)
            except (TypeError, ValueError):
                continue
            if value >= 0:
                result[destination] = value
                break
    return result


def _cache_metadata(row: dict[str, Any]) -> dict[str, Any]:
    pricing = row.get("pricing")
    if not isinstance(pricing, dict):
        pricing = {}
    result: dict[str, Any] = {}
    for source, destination in (
        ("input_cache_read", "cache_read_cost_per_million"),
        ("input_cache_write", "cache_write_cost_per_million"),
    ):
        try:
            value = round(float(pricing.get(source)) * 1_000_000, 10)
        except (TypeError, ValueError):
            continue
        if value >= 0:
            result[destination] = value
    supported = row.get("supported_parameters") or []
    result["input_cache_supported"] = bool(
        result or (isinstance(supported, list) and "cache_control" in supported)
    )
    return result


def _reasoning_metadata(row: dict[str, Any]) -> dict[str, Any]:
    reasoning = row.get("reasoning")
    if isinstance(reasoning, dict):
        efforts = reasoning.get("supported_efforts")
        return {
            "supported_reasoning_efforts": (
                [str(value) for value in efforts]
                if isinstance(efforts, list)
                else ["minimal", "low", "medium", "high", "xhigh", "max"]
            ),
            "default_reasoning_effort": str(
                reasoning.get("default_effort") or "auto"
            ),
            "reasoning_mandatory": bool(reasoning.get("mandatory", False)),
        }
    supported = row.get("supported_parameters") or []
    if isinstance(supported, list) and "reasoning" in supported:
        return {
            "supported_reasoning_efforts": [
                "minimal",
                "low",
                "medium",
                "high",
                "xhigh",
                "max",
            ],
            "default_reasoning_effort": "auto",
        }
    return {}


def _is_free_model(row: dict[str, Any]) -> bool:
    model_id = str(row.get("id", ""))
    pricing = _pricing(row)
    return (
        model_id == "openrouter/free"
        or model_id.endswith(":free")
        or (
            pricing.get("input_cost_per_million") == 0
            and pricing.get("output_cost_per_million") == 0
        )
    )


def _cost(model: ModelSpec, usage: Usage) -> float | None:
    if not model.remote:
        return 0.0
    if (
        model.input_cost_per_million is None
        or model.output_cost_per_million is None
    ):
        return None
    cached = min(usage.cached_input_tokens, usage.input_tokens)
    written = min(
        usage.cache_write_tokens, max(0, usage.input_tokens - cached)
    )
    if model.cache_read_cost_per_million is None:
        cached = 0
    if model.cache_write_cost_per_million is None:
        written = 0
    regular = max(0, usage.input_tokens - cached - written)
    return (
        regular * model.input_cost_per_million
        + cached
        * (
            model.cache_read_cost_per_million
            if model.cache_read_cost_per_million is not None
            else model.input_cost_per_million
        )
        + written
        * (
            model.cache_write_cost_per_million
            if model.cache_write_cost_per_million is not None
            else model.input_cost_per_million
        )
        + usage.output_tokens * model.output_cost_per_million
    ) / 1_000_000
