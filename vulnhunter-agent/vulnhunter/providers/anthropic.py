"""Anthropic Messages API provider."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

import httpx

from ..config import ProviderConfig
from ..models import ModelResponse, ModelSpec, ToolCall, Usage
from .base import HTTPProvider, ProviderError, raise_for_status
from .openai_compatible import _cost


def _positive_int(value: Any) -> int | None:
    try:
        result = int(value)
    except (TypeError, ValueError):
        return None
    return result if result > 0 else None


class AnthropicProvider(HTTPProvider):
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
            headers["x-api-key"] = key
        headers.setdefault("anthropic-version", "2023-06-01")
        return headers

    async def health(self, model: ModelSpec) -> tuple[bool, str]:
        try:
            credential = self.credential()
        except ProviderError as exc:
            return False, str(exc)
        if not credential:
            return False, f"{self.config.api_key_env or 'API key'} is not set"
        return True, "credentials configured"

    async def list_models(self) -> list[str]:
        return list(await self.list_model_metadata())

    async def list_model_metadata(self) -> dict[str, dict[str, Any]]:
        async with self.client() as client:
            response = await client.get("/v1/models")
        raise_for_status(response)
        payload = response.json()
        return {
            str(row["id"]): {
                "context_tokens": _positive_int(
                    row.get("context_length") or row.get("context_window")
                )
            }
            for row in payload.get("data", [])
            if isinstance(row, dict) and row.get("id")
        }

    async def complete(
        self,
        *,
        model: ModelSpec,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        response_schema: dict[str, Any] | None = None,
    ) -> ModelResponse:
        system_parts = [
            str(row.get("content", ""))
            for row in messages
            if row.get("role") == "system"
        ]
        conversation = [
            _anthropic_message(row)
            for row in messages
            if row.get("role") != "system"
        ]
        payload: dict[str, Any] = {
            "model": model.model,
            "max_tokens": model.max_output_tokens,
            "temperature": 0,
            "system": "\n\n".join(system_parts),
            "messages": conversation,
        }
        if model.reasoning_effort != "auto":
            payload["output_config"] = {"effort": model.reasoning_effort}
        if tools and model.tool_mode == "native":
            payload["tools"] = tools
        if response_schema:
            payload["system"] += (
                "\n\nYour final response must be JSON matching this schema:\n"
                + json.dumps(response_schema, separators=(",", ":"))
            )
        started = time.monotonic()
        try:
            async with self.client() as client:
                response = await client.post("/v1/messages", json=payload)
        except httpx.HTTPError as exc:
            raise ProviderError(f"Anthropic request failed: {exc}") from exc
        raise_for_status(response)
        data = response.json()
        content_parts: list[str] = []
        calls: list[ToolCall] = []
        for block in data.get("content", []):
            if block.get("type") == "text":
                content_parts.append(str(block.get("text", "")))
            elif block.get("type") == "tool_use":
                calls.append(
                    ToolCall(
                        id=str(block.get("id") or uuid.uuid4()),
                        name=str(block.get("name", "")),
                        arguments=block.get("input")
                        if isinstance(block.get("input"), dict)
                        else {},
                    )
                )
        usage_data = data.get("usage") or {}
        usage = Usage(
            input_tokens=int(usage_data.get("input_tokens") or 0),
            output_tokens=int(usage_data.get("output_tokens") or 0),
            cached_input_tokens=int(usage_data.get("cache_read_input_tokens") or 0),
            cache_write_tokens=int(usage_data.get("cache_creation_input_tokens") or 0),
            requests=1,
            duration_seconds=time.monotonic() - started,
        )
        usage.cost_usd = _cost(model, usage)
        return ModelResponse(
            content="\n".join(content_parts),
            tool_calls=calls,
            usage=usage,
            finish_reason=str(data.get("stop_reason") or ""),
            raw=data,
        )


def _anthropic_message(message: dict[str, Any]) -> dict[str, Any]:
    role = message.get("role")
    if role == "tool":
        return {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": str(message.get("tool_call_id", "")),
                    "content": str(message.get("content", "")),
                }
            ],
        }
    if role == "assistant" and message.get("tool_calls"):
        content: list[dict[str, Any]] = []
        if message.get("content"):
            content.append({"type": "text", "text": str(message["content"])})
        for call in message["tool_calls"]:
            function = call.get("function", {})
            arguments = function.get("arguments", "{}")
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    arguments = {}
            content.append(
                {
                    "type": "tool_use",
                    "id": str(call.get("id", "")),
                    "name": str(function.get("name", "")),
                    "input": arguments if isinstance(arguments, dict) else {},
                }
            )
        return {"role": "assistant", "content": content}
    return {
        "role": "assistant" if role == "assistant" else "user",
        "content": message.get("content", ""),
    }
