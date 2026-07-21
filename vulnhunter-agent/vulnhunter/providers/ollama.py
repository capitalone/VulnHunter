"""Native Ollama provider."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

import httpx

from ..config import ProviderConfig
from ..models import ModelResponse, ModelSpec, ToolCall, Usage
from .base import HTTPProvider, ProviderError, raise_for_status


class OllamaProvider(HTTPProvider):
    def __init__(
        self,
        config: ProviderConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(config, transport=transport)

    async def health(self, model: ModelSpec) -> tuple[bool, str]:
        try:
            models = await self.list_models()
        except Exception as exc:  # noqa: BLE001
            return False, str(exc)
        if model.model not in models:
            return False, f"model {model.model!r} is not installed"
        return True, "ok"

    async def list_models(self) -> list[str]:
        async with self.client() as client:
            response = await client.get("/api/tags")
        raise_for_status(response)
        payload = response.json()
        return [
            str(row["name"])
            for row in payload.get("models", [])
            if isinstance(row, dict) and row.get("name")
        ]

    async def list_model_metadata(self) -> dict[str, dict[str, Any]]:
        models = await self.list_models()
        metadata: dict[str, dict[str, Any]] = {}
        async with self.client() as client:
            for model_id in models:
                context_tokens: int | None = None
                try:
                    response = await client.post("/api/show", json={"model": model_id})
                    raise_for_status(response)
                    model_info = response.json().get("model_info", {})
                    if isinstance(model_info, dict):
                        for key, value in model_info.items():
                            if str(key).endswith(".context_length"):
                                context_tokens = int(value)
                                break
                except (httpx.HTTPError, ProviderError, TypeError, ValueError):
                    context_tokens = None
                metadata[model_id] = {"context_tokens": context_tokens}
        return metadata

    async def complete(
        self,
        *,
        model: ModelSpec,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        response_schema: dict[str, Any] | None = None,
    ) -> ModelResponse:
        payload: dict[str, Any] = {
            "model": model.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": 0, "num_predict": model.max_output_tokens},
        }
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
        if response_schema and model.capabilities.structured_output:
            payload["format"] = response_schema
        started = time.monotonic()
        try:
            async with self.client() as client:
                response = await client.post("/api/chat", json=payload)
        except httpx.HTTPError as exc:
            raise ProviderError(f"Ollama request failed: {exc}") from exc
        raise_for_status(response)
        data = response.json()
        message = data.get("message") or {}
        calls: list[ToolCall] = []
        for raw_call in message.get("tool_calls") or []:
            function = raw_call.get("function", {})
            args = function.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError as exc:
                    raise ProviderError(f"invalid Ollama tool arguments: {exc}") from exc
            calls.append(
                ToolCall(
                    id=str(raw_call.get("id") or uuid.uuid4()),
                    name=str(function.get("name", "")),
                    arguments=args if isinstance(args, dict) else {},
                )
            )
        usage = Usage(
            input_tokens=int(data.get("prompt_eval_count") or 0),
            output_tokens=int(data.get("eval_count") or 0),
            requests=1,
            cost_usd=0.0,
            duration_seconds=time.monotonic() - started,
        )
        return ModelResponse(
            content=str(message.get("content") or ""),
            tool_calls=calls,
            usage=usage,
            finish_reason=str(data.get("done_reason") or ""),
            raw=data,
        )
