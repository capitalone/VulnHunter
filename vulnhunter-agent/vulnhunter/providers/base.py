"""Provider protocol and provider factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
import subprocess
import time
from typing import Any, Protocol

import httpx

from ..config import ProviderConfig
from ..models import ModelResponse, ModelSpec


class ProviderError(RuntimeError):
    """A normalized provider transport or response error."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.retry_after = retry_after


class ModelProvider(Protocol):
    config: ProviderConfig

    async def health(self, model: ModelSpec) -> tuple[bool, str]:
        ...

    async def list_models(self) -> list[str]:
        ...

    async def list_model_metadata(self) -> dict[str, dict[str, Any]]:
        ...

    async def complete(
        self,
        *,
        model: ModelSpec,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        response_schema: dict[str, Any] | None = None,
    ) -> ModelResponse:
        ...

    def stream(
        self,
        *,
        model: ModelSpec,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        response_schema: dict[str, Any] | None = None,
    ) -> AsyncIterator[ModelResponse]:
        ...


class HTTPProvider:
    def __init__(
        self,
        config: ProviderConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.config = config
        self._transport = transport
        self._cached_credential = ""
        self._credential_expires_at = 0.0

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self.config.base_url,
            timeout=self.config.timeout_seconds,
            transport=self._transport,
            headers=self._headers(),
        )

    def _headers(self) -> dict[str, str]:
        return dict(self.config.headers)

    def credential(self) -> str:
        """Resolve an environment credential or a refreshable helper command."""
        environment_value = self.config.api_key()
        if environment_value:
            return environment_value
        if not self.config.credential_command:
            return ""
        if self._cached_credential and time.monotonic() < self._credential_expires_at:
            return self._cached_credential
        try:
            completed = subprocess.run(
                list(self.config.credential_command),
                capture_output=True,
                text=True,
                timeout=30,
                shell=False,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ProviderError(f"credential helper failed: {exc}") from exc
        credential = completed.stdout.strip()
        if completed.returncode != 0 or not credential:
            detail = completed.stderr.strip()[:500] or "no credential returned"
            raise ProviderError(f"credential helper failed: {detail}")
        self._cached_credential = credential
        # OAuth access tokens commonly live for one hour. Refresh conservatively.
        self._credential_expires_at = time.monotonic() + 45 * 60
        return credential

    async def stream(
        self,
        *,
        model: ModelSpec,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        response_schema: dict[str, Any] | None = None,
    ) -> AsyncIterator[ModelResponse]:
        """Portable fallback stream for providers without native streaming."""
        response = await self.complete(  # type: ignore[attr-defined]
            model=model,
            messages=messages,
            tools=tools,
            response_schema=response_schema,
        )
        yield response


def create_provider(
    config: ProviderConfig,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> ModelProvider:
    kind = config.kind.lower()
    if kind == "anthropic":
        from .anthropic import AnthropicProvider

        return AnthropicProvider(config, transport=transport)
    if kind == "ollama":
        from .ollama import OllamaProvider

        return OllamaProvider(config, transport=transport)
    if kind == "codex_cli":
        from .codex_cli import CodexCLIProvider

        return CodexCLIProvider(config)
    if kind in {"openai", "openrouter", "gemini", "openai_compatible"}:
        from .openai_compatible import OpenAICompatibleProvider

        return OpenAICompatibleProvider(config, transport=transport)
    raise ValueError(f"unsupported provider kind: {config.kind}")


def raise_for_status(response: httpx.Response) -> None:
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        body = exc.response.text[:1_000]
        retry_after: float | None = None
        try:
            retry_after = float(exc.response.headers.get("Retry-After", ""))
        except ValueError:
            pass
        raise ProviderError(
            f"{exc.response.status_code} from {exc.request.url}: {body}",
            status_code=exc.response.status_code,
            retry_after=retry_after,
        ) from exc
