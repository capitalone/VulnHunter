"""OrcaRouter model discovery and capability filtering.

The single source of truth for the model list is ``GET {api_base}/models``
against the configured inference origin. Live results are authoritative;
when discovery fails (offline, timeout, auth error) a small, verified
cold-start seed is used and the result is reported as degraded so the UI
says so rather than silently degrading to free text.

Capability filtering is metadata-driven and fail-closed: a model is offered
for an entry point only when the catalog explicitly proves it supports
that entry point. Nothing is inferred from a model's name.
"""

from __future__ import annotations

import enum
import json
import logging
from dataclasses import dataclass
from typing import Any

import httpx

from ..config import OrcaRouterConfig

logger = logging.getLogger(__name__)

# Bound the response we are willing to read/parse. A catalog response must
# not be able to consume unbounded memory.
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024

# Endpoint types that can carry a text chat/agent turn.
_TEXT_ENDPOINT_TYPES = frozenset({"openai", "openai-response", "anthropic", "gemini"})
# Endpoint types that are explicitly non-text; excluded from any chat view.
_NON_TEXT_ENDPOINT_TYPES = frozenset(
    {"image-generation", "openai-video", "jina-rerank", "embeddings"}
)


class ModelCapability(str, enum.Enum):
    """A place where the agent can send a model request."""

    CHAT = "chat"                    # text-only chat/agent
    IMAGE_INPUT = "image_input"      # multimodal understanding: image
    AUDIO_INPUT = "audio_input"
    VIDEO_INPUT = "video_input"
    EMBEDDING = "embedding"
    IMAGE_GENERATION = "image_generation"
    VIDEO_GENERATION = "video_generation"
    RERANK = "rerank"

    @property
    def required_modality(self) -> str | None:
        return {
            ModelCapability.IMAGE_INPUT: "image",
            ModelCapability.AUDIO_INPUT: "audio",
            ModelCapability.VIDEO_INPUT: "video",
        }.get(self)


# Catalog query parameter per capability. The agent only ever asks for the
# capabilities it actually uses; unsupported ones stay absent.
_CAPABILITY_QUERY = {"chat": "chat", "embedding": "embedding", "image": "image"}


@dataclass(frozen=True)
class ModelInfo:
    """One catalog record, normalized."""

    id: str
    name: str = ""
    context_length: int | None = None
    max_completion_tokens: int | None = None
    input_modalities: tuple[str, ...] = ()
    output_modalities: tuple[str, ...] = ()
    endpoint_types: tuple[str, ...] = ()
    reasoning: bool = False
    reasoning_efforts: tuple[str, ...] = ()
    source: str = "live"  # "live" | "seed"

    def is_text_chat(self) -> bool:
        types = set(self.endpoint_types)
        if types & _NON_TEXT_ENDPOINT_TYPES:
            return False
        # Fail closed: an empty endpoint list proves nothing about chat.
        return bool(types & _TEXT_ENDPOINT_TYPES)

    def supports(self, capability: ModelCapability) -> bool:
        """Metadata-only capability check. Unknown metadata → False."""
        types = set(self.endpoint_types)
        if capability is ModelCapability.CHAT:
            return self.is_text_chat()
        if capability is ModelCapability.EMBEDDING:
            return "embeddings" in types
        if capability is ModelCapability.IMAGE_GENERATION:
            return "image-generation" in types
        if capability is ModelCapability.VIDEO_GENERATION:
            return "openai-video" in types
        if capability is ModelCapability.RERANK:
            return "jina-rerank" in types
        modality = capability.required_modality
        if modality is None:
            return False
        # Multimodal understanding requires BOTH a text chat channel and an
        # explicit declaration of the modality actually being uploaded.
        return self.is_text_chat() and modality in self.input_modalities


@dataclass(frozen=True)
class ModelCatalog:
    """A resolved catalog plus how it was obtained."""

    models: tuple[ModelInfo, ...]
    source: str            # "live" | "seed" | "cache"
    degraded: bool = False
    error: str = ""        # safe, secret-free reason when degraded

    def for_capability(self, capability: ModelCapability) -> tuple[ModelInfo, ...]:
        return tuple(m for m in self.models if m.supports(capability))


def _as_str_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(str(v) for v in value if isinstance(v, (str, int)) and str(v))


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    n = int(value)
    return n if n > 0 else None


def parse_model(record: dict) -> ModelInfo | None:
    """Normalize one catalog record; return None for an unusable shape."""
    if not isinstance(record, dict):
        return None
    model_id = str(record.get("id", "") or "").strip()
    if not model_id:
        return None
    architecture = record.get("architecture")
    architecture = architecture if isinstance(architecture, dict) else {}
    top_provider = record.get("top_provider")
    top_provider = top_provider if isinstance(top_provider, dict) else {}

    context_length = _as_int(record.get("context_length")) or _as_int(
        top_provider.get("context_length")
    )
    max_completion = _as_int(record.get("max_completion_tokens")) or _as_int(
        top_provider.get("max_completion_tokens")
    )
    # Reasoning metadata may be advertised either as a flag or as an effort
    # ladder; preserve a verified ladder when present.
    efforts = _as_str_tuple(record.get("reasoning_efforts")) or _as_str_tuple(
        record.get("reasoning_effort_levels")
    )
    reasoning = bool(record.get("reasoning")) or bool(efforts)

    return ModelInfo(
        id=model_id,
        name=str(record.get("name", "") or ""),
        context_length=context_length,
        max_completion_tokens=max_completion,
        input_modalities=_as_str_tuple(architecture.get("input_modalities")),
        output_modalities=_as_str_tuple(architecture.get("output_modalities")),
        endpoint_types=_as_str_tuple(record.get("supported_endpoint_types")),
        reasoning=reasoning,
        reasoning_efforts=efforts,
        source="live",
    )


def parse_catalog(payload: Any, *, limit: int) -> tuple[ModelInfo, ...]:
    """Parse a ``/models`` payload, dropping unusable records and bounding size."""
    if not isinstance(payload, dict):
        return ()
    data = payload.get("data")
    if not isinstance(data, list):
        return ()
    out: list[ModelInfo] = []
    seen: set[str] = set()
    for record in data:
        if len(out) >= max(1, limit):
            break
        info = parse_model(record)
        if info is None or info.id in seen:
            continue
        seen.add(info.id)
        out.append(info)
    return tuple(out)


# --------------------------------------------------------------------------
# Verified cold-start seed
# --------------------------------------------------------------------------
# A small, verified fallback so a fresh installation (or a discovery outage)
# is still usable. It is used ONLY when live discovery fails; a live catalog
# is authoritative and the seed is never mixed into it. Metadata kept here
# (context window, input modalities, reasoning ladder) must survive a
# discovery outage — see the seed tests.
_VERIFIED_SEED: tuple[ModelInfo, ...] = (
    ModelInfo(
        id="openai/gpt-5.5",
        name="GPT-5.5",
        context_length=400_000,
        max_completion_tokens=128_000,
        input_modalities=("text", "image"),
        output_modalities=("text",),
        endpoint_types=("openai", "openai-response", "anthropic"),
        reasoning=True,
        reasoning_efforts=("low", "medium", "high", "xhigh"),
        source="seed",
    ),
    ModelInfo(
        id="anthropic/claude-opus-4.8",
        name="Claude Opus 4.8",
        context_length=200_000,
        max_completion_tokens=64_000,
        input_modalities=("text", "image"),
        output_modalities=("text",),
        endpoint_types=("anthropic", "openai"),
        reasoning=True,
        reasoning_efforts=("low", "medium", "high"),
        source="seed",
    ),
    ModelInfo(
        id="google/gemini-3.5-flash",
        name="Gemini 3.5 Flash",
        context_length=1_000_000,
        max_completion_tokens=64_000,
        input_modalities=("text", "image"),
        output_modalities=("text",),
        endpoint_types=("openai", "gemini", "anthropic"),
        source="seed",
    ),
    ModelInfo(
        id="deepseek/deepseek-v4-pro",
        name="DeepSeek V4 Pro",
        context_length=1_048_576,
        max_completion_tokens=384_000,
        input_modalities=("text",),
        output_modalities=("text",),
        endpoint_types=("openai", "openai-response"),
        source="seed",
    ),
    ModelInfo(
        id="orcarouter/auto",
        name="OrcaRouter Auto",
        input_modalities=("text",),
        output_modalities=("text",),
        endpoint_types=("openai", "anthropic", "gemini"),
        source="seed",
    ),
)


def verified_seed() -> tuple[ModelInfo, ...]:
    """The verified fallback catalog (never mixed into a live result)."""
    return _VERIFIED_SEED


class CatalogError(RuntimeError):
    """A discovery failure whose message is safe to show (no secrets)."""


def fetch_catalog(
    config: OrcaRouterConfig,
    api_key: str,
    *,
    capability: str | None = "chat",
    http_client: httpx.Client | None = None,
) -> tuple[ModelInfo, ...]:
    """Fetch and parse the live catalog from the configured API origin.

    Requests ``GET {api_base}/models`` (optionally ``?capability=…``) with
    Bearer auth, bounded by ``catalog_timeout_seconds`` and
    ``_MAX_RESPONSE_BYTES``. Raises :class:`CatalogError` on any failure.
    """
    url = config.api_base_url.rstrip("/") + "/models"
    params = {"capability": _CAPABILITY_QUERY[capability]} if capability in _CAPABILITY_QUERY else None
    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    client = http_client or httpx.Client()
    owns_client = http_client is None
    try:
        with client.stream(
            "GET", url, params=params, headers=headers,
            timeout=config.catalog_timeout_seconds,
        ) as response:
            if response.status_code == 401:
                raise CatalogError(
                    "OrcaRouter model catalog rejected the credential (HTTP 401)."
                )
            if response.status_code >= 400:
                raise CatalogError(
                    f"OrcaRouter model catalog returned HTTP {response.status_code}."
                )
            body = bytearray()
            for chunk in response.iter_bytes():
                body.extend(chunk)
                if len(body) > _MAX_RESPONSE_BYTES:
                    raise CatalogError("OrcaRouter model catalog response was too large.")
    except httpx.HTTPError as exc:
        raise CatalogError(f"OrcaRouter model catalog request failed: {type(exc).__name__}") from exc
    finally:
        if owns_client:
            client.close()

    try:
        payload = json.loads(bytes(body))
    except json.JSONDecodeError as exc:
        raise CatalogError("OrcaRouter model catalog returned invalid JSON.") from exc
    models = parse_catalog(payload, limit=config.catalog_limit)
    if not models:
        raise CatalogError("OrcaRouter model catalog returned no usable models.")
    return models


def discover_catalog(
    config: OrcaRouterConfig,
    api_key: str,
    *,
    capability: str | None = "chat",
    http_client: httpx.Client | None = None,
) -> ModelCatalog:
    """Resolve the catalog, falling back to the verified seed on failure.

    Live discovery is authoritative. On any failure the verified seed is
    returned with ``degraded=True`` and a safe reason — never free text and
    never an unverified example list.
    """
    if not config.catalog_enabled:
        return ModelCatalog(
            models=verified_seed(), source="seed", degraded=True,
            error="Live model discovery is disabled in configuration.",
        )
    try:
        models = fetch_catalog(
            config, api_key, capability=capability, http_client=http_client
        )
        return ModelCatalog(models=models, source="live", degraded=False)
    except CatalogError as exc:
        logger.warning("OrcaRouter catalog discovery failed: %s", exc)
        return ModelCatalog(
            models=verified_seed(), source="seed", degraded=True, error=str(exc)
        )
