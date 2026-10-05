"""Tests for OrcaRouter model discovery and capability filtering.

The dropdown bound to a real provider selector must come from the catalog
API and be filtered per capability, fail-closed on undeclared modalities,
and never degrade to free text or an unverified example list.
"""

from __future__ import annotations

import httpx
import pytest

from agent.config import OrcaRouterConfig
from agent.orcarouter import (
    ModelCapability,
    ModelInfo,
    ModelCatalog,
    discover_catalog,
    parse_catalog,
    verified_seed,
)

# A fixture catalog covering every capability the verifier asks for.
FIXTURE_MODELS = [
    # text-only chat
    {"id": "vendor/text-only", "supported_endpoint_types": ["openai"],
     "architecture": {"input_modalities": ["text"], "output_modalities": ["text"]},
     "context_length": 128000},
    # image-input chat
    {"id": "vendor/vision", "supported_endpoint_types": ["openai", "anthropic"],
     "architecture": {"input_modalities": ["text", "image"], "output_modalities": ["text"]}},
    # audio-input chat
    {"id": "vendor/audio", "supported_endpoint_types": ["openai"],
     "architecture": {"input_modalities": ["text", "audio"]}},
    # embedding
    {"id": "vendor/embed", "supported_endpoint_types": ["embeddings"],
     "architecture": {"input_modalities": ["text"]}},
    # image generation
    {"id": "vendor/imagegen", "supported_endpoint_types": ["image-generation"]},
    # video generation
    {"id": "vendor/video", "supported_endpoint_types": ["openai-video"]},
    # rerank
    {"id": "vendor/rerank", "supported_endpoint_types": ["jina-rerank"]},
    # undeclared-modality chat: must fail closed for multimodal
    {"id": "vendor/unknown-modal", "supported_endpoint_types": ["openai"]},
]


def fixture_catalog() -> tuple[ModelInfo, ...]:
    return parse_catalog({"data": FIXTURE_MODELS}, limit=100)


def ids(models) -> set[str]:
    return {m.id for m in models}


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def test_parse_preserves_vendor_namespace_and_metadata() -> None:
    parsed = parse_catalog(
        {"data": [{
            "id": "openai/gpt-5.5",
            "name": "GPT-5.5",
            "context_length": 400000,
            "max_completion_tokens": 128000,
            "architecture": {"input_modalities": ["text", "image"]},
            "supported_endpoint_types": ["openai", "anthropic"],
        }]},
        limit=10,
    )
    assert parsed[0].id == "openai/gpt-5.5"  # namespace untouched
    assert parsed[0].context_length == 400000
    assert "image" in parsed[0].input_modalities


def test_parse_drops_unusable_records_and_bounds_size() -> None:
    payload = {"data": [{"no_id": 1}, "nope", {"id": ""}, {"id": "ok/a"}]}
    assert ids(parse_catalog(payload, limit=10)) == {"ok/a"}
    many = {"data": [{"id": f"v/m{i}"} for i in range(50)]}
    assert len(parse_catalog(many, limit=5)) == 5


def test_parse_tolerates_missing_shape() -> None:
    assert parse_catalog({}, limit=5) == ()
    assert parse_catalog({"data": "nope"}, limit=5) == ()
    assert parse_catalog(None, limit=5) == ()


def test_parse_reads_top_provider_fallbacks() -> None:
    parsed = parse_catalog(
        {"data": [{"id": "v/x", "supported_endpoint_types": ["openai"],
                   "top_provider": {"context_length": 999, "max_completion_tokens": 111},
                   "architecture": {"input_modalities": ["text"]}}]},
        limit=5,
    )
    assert parsed[0].context_length == 999
    assert parsed[0].max_completion_tokens == 111


# ---------------------------------------------------------------------------
# Capability filtering (fail-closed)
# ---------------------------------------------------------------------------


def test_chat_capability_excludes_non_text_endpoints() -> None:
    models = parse_catalog({"data": FIXTURE_MODELS}, limit=100)
    chat = ids(ModelCatalog(models, "live").for_capability(ModelCapability.CHAT))
    assert "vendor/text-only" in chat
    assert "vendor/vision" in chat
    for excluded in (
        "vendor/embed",
        "vendor/imagegen",
        "vendor/video",
        "vendor/rerank",
    ):
        assert excluded not in chat


def test_embedding_capability_strict() -> None:
    models = parse_catalog({"data": FIXTURE_MODELS}, limit=100)
    assert ids(ModelCatalog(models, "live").for_capability(ModelCapability.EMBEDDING)) == {
        "vendor/embed"
    }


def test_image_generation_video_and_rerank_are_strict() -> None:
    models = parse_catalog({"data": FIXTURE_MODELS}, limit=100)
    cat = ModelCatalog(models, "live")
    assert ids(cat.for_capability(ModelCapability.IMAGE_GENERATION)) == {"vendor/imagegen"}
    assert ids(cat.for_capability(ModelCapability.VIDEO_GENERATION)) == {"vendor/video"}
    assert ids(cat.for_capability(ModelCapability.RERANK)) == {"vendor/rerank"}


def test_multimodal_fails_closed_on_undeclared_capability() -> None:
    models = parse_catalog({"data": FIXTURE_MODELS}, limit=100)
    cat = ModelCatalog(models, "live")
    image = ids(cat.for_capability(ModelCapability.IMAGE_INPUT))
    assert "vendor/vision" in image
    # A model with no architecture block must NOT be offered for images.
    assert "vendor/unknown-modal" not in image
    # A text-only model must not be offered either.
    assert "vendor/text-only" not in image
    # Every image-capable model must also be a valid chat model.
    chat = ids(cat.for_capability(ModelCapability.CHAT))
    assert image <= chat


def test_audio_input_requires_declared_audio_modality() -> None:
    models = parse_catalog({"data": FIXTURE_MODELS}, limit=100)
    cat = ModelCatalog(models, "live")
    assert ids(cat.for_capability(ModelCapability.AUDIO_INPUT)) == {"vendor/audio"}


def test_empty_endpoint_types_prove_nothing() -> None:
    info = ModelInfo(id="v/mystery")
    assert info.supports(ModelCapability.CHAT) is False
    assert info.supports(ModelCapability.IMAGE_INPUT) is False


def test_selector_options_change_when_capability_changes() -> None:
    models = parse_catalog({"data": FIXTURE_MODELS}, limit=100)
    cat = ModelCatalog(models, "live")
    text_options = {m.id for m in cat.for_capability(ModelCapability.CHAT)}
    image_options = {m.id for m in cat.for_capability(ModelCapability.IMAGE_INPUT)}
    assert image_options < text_options  # strictly narrower


# ---------------------------------------------------------------------------
# Live discovery
# ---------------------------------------------------------------------------


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_fetch_hits_api_origin_with_bearer_and_capability() -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"data": FIXTURE_MODELS})

    config = OrcaRouterConfig()
    with _client(handler) as client:
        catalog = discover_catalog(config, "sk-orca-fake", capability="chat", http_client=client)

    assert catalog.source == "live" and catalog.degraded is False
    assert seen["url"].startswith("https://api.orcarouter.ai/v1/models")
    assert "capability=chat" in seen["url"]
    assert seen["auth"] == "Bearer sk-orca-fake"
    assert len(catalog.models) == len(FIXTURE_MODELS)


def test_live_catalog_is_authoritative_seed_not_mixed_in() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": FIXTURE_MODELS})

    with _client(handler) as client:
        catalog = discover_catalog(
            OrcaRouterConfig(), "sk-orca-fake", capability="chat", http_client=client
        )
    live_ids = {m.id for m in catalog.models}
    assert live_ids.isdisjoint({m.id for m in verified_seed()})
    assert all(m.source == "live" for m in catalog.models)


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(401, json={"error": "bad key"}),
        httpx.Response(500, json={}),
        httpx.Response(200, text="not json"),
        httpx.Response(200, json={"data": []}),
    ],
)
def test_discovery_failure_falls_back_to_verified_seed(response: httpx.Response) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return response

    with _client(handler) as client:
        catalog = discover_catalog(
            OrcaRouterConfig(), "sk-orca-fake", capability="chat", http_client=client
        )
    assert catalog.source == "seed"
    assert catalog.degraded is True
    assert catalog.error
    assert catalog.models  # usable, not empty
    assert all(m.source == "seed" for m in catalog.models)


def test_network_error_is_degraded_and_secret_free() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom sk-orca-SECRET")

    with _client(handler) as client:
        catalog = discover_catalog(
            OrcaRouterConfig(), "sk-orca-SECRET", capability="chat", http_client=client
        )
    assert catalog.degraded
    assert "sk-orca-SECRET" not in catalog.error


def test_catalog_disabled_returns_seed_without_network() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        pytest.fail("must not hit the network when discovery is disabled")

    with _client(handler) as client:
        catalog = discover_catalog(
            OrcaRouterConfig(catalog_enabled=False), "k",
            capability="chat", http_client=client,
        )
    assert catalog.source == "seed" and catalog.degraded


def test_fetch_preserves_context_and_reasoning_metadata() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": [{
            "id": "openai/gpt-5.5",
            "context_length": 400000,
            "reasoning": True,
            "reasoning_efforts": ["low", "medium", "high", "xhigh"],
            "architecture": {"input_modalities": ["text", "image"]},
            "supported_endpoint_types": ["openai", "anthropic"],
        }]})

    with _client(handler) as client:
        catalog = discover_catalog(OrcaRouterConfig(), "k", capability="chat", http_client=client)
    model = catalog.models[0]
    assert model.reasoning_efforts == ("low", "medium", "high", "xhigh")
    assert model.context_length == 400000
    assert "image" in model.input_modalities


# ---------------------------------------------------------------------------
# Verified seed integrity
# ---------------------------------------------------------------------------


def test_seed_contains_the_documented_models() -> None:
    seed = {m.id for m in verified_seed()}
    assert seed == {
        "openai/gpt-5.5",
        "anthropic/claude-opus-4.8",
        "google/gemini-3.5-flash",
        "deepseek/deepseek-v4-pro",
        "orcarouter/auto",
    }


def test_seed_retains_gpt55_reasoning_ladder_and_modalities() -> None:
    gpt = next(m for m in verified_seed() if m.id == "openai/gpt-5.5")
    assert gpt.reasoning is True
    assert gpt.reasoning_efforts == ("low", "medium", "high", "xhigh")
    assert "image" in gpt.input_modalities
    assert gpt.context_length == 400000


def test_seed_models_are_offered_for_chat() -> None:
    cat = ModelCatalog(verified_seed(), "seed", degraded=True)
    assert len(cat.for_capability(ModelCapability.CHAT)) == len(verified_seed())


def test_incompatible_selection_is_cleared() -> None:
    """When the capability changes, a now-incompatible selection must clear."""
    models = parse_catalog({"data": FIXTURE_MODELS}, limit=100)
    cat = ModelCatalog(models, "live")

    def select(model_id: str, capability: ModelCapability) -> str | None:
        options = cat.for_capability(capability)
        return model_id if any(m.id == model_id for m in options) else None

    assert select("vendor/text-only", ModelCapability.CHAT) == "vendor/text-only"
    # Switching to image input invalidates the text-only selection.
    assert select("vendor/text-only", ModelCapability.IMAGE_INPUT) is None
    # An image model survives the switch.
    assert select("vendor/vision", ModelCapability.IMAGE_INPUT) == "vendor/vision"
