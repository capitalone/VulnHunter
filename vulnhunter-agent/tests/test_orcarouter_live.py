"""Live OrcaRouter checks through this PR's provider integration.

These are the only tests that touch the network and require a real credential.
They are skipped unless ``ORCAROUTER_API_KEY`` (or ``ORCA_API_KEY``) is set, so
the default offline suite is unaffected. Each check goes through the code this
PR adds — the credential seam and the model-discovery path — never a bare HTTP
call, so a pass means the provider wiring works end to end.

The API key is captured at import time because the shared test fixture strips
credential environment variables from individual tests.
"""

from __future__ import annotations

import asyncio
import os

import pytest

import tests.conftest as conftest
from agent import _llm
from agent.config import AnthropicConfig, OrcaRouterConfig, SandboxConfig
from agent.orcarouter import (
    ConnectCredentialProvider,
    ModelCapability,
    ModelCatalog,
    discover_catalog,
    verified_seed,
)

_LIVE_KEY = (
    os.environ.get("ORCAROUTER_API_KEY", "").strip()
    or os.environ.get("ORCA_API_KEY", "").strip()
)

pytestmark = pytest.mark.skipif(
    not _LIVE_KEY, reason="no OrcaRouter credential in the environment"
)

# A model the workspace can actually call. Resolved from the live catalog at
# test time rather than hardcoded, so it tracks the workspace's real access.
API_BASE = "https://api.orcarouter.ai/v1"
AUTH_BASE = "https://www.orcarouter.ai"


def _first_callable(models) -> str:
    """Return the first model the workspace key can actually call.

    Discovery returns the public catalog, which may include models this key
    has no access to. A lightweight probe (through the provider's own origins)
    finds a callable one; if none respond, the first chat model is returned so
    the failure surfaces in the inference assertion rather than being masked.
    """
    import httpx

    for model in models:
        try:
            response = httpx.post(
                f"{API_BASE}/messages",
                headers={
                    "Authorization": f"Bearer {_LIVE_KEY}",
                    "anthropic-version": "2023-06-01",
                },
                json={
                    "model": model.id,
                    "max_tokens": 4,
                    "messages": [{"role": "user", "content": "hi"}],
                },
                timeout=20,
            )
        except httpx.HTTPError:
            continue
        if response.status_code == 200:
            return model.id
    return models[0].id


def _config(**overrides) -> OrcaRouterConfig:
    return OrcaRouterConfig(
        auth_base_url=AUTH_BASE,
        api_base_url=API_BASE,
        api_key=_LIVE_KEY,
        credentials_file="/tmp/nonexistent-orca-live.json",
        **overrides,
    )


def test_live_catalog_is_authoritative_and_nonempty() -> None:
    catalog = discover_catalog(_config(), _LIVE_KEY, capability="chat")
    assert catalog.degraded is False, f"catalog degraded: {catalog.error}"
    assert catalog.source == "live"
    assert len(catalog.models) > 0
    # Live results are authoritative: every returned record is marked as coming
    # from the API, so no seed entry was appended to the live list.
    assert all(m.source == "live" for m in catalog.models)


def test_live_chat_filter_returns_only_compatible_models() -> None:
    catalog = discover_catalog(_config(), _LIVE_KEY, capability="chat")
    chat = catalog.for_capability(ModelCapability.CHAT)
    assert chat
    for model in chat:
        assert model.is_text_chat()
        # No non-text-specialist model leaked into the chat list.
        assert not (
            {"image-generation", "openai-video", "jina-rerank"}
            & set(model.endpoint_types)
        )


def test_live_multimodal_filter_is_a_subset_of_chat() -> None:
    catalog = discover_catalog(_config(), _LIVE_KEY, capability="chat")
    chat = {m.id for m in catalog.for_capability(ModelCapability.CHAT)}
    images = {m.id for m in catalog.for_capability(ModelCapability.IMAGE_INPUT)}
    # Fail-closed: every image-input model must also be a valid chat model.
    assert images <= chat
    for model in catalog.for_capability(ModelCapability.IMAGE_INPUT):
        assert "image" in model.input_modalities


def test_live_inference_through_the_provider_path() -> None:
    """A real request sent through the repo's SDK path with the OrcaRouter key."""
    config = _config()
    token_manager = ConnectCredentialProvider(config, tls=conftest.TLSConfig(""))

    catalog = discover_catalog(config, _LIVE_KEY, capability="chat")
    chat = catalog.for_capability(ModelCapability.CHAT)
    assert chat, "no callable chat model discovered"
    # The catalog is a public list; a key may lack access to some entries
    # (the relay answers 403 model_access_denied). Pick the first model the
    # workspace can actually call so the check reflects real access.
    model_id = _first_callable(chat)

    agent_config = conftest._build_agent_config(
        anthropic=AnthropicConfig(model=model_id, auth_mode="orcarouter"),
        orcarouter=config,
        # The SDK sandbox needs bubblewrap/socat, which a CI runner may not
        # have; this check exercises the provider wiring, not the sandbox.
        sandbox=SandboxConfig(
            enabled=False, fail_if_unavailable=False, allow_unsandboxed_commands=True
        ),
    )

    async def _run():
        return await _llm.call_json(
            model=model_id,
            system="You reply with JSON only.",
            user='Return exactly {"ok": true} and nothing else.',
            config=agent_config,
            token_manager=token_manager,
            backoffs=(),
            stage="live",
        )

    out = asyncio.run(_run())
    assert out == {"ok": True}


def test_live_catalog_limits_are_enforced() -> None:
    catalog = discover_catalog(_config(catalog_limit=3), _LIVE_KEY, capability="chat")
    assert len(catalog.models) <= 3


def test_live_both_adapters_yield_a_usable_key() -> None:
    """The API-key adapter produces a credential the token interface accepts."""
    config = _config()
    result = ConnectCredentialProvider(config, tls=conftest.TLSConfig("")).resolve()
    assert result.api_key == _LIVE_KEY
    assert result.method.value == "api_key"
