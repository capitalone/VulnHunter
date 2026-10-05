"""Integration tests for OrcaRouter wiring into the provider seams.

Proves:

* the provider is a first-class ``auth_mode`` value in config;
* both connect entries (API key + OAuth) remain independently usable;
* auth requests go ONLY to the auth origin and inference/catalog ONLY to the
  API origin (never derived from one another);
* the CLI settings JSON points ANTHROPIC_BASE_URL at the API origin without
  the trailing ``/v1`` and carries the key;
* the real scan session consumes the OrcaRouter credential with no
  per-entry-point auth logic;
* a terminal 401/403 marks the exact credential generation for reauth and
  never triggers a fake refresh.
"""

from __future__ import annotations

import json

import pytest

from agent import _llm, build_settings
from agent.config import AnthropicConfig, OrcaRouterConfig, load_config
from agent.orcarouter import ConnectCredentialProvider

FAKE_KEY = "sk-orca-INTEGRATION000000000000"
API_BASE = "https://api.orcarouter.ai/v1"
AUTH_BASE = "https://www.orcarouter.ai"


@pytest.fixture
def orcarouter_config(populated_agent_config):
    import dataclasses

    return dataclasses.replace(
        populated_agent_config,
        anthropic=AnthropicConfig(
            model="deepseek/deepseek-v4-pro",
            auth_mode="orcarouter",
        ),
        orcarouter=OrcaRouterConfig(
            auth_base_url=AUTH_BASE,
            api_base_url=API_BASE,
            api_key=FAKE_KEY,
        ),
    )


# ---------------------------------------------------------------------------
# Config: first-class auth_mode
# ---------------------------------------------------------------------------


def test_auth_mode_orcarouter_is_accepted(tmp_path, tmp_config) -> None:
    path = tmp_config(
        body=(
            "[anthropic]\n"
            'auth_mode = "orcarouter"\n'
            'model = "deepseek/deepseek-v4-pro"\n'
            "[orcarouter]\n"
            'connect = "oauth"\n'
            'flow = "b"\n'
        )
    )
    config = load_config(path)
    assert config.anthropic.auth_mode == "orcarouter"
    assert config.orcarouter.connect == "oauth"
    assert config.orcarouter.flow == "b"
    # api_key stays blank for orcarouter — the credential comes from the seam,
    # not from [anthropic].api_key.
    assert config.anthropic.api_key == ""


def test_invalid_connect_and_flow_rejected(tmp_config) -> None:
    with pytest.raises(ValueError, match="connect must be"):
        load_config(tmp_config(body='[orcarouter]\nconnect = "magic"\n[anthropic]\nmodel="m"\n'))
    with pytest.raises(ValueError, match="flow must be"):
        load_config(tmp_config(body='[orcarouter]\nflow = "c"\n[anthropic]\nmodel="m"\n'))


def test_origins_default_and_overrides(tmp_config, monkeypatch) -> None:
    # Defaults.
    cfg = load_config(tmp_config(body='[anthropic]\nmodel="m"\n'))
    assert cfg.orcarouter.auth_base_url == AUTH_BASE
    assert cfg.orcarouter.api_base_url == API_BASE

    # Shared self-hosted fallback applies to both.
    monkeypatch.setenv("ORCA_BASE_URL", "https://orca.internal.example")
    cfg = load_config(tmp_config(body='[anthropic]\nmodel="m"\n'))
    assert cfg.orcarouter.auth_base_url == "https://orca.internal.example"
    assert cfg.orcarouter.api_base_url == "https://orca.internal.example"

    # Explicit per-origin override wins over the shared fallback.
    monkeypatch.setenv("ORCA_API_BASE_URL", "https://api.self.example/v1")
    cfg = load_config(tmp_config(body='[anthropic]\nmodel="m"\n'))
    assert cfg.orcarouter.api_base_url == "https://api.self.example/v1"
    assert cfg.orcarouter.auth_base_url == "https://orca.internal.example"


# ---------------------------------------------------------------------------
# Credential seam → the two adapters, same downstream
# ---------------------------------------------------------------------------


def test_both_entries_selectable_and_source_agnostic(tmp_path) -> None:
    from agent.config import OrcaRouterConfig as C
    from agent.orcarouter import ConnectCredentialProvider

    # API-key entry.
    api_provider = ConnectCredentialProvider(
        C(credentials_file=str(tmp_path / "a.json"))
    )
    api_result = api_provider.store_api_key(FAKE_KEY)

    # OAuth entry against a fake auth server.
    oauth_provider = ConnectCredentialProvider(
        C(credentials_file=str(tmp_path / "b.json"), flow="b"),
        code_provider=lambda: "code",
        post=lambda url, body, t: (200, {"key": FAKE_KEY, "user_id": "1", "scope": "api"}),
    )
    oauth_result = oauth_provider.connect_oauth()

    # Same credential shape; the request path only reads api_key.
    assert api_result.api_key == oauth_result.api_key == FAKE_KEY
    assert api_result.method.value == "api_key"
    assert oauth_result.method.value == "oauth"
    assert oauth_provider.get_valid_token() == api_provider.get_valid_token()


def test_auth_requests_only_go_to_auth_origin(tmp_path) -> None:
    from agent.config import OrcaRouterConfig as C

    urls: list[str] = []

    def post(url, body, t):
        urls.append(url)
        return (200, {"key": FAKE_KEY, "user_id": "1", "scope": "api"})

    provider = ConnectCredentialProvider(
        C(credentials_file=str(tmp_path / "c.json"), flow="b"),
        code_provider=lambda: "code",
        post=post,
    )
    provider.connect_oauth()
    assert urls == [f"{AUTH_BASE}/api/v1/auth/keys"]
    # Never the (wrong) relay path.
    assert all("/v1/auth/keys" not in u.replace("/api/v1/auth/keys", "") for u in urls)


def test_authorize_url_is_on_auth_origin() -> None:
    from agent.config import OrcaRouterConfig as C
    from agent.orcarouter import OAuthConnect

    oauth = OAuthConnect(
        auth_base_url=AUTH_BASE, app_name="X", flow="b",
        open_browser=lambda u: None,
    )
    url = oauth.authorize_url(callback_url="oob", challenge="C", state="S")
    assert url.startswith(f"{AUTH_BASE}/auth?")
    assert "api.orcarouter.ai" not in url


def test_inference_and_catalog_only_go_to_api_origin() -> None:
    import httpx

    from agent.orcarouter import discover_catalog

    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json={"data": [
            {"id": "v/m", "supported_endpoint_types": ["openai"],
             "architecture": {"input_modalities": ["text"]}},
        ]})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        discover_catalog(OrcaRouterConfig(), FAKE_KEY, capability="chat", http_client=client)

    assert seen and all(u.startswith(f"{API_BASE}/models") for u in seen)
    assert all("www.orcarouter.ai" not in u for u in seen)


# ---------------------------------------------------------------------------
# CLI settings injection
# ---------------------------------------------------------------------------


def test_cli_settings_target_api_origin_without_v1(orcarouter_config) -> None:
    settings = json.loads(
        build_settings.build_claude_settings(
            orcarouter_config, FAKE_KEY, model="deepseek/deepseek-v4-pro"
        )
    )
    env = settings["env"]
    # The CLI appends /v1 itself, so the base must NOT carry it.
    assert env["ANTHROPIC_BASE_URL"] == "https://api.orcarouter.ai"
    assert env["ANTHROPIC_API_KEY"] == FAKE_KEY
    assert "ANTHROPIC_AUTH_TOKEN" not in env  # not the Bedrock path
    assert env.get("CLAUDE_CODE_USE_BEDROCK") is None


def test_sandbox_allowlists_both_orcarouter_origins(orcarouter_config) -> None:
    settings = json.loads(
        build_settings.build_claude_settings(orcarouter_config, FAKE_KEY, model="m")
    )
    domains = settings["sandbox"]["network"]["allowedDomains"]
    assert "api.orcarouter.ai" in domains
    assert "www.orcarouter.ai" in domains


def test_selfhosted_origin_flows_into_cli_base(populated_agent_config) -> None:
    import dataclasses

    cfg = dataclasses.replace(
        populated_agent_config,
        anthropic=AnthropicConfig(model="m", auth_mode="orcarouter"),
        orcarouter=OrcaRouterConfig(
            auth_base_url="https://orca.internal.example",
            api_base_url="https://orca.internal.example/v1",
        ),
    )
    env = json.loads(
        build_settings.build_claude_settings(cfg, "k", model="m")
    )["env"]
    assert env["ANTHROPIC_BASE_URL"] == "https://orca.internal.example"


# ---------------------------------------------------------------------------
# Scan session consumes the credential (no per-entry-point logic)
# ---------------------------------------------------------------------------


async def test_call_json_uses_orcarouter_credential(
    monkeypatch, orcarouter_config
) -> None:
    """The real one-shot call path resolves and forwards the OrcaRouter key.

    ``make_token_manager`` must return the OrcaRouter provider, its
    ``get_valid_token`` must yield the configured key, and ``_send_prompt``
    must be handed that key — with no OrcaRouter-specific branch anywhere in
    ``_llm`` (it only sees the shared ``TokenProvider`` interface).
    """
    from agent.auth import make_token_manager

    token_manager = make_token_manager(orcarouter_config)
    assert isinstance(token_manager, ConnectCredentialProvider)
    assert token_manager.get_valid_token() == FAKE_KEY

    captured: dict = {}

    async def fake_send_prompt(*, model, system, user, config, auth_token, cost_tracker=None):
        captured["auth_token"] = auth_token
        captured["model"] = model
        return '{"ok": true}'

    monkeypatch.setattr(_llm, "_send_prompt", fake_send_prompt)

    out = await _llm.call_json(
        model="deepseek/deepseek-v4-pro",
        system="s",
        user="u",
        config=orcarouter_config,
        token_manager=token_manager,
        backoffs=(),
    )
    assert out == {"ok": True}
    assert captured["auth_token"] == FAKE_KEY
    assert captured["model"] == "deepseek/deepseek-v4-pro"


# ---------------------------------------------------------------------------
# Terminal 401/403 → exactly-one-generation needsReauth, no fake refresh
# ---------------------------------------------------------------------------


def test_terminal_rejection_marks_exact_generation(
    monkeypatch, orcarouter_config, tmp_path
) -> None:
    from agent import runner
    from agent.orcarouter import CredentialStore

    creds = tmp_path / "orca.json"
    store = CredentialStore(creds)
    store.store_new(api_key=FAKE_KEY, method=__import__(
        "agent.orcarouter", fromlist=["ConnectMethod"]
    ).ConnectMethod.API_KEY)

    import dataclasses

    cfg = dataclasses.replace(
        orcarouter_config,
        orcarouter=dataclasses.replace(
            orcarouter_config.orcarouter, credentials_file=str(creds)
        ),
    )
    runner._mark_credential_rejected(cfg)

    record = store.load()
    assert record.needs_reauth is True
    assert record.api_key == FAKE_KEY  # not deleted
    # A second resolve is a hard reauth requirement, never a refresh.
    from agent.orcarouter import ConnectCredentialProvider, ReauthRequired

    provider = ConnectCredentialProvider(cfg.orcarouter)
    with pytest.raises(ReauthRequired):
        provider.resolve()
    # No refresh grant exists to call — the module exposes none.
    assert not hasattr(provider, "refresh")


def test_credential_rejection_detection_is_typed() -> None:
    from agent import runner

    class _Msg:
        def __init__(self, data):
            self.data = data

    assert runner._is_credential_rejection(_Msg({"error_status": 403, "error": "model_access_denied"})) is True
    # A typed 401 is caught by the broader auth-failure predicate.
    assert runner._is_auth_failure(_Msg({"error_status": 401})) is True
    # An untyped 403 is not treated as a credential failure.
    assert runner._is_credential_rejection(_Msg({"error": "model_access_denied"})) is False
    assert runner._is_credential_rejection(_Msg({"error_status": 500})) is False


# ---------------------------------------------------------------------------
# The large-context / model-tag path must not crash on vendor/model ids
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("model", ["deepseek/deepseek-v4-pro", "orcarouter/auto", "openai/gpt-5.5"])
def test_model_tag_handles_vendor_namespaced_ids(model: str) -> None:
    from agent.runner import _model_tag

    tag = _model_tag(model)
    assert tag and "/" not in tag
