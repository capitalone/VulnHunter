"""Tests for the OrcaRouter credential seam and its two adapters.

Covers: API-key save/read/clear/mask; PKCE verifier/challenge/state; the
authorize URL; the exchange path and body; success persistence; denial;
Flow A state mismatch; code reuse/expiry (403); scope downgrade; corrupt-key
terminal classification; exact-account 401 reconnect; 429; and network
failure — plus the invariant that no verifier or key leaks into logs/errors.
"""

from __future__ import annotations

import logging

import pytest

from agent.config import OrcaRouterConfig, TLSConfig
from agent.orcarouter import (
    ApiKeyConnect,
    ConnectCredentialProvider,
    ConnectMethod,
    CredentialStore,
    CredentialUnavailable,
    OAuthConnect,
    OAuthFlowError,
    ReauthRequired,
    challenge_for,
    cli_base_url,
    mask_key,
    new_state,
    new_verifier,
    state_matches,
    validated_origin,
)

FAKE_KEY = "sk-orca-TESTKEY1234567890abcdef"
VERIFIER = "verifier-sentinel-DO-NOT-LEAK"


class FakeReceiver:
    """Stand-in for the loopback listener in Flow A tests."""

    def __init__(self, params: dict | None) -> None:
        self.port = 51234
        self._params = params
        self.started = False
        self.stopped = False

    def start(self) -> None:
        self.started = True

    def wait(self, timeout: float) -> dict | None:
        return self._params

    def stop(self) -> None:
        self.stopped = True


def make_oauth(**kwargs) -> OAuthConnect:
    params = {
        "auth_base_url": "https://www.orcarouter.ai",
        "app_name": "Test App",
        "open_browser": lambda url: None,
    }
    params.update(kwargs)
    return OAuthConnect(**params)


def store_at(tmp_path) -> CredentialStore:
    return CredentialStore(tmp_path / "orca.json")


def provider_at(tmp_path, **cfg) -> ConnectCredentialProvider:
    config = OrcaRouterConfig(credentials_file=str(tmp_path / "orca.json"), **cfg)
    return ConnectCredentialProvider(config, tls=TLSConfig(ssl_cert_path=""))


# ---------------------------------------------------------------------------
# PKCE primitives
# ---------------------------------------------------------------------------


def test_verifier_is_fresh_crypto_randomness_per_attempt() -> None:
    a, b = new_verifier(), new_verifier()
    assert a and b and a != b
    assert "=" not in a  # base64url, unpadded


def test_challenge_is_unpadded_base64url_sha256() -> None:
    import base64
    import hashlib

    verifier = new_verifier()
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )
    assert challenge_for(verifier) == expected
    assert "=" not in challenge_for(verifier)


def test_state_is_fresh_and_matches_constant_time_contract() -> None:
    s = new_state()
    assert state_matches(s, s) is True
    assert state_matches(s, "other") is False
    assert state_matches(s, None) is False
    assert state_matches("", "") is False


# ---------------------------------------------------------------------------
# Origins
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://www.orcarouter.ai",
        "https://api.orcarouter.ai/v1",
        "http://127.0.0.1:8080",
        "http://localhost:3000",
    ],
)
def test_validated_origin_accepts_https_and_loopback_http(url: str) -> None:
    assert validated_origin(url, what="x") == url.rstrip("/")


@pytest.mark.parametrize(
    "url",
    ["http://evil.example.com", "ftp://api.orcarouter.ai", "https://user:pw@x.ai", ""],
)
def test_validated_origin_rejects_bad_inputs(url: str) -> None:
    with pytest.raises(Exception):
        validated_origin(url, what="x")


def test_cli_base_url_strips_trailing_v1_only() -> None:
    assert cli_base_url("https://api.orcarouter.ai/v1") == "https://api.orcarouter.ai"
    assert cli_base_url("https://api.orcarouter.ai") == "https://api.orcarouter.ai"
    assert cli_base_url("http://127.0.0.1:9000/v1") == "http://127.0.0.1:9000"


# ---------------------------------------------------------------------------
# API-key adapter
# ---------------------------------------------------------------------------


def test_api_key_adapter_stores_reads_and_masks(tmp_path) -> None:
    store = store_at(tmp_path)
    record = ApiKeyConnect(store).store(FAKE_KEY)
    assert record.api_key == FAKE_KEY
    assert record.method == ConnectMethod.API_KEY.value
    assert store.load().api_key == FAKE_KEY
    assert mask_key(FAKE_KEY) == "sk-orca-...cdef"
    assert FAKE_KEY not in mask_key(FAKE_KEY)


def test_api_key_adapter_clear(tmp_path) -> None:
    store = store_at(tmp_path)
    ApiKeyConnect(store).store(FAKE_KEY)
    store.clear()
    assert store.load() is None


def test_api_key_adapter_rejects_empty() -> None:
    from agent.orcarouter import CredentialError

    with pytest.raises(CredentialError):
        ApiKeyConnect(CredentialStore("/tmp/never.json")).store("  ")


def test_credential_file_permissions_are_owner_only(tmp_path) -> None:
    import os
    import stat

    store = store_at(tmp_path)
    ApiKeyConnect(store).store(FAKE_KEY)
    mode = stat.S_IMODE(os.stat(store.path).st_mode)
    assert mode == 0o600


# ---------------------------------------------------------------------------
# Both adapters yield the same credential shape; downstream is source-agnostic
# ---------------------------------------------------------------------------


def test_both_adapters_return_same_credential_result(tmp_path) -> None:
    config = OrcaRouterConfig(credentials_file=str(tmp_path / "orca.json"))
    provider = ConnectCredentialProvider(config)

    # API-key adapter.
    key_result = provider.store_api_key(FAKE_KEY)
    # OAuth adapter (Flow B so the adapter supplies its own state), returning
    # the SAME kind of key from a fake exchange.
    oauth_provider = ConnectCredentialProvider(
        OrcaRouterConfig(credentials_file=str(tmp_path / "oauth.json"), flow="b"),
        post=lambda url, body, t: (200, {"key": FAKE_KEY, "user_id": "7", "scope": "api"}),
        code_provider=lambda: "the-code",
    )
    oauth_result = oauth_provider.connect_oauth()

    # Both adapters produce the identical credential value...
    assert key_result.api_key == oauth_result.api_key == FAKE_KEY
    # ...from different user-facing entries...
    assert key_result.method != oauth_result.method
    # ...and the downstream token interface cannot tell them apart.
    assert oauth_provider.get_valid_token() == provider.get_valid_token()
    assert isinstance(provider.get_valid_token(), str)


def test_connect_seam_defines_and_uses_two_adapters(tmp_path) -> None:
    provider = provider_at(tmp_path)
    assert isinstance(provider._api_adapter, ApiKeyConnect)
    assert isinstance(provider._oauth_adapter, OAuthConnect)


# ---------------------------------------------------------------------------
# Flow A
# ---------------------------------------------------------------------------


def test_flow_a_happy_path_persists_and_uses_auth_origin(tmp_path) -> None:
    calls: list[tuple[str, dict, float]] = []

    def fake_post(url, body, timeout):
        calls.append((url, body, timeout))
        return (200, {"key": FAKE_KEY, "user_id": "42", "scope": "api"})

    receiver = FakeReceiver({"code": "the-code", "state": "REPLACED"})
    oauth = make_oauth(flow="a", post=fake_post, receiver_factory=lambda: receiver)

    # Flow A needs the state the adapter generated, so capture it from the
    # authorize URL and echo it back through the receiver.
    captured: dict = {}
    orig_url = oauth.authorize_url

    def capture_url(*, callback_url, challenge, state):
        captured["state"] = state
        captured["challenge"] = challenge
        captured["callback_url"] = callback_url
        return orig_url(callback_url=callback_url, challenge=challenge, state=state)

    oauth.authorize_url = capture_url  # type: ignore[assignment]
    receiver._params = {"code": "the-code", "state": ""}
    # Patch wait() to echo the real state.
    def wait(timeout):
        return {"code": "the-code", "state": captured["state"]}

    receiver.wait = wait  # type: ignore[assignment]

    result = oauth.connect()
    assert result["key"] == FAKE_KEY
    assert receiver.started and receiver.stopped
    # Exchange hits the AUTH origin at the fixed /api/v1/auth/keys path.
    url, body, _ = calls[0]
    assert url == "https://www.orcarouter.ai/api/v1/auth/keys"
    assert "/v1/auth/keys" in url  # the correct, documented path
    assert body["code"] == "the-code"
    assert body["code_challenge_method"] == "S256"
    assert "code_verifier" in body
    # The callback_url is loopback with the ephemeral port.
    assert captured["callback_url"] == "http://127.0.0.1:51234/cb"
    # Only the S256 challenge — never the verifier — is on the authorize URL.
    assert captured["challenge"] == challenge_for(body["code_verifier"])
    assert body["code_verifier"] != captured["challenge"]


def test_authorize_url_uses_auth_origin_and_s256() -> None:
    oauth = make_oauth()
    url = oauth.authorize_url(callback_url="oob", challenge="CH", state="ST")
    assert url.startswith("https://www.orcarouter.ai/auth?")
    assert "code_challenge_method=S256" in url
    assert "callback_url=oob" in url
    assert "scope=api" in url
    assert "code_verifier" not in url


def test_flow_a_state_mismatch_is_refused(tmp_path) -> None:
    called = {"n": 0}

    def fake_post(url, body, timeout):
        called["n"] += 1
        return (200, {"key": FAKE_KEY})

    receiver = FakeReceiver({"code": "c", "state": "attacker-state"})
    oauth = make_oauth(flow="a", post=fake_post, receiver_factory=lambda: receiver)
    with pytest.raises(OAuthFlowError, match="state did not match"):
        oauth.connect()
    assert called["n"] == 0  # code never redeemed


def test_flow_a_declined_is_reported_and_stops(tmp_path) -> None:
    oauth = make_oauth(
        flow="a",
        post=lambda *a: pytest.fail("must not exchange on denial"),
        receiver_factory=lambda: FakeReceiver({"error": "access_denied", "state": ""}),
    )
    # Echo the correct state so we reach the error branch.
    captured: dict = {}
    orig = oauth.authorize_url

    def capture_url(*, callback_url, challenge, state):
        captured["state"] = state
        return orig(callback_url=callback_url, challenge=challenge, state=state)

    oauth.authorize_url = capture_url  # type: ignore[assignment]
    receiver = FakeReceiver(None)
    receiver.wait = lambda t: {"error": "access_denied", "state": captured["state"]}  # type: ignore[assignment]
    oauth._receiver_factory = lambda: receiver
    with pytest.raises(OAuthFlowError, match="denied"):
        oauth.connect()


def test_flow_a_timeout_does_not_hang(tmp_path) -> None:
    oauth = make_oauth(
        flow="a",
        post=lambda *a: pytest.fail("must not exchange on timeout"),
        receiver_factory=lambda: FakeReceiver(None),  # wait() returns None
    )
    with pytest.raises(OAuthFlowError, match="timed out"):
        oauth.connect()


# ---------------------------------------------------------------------------
# Flow B
# ---------------------------------------------------------------------------


def test_flow_b_uses_oob_callback_and_s256() -> None:
    oauth = make_oauth(flow="b", code_provider=lambda: "the-code")
    seen: dict = {}
    orig = oauth.authorize_url

    def capture(*, callback_url, challenge, state):
        seen["callback_url"] = callback_url
        return orig(callback_url=callback_url, challenge=challenge, state=state)

    oauth.authorize_url = capture  # type: ignore[assignment]
    oauth._post = lambda url, body, t: (
        (200, {"key": FAKE_KEY, "user_id": "1", "scope": "api"})
    )
    result = oauth.connect()
    assert result["key"] == FAKE_KEY
    assert seen["callback_url"] == "oob"


def test_flow_b_empty_code_is_cancelled() -> None:
    oauth = make_oauth(flow="b", code_provider=lambda: "   ")
    with pytest.raises(OAuthFlowError, match="cancelled"):
        oauth.connect()


# ---------------------------------------------------------------------------
# Exchange error taxonomy
# ---------------------------------------------------------------------------


def test_exchange_403_is_terminal_unusable_code() -> None:
    oauth = make_oauth(flow="b", code_provider=lambda: "used", post=lambda *a: (403, {}))
    with pytest.raises(OAuthFlowError, match="rejected the authorization code"):
        oauth.connect()


def test_exchange_400_is_a_downgrade_refusal() -> None:
    oauth = make_oauth(flow="b", code_provider=lambda: "c", post=lambda *a: (400, {}))
    with pytest.raises(OAuthFlowError, match="code_challenge_method"):
        oauth.connect()


def test_exchange_429_is_actionable() -> None:
    oauth = make_oauth(flow="b", code_provider=lambda: "c", post=lambda *a: (429, {}))
    with pytest.raises(OAuthFlowError, match="rate-limited"):
        oauth.connect()


def test_exchange_network_failure_is_wrapped_without_leaking() -> None:
    def boom(url, body, timeout):
        raise ConnectionError(f"connect failed for {url}?code=SECRETCODE")

    oauth = make_oauth(flow="b", code_provider=lambda: "SECRETCODE", post=boom)
    with pytest.raises(OAuthFlowError) as excinfo:
        oauth.connect()
    assert "SECRETCODE" not in str(excinfo.value)


def test_scope_downgrade_is_reported() -> None:
    oauth = make_oauth(
        flow="b",
        code_provider=lambda: "c",
        scope="connector",
        post=lambda *a: (200, {"key": FAKE_KEY, "scope": "api"}),
    )
    # asked for connector, granted api → narrower than requested → refuse loudly.
    with pytest.raises(OAuthFlowError, match="granted scope"):
        oauth.connect()


def test_exchange_uses_read_back_scope_not_requested_scope() -> None:
    oauth = make_oauth(
        flow="b",
        code_provider=lambda: "c",
        post=lambda *a: (200, {"key": FAKE_KEY, "user_id": "9", "scope": "api"}),
    )
    assert oauth.connect()["scope"] == "api"


# ---------------------------------------------------------------------------
# Secrets must not leak
# ---------------------------------------------------------------------------


def test_verifier_never_appears_in_logs_or_errors(caplog) -> None:
    import logging as _logging

    captured: dict = {}
    oauth = make_oauth(flow="b", code_provider=lambda: "c")

    orig_url = oauth.authorize_url

    def capture(*, callback_url, challenge, state):
        captured["challenge"] = challenge
        return orig_url(callback_url=callback_url, challenge=challenge, state=state)

    oauth.authorize_url = capture  # type: ignore[assignment]

    def fake_post(url, body, timeout):
        captured["verifier"] = body["code_verifier"]
        return (200, {"key": FAKE_KEY, "user_id": "1", "scope": "api"})

    oauth._post = fake_post
    with caplog.at_level(_logging.DEBUG):
        oauth.connect()

    verifier = captured["verifier"]
    log_text = "\n".join(r.getMessage() for r in caplog.records)
    assert verifier not in log_text
    assert verifier not in captured["challenge"]
    assert FAKE_KEY not in log_text


def test_key_never_appears_in_status_or_errors(tmp_path) -> None:
    provider = provider_at(tmp_path)
    provider.store_api_key(FAKE_KEY)

    seen: list[str] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            seen.append(record.getMessage())

    logger = logging.getLogger("agent.orcarouter.connect")
    handler = _Capture()
    logger.addHandler(handler)
    try:
        provider.resolve()
    finally:
        logger.removeHandler(handler)
    assert all(FAKE_KEY not in m for m in seen)


# ---------------------------------------------------------------------------
# Resolution, terminal classification, generation-safe 401
# ---------------------------------------------------------------------------


def test_resolve_prefers_store_over_config(tmp_path) -> None:
    provider = provider_at(tmp_path, api_key="sk-orca-fromconfig")
    provider.store_api_key(FAKE_KEY)
    assert provider.get_valid_token() == FAKE_KEY


def test_resolve_falls_back_to_config_key(tmp_path) -> None:
    provider = provider_at(tmp_path, api_key="sk-orca-fromconfig")
    assert provider.get_valid_token() == "sk-orca-fromconfig"


def test_resolve_without_any_credential_is_unavailable(tmp_path) -> None:
    with pytest.raises(CredentialUnavailable):
        provider_at(tmp_path).resolve()


def test_corrupt_oauth_key_is_terminal(tmp_path) -> None:
    store = store_at(tmp_path)
    from agent.orcarouter import CredentialRecord

    store.save(CredentialRecord(api_key="garbage-not-a-key", method="oauth"))
    provider = ConnectCredentialProvider(
        OrcaRouterConfig(credentials_file=str(tmp_path / "orca.json"))
    )
    with pytest.raises(ReauthRequired):
        provider.resolve()


def test_needs_reauth_credential_is_not_silently_refreshed(tmp_path) -> None:
    provider = provider_at(tmp_path)
    provider.store_api_key(FAKE_KEY)
    assert provider.note_rejection(api_key=FAKE_KEY, generation=1) is True
    with pytest.raises(ReauthRequired, match="rejected"):
        provider.resolve()
    # Old secret is retained (never silently deleted before a new login).
    assert provider.store.load().api_key == FAKE_KEY


def test_401_marks_only_the_exact_generation(tmp_path) -> None:
    provider = provider_at(tmp_path)
    provider.store_api_key(FAKE_KEY)          # generation 1
    # Re-login advances the generation; a late 401 from gen 1 must not poison it.
    provider.store_api_key("sk-orca-SECONDKEY0000000000abcd")  # generation 2
    assert provider.note_rejection(api_key=FAKE_KEY, generation=1) is False
    result = provider.resolve()
    assert result.api_key == "sk-orca-SECONDKEY0000000000abcd"
    assert result.needs_reauth is False


def test_regeneration_clears_needs_reauth(tmp_path) -> None:
    provider = provider_at(tmp_path)
    provider.store_api_key(FAKE_KEY)
    provider.note_rejection(api_key=FAKE_KEY, generation=1)
    fresh = provider.store_api_key("sk-orca-NEWKEY00000000000000abcd")
    assert fresh.needs_reauth is False
    assert provider.resolve().api_key == "sk-orca-NEWKEY00000000000000abcd"


def test_clear_removes_credential(tmp_path) -> None:
    provider = provider_at(tmp_path)
    provider.store_api_key(FAKE_KEY)
    provider.clear()
    with pytest.raises(CredentialUnavailable):
        provider.resolve()


def test_corrupt_store_file_is_tolerated(tmp_path) -> None:
    path = tmp_path / "orca.json"
    path.write_text("{not json")
    store = CredentialStore(path)
    assert store.load() is None


def test_generation_increments_on_each_login(tmp_path) -> None:
    provider = provider_at(tmp_path)
    assert provider.store_api_key(FAKE_KEY).generation == 1
    assert provider.store_api_key("sk-orca-OTHER000000000000000000").generation == 2
