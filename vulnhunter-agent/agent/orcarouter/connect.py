"""OrcaRouter credential acquisition — the connect seam and its two adapters.

One interface, two adapters, one result:

* :class:`ApiKeyConnect` — the user pastes (or configures) an existing
  ``sk-orca-…`` key.
* :class:`OAuthConnect` — OAuth 2.0 + PKCE (Flow A loopback redirect or
  Flow B out-of-band code) yields a durable API key.

:class:`ConnectCredentialProvider` owns the small interface and adapts the
result to the project's existing ``TokenProvider`` protocol
(``get_valid_token``), so the SDK call sites and the model catalog never
see which entry produced the key.

Security notes baked in here:

* Flow A compares the echoed ``state`` with a constant-time comparison
  before the code is redeemed.
* Verifier and state are generated fresh per attempt from a CSPRNG and the
  verifier never leaves the process until the exchange — it is not placed
  in the authorize URL, logs, or errors.
* Exchange errors are mapped to actionable messages; the response body's
  credential material is never surfaced.
"""

from __future__ import annotations

import http.server
import logging
import queue
import threading
import time
import webbrowser
from typing import Callable

import httpx

from .._url import redact
from ..config import OrcaRouterConfig, TLSConfig
from ._origins import (
    AUTHORIZE_PATH,
    EXCHANGE_PATH,
    OriginError,
    validated_origin,
)
from ._pkce import challenge_for, new_state, new_verifier, state_matches
from .credentials import (
    ConnectMethod,
    CredentialError,
    CredentialRecord,
    CredentialResult,
    CredentialStore,
    CredentialUnavailable,
    ReauthRequired,
    mask_key,
)

logger = logging.getLogger(__name__)

# Path the loopback listener serves (Flow A). Fixed by our own authorize call.
CALLBACK_PATH = "/cb"

# Scope that satisfies inference against the relay.
_INFERENCE_SCOPE = "api"


class OAuthFlowError(CredentialError):
    """A user-actionable failure in the OAuth 2.0 + PKCE connect flow."""


# Injectable seams (tests substitute fakes; production uses the defaults).
PostFn = Callable[[str, dict, float], "tuple[int, dict]"]
OpenBrowserFn = Callable[[str], None]


def _default_post(url: str, body: dict, timeout: float, *, verify) -> tuple[int, dict]:
    with httpx.Client(verify=verify) as client:
        response = client.post(
            url,
            json=body,
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
    try:
        payload = response.json()
    except ValueError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    return response.status_code, payload


class _LoopbackReceiver:
    """Single-use loopback HTTP listener for the Flow A redirect.

    Binds an ephemeral port on 127.0.0.1 BEFORE the browser is opened so the
    callback URL is known and nothing races. Serves `/cb`, hands the query
    parameters back to the caller, answers the browser with a short
    close-this-tab page, and shuts the socket down.
    """

    def __init__(self) -> None:
        self._results: "queue.Queue[dict]" = queue.Queue(maxsize=1)
        receiver = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args) -> None:  # noqa: D401 - silence access log
                return

            def do_GET(self) -> None:  # noqa: N802 - http.server API
                from urllib.parse import parse_qs, urlparse

                parsed = urlparse(self.path)
                if parsed.path != CALLBACK_PATH:
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(
                    b"<html><body><p>OrcaRouter connected. "
                    b"You can close this tab.</p></body></html>"
                )
                params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                try:
                    receiver._results.put_nowait(params)
                except queue.Full:
                    pass

        self._server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        self.port = int(self._server.server_address[1])
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )

    def start(self) -> None:
        self._thread.start()

    def wait(self, timeout: float) -> dict | None:
        try:
            return self._results.get(timeout=timeout)
        except queue.Empty:
            return None

    def stop(self) -> None:
        try:
            self._server.shutdown()
        except Exception:  # noqa: BLE001 - best-effort socket cleanup
            pass
        try:
            self._server.server_close()
        except Exception:  # noqa: BLE001
            pass


class OAuthConnect:
    """OAuth 2.0 + PKCE adapter producing a durable OrcaRouter API key."""

    def __init__(
        self,
        *,
        auth_base_url: str,
        app_name: str,
        scope: str = _INFERENCE_SCOPE,
        flow: str = "a",
        client_id: str = "",
        login_timeout_seconds: int = 300,
        http_timeout_seconds: int = 30,
        tls_verify: str | bool = True,
        post: PostFn | None = None,
        open_browser: OpenBrowserFn | None = None,
        receiver_factory: Callable[[], _LoopbackReceiver] | None = None,
        code_provider: Callable[[], str] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        try:
            self._auth_base = validated_origin(auth_base_url, what="orcarouter auth base")
        except OriginError as exc:
            raise OAuthFlowError(str(exc)) from exc
        self._app_name = app_name or "VulnHunter Agent"
        self._scope = scope or _INFERENCE_SCOPE
        self._flow = (flow or "a").lower()
        self._client_id = client_id
        self._timeout = login_timeout_seconds
        self._http_timeout = http_timeout_seconds
        self._verify = tls_verify
        self._post = post or (
            lambda url, body, t: _default_post(url, body, t, verify=self._verify)
        )
        self._open_browser = open_browser or webbrowser.open
        self._receiver_factory = receiver_factory or _LoopbackReceiver
        self._code_provider = code_provider
        self._clock = clock

    # -- pure helpers -----------------------------------------------------

    def authorize_url(self, *, callback_url: str, challenge: str, state: str) -> str:
        """Build the consent-screen URL (auth origin, fixed /auth path)."""
        from urllib.parse import urlencode

        params = {
            "callback_url": callback_url,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
            "app_name": self._app_name,
            "scope": self._scope,
        }
        if self._client_id:
            params["client_id"] = self._client_id
        return f"{self._auth_base}{AUTHORIZE_PATH}?" + urlencode(params)

    def exchange_url(self) -> str:
        """The code-for-key exchange URL (auth origin — never the API origin)."""
        return f"{self._auth_base}{EXCHANGE_PATH}"

    # -- exchange ---------------------------------------------------------

    def _exchange(self, code: str, verifier: str) -> dict:
        try:
            status, payload = self._post(
                self.exchange_url(),
                {
                    "code": code,
                    "code_verifier": verifier,
                    "code_challenge_method": "S256",
                },
                self._http_timeout,
            )
        except Exception as exc:  # noqa: BLE001 - transport failure at the boundary
            # Never include the request/response material — it carries the code
            # and verifier.
            raise OAuthFlowError(
                f"OrcaRouter key exchange failed: {type(exc).__name__}"
            ) from exc
        if status == 200 and str(payload.get("key", "")).strip():
            granted = str(payload.get("scope", "") or "")
            # The response says what was GRANTED, not what we asked for. A
            # narrower grant (e.g. asked connector, got api) means the account
            # lacked the wider role — say so rather than assume we hold it.
            if granted and granted != self._scope:
                raise OAuthFlowError(
                    f"OrcaRouter granted scope {granted!r}, not the requested "
                    f"{self._scope!r}; the account may not hold that grant"
                )
            return {
                "key": str(payload["key"]),
                "user_id": str(payload.get("user_id", "") or ""),
                "scope": granted or _INFERENCE_SCOPE,
            }
        # Never surface the response body — it can echo request material.
        if status == 403:
            raise OAuthFlowError(
                "OrcaRouter rejected the authorization code (unknown, expired, "
                "already used, or the verifier did not match). Start the login again."
            )
        if status == 400:
            raise OAuthFlowError(
                "OrcaRouter rejected the code_challenge_method (S256) — the "
                "authorization was downgraded. Start the login again."
            )
        if status == 429:
            raise OAuthFlowError(
                "OrcaRouter rate-limited the key issuance (10 PKCE keys per user "
                "per 24 hours). Reuse the stored credential or try again later."
            )
        raise OAuthFlowError(f"OrcaRouter key exchange failed with HTTP {status}")

    # -- flow A / B -------------------------------------------------------

    def connect(self) -> dict:
        """Run the flow and return ``{key, user_id, scope}``.

        Raises :class:`OAuthFlowError` on denial, state mismatch, timeout, or
        any exchange/network failure. Never hangs and never hot-loops.
        """
        verifier = new_verifier()
        challenge = challenge_for(verifier)
        state = new_state()

        if self._flow == "a":
            code = self._run_loopback(challenge, state)
        else:
            code = self._run_out_of_band(challenge, state)

        return self._exchange(code, verifier)

    def _run_loopback(self, challenge: str, state: str) -> str:
        receiver = self._receiver_factory()
        receiver.start()
        try:
            callback_url = f"http://127.0.0.1:{receiver.port}{CALLBACK_PATH}"
            url = self.authorize_url(
                callback_url=callback_url, challenge=challenge, state=state
            )
            self._announce(url)
            params = receiver.wait(self._timeout)
            if params is None:
                raise OAuthFlowError(
                    "OrcaRouter authorization timed out before a callback arrived."
                )
        finally:
            receiver.stop()

        # Compare state before doing anything else.
        if not state_matches(state, params.get("state")):
            raise OAuthFlowError(
                "OrcaRouter callback state did not match; refusing the code."
            )
        error = params.get("error")
        if error:
            raise OAuthFlowError(_describe_callback_error(error))
        code = params.get("code")
        if not code:
            raise OAuthFlowError("OrcaRouter callback carried no authorization code.")
        return code

    def _run_out_of_band(self, challenge: str, state: str) -> str:
        url = self.authorize_url(callback_url="oob", challenge=challenge, state=state)
        self._announce(url)
        provider = self._code_provider
        if provider is None:
            provider = lambda: input("Paste the code shown by OrcaRouter: ").strip()  # noqa: E731
        try:
            code = (provider() or "").strip()
        except EOFError as exc:
            raise OAuthFlowError(
                "No code supplied; the out-of-band login was cancelled."
            ) from exc
        if not code:
            raise OAuthFlowError("No code supplied; the OrcaRouter login was cancelled.")
        return code

    def _announce(self, url: str) -> None:
        # The URL contains only the challenge and state — never the verifier.
        logger.info("Authorize OrcaRouter in your browser: %s", redact(url))
        print(
            "OrcaRouter: open this URL to authorize if your browser does not "
            f"open automatically:\n{url}"
        )
        try:
            self._open_browser(url)
        except Exception:  # noqa: BLE001 - headless hosts have no browser
            logger.info("Could not open a browser automatically; use the URL above.")


def _describe_callback_error(error: str) -> str:
    if error == "access_denied":
        return "OrcaRouter authorization was denied."
    return f"OrcaRouter authorization failed: {error}"


class ApiKeyConnect:
    """API-key adapter — store a user-supplied ``sk-orca-…`` key."""

    def __init__(self, store: CredentialStore) -> None:
        self._store = store

    def store(self, api_key: str) -> CredentialRecord:
        key = (api_key or "").strip()
        if not key:
            raise CredentialError("An OrcaRouter API key is required.")
        # Lightweight format check only — an sk-orca- prefix is not proof the
        # key is valid; the first real request establishes that.
        if not key.startswith("sk-orca-"):
            logger.warning(
                "OrcaRouter API key does not start with 'sk-orca-' (%s)",
                mask_key(key),
            )
        return self._store.store_new(api_key=key, method=ConnectMethod.API_KEY)


class ConnectCredentialProvider:
    """The credential interface; both adapters live behind it.

    Implements the project's ``TokenProvider`` protocol so existing call
    sites (``auth_token = token_manager.get_valid_token()``) work unchanged.
    """

    def __init__(
        self,
        config: OrcaRouterConfig,
        *,
        store: CredentialStore | None = None,
        tls: TLSConfig | None = None,
        post: PostFn | None = None,
        open_browser: OpenBrowserFn | None = None,
        receiver_factory: Callable[[], _LoopbackReceiver] | None = None,
        code_provider: Callable[[], str] | None = None,
    ) -> None:
        self._config = config
        self._store = store or CredentialStore(
            config.credentials_file or "~/.vulnhunter/orcarouter.json"
        )
        verify: str | bool = tls.ssl_cert_path if tls and tls.ssl_cert_path else True
        self._api_adapter = ApiKeyConnect(self._store)
        self._oauth_adapter = OAuthConnect(
            auth_base_url=config.auth_base_url,
            app_name=config.app_name,
            scope=config.scope,
            flow=config.flow,
            client_id=config.client_id,
            login_timeout_seconds=config.login_timeout_seconds,
            http_timeout_seconds=config.http_timeout_seconds,
            tls_verify=verify,
            post=post,
            open_browser=open_browser,
            receiver_factory=receiver_factory,
            code_provider=code_provider,
        )

    # -- TokenProvider ----------------------------------------------------

    def get_valid_token(self) -> str:
        return self.resolve().api_key

    # -- resolution -------------------------------------------------------

    def resolve(self) -> CredentialResult:
        """Return the usable credential, or raise.

        Precedence: the stored credential is authoritative — it is what makes
        a durable PKCE key reusable across restarts without re-authorizing,
        and a rejected one stays a terminal reauthentication requirement
        (never a silent switch to another credential). A key supplied via
        config/env is used only when nothing is stored.
        """
        record = self._store.load()
        if record is not None:
            if record.needs_reauth:
                # A revoked durable key is a terminal reauthentication
                # requirement — no fake refresh is attempted.
                raise ReauthRequired(
                    "The stored OrcaRouter credential was rejected; reconnect "
                    "with the API key or sign in again."
                )
            self._classify(record)
            return self._as_result(record, source="store")
        env_key = (self._config.api_key or "").strip()
        if env_key:
            return CredentialResult(
                api_key=env_key,
                method=ConnectMethod.API_KEY,
                source="config",
            )
        raise CredentialUnavailable(
            "No OrcaRouter credential is configured. Paste an sk-orca- API key "
            "or run the OrcaRouter OAuth login."
        )

    @staticmethod
    def _classify(record: CredentialRecord) -> None:
        """Reject a corrupt/truncated OAuth credential as a terminal state."""
        if record.method == ConnectMethod.OAUTH.value and not record.api_key.startswith(
            "sk-orca-"
        ):
            raise ReauthRequired(
                "The stored OrcaRouter login credential is corrupt or truncated; "
                "sign in again."
            )

    @staticmethod
    def _as_result(record: CredentialRecord, *, source: str) -> CredentialResult:
        return CredentialResult(
            api_key=record.api_key,
            method=ConnectMethod(record.method),
            scope=record.scope,
            user_id=record.user_id,
            source=source,
            generation=record.generation,
            needs_reauth=record.needs_reauth,
        )

    # -- the two adapters, explicitly exposed -----------------------------

    def store_api_key(self, api_key: str) -> CredentialResult:
        """API-key adapter entry point."""
        record = self._api_adapter.store(api_key)
        return self._as_result(record, source="api_key")

    def connect_oauth(self) -> CredentialResult:
        """OAuth 2.0 + PKCE adapter entry point."""
        result = self._oauth_adapter.connect()
        record = self._store.store_new(
            api_key=result["key"],
            method=ConnectMethod.OAUTH,
            scope=result.get("scope", "api"),
            user_id=result.get("user_id", ""),
        )
        return self._as_result(record, source="oauth")

    def clear(self) -> None:
        """Remove the stored credential (both entries must support clearing)."""
        self._store.clear()

    def note_rejection(self, *, api_key: str, generation: int) -> bool:
        """Mark the exact rejected credential generation as needing reauth."""
        return self._store.mark_rejected(api_key=api_key, generation=generation)

    @property
    def store(self) -> CredentialStore:
        return self._store
