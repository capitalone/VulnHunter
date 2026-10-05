"""OrcaRouter credential model and durable store.

Both connect entry points — a pasted API key and an OAuth 2.0 + PKCE
login — converge on the SAME downstream artifact: a normal OrcaRouter API
key. They are modelled as two adapters over one interface
(:class:`ConnectCredentialProvider`) returning the same
:class:`CredentialResult`, so the provider request path and the model
catalog never need to know which path produced the key.

The store reuses the project's existing hardened-writer idiom (see
``agent/audit.py``): a 0o700 directory and a 0o600 JSON file written
atomically. It is not a new secret manager — just the same file
convention used elsewhere under ``~/.vulnhunter/``.
"""

from __future__ import annotations

import enum
import json
import os
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

# A PKCE-issued key is a durable API key, NOT a refresh token: there is no
# refresh endpoint to call later. Treat an upstream 401 from the relay as a
# terminal reauthentication requirement for the exact account/generation
# that made the rejected request.
DEFAULT_CREDENTIALS_PATH = "~/.vulnhunter/orcarouter.json"


class ConnectMethod(str, enum.Enum):
    """Which user-facing entry produced the credential."""

    API_KEY = "api_key"
    OAUTH = "oauth"


class CredentialError(RuntimeError):
    """Base class for OrcaRouter credential problems."""


class CredentialUnavailable(CredentialError):
    """No usable credential is configured (nothing to send yet)."""


class ReauthRequired(CredentialError):
    """The stored credential was rejected and must be re-established."""


@dataclass(frozen=True)
class CredentialResult:
    """The one credential shape every adapter returns.

    ``source`` records how it was obtained (for status display only); the
    request path and catalog read ``api_key`` and nothing else.
    """

    api_key: str
    method: ConnectMethod
    scope: str = "api"
    user_id: str = ""
    source: str = "store"
    generation: int = 0
    needs_reauth: bool = False


def mask_key(key: str) -> str:
    """Mask an API key for display/logs — never returns the full secret."""
    if not key:
        return ""
    if len(key) <= 8:
        return "***"
    return f"{key[:8]}...{key[-4:]}"


@dataclass
class CredentialRecord:
    """Persisted credential state for the OrcaRouter provider."""

    api_key: str
    method: str = ConnectMethod.API_KEY.value
    scope: str = "api"
    user_id: str = ""
    # Incremented every time a NEW credential is stored. A 401 from the relay
    # only invalidates the exact generation that made the request, so a late
    # failure from an old request can never mark a freshly reauthorized
    # credential broken.
    generation: int = 1
    # Set when the relay rejected this credential. The old secret is kept
    # (never silently deleted) until a new login succeeds.
    needs_reauth: bool = False
    created_at: float = field(default_factory=time.time)

    def masked_key(self) -> str:
        return mask_key(self.api_key)


def resolve_credentials_path(override: str = "") -> Path:
    """Resolve the credential-store path (explicit override, then default)."""
    raw = (override or "").strip() or DEFAULT_CREDENTIALS_PATH
    return Path(raw).expanduser()


class CredentialStore:
    """Read/write the OrcaRouter credential record with hardened permissions."""

    def __init__(self, path: str | os.PathLike[str] = DEFAULT_CREDENTIALS_PATH):
        self.path = Path(path).expanduser()

    def load(self) -> CredentialRecord | None:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except OSError:
            return None
        if not raw.strip():
            # A truncated/empty file is treated as "no usable credential"
            # rather than raising — re-login repairs it.
            return None
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if not isinstance(data, dict) or not str(data.get("api_key", "")).strip():
            return None
        known = {f for f in CredentialRecord.__dataclass_fields__}
        return CredentialRecord(**{k: v for k, v in data.items() if k in known})

    def save(self, record: CredentialRecord) -> None:
        directory = self.path.parent
        directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass  # best-effort; not all filesystems allow it
        payload = json.dumps(asdict(record), sort_keys=True)
        fd, tmp = tempfile.mkstemp(dir=str(directory), prefix=".tmp-", suffix=".json")
        try:
            # 0o600 like audit.py — os.open with an explicit mode, not the
            # umask-dependent default.
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def clear(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass

    def store_new(
        self,
        *,
        api_key: str,
        method: ConnectMethod,
        scope: str = "api",
        user_id: str = "",
    ) -> CredentialRecord:
        """Persist a (re)established credential, advancing the generation."""
        previous = self.load()
        generation = (previous.generation + 1) if previous else 1
        record = CredentialRecord(
            api_key=api_key,
            method=method.value,
            scope=scope,
            user_id=user_id,
            generation=generation,
            needs_reauth=False,
        )
        self.save(record)
        return record

    def mark_rejected(self, *, api_key: str, generation: int) -> bool:
        """Flag the EXACT rejected credential generation as needing reauth.

        Returns True only when the stored record still matches both the key
        and the generation that made the rejected request. A late failure
        carrying an older generation (or a different key) is ignored, so it
        cannot poison a credential that was reauthorized in the meantime.
        """
        record = self.load()
        if record is None:
            return False
        if record.generation != generation or record.api_key != api_key:
            return False
        if record.needs_reauth:
            return True
        record.needs_reauth = True
        self.save(record)
        return True
