"""PKCE helpers for the OrcaRouter OAuth 2.0 connect flow.

Everything here is stdlib-only: ``secrets`` for the verifier/state, and
``hashlib`` + ``base64`` for the S256 challenge. No third-party crypto
dependency is introduced.

Invariants enforced by this module:

* the verifier is fresh cryptographic randomness on every attempt;
* the challenge is ``base64url(sha256(verifier))`` with no padding;
* the verifier is never placed in a URL, log, or error message — only the
  challenge is sent to the authorization endpoint.
"""

from __future__ import annotations

import base64
import hashlib
import secrets

# 32 bytes → 43 base64url chars, the RFC 7636 recommended verifier size.
_VERIFIER_BYTES = 32
# 16 bytes → 22 base64url chars of CSRF entropy.
_STATE_BYTES = 16


def b64url(raw: bytes) -> str:
    """base64url without padding (RFC 7636 §4.2 encoding)."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def new_verifier() -> str:
    """A fresh high-entropy PKCE code verifier."""
    return b64url(secrets.token_bytes(_VERIFIER_BYTES))


def challenge_for(verifier: str) -> str:
    """``base64url(sha256(verifier))`` — the S256 code challenge."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return b64url(digest)


def new_state() -> str:
    """A fresh opaque CSRF state value."""
    return b64url(secrets.token_bytes(_STATE_BYTES))


def state_matches(expected: str, received: str | None) -> bool:
    """Constant-time comparison of the echoed CSRF state.

    Returns False for a missing or non-string value rather than raising, so
    callers can branch to a clean error path.
    """
    if not expected or not isinstance(received, str):
        return False
    return secrets.compare_digest(expected, received)
