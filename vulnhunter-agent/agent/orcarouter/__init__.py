"""First-class OrcaRouter provider for the VulnHunter agent.

OrcaRouter is an OpenAI-compatible AI gateway that routes many providers
behind one endpoint. This package adds it as a named provider with two
explicit authentication choices that both yield one ordinary OrcaRouter API
key (``sk-orca-…``):

* paste an existing API key — :class:`ApiKeyConnect`
* OAuth 2.0 + PKCE browser login — :class:`OAuthConnect`

Both are adapters over :class:`ConnectCredentialProvider`, which implements
the project's existing ``TokenProvider`` protocol. Live model discovery and
capability filtering live in :mod:`agent.orcarouter.models`.
"""

from __future__ import annotations

from .connect import (
    ApiKeyConnect,
    ConnectCredentialProvider,
    OAuthConnect,
    OAuthFlowError,
    _LoopbackReceiver,
)
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
from .models import (
    ModelCapability,
    ModelCatalog,
    ModelInfo,
    CatalogError,
    discover_catalog,
    fetch_catalog,
    parse_catalog,
    verified_seed,
)
from ._origins import OriginError, cli_base_url, join_path, validated_origin
from ._pkce import challenge_for, new_state, new_verifier, state_matches

__all__ = [
    "ApiKeyConnect",
    "CatalogError",
    "ConnectCredentialProvider",
    "ConnectMethod",
    "CredentialError",
    "CredentialRecord",
    "CredentialResult",
    "CredentialStore",
    "CredentialUnavailable",
    "ModelCapability",
    "ModelCatalog",
    "ModelInfo",
    "OAuthConnect",
    "OAuthFlowError",
    "OriginError",
    "ReauthRequired",
    "challenge_for",
    "cli_base_url",
    "discover_catalog",
    "fetch_catalog",
    "join_path",
    "mask_key",
    "new_state",
    "new_verifier",
    "parse_catalog",
    "state_matches",
    "validated_origin",
    "verified_seed",
]
