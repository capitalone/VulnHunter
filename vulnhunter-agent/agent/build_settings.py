"""Build the Claude Code settings JSON the SDK passes through to the CLI.

Routes Anthropic calls either directly to the Anthropic API (``api_key``
mode) or through an AWS Bedrock proxy fronted by an OAuth bearer token
(``bedrock_oauth`` mode), blanks out inherited HTTP proxies, applies an
OS-level sandbox, and (optionally) enables OTLP telemetry.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from .config import AgentConfig

# Match the 1-million-context variant of a Claude model. Used to pick a
# higher autocompact threshold (more headroom) when the user opts into the
# larger context window.
_LONG_CONTEXT_RE = re.compile(r"\[1m\]|_1m\b", re.IGNORECASE)

# Deny system paths, restrict reads/writes to the cwd (cloned repo).
# "." resolves to cwd inside Claude Code's sandbox.
_SANDBOX_DENY_READ_PATHS = ["/app", "/etc", "/proc", "/root", "/home", "/var", "/sys", "/run"]
_SANDBOX_DENY_WRITE_PATHS = ["/"]
_SANDBOX_ALLOW_READ_PATHS = ["."]
_SANDBOX_ALLOW_WRITE_PATHS = ["."]

_DEFAULT_OTEL_RESOURCE_ATTRIBUTES = "service.name=vulnhunter-agent,type=cli"


def resolve_autocompact_pct(model: str, override: int | None) -> int:
    """Pick the context-compaction threshold for a given model.

    - explicit ``override`` wins
    - 1M-context variants → 90% (~100K headroom)
    - standard 200K models → 85% (~30K headroom)
    """
    if override is not None:
        return override
    return 90 if _LONG_CONTEXT_RE.search(model or "") else 85


def _anthropic_host(cfg: AgentConfig) -> str:
    """The network host the SDK talks to, for the sandbox allow-list."""
    if cfg.anthropic.auth_mode == "bedrock_oauth":
        return urlparse(cfg.anthropic.bedrock_base_url).hostname or ""
    return "api.anthropic.com"


def _build_sandbox(cfg: AgentConfig) -> dict:
    host = _anthropic_host(cfg)
    allowed_domains = [host] if host else []
    return {
        "enabled": cfg.sandbox.enabled,
        "failIfUnavailable": cfg.sandbox.fail_if_unavailable,
        "allowUnsandboxedCommands": cfg.sandbox.allow_unsandboxed_commands,
        "filesystem": {
            "denyRead": list(_SANDBOX_DENY_READ_PATHS),
            "allowRead": list(_SANDBOX_ALLOW_READ_PATHS),
            "denyWrite": list(_SANDBOX_DENY_WRITE_PATHS),
            "allowWrite": list(_SANDBOX_ALLOW_WRITE_PATHS),
        },
        "network": {"allowedDomains": allowed_domains},
    }


def build_claude_settings(
    cfg: AgentConfig,
    auth_token: str,
    *,
    model: str,
    scan_id: str = "",
) -> str:
    """Return a JSON string matching Claude Code's settings file schema."""
    autocompact_pct = resolve_autocompact_pct(
        model, cfg.scan.autocompact_pct_override
    )
    no_proxy = cfg.scan.no_proxy
    env: dict[str, str] = {
        "CLAUDE_AUTOCOMPACT_PCT_OVERRIDE": str(autocompact_pct),
        "http_proxy": "",
        "https_proxy": "",
        "HTTP_PROXY": "",
        "HTTPS_PROXY": "",
        "no_proxy": no_proxy,
        "NO_PROXY": no_proxy,
        "NODE_TLS_REJECT_UNAUTHORIZED": "",
    }

    if cfg.anthropic.auth_mode == "bedrock_oauth":
        env.update(
            {
                "CLAUDE_CODE_SKIP_BEDROCK_AUTH": "1",
                "CLAUDE_CODE_USE_BEDROCK": "1",
                "AWS_REGION": cfg.anthropic.aws_region,
                "ANTHROPIC_BEDROCK_BASE_URL": cfg.anthropic.bedrock_base_url,
                "ANTHROPIC_AUTH_TOKEN": auth_token,
                # Extend the prompt-cache TTL from the 5-minute default to
                # ~1 hour on Bedrock. Same write/read pricing as the default
                # TTL, so for multi-turn scans (often 30-60 minutes total)
                # this is strictly cheaper: we pay the cache-creation premium
                # once instead of once per cache eviction.
                "ENABLE_PROMPT_CACHING_1H_BEDROCK": "1",
            }
        )
    else:
        # Direct Anthropic API. The API key rides in as auth_token (from the
        # token provider) or falls back to the configured value.
        env["ANTHROPIC_API_KEY"] = auth_token or cfg.anthropic.api_key

    # Cap how long an async subagent (Task tool) can go without forward
    # progress before the CLI returns a "Request timed out" tool result
    # to the orchestrator. Set 0 in config to fall through to the CLI default.
    if cfg.scan.async_agent_stall_timeout_ms > 0:
        env["CLAUDE_ASYNC_AGENT_STALL_TIMEOUT_MS"] = str(
            cfg.scan.async_agent_stall_timeout_ms
        )

    if cfg.telemetry.enabled and cfg.telemetry.otel_exporter_otlp_endpoint:
        resource_attributes = (
            cfg.telemetry.resource_attributes or _DEFAULT_OTEL_RESOURCE_ATTRIBUTES
        )
        if scan_id:
            resource_attributes = f"{resource_attributes},scan.id={scan_id}"
        env.update(
            {
                "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
                "OTEL_SERVICE_NAME": "vulnhunter-agent",
                "OTEL_METRICS_EXPORTER": "otlp",
                "OTEL_LOG_USER_PROMPTS": "1",
                "OTEL_EXPORTER_OTLP_PROTOCOL": "grpc",
                "OTEL_EXPORTER_OTLP_ENDPOINT": cfg.telemetry.otel_exporter_otlp_endpoint,
                "OTEL_EXPORTER_OTLP_TIMEOUT": "60000",
                "OTEL_LOGS_EXPORT_INTERVAL": "15000",
                "OTEL_METRIC_EXPORT_INTERVAL": "60000",
                "OTEL_METRIC_EXPORT_TIMEOUT": "30000",
                "CLAUDE_CODE_OTEL_SHUTDOWN_TIMEOUT_MS": "30000",
                "OTEL_LOG_TOOL_DETAILS": "1",
                "OTEL_LOG_TOOL_CONTENT": "1",
                "OTEL_RESOURCE_ATTRIBUTES": resource_attributes,
            }
        )
    else:
        env["CLAUDE_CODE_ENABLE_TELEMETRY"] = "0"

    return json.dumps(
        {
            "env": env,
            "sandbox": _build_sandbox(cfg),
        }
    )
