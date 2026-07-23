"""Tests for agent.build_settings: env + sandbox JSON construction."""

from __future__ import annotations

import json
import os
from collections.abc import Callable

import pytest

from agent.build_settings import _build_sandbox, build_claude_settings
from agent.config import (
    AgentConfig,
    AnthropicConfig,
    SandboxConfig,
    TelemetryConfig,
)


# ---------------------------------------------------------------------------
# _build_sandbox
# ---------------------------------------------------------------------------


class TestBuildSandbox:
    def test_allowed_domains_contains_bedrock_host(
        self, agent_config: Callable[..., AgentConfig]
    ) -> None:
        cfg = agent_config(
            anthropic=AnthropicConfig(
                model="claude-opus-4-8",
                auth_mode="bedrock_oauth",
                bedrock_base_url="https://bedrock.example.com:443/path",
                aws_region="us-east-1",
            )
        )
        sandbox = _build_sandbox(cfg)
        assert sandbox["network"]["allowedDomains"] == ["bedrock.example.com"]

    def test_api_key_mode_allows_anthropic_api_host(
        self, agent_config: Callable[..., AgentConfig]
    ) -> None:
        cfg = agent_config(
            anthropic=AnthropicConfig(
                model="claude-opus-4-8",
                auth_mode="api_key",
                api_key="sk-test",
            )
        )
        sandbox = _build_sandbox(cfg)
        assert sandbox["network"]["allowedDomains"] == ["api.anthropic.com"]

    def test_sandbox_flags_propagate(
        self, agent_config: Callable[..., AgentConfig]
    ) -> None:
        cfg = agent_config(
            sandbox=SandboxConfig(
                enabled=False,
                fail_if_unavailable=False,
                allow_unsandboxed_commands=True,
            )
        )
        sandbox = _build_sandbox(cfg)
        assert sandbox["enabled"] is False
        assert sandbox["failIfUnavailable"] is False
        assert sandbox["allowUnsandboxedCommands"] is True

    def test_empty_bedrock_hostname_yields_empty_allowed_domains(
        self, agent_config: Callable[..., AgentConfig]
    ) -> None:
        cfg = agent_config(
            anthropic=AnthropicConfig(
                model="m",
                auth_mode="bedrock_oauth",
                bedrock_base_url="not-a-url",
                aws_region="us-east-1",
            )
        )
        sandbox = _build_sandbox(cfg)
        assert sandbox["network"]["allowedDomains"] == []

    def test_sigv4_default_endpoint_allows_regional_bedrock_and_sts(
        self, agent_config: Callable[..., AgentConfig]
    ) -> None:
        cfg = agent_config(
            anthropic=AnthropicConfig(
                model="us.anthropic.claude-opus-4-8",
                auth_mode="bedrock_sigv4",
                aws_region="us-east-1",
            )
        )
        domains = _build_sandbox(cfg)["network"]["allowedDomains"]
        assert "bedrock-runtime.us-east-1.amazonaws.com" in domains
        assert "sts.us-east-1.amazonaws.com" in domains

    def test_sigv4_explicit_endpoint_wins_for_bedrock_host(
        self, agent_config: Callable[..., AgentConfig]
    ) -> None:
        cfg = agent_config(
            anthropic=AnthropicConfig(
                model="us.anthropic.claude-opus-4-8",
                auth_mode="bedrock_sigv4",
                aws_region="us-west-2",
                bedrock_base_url="https://bedrock.vpce.example.com",
            )
        )
        domains = _build_sandbox(cfg)["network"]["allowedDomains"]
        assert "bedrock.vpce.example.com" in domains
        # STS still allowed for credential resolution in the region.
        assert "sts.us-west-2.amazonaws.com" in domains

    def test_sigv4_allows_reading_aws_config_dir(
        self, agent_config: Callable[..., AgentConfig]
    ) -> None:
        # The deny-read list covers /home and /root, which on Linux hides
        # ~/.aws (config, credentials, SSO cache) and would silently reduce
        # the credential chain to env vars only. SigV4 mode must carve out
        # a read-only allow for ~/.aws so aws_profile / SSO work sandboxed.
        cfg = agent_config(
            anthropic=AnthropicConfig(
                model="us.anthropic.claude-opus-4-8",
                auth_mode="bedrock_sigv4",
                aws_region="us-east-1",
            )
        )
        fs = _build_sandbox(cfg)["filesystem"]
        assert os.path.expanduser("~/.aws") in fs["allowRead"]
        # Read-only: the write allow-list is untouched.
        assert fs["allowWrite"] == ["."]

    def test_non_sigv4_modes_do_not_expose_aws_config_dir(
        self, agent_config: Callable[..., AgentConfig]
    ) -> None:
        for anthropic in (
            AnthropicConfig(model="m", auth_mode="api_key", api_key="sk-test"),
            AnthropicConfig(
                model="m",
                auth_mode="bedrock_oauth",
                bedrock_base_url="https://bedrock.example.com",
                aws_region="us-east-1",
            ),
        ):
            cfg = agent_config(anthropic=anthropic)
            fs = _build_sandbox(cfg)["filesystem"]
            assert os.path.expanduser("~/.aws") not in fs["allowRead"]


# ---------------------------------------------------------------------------
# build_claude_settings
# ---------------------------------------------------------------------------


class TestBuildClaudeSettings:
    def test_returns_valid_json(
        self, populated_agent_config: AgentConfig
    ) -> None:
        out = build_claude_settings(populated_agent_config, "tok", model="claude-opus-4-8")
        parsed = json.loads(out)
        assert "env" in parsed
        assert "sandbox" in parsed

    def test_env_has_bedrock_keys(
        self, populated_agent_config: AgentConfig
    ) -> None:
        out = json.loads(build_claude_settings(populated_agent_config, "tok-xyz", model="claude-opus-4-8"))
        env = out["env"]
        assert env["CLAUDE_CODE_USE_BEDROCK"] == "1"
        assert env["ANTHROPIC_AUTH_TOKEN"] == "tok-xyz"
        assert env["ANTHROPIC_BEDROCK_BASE_URL"] == "https://bedrock.example.com"
        assert env["AWS_REGION"] == "us-east-1"

    def test_telemetry_disabled_omits_otel(
        self, populated_agent_config: AgentConfig
    ) -> None:
        out = json.loads(build_claude_settings(populated_agent_config, "tok", model="claude-opus-4-8"))
        env = out["env"]
        assert env["CLAUDE_CODE_ENABLE_TELEMETRY"] == "0"
        for key in env:
            assert not key.startswith("OTEL_")

    def test_telemetry_enabled_sets_otel(
        self, agent_config: Callable[..., AgentConfig]
    ) -> None:
        cfg = agent_config(
            telemetry=TelemetryConfig(
                enabled=True,
                otel_exporter_otlp_endpoint="https://otel.example.com",
            )
        )
        out = json.loads(build_claude_settings(cfg, "tok", model="claude-opus-4-8"))
        env = out["env"]
        assert env["CLAUDE_CODE_ENABLE_TELEMETRY"] == "1"
        assert env["OTEL_SERVICE_NAME"] == "vulnhunter-agent"
        assert env["OTEL_EXPORTER_OTLP_ENDPOINT"] == "https://otel.example.com"
        assert "OTEL_RESOURCE_ATTRIBUTES" in env

    def test_scan_id_flows_into_resource_attributes(
        self, agent_config: Callable[..., AgentConfig]
    ) -> None:
        cfg = agent_config(
            telemetry=TelemetryConfig(
                enabled=True,
                otel_exporter_otlp_endpoint="https://otel.example.com",
            )
        )
        out = json.loads(build_claude_settings(cfg, "tok", scan_id="abc-123", model="claude-opus-4-8"))
        attrs = out["env"]["OTEL_RESOURCE_ATTRIBUTES"]
        assert "scan.id=abc-123" in attrs

    def test_scan_id_absent_when_telemetry_off(
        self, populated_agent_config: AgentConfig
    ) -> None:
        out = json.loads(
            build_claude_settings(populated_agent_config, "tok", scan_id="abc", model="claude-opus-4-8")
        )
        # No OTEL_* keys at all when telemetry off.
        for key in out["env"]:
            assert not key.startswith("OTEL_")

    def test_autocompact_pct_propagates_as_string(
        self, populated_agent_config: AgentConfig
    ) -> None:
        out = json.loads(build_claude_settings(populated_agent_config, "tok", model="claude-opus-4-8"))
        assert out["env"]["CLAUDE_AUTOCOMPACT_PCT_OVERRIDE"] == "85"

    def test_autocompact_defaults_to_85_for_standard_context(
        self, agent_config_factory
    ) -> None:
        cfg = agent_config_factory(autocompact_pct_override=None)
        out = json.loads(build_claude_settings(cfg, "tok", model="claude-opus-4-8"))
        assert out["env"]["CLAUDE_AUTOCOMPACT_PCT_OVERRIDE"] == "85"

    def test_autocompact_defaults_to_90_for_1m_context(
        self, agent_config_factory
    ) -> None:
        cfg = agent_config_factory(autocompact_pct_override=None)
        out = json.loads(
            build_claude_settings(cfg, "tok", model="claude-opus-4-8[1m]")
        )
        assert out["env"]["CLAUDE_AUTOCOMPACT_PCT_OVERRIDE"] == "90"

    def test_autocompact_explicit_override_wins(
        self, agent_config_factory
    ) -> None:
        # Even with a 1M model, an explicit config value wins.
        cfg = agent_config_factory(autocompact_pct_override=70)
        out = json.loads(
            build_claude_settings(cfg, "tok", model="claude-opus-4-8[1m]")
        )
        assert out["env"]["CLAUDE_AUTOCOMPACT_PCT_OVERRIDE"] == "70"

    def test_prompt_caching_1h_bedrock_enabled(
        self, populated_agent_config: AgentConfig
    ) -> None:
        out = json.loads(
            build_claude_settings(
                populated_agent_config, "tok", model="claude-opus-4-8"
            )
        )
        # Strict allow-list: scans run 30-60+ minutes, so the 5-min
        # default cache TTL would evict between phase boundaries and
        # we'd re-pay the cache-write premium repeatedly. The 1-hour
        # TTL has no extra per-token cost.
        assert out["env"]["ENABLE_PROMPT_CACHING_1H_BEDROCK"] == "1"

    def test_http_proxy_blanked(
        self, populated_agent_config: AgentConfig
    ) -> None:
        env = json.loads(build_claude_settings(populated_agent_config, "tok", model="claude-opus-4-8"))["env"]
        for key in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
            assert env[key] == ""

    def test_no_proxy_comes_from_config(
        self, agent_config_factory
    ) -> None:
        cfg = agent_config_factory(no_proxy="localhost,10.0.0.0/8,.internal.example")
        env = json.loads(build_claude_settings(cfg, "tok", model="claude-opus-4-8"))["env"]
        assert env["NO_PROXY"] == "localhost,10.0.0.0/8,.internal.example"
        assert env["no_proxy"] == "localhost,10.0.0.0/8,.internal.example"

    def test_api_key_mode_sets_api_key_and_omits_bedrock(
        self, agent_config: Callable[..., AgentConfig]
    ) -> None:
        cfg = agent_config(
            anthropic=AnthropicConfig(
                model="claude-opus-4-8",
                auth_mode="api_key",
                api_key="sk-fromconfig",
            )
        )
        # auth_token empty → falls back to configured api_key.
        env = json.loads(build_claude_settings(cfg, "", model="claude-opus-4-8"))["env"]
        assert env["ANTHROPIC_API_KEY"] == "sk-fromconfig"
        assert "CLAUDE_CODE_USE_BEDROCK" not in env
        assert "ANTHROPIC_AUTH_TOKEN" not in env

    def test_api_key_mode_prefers_passed_token(
        self, agent_config: Callable[..., AgentConfig]
    ) -> None:
        cfg = agent_config(
            anthropic=AnthropicConfig(
                model="claude-opus-4-8",
                auth_mode="api_key",
                api_key="sk-fromconfig",
            )
        )
        env = json.loads(build_claude_settings(cfg, "sk-passed", model="claude-opus-4-8"))["env"]
        assert env["ANTHROPIC_API_KEY"] == "sk-passed"

    def test_sigv4_sets_bedrock_but_omits_bearer_and_skip_auth(
        self, agent_config: Callable[..., AgentConfig]
    ) -> None:
        # The core SigV4 contract: Bedrock on, region set, prompt caching on,
        # and — critically — NO bearer token and NO skip-auth flag, so the CLI
        # falls through to AWS SigV4 signing.
        cfg = agent_config(
            anthropic=AnthropicConfig(
                model="us.anthropic.claude-opus-4-8",
                auth_mode="bedrock_sigv4",
                aws_region="us-east-1",
            )
        )
        env = json.loads(
            build_claude_settings(cfg, "", model="us.anthropic.claude-opus-4-8")
        )["env"]
        assert env["CLAUDE_CODE_USE_BEDROCK"] == "1"
        assert env["AWS_REGION"] == "us-east-1"
        assert env["ENABLE_PROMPT_CACHING_1H_BEDROCK"] == "1"
        assert "ANTHROPIC_AUTH_TOKEN" not in env
        assert "CLAUDE_CODE_SKIP_BEDROCK_AUTH" not in env
        assert "ANTHROPIC_API_KEY" not in env
        # No explicit endpoint / profile → those keys are omitted.
        assert "ANTHROPIC_BEDROCK_BASE_URL" not in env
        assert "AWS_PROFILE" not in env

    def test_sigv4_sets_profile_and_endpoint_when_configured(
        self, agent_config: Callable[..., AgentConfig]
    ) -> None:
        cfg = agent_config(
            anthropic=AnthropicConfig(
                model="us.anthropic.claude-opus-4-8",
                auth_mode="bedrock_sigv4",
                aws_region="us-west-2",
                aws_profile="vulnhunter",
                bedrock_base_url="https://bedrock.vpce.example.com",
            )
        )
        env = json.loads(
            build_claude_settings(cfg, "", model="us.anthropic.claude-opus-4-8")
        )["env"]
        assert env["AWS_PROFILE"] == "vulnhunter"
        assert env["ANTHROPIC_BEDROCK_BASE_URL"] == "https://bedrock.vpce.example.com"
        assert env["AWS_REGION"] == "us-west-2"


# ---------------------------------------------------------------------------
# Snapshot test (syrupy)
# ---------------------------------------------------------------------------


def test_snapshot_rendered_settings(
    populated_agent_config: AgentConfig, snapshot
) -> None:
    """Lock the rendered JSON for a known fixture (telemetry off, sandbox on)."""
    rendered = build_claude_settings(populated_agent_config, "stub-token", model="claude-opus-4-8")
    parsed = json.loads(rendered)
    # Sort env keys for stable output.
    parsed["env"] = dict(sorted(parsed["env"].items()))
    canonical = json.dumps(parsed, indent=2, sort_keys=True)
    assert canonical == snapshot
