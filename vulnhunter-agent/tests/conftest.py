"""Shared pytest fixtures for the agent test suite.

All fixtures avoid real network/IO; tests using them stay deterministic.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from agent.config import (
    AgentConfig,
    AnthropicConfig,
    AuditConfig,
    GitHubConfig,
    IssuesConfig,
    LoggingConfig,
    OAuthConfig,
    PublishConfig,
    RepoPropertiesConfig,
    SandboxConfig,
    ScanConfig,
    TLSConfig,
    TelemetryConfig,
    VerifyConfig,
)


FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip env vars that would otherwise leak into the test process.

    - VULNHUNT_*: agent config, must start from a known state.
    - *_PROXY / NO_PROXY: httpx auto-picks these up; if the dev shell has
      a SOCKS proxy configured, every respx-mocked test would try to
      route through it and fail with "socksio not installed".
    """
    for key in list(os.environ):
        if key.startswith("VULNHUNT_") or key.upper() in (
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "FTP_PROXY",
            "SOCKS_PROXY",
        ):
            monkeypatch.delenv(key, raising=False)


@pytest.fixture
def tmp_config(tmp_path: Path) -> Callable[..., Path]:
    """Factory that writes a TOML config file under tmp_path.

    Pass `body` for a literal TOML string, or `sections` for a dict
    of {section: {key: value}}.
    """

    def _make(
        *,
        body: str | None = None,
        sections: dict[str, dict[str, Any]] | None = None,
        name: str = "config.toml",
    ) -> Path:
        path = tmp_path / name
        if body is not None:
            path.write_text(body)
            return path

        sections = sections or {}
        lines: list[str] = []
        for section, kv in sections.items():
            lines.append(f"[{section}]")
            for key, value in kv.items():
                lines.append(f"{key} = {_render_toml_scalar(value)}")
            lines.append("")
        path.write_text("\n".join(lines))
        return path

    return _make


def _render_toml_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        rendered = ", ".join(_render_toml_scalar(v) for v in value)
        return f"[{rendered}]"
    # Strings: escape backslash and double-quote.
    text = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{text}"'


def _build_agent_config(**overrides: Any) -> AgentConfig:
    """Construct a populated AgentConfig with sensible defaults."""
    defaults: dict[str, Any] = {
        "anthropic": AnthropicConfig(
            model="claude-opus-4-8",
            auth_mode="bedrock_oauth",
            api_key="",
            bedrock_base_url="https://bedrock.example.com",
            aws_region="us-east-1",
        ),
        "oauth": OAuthConfig(
            token_endpoint="https://oauth.example.com/token",
            client_id="cid",
            client_secret="csecret",
            expiry_safety_factor=0.9,
            default_lifetime_seconds=3600,
            http_timeout_seconds=30,
        ),
        "tls": TLSConfig(ssl_cert_path=""),
        "sandbox": SandboxConfig(
            enabled=True,
            fail_if_unavailable=True,
            allow_unsandboxed_commands=False,
        ),
        "telemetry": TelemetryConfig(
            enabled=False,
            otel_exporter_otlp_endpoint="",
            resource_attributes="",
        ),
        "scan": ScanConfig(
            clone_base_dir="./clones",
            clone_timeout_seconds=300,
            allowed_tools=["Read", "Grep"],
            permission_mode="acceptEdits",
            autocompact_pct_override=85,
            async_agent_stall_timeout_ms=1_200_000,
            no_proxy="localhost,127.0.0.1,10.0.0.0/8",
        ),
        "github": GitHubConfig(
            host="github.com",
            scan_token="",
            reports_token="",
            broker_token_dir="",
        ),
        "publish": PublishConfig(
            enabled=False,
            destination_repo="",
            branch="main",
            commit_author_name="VulnHunter Agent",
            commit_author_email="vulnhunter@example.com",
        ),
        "issues": IssuesConfig(
            enabled=False,
            target_repo="",
            labels=["security", "vulnhunter"],
            dedup_label="vulnhunter",
            haiku_model="claude-haiku-4-5",
            sonnet_model="claude-sonnet-5",
            semantic_dedup=True,
            request_timeout_seconds=60,
            max_open_issues=1000,
            token_budget_fraction=0.7,
            model_context_tokens=200_000,
            notify_clean_scan=True,
            clean_scan_label="VulnHunter: clean-scan",
        ),
        "logging": LoggingConfig(per_turn_usage=False, retries=False),
        "verify": VerifyConfig(
            scratch_base_dir="./verify_runs",
            clone_timeout_seconds=300,
            repo_aliases={},
        ),
        "audit": AuditConfig(
            enabled=False,
            events_path="/tmp/vulnhunter-test-audit.jsonl",
            findings_path="/tmp/vulnhunter-test-findings.jsonl",
            stdout=False,
            app_id="NA",
            actor="vulnhunter-agent-test",
            strict=False,
        ),
        "repo_properties": RepoPropertiesConfig(github_property_map={}),
        "source_path": None,
    }
    defaults.update(overrides)
    return AgentConfig(**defaults)


@pytest.fixture
def agent_config() -> Callable[..., AgentConfig]:
    """Factory returning an AgentConfig with overridable sub-sections."""
    return _build_agent_config


@pytest.fixture
def agent_config_factory() -> Callable[..., AgentConfig]:
    """Factory whose kwargs tweak individual scalar fields of ScanConfig.

    Convenience over ``agent_config`` for tests that only need to flip one
    scan-level field (e.g. ``autocompact_pct_override``) without rebuilding
    the whole nested structure.
    """

    def _factory(**scan_overrides: Any) -> AgentConfig:
        base = _build_agent_config()
        scan_kwargs = {
            "clone_base_dir": base.scan.clone_base_dir,
            "clone_timeout_seconds": base.scan.clone_timeout_seconds,
            "allowed_tools": list(base.scan.allowed_tools),
            "permission_mode": base.scan.permission_mode,
            "autocompact_pct_override": base.scan.autocompact_pct_override,
            "async_agent_stall_timeout_ms": base.scan.async_agent_stall_timeout_ms,
            "no_proxy": base.scan.no_proxy,
        }
        scan_kwargs.update(scan_overrides)
        return _build_agent_config(scan=ScanConfig(**scan_kwargs))

    return _factory


@pytest.fixture
def populated_agent_config() -> AgentConfig:
    """A ready-to-use AgentConfig populated with realistic test values."""
    return _build_agent_config()


@pytest.fixture
def fake_skill_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Create <tmp>/.claude/skills/vulnhunt/SKILL.md and point HOME there.

    Returns the skill directory itself.
    """
    home = tmp_path / "home"
    skill = home / ".claude" / "skills" / "vulnhunt"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("# vulnhunt skill (test fixture)\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    return skill


@pytest.fixture
def fake_clones(tmp_path: Path) -> Path:
    """A clone-base directory pre-populated with a couple of sample clones."""
    base = tmp_path / "clones"
    base.mkdir()
    (base / "alpha").mkdir()
    (base / "alpha" / ".git").mkdir()
    (base / "beta").mkdir()
    (base / "beta" / ".git").mkdir()
    return base
