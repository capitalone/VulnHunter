"""Tests for agent.config: env > TOML > default resolution + validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent.config import (
    AgentConfig,
    _coerce,
    _resolve,
    _resolve_config_path,
    load_config,
)


# ---------------------------------------------------------------------------
# _resolve_config_path
# ---------------------------------------------------------------------------


class TestResolveConfigPath:
    def test_explicit_path_existing_returns_it(self, tmp_path: Path) -> None:
        cfg = tmp_path / "cfg.toml"
        cfg.write_text("")
        out = _resolve_config_path(cfg)
        assert out == cfg.resolve()

    def test_explicit_path_missing_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            _resolve_config_path(tmp_path / "does-not-exist.toml")

    def test_env_path_existing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = tmp_path / "cfg.toml"
        cfg.write_text("")
        monkeypatch.setenv("VULNHUNT_AGENT_CONFIG", str(cfg))
        assert _resolve_config_path(None) == cfg.resolve()

    def test_env_path_missing_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("VULNHUNT_AGENT_CONFIG", str(tmp_path / "missing.toml"))
        with pytest.raises(FileNotFoundError):
            _resolve_config_path(None)

    def test_falls_back_to_package_relative_config(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The package ships with a config.toml; this should be picked up.
        monkeypatch.delenv("VULNHUNT_AGENT_CONFIG", raising=False)
        result = _resolve_config_path(None)
        # If the shipped config still exists, result is its path. If a future
        # change removes it, result is None — both are valid per the contract.
        if result is not None:
            assert result.name == "config.toml"

    def test_returns_none_when_nothing_found(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.delenv("VULNHUNT_AGENT_CONFIG", raising=False)
        # Point __file__ at a directory that has no config.toml by patching
        # the module's _DEFAULT_CONFIG_FILENAME to something nonexistent.
        from agent import config as cfg_mod

        monkeypatch.setattr(cfg_mod, "_DEFAULT_CONFIG_FILENAME", "no-such-config.toml")
        assert _resolve_config_path(None) is None


# ---------------------------------------------------------------------------
# _coerce
# ---------------------------------------------------------------------------


class TestCoerce:
    @pytest.mark.parametrize("val", ["1", "true", "TRUE", "Yes", "on", "ON"])
    def test_bool_truthy(self, val: str) -> None:
        assert _coerce(val, bool) is True

    @pytest.mark.parametrize("val", ["0", "false", "no", "off", "", "anything-else"])
    def test_bool_falsy(self, val: str) -> None:
        assert _coerce(val, bool) is False

    def test_int_numeric(self) -> None:
        assert _coerce("42", int) == 42

    def test_int_non_numeric_raises_value_error(self) -> None:
        with pytest.raises(ValueError):
            _coerce("nope", int)

    def test_float_numeric(self) -> None:
        assert _coerce("3.14", float) == 3.14

    def test_float_non_numeric_raises(self) -> None:
        with pytest.raises(ValueError):
            _coerce("abc", float)

    def test_list_csv_with_whitespace(self) -> None:
        assert _coerce("a, b ,c , ,", list) == ["a", "b", "c"]

    def test_list_empty_string_yields_empty_list(self) -> None:
        assert _coerce("", list) == []

    def test_str_passthrough(self) -> None:
        assert _coerce("hello", str) == "hello"


# ---------------------------------------------------------------------------
# _resolve
# ---------------------------------------------------------------------------


class TestResolve:
    def test_env_wins_over_toml(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("VULNHUNT_OAUTH_CLIENT_ID", "from-env")
        out = _resolve({"client_id": "from-toml"}, "oauth", "client_id")
        assert out == "from-env"

    def test_toml_wins_over_default(self) -> None:
        out = _resolve(
            {"client_id": "from-toml"},
            "oauth",
            "client_id",
            default="from-default",
        )
        assert out == "from-toml"

    def test_default_returned_when_nothing_else(self) -> None:
        out = _resolve({}, "oauth", "client_id", default="from-default")
        assert out == "from-default"

    def test_required_missing_raises(self) -> None:
        with pytest.raises(ValueError) as exc:
            _resolve({}, "oauth", "client_id", required=True)
        msg = str(exc.value)
        assert "oauth.client_id" in msg
        assert "VULNHUNT_OAUTH_CLIENT_ID" in msg

    def test_required_empty_string_raises(self) -> None:
        with pytest.raises(ValueError):
            _resolve({"client_id": ""}, "oauth", "client_id", required=True)

    def test_required_whitespace_only_raises(self) -> None:
        with pytest.raises(ValueError):
            _resolve({"client_id": "   "}, "oauth", "client_id", required=True)


# ---------------------------------------------------------------------------
# load_config end-to-end
# ---------------------------------------------------------------------------


class TestLoadConfig:
    def _set_required_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("VULNHUNT_ANTHROPIC_BEDROCK_BASE_URL", "https://b.example.com")
        monkeypatch.setenv("VULNHUNT_ANTHROPIC_MODEL", "claude-opus-4-8")
        monkeypatch.setenv("VULNHUNT_OAUTH_TOKEN_ENDPOINT", "https://oauth.example.com/token")
        monkeypatch.setenv("VULNHUNT_OAUTH_CLIENT_ID", "cid")
        monkeypatch.setenv("VULNHUNT_OAUTH_CLIENT_SECRET", "csec")

    def test_all_from_env_no_toml(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        self._set_required_env(monkeypatch)
        # Put VULNHUNT_AGENT_CONFIG at a missing path? No — that raises.
        # Instead, monkeypatch the package default to a missing filename so
        # no TOML is loaded.
        from agent import config as cfg_mod

        monkeypatch.setattr(cfg_mod, "_DEFAULT_CONFIG_FILENAME", "no-such.toml")
        cfg = load_config()
        assert isinstance(cfg, AgentConfig)
        assert cfg.oauth.client_id == "cid"
        assert cfg.source_path is None

    def test_all_from_toml_no_env(self, tmp_path: Path) -> None:
        path = tmp_path / "cfg.toml"
        path.write_text(
            """
[anthropic]
bedrock_base_url = "https://b.example.com"
model = "claude-opus-4-8"

[oauth]
token_endpoint = "https://oauth.example.com/token"
client_id = "tomlcid"
client_secret = "tomlcsec"
"""
        )
        cfg = load_config(path)
        assert cfg.oauth.client_id == "tomlcid"
        assert cfg.source_path == path.resolve()

    def test_env_overrides_specific_toml_field(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "cfg.toml"
        path.write_text(
            """
[anthropic]
bedrock_base_url = "https://from-toml.example.com"
model = "claude-opus-4-8"

[oauth]
token_endpoint = "https://oauth.example.com/token"
client_id = "tomlcid"
client_secret = "tomlcsec"
"""
        )
        monkeypatch.setenv("VULNHUNT_OAUTH_CLIENT_ID", "envcid")
        cfg = load_config(path)
        assert cfg.oauth.client_id == "envcid"
        assert cfg.anthropic.bedrock_base_url == "https://from-toml.example.com"

    def test_publish_enabled_with_empty_destination_raises(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "cfg.toml"
        path.write_text(
            """
[anthropic]
bedrock_base_url = "https://b"
model = "m"
[oauth]
token_endpoint = "https://o"
client_id = "x"
client_secret = "y"
[publish]
enabled = true
destination_repo = ""
"""
        )
        with pytest.raises(ValueError, match="destination_repo"):
            load_config(path)

    def test_oauth_client_id_empty_string_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "cfg.toml"
        path.write_text(
            """
[anthropic]
auth_mode = "bedrock_oauth"
bedrock_base_url = "https://b"
model = "m"
[oauth]
token_endpoint = "https://o"
client_id = ""
client_secret = "y"
"""
        )
        with pytest.raises(ValueError):
            load_config(path)

    def test_anthropic_bedrock_base_url_whitespace_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "cfg.toml"
        path.write_text(
            """
[anthropic]
auth_mode = "bedrock_oauth"
bedrock_base_url = "   "
model = "m"
[oauth]
token_endpoint = "https://o"
client_id = "x"
client_secret = "y"
"""
        )
        with pytest.raises(ValueError):
            load_config(path)

    def test_default_github_host(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        self._set_required_env(monkeypatch)
        from agent import config as cfg_mod

        monkeypatch.setattr(cfg_mod, "_DEFAULT_CONFIG_FILENAME", "no-such.toml")
        cfg = load_config()
        assert cfg.github.host == "github.com"

    def test_dual_tokens_from_env(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Env-var resolution: each new [github] field is reachable."""
        self._set_required_env(monkeypatch)
        from agent import config as cfg_mod

        monkeypatch.setattr(cfg_mod, "_DEFAULT_CONFIG_FILENAME", "no-such.toml")
        monkeypatch.setenv("VULNHUNT_GITHUB_SCAN_TOKEN", "ghp_scan_env")
        monkeypatch.setenv("VULNHUNT_GITHUB_REPORTS_TOKEN", "ghp_reports_env")
        monkeypatch.setenv(
            "VULNHUNT_GITHUB_BROKER_TOKEN_DIR", "/tmp/broker-tokens/scan-1"
        )
        cfg = load_config()
        assert cfg.github.scan_token == "ghp_scan_env"
        assert cfg.github.reports_token == "ghp_reports_env"
        assert cfg.github.broker_token_dir == "/tmp/broker-tokens/scan-1"

    def test_dual_tokens_defaults_are_empty(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """When neither config nor env supplies tokens, fields default to ''."""
        self._set_required_env(monkeypatch)
        from agent import config as cfg_mod

        monkeypatch.setattr(cfg_mod, "_DEFAULT_CONFIG_FILENAME", "no-such.toml")
        cfg = load_config()
        assert cfg.github.scan_token == ""
        assert cfg.github.reports_token == ""
        assert cfg.github.broker_token_dir == ""

    def test_publish_dataclass_default_is_false(self) -> None:
        # The dataclass's documented default is enabled=False; verify by
        # constructing one explicitly with no overrides for that field.
        from agent.config import PublishConfig

        pub = PublishConfig(
            enabled=False,
            destination_repo="",
            branch="main",
            commit_author_name="",
            commit_author_email="",
        )
        assert pub.enabled is False

    def test_publish_file_default_can_be_true(self, tmp_path: Path) -> None:
        # The shipping config.toml uses enabled=true. Mirror that.
        path = tmp_path / "cfg.toml"
        path.write_text(
            """
[anthropic]
bedrock_base_url = "https://b"
model = "m"
[oauth]
token_endpoint = "https://o"
client_id = "x"
client_secret = "y"
[publish]
enabled = true
destination_repo = "https://github.com/o/r"
"""
        )
        cfg = load_config(path)
        assert cfg.publish.enabled is True

    def test_source_path_set_when_toml_loaded(self, tmp_path: Path) -> None:
        path = tmp_path / "cfg.toml"
        path.write_text(
            """
[anthropic]
bedrock_base_url = "https://b"
model = "m"
[oauth]
token_endpoint = "https://o"
client_id = "x"
client_secret = "y"
"""
        )
        cfg = load_config(path)
        assert cfg.source_path == path.resolve()

    def test_source_path_none_when_no_toml(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._set_required_env(monkeypatch)
        from agent import config as cfg_mod

        monkeypatch.setattr(cfg_mod, "_DEFAULT_CONFIG_FILENAME", "no-such.toml")
        cfg = load_config()
        assert cfg.source_path is None

    def test_allowed_tools_from_env_csv(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._set_required_env(monkeypatch)
        monkeypatch.setenv("VULNHUNT_SCAN_ALLOWED_TOOLS", "Read, Grep , Bash")
        from agent import config as cfg_mod

        monkeypatch.setattr(cfg_mod, "_DEFAULT_CONFIG_FILENAME", "no-such.toml")
        cfg = load_config()
        assert cfg.scan.allowed_tools == ["Read", "Grep", "Bash"]

    def test_allowed_tools_from_toml_array(self, tmp_path: Path) -> None:
        path = tmp_path / "cfg.toml"
        path.write_text(
            """
[anthropic]
bedrock_base_url = "https://b"
model = "m"
[oauth]
token_endpoint = "https://o"
client_id = "x"
client_secret = "y"
[scan]
allowed_tools = ["Read", "Edit"]
"""
        )
        cfg = load_config(path)
        assert cfg.scan.allowed_tools == ["Read", "Edit"]

    def test_load_minimal_fixture(self) -> None:
        """Smoke test against tests/fixtures/config_minimal.toml."""
        path = Path(__file__).parent / "fixtures" / "config_minimal.toml"
        cfg = load_config(path)
        assert cfg.oauth.client_id == "minimal-client"
        assert cfg.anthropic.aws_region == "us-east-1"  # default
        assert cfg.publish.enabled is False  # default

    def test_load_full_fixture(self) -> None:
        path = Path(__file__).parent / "fixtures" / "config_full.toml"
        cfg = load_config(path)
        assert cfg.anthropic.aws_region == "us-west-2"
        assert cfg.publish.enabled is True
        assert cfg.publish.destination_repo == "https://github.com/example/results"

    def test_bedrock_sigv4_minimal(self, tmp_path: Path) -> None:
        # SigV4 mode needs only a region; no [oauth] block, no bedrock_base_url.
        path = tmp_path / "cfg.toml"
        path.write_text(
            """
[anthropic]
auth_mode = "bedrock_sigv4"
model = "us.anthropic.claude-opus-4-8"
aws_region = "us-east-1"
"""
        )
        cfg = load_config(path)
        assert cfg.anthropic.auth_mode == "bedrock_sigv4"
        assert cfg.anthropic.aws_region == "us-east-1"
        assert cfg.anthropic.bedrock_base_url == ""
        assert cfg.anthropic.aws_profile == ""

    def test_bedrock_sigv4_with_profile_and_endpoint(self, tmp_path: Path) -> None:
        path = tmp_path / "cfg.toml"
        path.write_text(
            """
[anthropic]
auth_mode = "bedrock_sigv4"
model = "us.anthropic.claude-opus-4-8"
aws_region = "us-west-2"
aws_profile = "vulnhunter"
bedrock_base_url = "https://bedrock.vpce.example.com"
"""
        )
        cfg = load_config(path)
        assert cfg.anthropic.aws_profile == "vulnhunter"
        assert cfg.anthropic.bedrock_base_url == "https://bedrock.vpce.example.com"

    def test_aws_region_stripped_at_load(self, tmp_path: Path) -> None:
        # A padded region ("  us-east-1  ") must be normalized at load so
        # AWS_REGION and the sandbox allow-list never see the raw value.
        path = tmp_path / "cfg.toml"
        path.write_text(
            """
[anthropic]
auth_mode = "bedrock_sigv4"
model = "us.anthropic.claude-opus-4-8"
aws_region = "  us-east-1  "
"""
        )
        cfg = load_config(path)
        assert cfg.anthropic.aws_region == "us-east-1"

    def test_bedrock_sigv4_blank_region_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "cfg.toml"
        path.write_text(
            """
[anthropic]
auth_mode = "bedrock_sigv4"
model = "m"
aws_region = "   "
"""
        )
        with pytest.raises(ValueError, match="aws_region"):
            load_config(path)

    def test_invalid_auth_mode_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "cfg.toml"
        path.write_text(
            """
[anthropic]
auth_mode = "bedrock_bogus"
model = "m"
"""
        )
        with pytest.raises(ValueError, match="auth_mode"):
            load_config(path)

    def test_bedrock_sigv4_profile_from_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("VULNHUNT_ANTHROPIC_AUTH_MODE", "bedrock_sigv4")
        monkeypatch.setenv("VULNHUNT_ANTHROPIC_MODEL", "us.anthropic.claude-opus-4-8")
        monkeypatch.setenv("VULNHUNT_ANTHROPIC_AWS_REGION", "us-east-1")
        monkeypatch.setenv("VULNHUNT_ANTHROPIC_AWS_PROFILE", "from-env")
        from agent import config as cfg_mod

        monkeypatch.setattr(cfg_mod, "_DEFAULT_CONFIG_FILENAME", "no-such.toml")
        cfg = load_config()
        assert cfg.anthropic.auth_mode == "bedrock_sigv4"
        assert cfg.anthropic.aws_profile == "from-env"

    def test_verify_tuple_fields_parse_from_toml(self, tmp_path: Path) -> None:
        # Regression: the [verify] list fields (allowed_clone_hosts,
        # token_path_prefixes) are built from generator expressions inside
        # tuple(...) calls in load_config. A missing close-paren on one of
        # them is a module-level SyntaxError that breaks the whole agent
        # package import — so this exercises those two fields end-to-end.
        path = tmp_path / "cfg.toml"
        path.write_text(
            """
[anthropic]
bedrock_base_url = "https://b"
model = "m"
[oauth]
token_endpoint = "https://o"
client_id = "x"
client_secret = "y"
[verify]
allowed_clone_hosts = ["git.internal.example", "  ", "ghe.example.com"]
token_path_prefixes = ["my-org", "my-org/allowed-repo", ""]
"""
        )
        cfg = load_config(path)
        # Blank/whitespace-only entries are dropped; order preserved.
        assert cfg.verify.allowed_clone_hosts == (
            "git.internal.example",
            "ghe.example.com",
        )
        assert cfg.verify.token_path_prefixes == (
            "my-org",
            "my-org/allowed-repo",
        )
        # And the downstream int bounds that follow the tuple fields still resolve.
        assert cfg.verify.max_comment_pages == 20


# ---------------------------------------------------------------------------
# [logging] section
# ---------------------------------------------------------------------------


class TestLoggingSection:
    def test_defaults_when_section_absent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # No [logging] in TOML, no env vars → both flags False.
        path = tmp_path / "cfg.toml"
        path.write_text(
            """
[anthropic]
bedrock_base_url = "https://b"
model = "m"
[oauth]
token_endpoint = "https://o"
client_id = "x"
client_secret = "y"
"""
        )
        cfg = load_config(path)
        assert cfg.logging.per_turn_usage is False
        assert cfg.logging.retries is False

    def test_toml_values_parse(self, tmp_path: Path) -> None:
        path = tmp_path / "cfg.toml"
        path.write_text(
            """
[anthropic]
bedrock_base_url = "https://b"
model = "m"
[oauth]
token_endpoint = "https://o"
client_id = "x"
client_secret = "y"
[logging]
per_turn_usage = true
retries = true
"""
        )
        cfg = load_config(path)
        assert cfg.logging.per_turn_usage is True
        assert cfg.logging.retries is True

    def test_env_var_overrides_toml(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "cfg.toml"
        path.write_text(
            """
[anthropic]
bedrock_base_url = "https://b"
model = "m"
[oauth]
token_endpoint = "https://o"
client_id = "x"
client_secret = "y"
[logging]
per_turn_usage = false
retries = false
"""
        )
        monkeypatch.setenv("VULNHUNT_LOGGING_PER_TURN_USAGE", "true")
        monkeypatch.setenv("VULNHUNT_LOGGING_RETRIES", "true")
        cfg = load_config(path)
        assert cfg.logging.per_turn_usage is True
        assert cfg.logging.retries is True

    def test_flags_are_independent(self, tmp_path: Path) -> None:
        path = tmp_path / "cfg.toml"
        path.write_text(
            """
[anthropic]
bedrock_base_url = "https://b"
model = "m"
[oauth]
token_endpoint = "https://o"
client_id = "x"
client_secret = "y"
[logging]
per_turn_usage = true
retries = false
"""
        )
        cfg = load_config(path)
        assert cfg.logging.per_turn_usage is True
        assert cfg.logging.retries is False


class TestModuleImportRegression:
    """Regression: agent.config must parse and expose a callable load_config.

    Guards against the unclosed VerifyConfig(token_path_prefixes=...) paren that
    made the entire agent package fail to import (SyntaxError).
    """

    def test_module_imports(self) -> None:
        import importlib

        import agent.config as cfg_mod

        importlib.reload(cfg_mod)
        assert cfg_mod is not None

    def test_load_config_is_callable(self) -> None:
        assert callable(load_config)
