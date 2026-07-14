"""Tests for agent.repo_properties: GitHub fetch + CLI/GitHub/blank precedence."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import httpx
import pytest
import respx

from agent import repo_properties as rp_mod
from agent.config import RepoPropertiesConfig
from agent.repo_properties import (
    RepoProperties,
    _coerce_from_payload,
    _stringify,
    fetch_from_github,
    resolve,
)


# A representative operator-defined property map: GitHub custom-property
# name → emitted findings-stream field name. The agent ships with an
# empty map; these are illustrative names, not internal schema.
_PROP_MAP = {
    "appId": "app_id_tag",
    "appConfigItem": "app_config_item",
    "componentList": "component",
    "componentConfigItems": "component_config_item",
}


@pytest.fixture(autouse=True)
def _stub_resolve_verify(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force verify=True to avoid a str-verify DeprecationWarning in respx tests.

    Same pattern the issues-stage tests use — a configured CA-bundle path
    makes ``resolve_verify`` return a string, which httpx now flags as
    deprecated.
    """
    monkeypatch.setattr(rp_mod, "resolve_verify", lambda tls: True)


# ---------------------------------------------------------------------------
# _stringify
# ---------------------------------------------------------------------------


class TestStringify:
    def test_none_maps_to_blank(self) -> None:
        assert _stringify(None) == ""

    def test_list_joined_with_commas(self) -> None:
        assert _stringify(["A", "B", "C"]) == "A,B,C"

    def test_list_strips_and_skips_none(self) -> None:
        assert _stringify([" A ", None, "B"]) == "A,B"

    def test_scalar_stringified_and_trimmed(self) -> None:
        assert _stringify("  hello  ") == "hello"
        assert _stringify(42) == "42"


# ---------------------------------------------------------------------------
# _coerce_from_payload
# ---------------------------------------------------------------------------


class TestCoerceFromPayload:
    def test_mapped_fields_extracted(self) -> None:
        payload = [
            {"property_name": "appId", "value": "BASE"},
            {"property_name": "appConfigItem", "value": "CI636204641"},
            {"property_name": "componentList", "value": "SomeComponent"},
            {"property_name": "componentConfigItems", "value": "CI636332969"},
        ]
        p = _coerce_from_payload(payload, _PROP_MAP)
        assert p.get("app_id_tag") == "BASE"
        assert p.get("app_config_item") == "CI636204641"
        assert p.get("component") == "SomeComponent"
        assert p.get("component_config_item") == "CI636332969"

    def test_multi_select_joined(self) -> None:
        p = _coerce_from_payload(
            [{"property_name": "componentList", "value": ["Alpha", "Beta"]}],
            _PROP_MAP,
        )
        assert p.get("component") == "Alpha,Beta"

    def test_unknown_property_ignored(self) -> None:
        p = _coerce_from_payload(
            [
                {"property_name": "randomProperty", "value": "x"},
                {"property_name": "appId", "value": "BASE"},
            ],
            _PROP_MAP,
        )
        assert p.get("app_id_tag") == "BASE"
        assert "randomProperty" not in p.values
        # unknown property is silently dropped, not an error

    def test_only_present_properties_populated(self) -> None:
        p = _coerce_from_payload(
            [{"property_name": "appId", "value": "BASE"}], _PROP_MAP
        )
        assert p.values == {"app_id_tag": "BASE"}

    def test_non_list_payload_returns_blank(self) -> None:
        assert _coerce_from_payload({"foo": "bar"}, _PROP_MAP) == RepoProperties()

    def test_empty_list_returns_blank(self) -> None:
        assert _coerce_from_payload([], _PROP_MAP) == RepoProperties()


# ---------------------------------------------------------------------------
# resolve() precedence
# ---------------------------------------------------------------------------


class TestResolve:
    def test_cli_wins_over_github(self) -> None:
        cli = RepoProperties(values={"app_id_tag": "FROM-CLI"})
        gh = RepoProperties(values={"app_id_tag": "FROM-GH"})
        assert resolve(cli_overrides=cli, github=gh).get("app_id_tag") == "FROM-CLI"

    def test_github_fills_gaps(self) -> None:
        cli = RepoProperties(values={"component": "COMP-FROM-CLI"})
        gh = RepoProperties(
            values={
                "app_id_tag": "APP-FROM-GH",
                "component": "COMP-FROM-GH",  # overridden by CLI
            }
        )
        r = resolve(cli_overrides=cli, github=gh)
        assert r.get("component") == "COMP-FROM-CLI"
        assert r.get("app_id_tag") == "APP-FROM-GH"

    def test_blank_when_both_missing(self) -> None:
        r = resolve(cli_overrides=RepoProperties(), github=None)
        assert r == RepoProperties()

    def test_none_github_treated_as_blank(self) -> None:
        cli = RepoProperties(values={"component": "COMP"})
        r = resolve(cli_overrides=cli, github=None)
        assert r.get("component") == "COMP"


# ---------------------------------------------------------------------------
# fetch_from_github
# ---------------------------------------------------------------------------


class TestFetchFromGitHub:
    def _cfg(self, agent_config: Callable[..., Any]) -> Any:
        # scan_token needs to be set — helpers use it via get_github_token.
        # The property map must be non-empty or the fetch short-circuits.
        from agent.config import GitHubConfig

        return agent_config(
            github=GitHubConfig(
                host="github.com",
                scan_token="fake-token",
                reports_token="",
                broker_token_dir="",
            ),
            repo_properties=RepoPropertiesConfig(github_property_map=_PROP_MAP),
        )

    @respx.mock
    def test_happy_path(self, agent_config: Callable[..., Any]) -> None:
        cfg = self._cfg(agent_config)
        respx.get("https://api.github.com/repos/o/r/properties/values").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {"property_name": "appId", "value": "BASE"},
                    {"property_name": "componentList", "value": ["Alpha", "Beta"]},
                ],
            )
        )
        p = fetch_from_github("https://github.com/o/r", config=cfg)
        assert p.get("app_id_tag") == "BASE"
        assert p.get("component") == "Alpha,Beta"

    def test_empty_map_skips_fetch(self, agent_config: Callable[..., Any]) -> None:
        # No property map configured → opt-in feature is off; no network.
        from agent.config import GitHubConfig

        cfg = agent_config(
            github=GitHubConfig(
                host="github.com",
                scan_token="fake-token",
                reports_token="",
                broker_token_dir="",
            ),
            repo_properties=RepoPropertiesConfig(github_property_map={}),
        )
        assert fetch_from_github("https://github.com/o/r", config=cfg) == RepoProperties()

    @respx.mock
    def test_404_returns_blank(self, agent_config: Callable[..., Any]) -> None:
        cfg = self._cfg(agent_config)
        respx.get("https://api.github.com/repos/o/r/properties/values").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        assert fetch_from_github("https://github.com/o/r", config=cfg) == RepoProperties()

    @respx.mock
    def test_401_returns_blank(self, agent_config: Callable[..., Any]) -> None:
        cfg = self._cfg(agent_config)
        respx.get("https://api.github.com/repos/o/r/properties/values").mock(
            return_value=httpx.Response(401, json={"message": "Bad credentials"})
        )
        assert fetch_from_github("https://github.com/o/r", config=cfg) == RepoProperties()

    @respx.mock
    def test_network_error_returns_blank(
        self, agent_config: Callable[..., Any]
    ) -> None:
        cfg = self._cfg(agent_config)
        respx.get("https://api.github.com/repos/o/r/properties/values").mock(
            side_effect=httpx.ConnectError("connection refused")
        )
        assert fetch_from_github("https://github.com/o/r", config=cfg) == RepoProperties()

    def test_missing_scan_token_returns_blank(
        self, agent_config: Callable[..., Any]
    ) -> None:
        # Property map set but empty scan_token — should skip fetch.
        cfg = agent_config(
            repo_properties=RepoPropertiesConfig(github_property_map=_PROP_MAP),
        )
        assert fetch_from_github("https://github.com/o/r", config=cfg) == RepoProperties()

    def test_unparseable_url_returns_blank(
        self, agent_config: Callable[..., Any]
    ) -> None:
        cfg = self._cfg(agent_config)
        assert fetch_from_github("not-a-url", config=cfg) == RepoProperties()


# ---------------------------------------------------------------------------
# build_finding_event round-trip with properties
# ---------------------------------------------------------------------------


class TestBuildFindingEventPropertiesRoundTrip:
    def test_populated_properties_emit(self) -> None:
        from agent.audit import build_finding_event

        e = build_finding_event(
            app_id="app",
            repo_slug="org/repo",
            report_id="R",
            finding_id="R:VULN-001",
            vuln_id="VULN-001",
            title="t",
            cwe="CWE-89",
            severity="critical",
            status="OPEN",
            location="src/x.py:1",
            root_cause="rc",
            repo_properties={
                "app_id_tag": "BASE",
                "app_config_item": "CI636204641",
                "component": "Alpha,Beta",
                "component_config_item": "CI636332969",
            },
        )
        assert e["app_id_tag"] == "BASE"
        assert e["app_config_item"] == "CI636204641"
        assert e["component"] == "Alpha,Beta"
        assert e["component_config_item"] == "CI636332969"

    def test_blank_properties_dropped_from_json(self) -> None:
        """Blank values are dropped; verify emitted JSON omits the keys."""
        import json

        from agent.audit import _serialize, build_finding_event

        e = build_finding_event(
            app_id="app",
            repo_slug="org/repo",
            report_id="R",
            finding_id="R:VULN-001",
            vuln_id="VULN-001",
            title="t",
            cwe="CWE-89",
            severity="critical",
            status="OPEN",
            location="src/x.py:1",
            root_cause="rc",
            repo_properties={"app_id_tag": "", "component": ""},
        )
        line = _serialize(e)
        parsed = json.loads(line)
        assert "app_id_tag" not in parsed
        assert "component" not in parsed

    def test_no_properties_arg_emits_no_extra_keys(self) -> None:
        from agent.audit import build_finding_event

        e = build_finding_event(
            app_id="app",
            repo_slug="org/repo",
            report_id="R",
            finding_id="R:VULN-001",
            vuln_id="VULN-001",
            title="t",
            cwe="CWE-89",
            severity="critical",
            status="OPEN",
            location="src/x.py:1",
            root_cause="rc",
        )
        # None passed → the base schema keys only, no operator tags.
        assert "app_id_tag" not in e


class TestPreflightOrdering:
    """The GitHub properties fetch must run before the SDK scan session.

    A broken /properties/values endpoint should surface immediately,
    not after a 20-minute /vulnhunt scan completes. Ordering is
    enforced by placing ``_resolve_repo_properties`` in preflight in
    ``_run_scan_flow``, above the ``run_vulnhunt`` call.
    """

    def test_fetch_runs_before_run_vulnhunt(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Assert call order: repo_props.fetch_from_github → run_vulnhunt."""
        from agent import __main__ as main_mod
        from agent.config import GitHubConfig

        call_order: list[str] = []

        # Fake fetch → records order, returns a mapped property value.
        def _fake_fetch(repo_url: str, *, config, timeout_seconds=30):
            call_order.append("fetch_from_github")
            return main_mod.repo_props.RepoProperties(
                values={"app_id_tag": "from-github"}
            )

        # Fake run_vulnhunt → records order, returns a synthetic results dir.
        async def _fake_run_vulnhunt(clone_dir, config, **kwargs):
            call_order.append("run_vulnhunt")
            # Runner would create this dir; we synthesize it so the
            # rest of the flow (issues stage lookup) doesn't crash.
            results_dir = clone_dir / "x_VULNHUNT_RESULTS_opus47_2026-07-01-000000"
            results_dir.mkdir(parents=True, exist_ok=True)
            return results_dir

        def _fake_clone(repo_url, base, **kwargs):
            call_order.append("shallow_clone")
            d = tmp_path / "clone"
            d.mkdir(exist_ok=True)
            return d

        class _FakeOAuth:
            def __init__(self, *a, **k):
                pass

            def get_valid_token(self):
                return "t"

        # Config with scan token + a non-empty property map so the
        # properties fetch engages; issues stage disabled so the flow
        # exits cleanly.
        from tests.conftest import _build_agent_config
        from agent.config import AuditConfig

        cfg = _build_agent_config(
            github=GitHubConfig(
                host="github.com",
                scan_token="ghp_x",
                reports_token="",
                broker_token_dir="",
            ),
            repo_properties=RepoPropertiesConfig(
                github_property_map={"appId": "app_id_tag"}
            ),
            audit=AuditConfig(
                enabled=True,
                events_path=str(tmp_path / "audit.jsonl"),
                findings_path=str(tmp_path / "findings.jsonl"),
                stdout=False,
                app_id="NA",
                actor="tester",
                strict=False,
            ),
        )
        monkeypatch.setattr(main_mod, "load_config", lambda _p: cfg)
        monkeypatch.setattr(main_mod, "shallow_clone", _fake_clone)
        monkeypatch.setattr(main_mod, "run_vulnhunt", _fake_run_vulnhunt)
        monkeypatch.setattr(main_mod, "make_token_manager", lambda *a, **k: _FakeOAuth())
        monkeypatch.setattr(
            main_mod, "_preflight_standalone_tokens", lambda **_kw: None
        )
        monkeypatch.setattr(
            main_mod.repo_props, "fetch_from_github", _fake_fetch
        )

        # No issues stage, no publish stage — just scan.
        argv = [
            "--mode=scan",
            "https://github.com/o/r",
            "--no-publish",
            "--no-issues",
        ]
        exit_code = main_mod.main(argv)
        assert exit_code == 0, f"main returned {exit_code}"

        # Preflight ordering: fetch_from_github MUST come before run_vulnhunt.
        fetch_idx = call_order.index("fetch_from_github")
        run_idx = call_order.index("run_vulnhunt")
        assert fetch_idx < run_idx, (
            f"fetch must precede run_vulnhunt; got order={call_order}"
        )

    def test_fetch_skipped_when_audit_disabled(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """--no-audit must skip the properties fetch entirely."""
        from agent import __main__ as main_mod
        from agent.config import GitHubConfig

        called = {"n": 0}

        def _fake_fetch(*a, **k):
            called["n"] += 1
            return main_mod.repo_props.RepoProperties()

        async def _fake_run_vulnhunt(clone_dir, config, **kwargs):
            results_dir = clone_dir / "x_VULNHUNT_RESULTS_opus47_2026-07-01-000000"
            results_dir.mkdir(parents=True, exist_ok=True)
            return results_dir

        def _fake_clone(repo_url, base, **kwargs):
            d = tmp_path / "clone"
            d.mkdir(exist_ok=True)
            return d

        class _FakeOAuth:
            def __init__(self, *a, **k):
                pass

            def get_valid_token(self):
                return "t"

        from tests.conftest import _build_agent_config

        cfg = _build_agent_config(
            github=GitHubConfig(
                host="github.com",
                scan_token="ghp_x",
                reports_token="",
                broker_token_dir="",
            ),
            repo_properties=RepoPropertiesConfig(
                github_property_map={"appId": "app_id_tag"}
            ),
        )
        monkeypatch.setattr(main_mod, "load_config", lambda _p: cfg)
        monkeypatch.setattr(main_mod, "shallow_clone", _fake_clone)
        monkeypatch.setattr(main_mod, "run_vulnhunt", _fake_run_vulnhunt)
        monkeypatch.setattr(main_mod, "make_token_manager", lambda *a, **k: _FakeOAuth())
        monkeypatch.setattr(
            main_mod, "_preflight_standalone_tokens", lambda **_kw: None
        )
        monkeypatch.setattr(
            main_mod.repo_props, "fetch_from_github", _fake_fetch
        )

        argv = [
            "--mode=scan",
            "https://github.com/o/r",
            "--no-publish",
            "--no-issues",
            "--no-audit",
        ]
        main_mod.main(argv)
        assert called["n"] == 0, (
            "GitHub properties fetch must not run when audit is disabled"
        )
