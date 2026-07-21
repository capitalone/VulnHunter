from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from vulnhunter.config import ProviderConfig, parse_engine_config
from vulnhunter.engine import ScanEngine, _await_provider_response, estimate_scan
from vulnhunter.inventory import build_inventory
from vulnhunter.models import (
    ModelSpec,
    ModelResponse,
    ScanLevel,
    ScanLimits,
    ScanRequest,
    Usage,
)
from vulnhunter.providers import ProviderError


class FakeProvider:
    def __init__(self, name: str) -> None:
        self.config = ProviderConfig(
            name=name,
            kind="openai_compatible",
            base_url="http://fake",
            remote=False,
        )
        self.name = name
        self.calls = 0

    async def health(self, model: Any) -> tuple[bool, str]:
        return True, "ok"

    async def list_models(self) -> list[str]:
        return ["fake"]

    async def complete(
        self,
        *,
        model: Any,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        response_schema: dict[str, Any] | None = None,
    ) -> ModelResponse:
        self.calls += 1
        text = "\n".join(str(row.get("content", "")) for row in messages)
        if "Independently falsify" in text:
            payload = {
                "verdict": "CONFIRMED",
                "source_reachable": True,
                "attacker_controlled": True,
                "trace_complete": True,
                "blocking_control_found": False,
                "new_capability_proven": True,
                "rationale": "The unscoped lookup is reachable.",
                "incorrect_claims": [],
                "missing_evidence": [],
            }
        else:
            payload = {
                "candidates": [
                    {
                        "title": "Unscoped account lookup",
                        "classification": "IDOR",
                        "severity": "High",
                        "cwe": "CWE-639",
                        "source": {"file": "app.py", "line": 1},
                        "sink": {"file": "app.py", "line": 2},
                        "trace": [
                            {
                                "file": "app.py",
                                "line": 1,
                                "claim": "request account id reaches lookup",
                            }
                        ],
                        "root_cause": "Account lookup is not scoped to the current user.",
                        "attacker_prerequisites": ["authenticated user"],
                        "new_capability": "Read another user's account.",
                        "contradicting_evidence": [],
                        "fix_strategy": "Scope lookup to the authenticated user.",
                        "poc": "Request another user's account id.",
                        "exploit_test": "Assert cross-user lookup is rejected.",
                    }
                ],
                "coverage": {
                    "files_reviewed": ["app.py"],
                    "unresolved_files": [],
                    "notes": "",
                },
            }
        return ModelResponse(
            content=json.dumps(payload),
            usage=Usage(input_tokens=100, output_tokens=50, cost_usd=0.0),
        )


class RateLimitedOnceProvider(FakeProvider):
    async def complete(self, **kwargs: Any) -> ModelResponse:
        if self.calls == 0:
            self.calls += 1
            raise ProviderError(
                "429 rate limit exceeded", status_code=429, retry_after=0.01
            )
        return await super().complete(**kwargs)


class InvalidContractProvider(FakeProvider):
    async def complete(self, **kwargs: Any) -> ModelResponse:
        self.calls += 1
        return ModelResponse(
            content=json.dumps({"candidates": []}),
            usage=Usage(
                input_tokens=100,
                output_tokens=25,
                requests=1,
                cost_usd=0.25,
                cost_source="provider",
            ),
        )


def _config() -> Any:
    raw = {
        "providers": {
            "one": {
                "kind": "openai_compatible",
                "base_url": "http://one",
                "remote": False,
            },
            "two": {
                "kind": "openai_compatible",
                "base_url": "http://two",
                "remote": False,
            },
        },
        "models": {
            "model-a": {"provider": "one", "model": "a", "priority": 1},
            "model-b": {"provider": "two", "model": "b", "priority": 2},
        },
    }
    return parse_engine_config(raw)


def _free_config() -> Any:
    raw = {
        "providers": {
            "router": {
                "kind": "openrouter",
                "base_url": "http://router",
                "remote": True,
            }
        },
        "models": {
            f"free-{index}": {
                "provider": "router",
                "model": f"vendor/free-{index}:free",
                "priority": index,
                "input_cost_per_million": 0,
                "output_cost_per_million": 0,
            }
            for index in range(1, 4)
        },
    }
    return parse_engine_config(raw)


@pytest.mark.asyncio
async def test_team_scan_unions_and_reviews(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "def account(account_id):\n    return db.get(account_id)\n"
    )
    config = _config()
    engine = ScanEngine(
        config,
        providers={"one": FakeProvider("one"), "two": FakeProvider("two")},
    )
    manifest, results = await engine.scan(
        ScanRequest(
            repository=str(repo),
            level=ScanLevel.STANDARD,
            model_aliases=["model-a", "model-b"],
        )
    )

    assert manifest["status"] == "COMPLETE_FINDINGS"
    assert len(manifest["findings"]) == 1
    assert manifest["reviews"] == 1
    assert (results / "run_manifest.json").is_file()
    assert (results / "scan_manifest.json").is_file()
    assert "VULN-001" in (results / "README.md").read_text()


@pytest.mark.asyncio
async def test_scan_emits_progress_for_work_and_reporting(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hello')\n")
    config = _config()
    events: list[tuple[str, dict[str, Any]]] = []
    engine = ScanEngine(
        config,
        providers={"one": FakeProvider("one"), "two": FakeProvider("two")},
        progress=lambda event, details: events.append((event, details)),
    )

    await engine.scan(
        ScanRequest(
            repository=str(repo),
            level=ScanLevel.QUICK,
            model_aliases=["model-a"],
        )
    )

    names = [event for event, _details in events]
    assert "inventory_complete" in names
    assert "phase_started" in names
    assert "assignment_started" in names
    assert "assignment_complete" in names
    assert "candidates_merged" in names
    assert names[-2:] == ["report_started", "scan_complete"]


@pytest.mark.asyncio
async def test_rate_limit_retry_is_tracked_and_reported(
    monkeypatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hello')\n")
    config = _config()
    async def no_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr("vulnhunter.engine.asyncio.sleep", no_sleep)
    monkeypatch.setattr("vulnhunter.engine.random.uniform", lambda _a, _b: 0.0)
    events: list[tuple[str, dict[str, Any]]] = []
    engine = ScanEngine(
        config,
        providers={
            "one": RateLimitedOnceProvider("one"),
            "two": FakeProvider("two"),
        },
        progress=lambda event, details: events.append((event, details)),
    )

    manifest, _results = await engine.scan(
        ScanRequest(
            repository=str(repo),
            level=ScanLevel.QUICK,
            model_aliases=["model-a"],
        )
    )

    assert manifest["usage"]["rate_limit_retries"] == 1
    assert any(event == "rate_limited" for event, _details in events)


@pytest.mark.asyncio
async def test_invalid_model_contract_is_classified_and_billed(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hello')\n")
    config = _config()
    events: list[tuple[str, dict[str, Any]]] = []
    engine = ScanEngine(
        config,
        providers={
            "one": InvalidContractProvider("one"),
            "two": FakeProvider("two"),
        },
        progress=lambda event, details: events.append((event, details)),
    )

    manifest, _results = await engine.scan(
        ScanRequest(
            repository=str(repo),
            level=ScanLevel.QUICK,
            model_aliases=["model-a"],
        )
    )

    failed = next(details for event, details in events if event == "assignment_failed")
    assert failed["error"].startswith("ModelOutputError:")
    assert "after 3 repair attempts" in failed["error"]
    repairs = [details for event, details in events if event == "model_output_retry"]
    assert [row["attempt"] for row in repairs] == [1, 2, 3]
    assert failed["cost_usd"] == pytest.approx(1.0)
    assert manifest["status"] == "INCOMPLETE_COVERAGE"
    assert manifest["usage"]["cost_usd"] == pytest.approx(1.0)
    assert manifest["usage"]["requests"] == 4


@pytest.mark.asyncio
async def test_all_free_team_enables_serial_pacing(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hello')\n")
    config = _free_config()
    events: list[tuple[str, dict[str, Any]]] = []
    engine = ScanEngine(
        config,
        providers={"router": FakeProvider("router")},
        progress=lambda event, details: events.append((event, details)),
    )

    async def no_pace(_model: Any) -> None:
        return None

    monkeypatch.setattr(engine, "_pace_request", no_pace)
    await engine.scan(
        ScanRequest(
            repository=str(repo),
            level=ScanLevel.QUICK,
            model_aliases=["free-1", "free-2", "free-3"],
            limits=ScanLimits(max_workers=8),
        )
    )

    free_event = next(details for event, details in events if event == "free_team_mode")
    assert free_event["models"] == 3
    assert free_event["max_workers"] == 1


@pytest.mark.asyncio
async def test_provider_wait_emits_periodic_heartbeats() -> None:
    waits: list[float] = []

    async def delayed_response() -> ModelResponse:
        import asyncio

        await asyncio.sleep(0.035)
        return ModelResponse(content="done")

    response = await _await_provider_response(
        delayed_response(),
        on_wait=waits.append,
        heartbeat_seconds=0.01,
    )

    assert response.content == "done"
    assert len(waits) >= 2


def test_estimate_models_repository_partitions_and_agent_rounds(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    for index in range(8):
        (repo / f"module_{index}.py").write_text("x = 1\n" * 5_000)
    config = _config()
    priced_models = [
        ModelSpec(
            alias=model.alias,
            provider=model.provider,
            model=model.model,
            remote=True,
            input_cost_per_million=2.0,
            output_cost_per_million=8.0,
        )
        for model in config.models.values()
    ]

    estimate = estimate_scan(
        build_inventory(repo), priced_models, level=ScanLevel.STANDARD
    )

    assert estimate["partitions"] >= 1
    assert estimate["requests_high"] > estimate["requests_low"] > 1
    assert estimate["input_tokens_high"] > estimate["input_tokens_low"]
    assert estimate["cost_high_usd"] > estimate["cost_low_usd"] > 0
    assert "tool rounds" in estimate["basis"]


@pytest.mark.asyncio
async def test_budget_cutoff_is_incomplete(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hello')\n")
    config = _config()
    engine = ScanEngine(
        config,
        providers={"one": FakeProvider("one"), "two": FakeProvider("two")},
    )
    manifest, results = await engine.scan(
        ScanRequest(
            repository=str(repo),
            level=ScanLevel.QUICK,
            model_aliases=["model-a"],
            limits=ScanLimits(max_tokens=1),
        )
    )
    assert manifest["status"] == "INCOMPLETE_LIMIT"
    assert manifest["coverage"]["complete"] is False
    legacy = json.loads((results / "scan_manifest.json").read_text())
    assert legacy["agent_exit_code"] == 4
    assert "must not be interpreted as clean" in (
        results / "README.md"
    ).read_text()


@pytest.mark.asyncio
async def test_resume_reuses_completed_assignments(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "def account(account_id):\n    return db.get(account_id)\n"
    )
    config = _config()
    provider_one = FakeProvider("one")
    provider_two = FakeProvider("two")
    engine = ScanEngine(
        config,
        providers={"one": provider_one, "two": provider_two},
    )
    first, results = await engine.scan(
        ScanRequest(
            repository=str(repo),
            level=ScanLevel.STANDARD,
            model_aliases=["model-a", "model-b"],
        )
    )
    first_calls = provider_one.calls + provider_two.calls
    assert first_calls > 0

    second, resumed_results = await engine.scan(
        ScanRequest(
            repository=str(repo),
            level=ScanLevel.STANDARD,
            model_aliases=["model-a", "model-b"],
            results_dir=str(results),
            resume=True,
        )
    )
    assert resumed_results == results
    assert second["status"] == first["status"]
    assert provider_one.calls + provider_two.calls == first_calls
