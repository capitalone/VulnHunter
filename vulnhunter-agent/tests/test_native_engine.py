from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from vulnhunter.config import ProviderConfig, parse_engine_config
from vulnhunter.engine import (
    ScanEngine,
    _add_safe_schema_defaults,
    _await_provider_response,
    _normalized_tool_evidence,
    _partition_limits,
    _provider_error_retryable,
    _prune_schema_extras,
    estimate_model_cost,
    estimate_scan,
    merge_candidates,
)
from vulnhunter.inventory import build_inventory
from vulnhunter.models import (
    Assignment,
    Candidate,
    ModelSpec,
    ModelResponse,
    ScanLevel,
    ScanLimits,
    ScanRequest,
    Usage,
    ToolCall,
)
from vulnhunter.prompts import CANDIDATE_SCHEMA, VALIDATION_SCHEMA
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
        if "Build a concise repository-scoped security threat model" in text:
            payload = {
                "product_surfaces": ["test service"],
                "actors": ["remote user"],
                "external_entrypoints": ["HTTP request"],
                "privileged_workflows": ["account lookup"],
                "assets": ["account data"],
                "dependency_attackers": [],
                "trust_boundaries": ["request to account lookup"],
                "security_invariants": ["accounts are tenant scoped"],
                "external_controls": [],
                "proof_gaps": [],
            }
        elif "Validate the candidate" in text:
            payload = {
                "verdict": "CONFIRMED",
                "disposition": "REPORTABLE",
                "method": "static source/control/sink trace",
                "source_reachable": True,
                "attacker_controlled": True,
                "blocking_control_found": False,
                "impact_proven": True,
                "evidence": [{"file": "app.py", "line": 1}],
                "counterevidence": [],
                "proof_gaps": [],
                "rationale": "The unscoped lookup is reachable.",
                "recommended_severity": "High",
                "sandbox_commands": [],
            }
        elif "Calibrate the validated candidate's attack path" in text:
            payload = {
                "attacker_position": "authenticated user",
                "preconditions": ["know another account id"],
                "boundary_crossed": "tenant boundary",
                "assets_reached": ["another account"],
                "blast_radius": "one selected account",
                "compensating_controls": [],
                "exploit_reliability": "high",
                "severity": "High",
                "severity_rationale": "Cross-tenant read.",
            }
        elif "Independently falsify" in text:
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


def test_quick_uses_context_aware_tool_shards() -> None:
    assert _partition_limits(ScanLevel.QUICK, 259_000) == (750_000, 40)
    assert _partition_limits(ScanLevel.STANDARD, 259_000) == (200_000, 15)


def test_successful_codex_read_command_closes_only_named_paths() -> None:
    expected = ["src/auth.ts", "src/other.ts"]
    calls = [
        {
            "name": "run_command",
            "arguments": {
                "command": (
                    "$files=@('src/auth.ts'); foreach($f in $files) "
                    "{ Get-Content -LiteralPath $f }"
                )
            },
            "status": "completed",
            "exit_code": 0,
            "result_sha256": "abc",
        },
        {
            "name": "run_command",
            "arguments": {"command": "Get-Content src/other.ts"},
            "status": "failed",
            "exit_code": 1,
            "result_sha256": "def",
        },
    ]

    evidence = _normalized_tool_evidence(calls, expected)

    credited = {
        row["path"]
        for row in evidence
        if row["tool"] == "run_command_path"
    }
    assert credited == {"src/auth.ts"}


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


class ToolThenMalformedProvider(FakeProvider):
    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.message_batches: list[list[dict[str, Any]]] = []

    async def complete(self, **kwargs: Any) -> ModelResponse:
        self.calls += 1
        messages = kwargs["messages"]
        self.message_batches.append(messages)
        if self.calls == 1:
            return ModelResponse(
                tool_calls=[
                    ToolCall(
                        id="read-1",
                        name="read_file",
                        arguments={"path": "app.py"},
                    )
                ],
                usage=Usage(requests=1),
            )
        if self.calls == 2:
            return ModelResponse(
                content=json.dumps(
                    {
                        "coverage": {
                            "files_reviewed": ["app.py"],
                            "unresolved_files": [],
                            "notes": "",
                        }
                    }
                ),
                usage=Usage(requests=1),
            )
        return ModelResponse(
            content=json.dumps(
                {
                    "candidates": [],
                    "coverage": {
                        "files_reviewed": ["app.py"],
                        "unresolved_files": [],
                        "notes": "",
                    },
                }
            ),
            usage=Usage(requests=1),
        )


class DuplicateToolProvider(FakeProvider):
    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.final_messages: list[dict[str, Any]] = []

    async def complete(self, **kwargs: Any) -> ModelResponse:
        self.calls += 1
        if self.calls <= 2:
            return ModelResponse(
                tool_calls=[
                    ToolCall(
                        id=f"read-{self.calls}",
                        name="read_file",
                        arguments={"path": "app.py"},
                    )
                ],
                usage=Usage(requests=1),
            )
        self.final_messages = kwargs["messages"]
        return ModelResponse(
            content=json.dumps(
                {
                    "candidates": [],
                    "coverage": {
                        "files_reviewed": ["app.py"],
                        "unresolved_files": [],
                        "notes": "",
                    },
                }
            ),
            usage=Usage(requests=1),
        )


def test_schema_cleanup_only_removes_extras_and_adds_coverage_notes() -> None:
    payload = {
        "candidates": [],
        "coverage": {
            "files_reviewed": ["app.py"],
            "unresolved_files": [],
            "summary": "not part of the contract",
        },
        "summary": "also not part of the contract",
    }

    _prune_schema_extras(payload, CANDIDATE_SCHEMA)
    _add_safe_schema_defaults(payload, CANDIDATE_SCHEMA)

    assert payload == {
        "candidates": [],
        "coverage": {
            "files_reviewed": ["app.py"],
            "unresolved_files": [],
            "notes": "",
        },
    }


def test_coverage_keeps_out_of_shard_paths_supplemental() -> None:
    assignment = Assignment(
        assignment_id="hunt-1",
        kind="hunt",
        model_alias="model-a",
        files=[".github/workflows/deploy.yml", "app.py"],
    )
    payload = {
        "coverage": {
            "files_reviewed": [
                "github/workflows/deploy.yml",
                "related.py",
            ],
            "unresolved_files": [],
            "notes": "",
        },
        "_provenance": {"tool_calls": []},
    }

    ScanEngine._normalize_assignment_coverage(assignment, payload)

    assert payload["coverage"]["files_reviewed"] == [
        ".github/workflows/deploy.yml"
    ]
    assert payload["coverage"]["unresolved_files"] == ["app.py"]
    supplemental = next(
        row
        for row in assignment.evidence
        if row.get("tool") == "supplemental_coverage_claim"
    )
    assert supplemental["paths"] == ["related.py"]
    assert assignment.coverage_quality == "self_reported"


@pytest.mark.asyncio
async def test_schema_repair_does_not_resend_repository_tool_transcript(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text("print('hello')\n")
    provider = ToolThenMalformedProvider("one")
    config = _config()
    engine = ScanEngine(config, providers={"one": provider, "two": FakeProvider("two")})

    payload, usage = await engine._tool_loop(
        config.models["model-a"],
        root=tmp_path,
        allowed_files={"app.py"},
        user_prompt="Audit app.py",
        schema=CANDIDATE_SCHEMA,
        execute=False,
    )

    assert payload["candidates"] == []
    assert usage.requests == 3
    repair_messages = provider.message_batches[2]
    assert len(repair_messages) == 2
    assert {row["role"] for row in repair_messages} == {"system", "user"}
    assert "print('hello')" not in str(repair_messages)


@pytest.mark.asyncio
async def test_duplicate_tool_result_is_not_retransmitted(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('unique-tool-content')\n")
    provider = DuplicateToolProvider("one")
    config = _config()
    events: list[tuple[str, dict[str, Any]]] = []
    engine = ScanEngine(
        config,
        providers={"one": provider, "two": FakeProvider("two")},
        progress=lambda event, details: events.append((event, details)),
    )

    await engine._tool_loop(
        config.models["model-a"],
        root=tmp_path,
        allowed_files={"app.py"},
        user_prompt="Audit app.py",
        schema=CANDIDATE_SCHEMA,
        execute=False,
    )

    tool_messages = [
        str(row["content"])
        for row in provider.final_messages
        if row["role"] == "tool"
    ]
    assert sum("unique-tool-content" in content for content in tool_messages) == 1
    assert any('"duplicate": true' in content for content in tool_messages)
    assert any(event == "duplicate_tool_call" for event, _details in events)


@pytest.mark.asyncio
async def test_provider_managed_validation_commands_run_in_engine_docker(
    monkeypatch, tmp_path: Path
) -> None:
    (tmp_path / "app.py").write_text("print('fixture')\n", encoding="utf-8")

    class ManagedProvider(FakeProvider):
        manages_repository_tools = True

        async def complete(self, **kwargs) -> ModelResponse:
            self.calls += 1
            messages = kwargs["messages"]
            received_results = "Sandbox execution results" in str(messages)
            payload = {
                "verdict": "CONFIRMED",
                "disposition": "REPORTABLE",
                "method": (
                    "Docker reproduction passed"
                    if received_results
                    else "provisional static trace"
                ),
                "source_reachable": True,
                "attacker_controlled": True,
                "blocking_control_found": False,
                "impact_proven": True,
                "evidence": [{"file": "app.py", "line": 1}],
                "counterevidence": [],
                "proof_gaps": [],
                "rationale": "Runtime proof returned by the engine.",
                "recommended_severity": "High",
                "sandbox_commands": (
                    []
                    if received_results
                    else [
                        {
                            "argv": ["python", "-m", "unittest", "-v"],
                            "timeout_seconds": 30,
                        }
                    ]
                ),
            }
            return ModelResponse(
                content=json.dumps(payload),
                usage=Usage(input_tokens=10, output_tokens=5, requests=1),
                raw={"tool_events": []},
            )

    class FakeSandbox:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def run(self, argv, *, timeout_seconds):
            assert argv == ["python", "-m", "unittest", "-v"]
            assert timeout_seconds == 30
            return {
                "returncode": 0,
                "stdout": "2 tests passed",
                "stderr": "",
                "command_log": "validation_artifacts/command-test.json",
            }

    monkeypatch.setattr("vulnhunter.engine.DockerSandbox", FakeSandbox)
    config = _config()
    provider = ManagedProvider("one")
    events: list[tuple[str, dict[str, Any]]] = []
    engine = ScanEngine(
        config,
        providers={"one": provider, "two": FakeProvider("two")},
        progress=lambda event, details: events.append((event, details)),
    )

    payload, usage = await engine._tool_loop(
        config.models["model-a"],
        root=tmp_path,
        allowed_files={"app.py"},
        user_prompt="Validate the candidate",
        schema=VALIDATION_SCHEMA,
        execute=True,
    )

    assert provider.calls == 2
    assert usage.requests == 2
    assert payload["sandbox_commands"] == []
    assert payload["method"] == "Docker reproduction passed"
    assert payload["_provenance"]["tool_calls"][0]["artifact"].endswith(
        "command-test.json"
    )
    assert any(event == "sandbox_command_complete" for event, _ in events)


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
    assert "after 1 repair attempts" in failed["error"]
    assert "exhausted 3 complete task retries" in failed["error"]
    repairs = [details for event, details in events if event == "model_output_retry"]
    assert [row["attempt"] for row in repairs] == [1] * 8
    task_retries = [
        details for event, details in events if event == "assignment_output_retry"
    ]
    assert [row["retry"] for row in task_retries] == [1, 2, 3, 1, 2, 3]
    assert failed["cost_usd"] == pytest.approx(2.0)
    assert manifest["status"] == "INCOMPLETE_COVERAGE"
    # Both the mandatory threat-model pass and the blind hunt exhaust their
    # structured-output retries. Usage from neither failed phase may disappear.
    assert manifest["usage"]["cost_usd"] == pytest.approx(4.0)
    assert manifest["usage"]["requests"] == 16


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
async def test_codex_cli_provider_work_is_serialized() -> None:
    config = parse_engine_config(
        {
            "providers": {"codex": {"kind": "codex_cli", "remote": True}},
            "models": {
                "codex": {
                    "provider": "codex",
                    "model": "gpt-test",
                    "remote": True,
                }
            },
        }
    )
    engine = ScanEngine(config, providers={"codex": FakeProvider("codex")})
    active = 0
    maximum_active = 0

    async def work() -> tuple[dict[str, Any], Usage]:
        nonlocal active, maximum_active
        active += 1
        maximum_active = max(maximum_active, active)
        await asyncio.sleep(0.01)
        active -= 1
        return {}, Usage()

    await asyncio.gather(
        engine._run_with_provider_limit("codex", work),
        engine._run_with_provider_limit("codex", work),
        engine._run_with_provider_limit("codex", work),
    )

    assert maximum_active == 1


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
    assert estimate["repository_lines"] == 40_000
    assert estimate["base_system_prompt_tokens"] > 0
    assert "validation/attack paths" in estimate["basis"]


def test_model_cost_accounts_for_cached_input() -> None:
    model = ModelSpec(
        alias="priced",
        provider="router",
        model="vendor/model",
        remote=True,
        input_cost_per_million=2.0,
        output_cost_per_million=8.0,
        cache_read_cost_per_million=0.5,
    )

    cost = estimate_model_cost(
        model,
        1_000_000,
        100_000,
        cached_input_tokens=800_000,
    )

    assert cost == pytest.approx(1.6)


def test_provider_retry_classification_rejects_hard_quota_errors() -> None:
    assert not _provider_error_retryable(
        ProviderError("You've hit your usage limit; purchase more credits")
    )
    assert not _provider_error_retryable(
        ProviderError("invalid_request_error", status_code=400)
    )
    assert _provider_error_retryable(
        ProviderError("rate limited", status_code=429, retry_after=1)
    )
    assert _provider_error_retryable(
        ProviderError("transport connection closed")
    )
    assert _provider_error_retryable(
        ProviderError(
            "stream disconnected before completion: No such host is known. "
            "(os error 11001)"
        )
    )


@pytest.mark.asyncio
async def test_nonretryable_provider_failure_opens_run_circuit() -> None:
    config = _config()
    engine = ScanEngine(
        config,
        providers={"one": FakeProvider("one"), "two": FakeProvider("two")},
    )
    calls = 0

    async def exhausted() -> tuple[dict[str, Any], Usage]:
        nonlocal calls
        calls += 1
        raise ProviderError("You've hit your usage limit")

    with pytest.raises(ProviderError):
        await engine._run_with_provider_limit("one", exhausted)
    with pytest.raises(ProviderError, match="provider disabled"):
        await engine._run_with_provider_limit("one", exhausted)

    assert calls == 1


def _candidate(
    candidate_id: str,
    *,
    title: str,
    classification: str,
    cwe: str,
    source_line: int,
    sink_line: int,
    sink_file: str = "routes/audio.ts",
) -> Candidate:
    return Candidate(
        candidate_id=candidate_id,
        title=title,
        classification=classification,
        severity="High",
        cwe=cwe,
        source={"file": "routes/audio.ts", "line": source_line},
        sink={"file": sink_file, "line": sink_line},
        trace=[],
        root_cause=title,
        attacker_prerequisites=["authenticated"],
        new_capability="impact",
        contradicting_evidence=[],
        fix_strategy="fix",
        affected_instances=[{"file": sink_file, "line": sink_line}],
    )


def test_candidate_merge_consolidates_paraphrases_but_not_other_mechanisms() -> None:
    cache_one = _candidate(
        "raw-1",
        title="Global idempotency cache leaks another tenant's result",
        classification="Cross-tenant cache collision",
        cwe="CWE-639",
        source_line=134,
        sink_line=162,
    )
    cache_two = _candidate(
        "raw-2",
        title="Principal-free cache returns another user's audio",
        classification="Cross-user cache disclosure",
        cwe="CWE-524",
        source_line=134,
        sink_line=165,
    )
    upload = _candidate(
        "raw-3",
        title="Unbounded multipart upload exhausts memory",
        classification="Uncontrolled resource consumption",
        cwe="CWE-400",
        source_line=98,
        sink_line=14,
    )

    merged = merge_candidates([cache_one, cache_two, upload])

    assert len(merged) == 2
    assert merged[0].duplicate_candidate_ids == ["raw-2"]
    assert {"line": 162, "file": "routes/audio.ts"} in merged[0].affected_instances
    assert {"line": 165, "file": "routes/audio.ts"} in merged[0].affected_instances


def test_candidate_merge_consolidates_shared_log_endpoint_and_resource_sink() -> None:
    log_one = _candidate(
        "log-1",
        title="Authenticated users can read shared global logs",
        classification="Cross-tenant information disclosure",
        cwe="CWE-862",
        source_line=55,
        sink_line=39,
        sink_file="routes/logs.ts",
    )
    log_one.source = {"file": "services/chat.ts", "line": 55}
    log_two = _candidate(
        "log-2",
        title="Global logs expose another tenant's data",
        classification="Missing authorization for operational logs",
        cwe="CWE-862",
        source_line=20,
        sink_line=52,
        sink_file="routes/logs.ts",
    )
    log_two.source = {"file": "components/Logs.tsx", "line": 20}
    disk_one = _candidate(
        "disk-1",
        title="Log ingestion permits disk exhaustion",
        classification="Resource exhaustion",
        cwe="CWE-400",
        source_line=16,
        sink_line=31,
        sink_file="utils/logger.ts",
    )
    disk_one.source = {"file": "routes/logs.ts", "line": 16}
    disk_two = _candidate(
        "disk-2",
        title="Log ingestion causes synchronous disk amplification",
        classification="Uncontrolled resource consumption",
        cwe="CWE-400",
        source_line=16,
        sink_line=31,
        sink_file="utils/logger.ts",
    )
    disk_two.source = {"file": "routes/logs.ts", "line": 16}

    merged = merge_candidates([log_one, log_two, disk_one, disk_two])

    assert len(merged) == 2
    assert merged[0].duplicate_candidate_ids == ["log-2"]
    assert merged[1].duplicate_candidate_ids == ["disk-2"]


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
    state = json.loads((results / "run_state.json").read_text())
    assert Path(state["repository"]) == repo.resolve()
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
