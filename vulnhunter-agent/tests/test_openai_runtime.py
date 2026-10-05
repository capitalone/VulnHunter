"""Focused tests for the Responses-compatible GPT-5.6 Sol runtime."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from agent.config import OpenAIConfig, RuntimeConfig, load_config
from agent.openai_runtime import (
    OpenAIResponsesError,
    OpenAIUsage,
    OpenAIToolRuntime,
    ResponsesClient,
    ToolWorkspace,
    complete_text,
)
from agent.runner import _SessionResult, run_vulnhunt


def _openai_config(base, *, base_url: str = "https://gateway.example/v1"):
    return dataclasses.replace(
        base,
        runtime=RuntimeConfig(provider="openai"),
        openai=OpenAIConfig(
            model="gpt-5.6-sol",
            base_url=base_url,
            api_key="sk-test",
            reasoning_effort="xhigh",
            request_timeout_seconds=30,
            max_tool_rounds=20,
            max_concurrent_agents=3,
        ),
    )


def _message(text: str) -> dict[str, Any]:
    return {
        "type": "message",
        "role": "assistant",
        "content": [{"type": "output_text", "text": text}],
    }


def test_openai_config_does_not_require_anthropic_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    path = tmp_path / "config.toml"
    path.write_text(
        """
[runtime]
provider = "openai"

[openai]
base_url = "https://gateway.example/openai/v1/"
api_key = "test-key"
model = "gpt-5.6-sol"
reasoning_effort = "xhigh"
""",
        encoding="utf-8",
    )

    config = load_config(path)

    assert config.model_provider == "openai"
    assert config.model == "gpt-5.6-sol"
    assert config.openai.base_url == "https://gateway.example/openai/v1"
    assert config.anthropic.model == ""


def test_openai_config_rejects_invalid_reasoning_effort(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        """
[runtime]
provider = "openai"
[openai]
reasoning_effort = "extreme"
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="reasoning_effort"):
        load_config(path)


@pytest.mark.asyncio
async def test_complete_text_uses_responses_endpoint_and_xhigh(
    populated_agent_config,
) -> None:
    config = _openai_config(
        populated_agent_config,
        base_url="https://gateway.example/custom/v1/",
    )
    captured: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(json.loads(request.content))
        assert request.url == "https://gateway.example/custom/v1/responses"
        assert request.headers["Authorization"] == "Bearer sk-test"
        return httpx.Response(
            200,
            json={
                "status": "completed",
                "output": [_message('{"ok": true}')],
                "usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        responses = ResponsesClient(config, client=http, retry_backoffs=())
        text, usage = await complete_text(
            config=config,
            api_key="sk-test",
            model="gpt-5.6-sol",
            system="Return JSON.",
            user="Do it.",
            client=responses,
        )

    assert text == '{"ok": true}'
    assert usage.total_tokens == 15
    assert captured[0]["model"] == "gpt-5.6-sol"
    assert captured[0]["reasoning"] == {"effort": "xhigh"}
    assert captured[0]["store"] is False
    assert "tools" not in captured[0]


@pytest.mark.asyncio
async def test_tool_loop_replays_response_items_and_tool_output(
    tmp_path: Path,
    populated_agent_config,
) -> None:
    config = _openai_config(populated_agent_config)
    repo = tmp_path / "repo"
    results = repo / "results"
    repo.mkdir()
    results.mkdir()
    source = repo / "app.py"
    source.write_text("danger = request.args['x']\n", encoding="utf-8")
    requests: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        requests.append(body)
        if len(requests) == 1:
            return httpx.Response(
                200,
                json={
                    "status": "completed",
                    "output": [
                        {"type": "reasoning", "id": "rs_1", "encrypted_content": "abc"},
                        {
                            "type": "function_call",
                            "id": "fc_1",
                            "call_id": "call_1",
                            "name": "read_file",
                            "arguments": json.dumps({"path": str(source)}),
                        },
                    ],
                    "usage": {"input_tokens": 8, "output_tokens": 3},
                },
            )
        return httpx.Response(
            200,
            json={
                "status": "completed",
                "output": [_message("done")],
                "usage": {"input_tokens": 20, "output_tokens": 2},
            },
        )

    workspace = ToolWorkspace(
        cwd=repo,
        read_roots=[repo],
        write_root=results,
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        responses = ResponsesClient(config, client=http, retry_backoffs=())
        async with OpenAIToolRuntime(
            config,
            model="gpt-5.6-sol",
            api_key="sk-test",
            workspace=workspace,
            instructions="Audit the repo.",
            client=responses,
        ) as runtime:
            result = await runtime.run("Start")

    assert result.text == "done"
    assert result.usage.requests == 2
    assert requests[0]["include"] == ["reasoning.encrypted_content"]
    replay = requests[1]["input"]
    assert any(item.get("type") == "reasoning" for item in replay)
    tool_output = next(item for item in replay if item.get("type") == "function_call_output")
    assert tool_output["call_id"] == "call_1"
    assert "danger = request.args" in tool_output["output"]


@pytest.mark.asyncio
async def test_parallel_subagents_are_pinned_to_same_model_and_effort(
    tmp_path: Path,
    populated_agent_config,
) -> None:
    config = _openai_config(populated_agent_config)
    repo = tmp_path / "repo"
    results = repo / "results"
    repo.mkdir()
    results.mkdir()
    requests: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        requests.append(body)
        first_content = body["input"][0].get("content", "")
        if any(item.get("type") == "function_call_output" for item in body["input"]):
            return httpx.Response(
                200,
                json={"status": "completed", "output": [_message("root done")]},
            )
        if first_content == "root":
            return httpx.Response(
                200,
                json={
                    "status": "completed",
                    "output": [
                        {
                            "type": "function_call",
                            "call_id": "a",
                            "name": "spawn_agent",
                            "arguments": json.dumps({"name": "A", "prompt": "worker A"}),
                        },
                        {
                            "type": "function_call",
                            "call_id": "b",
                            "name": "spawn_agent",
                            "arguments": json.dumps({"name": "B", "prompt": "worker B"}),
                        },
                    ],
                },
            )
        if first_content in ("worker A", "worker B"):
            return httpx.Response(
                200,
                json={"status": "completed", "output": [_message(first_content + " done")]},
            )
        raise AssertionError(f"unexpected request: {body}")

    workspace = ToolWorkspace(cwd=repo, read_roots=[repo], write_root=results)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        responses = ResponsesClient(config, client=http, retry_backoffs=())
        async with OpenAIToolRuntime(
            config,
            model="gpt-5.6-sol",
            api_key="sk-test",
            workspace=workspace,
            instructions="Audit.",
            client=responses,
        ) as runtime:
            result = await runtime.run("root")

    assert result.text == "root done"
    assert len(requests) == 4
    assert {request["model"] for request in requests} == {"gpt-5.6-sol"}
    assert {request["reasoning"]["effort"] for request in requests} == {"xhigh"}


def test_workspace_rejects_source_write_and_symlink_escape(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    results = repo / "results"
    outside = tmp_path / "outside"
    repo.mkdir()
    results.mkdir()
    outside.mkdir()
    workspace = ToolWorkspace(cwd=repo, read_roots=[repo], write_root=results)

    with pytest.raises(ValueError, match="writes are restricted"):
        workspace.write_file(str(repo / "source.py"), "changed")

    (results / "escape").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="writes are restricted"):
        workspace.write_file(str(results / "escape" / "leak.txt"), "secret")


@pytest.mark.asyncio
async def test_scan_dispatches_openai_runtime_without_claude(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    populated_agent_config,
) -> None:
    from agent import runner

    config = _openai_config(populated_agent_config)
    clone = tmp_path / "clone"
    clone.mkdir()
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text("scan", encoding="utf-8")
    calls: list[dict[str, Any]] = []

    class TokenManager:
        def get_valid_token(self) -> str:
            return "openai-key"

    async def fake_openai(**kwargs: Any) -> _SessionResult:
        calls.append(kwargs)
        (kwargs["results_dir"] / "README.md").write_text("# report", encoding="utf-8")
        return _SessionResult(
            results_dir=kwargs["results_dir"],
            cost_usd=0.0,
            duration_s=1.0,
            num_turns=2,
        )

    monkeypatch.setattr(runner, "make_token_manager", lambda *_a, **_k: TokenManager())
    monkeypatch.setattr(runner, "_vulnhunt_skill_path", lambda: skill)
    monkeypatch.setattr(runner, "_run_openai_scan_session", fake_openai)
    monkeypatch.setattr(
        runner,
        "ClaudeSDKClient",
        lambda *_a, **_k: pytest.fail("Claude runtime should not be constructed"),
    )

    output = await run_vulnhunt(clone, config, backoffs=())

    assert output is not None
    assert calls[0]["model"] == "gpt-5.6-sol"
    assert calls[0]["auth_token"] == "openai-key"


@pytest.mark.asyncio
async def test_runtime_treats_refusal_as_failure(
    tmp_path: Path,
    populated_agent_config,
) -> None:
    config = _openai_config(populated_agent_config)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "status": "completed",
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "refusal", "refusal": "cannot help"}],
                    }
                ],
            },
        )

    repo = tmp_path / "repo"
    results = repo / "results"
    repo.mkdir()
    results.mkdir()
    workspace = ToolWorkspace(cwd=repo, read_roots=[repo], write_root=results)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        responses = ResponsesClient(config, client=http, retry_backoffs=())
        async with OpenAIToolRuntime(
            config,
            model="gpt-5.6-sol",
            api_key="sk-test",
            workspace=workspace,
            instructions="Audit.",
            client=responses,
        ) as runtime:
            with pytest.raises(OpenAIResponsesError, match="refused"):
                await runtime.run("start")


@pytest.mark.asyncio
async def test_json_llm_path_uses_openai_responses(
    monkeypatch: pytest.MonkeyPatch,
    populated_agent_config,
) -> None:
    from agent import _llm

    config = _openai_config(populated_agent_config)
    calls: list[dict[str, Any]] = []

    async def fake_complete_text(**kwargs: Any):
        calls.append(kwargs)
        return '{"findings": []}', OpenAIUsage(
            input_tokens=10,
            output_tokens=3,
            total_tokens=13,
            requests=1,
        )

    monkeypatch.setattr(_llm, "complete_text", fake_complete_text)
    monkeypatch.setattr(
        _llm,
        "ClaudeSDKClient",
        lambda *_a, **_k: pytest.fail("Claude should not be used"),
    )
    costs = _llm.CostStats()

    text = await _llm._send_prompt(
        model="gpt-5.6-sol",
        system="Return JSON.",
        user="Extract.",
        config=config,
        auth_token="sk-test",
        cost_tracker=costs,
    )

    assert text == '{"findings": []}'
    assert calls[0]["model"] == "gpt-5.6-sol"
    assert costs.calls == 1
    assert costs.num_turns == 1
    assert costs.cost_usd == 0


@pytest.mark.asyncio
async def test_verify_dispatches_openai_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    populated_agent_config,
) -> None:
    from agent import verify_runner

    config = _openai_config(populated_agent_config)
    expected = verify_runner.VerifySessionResult(
        kind=verify_runner.OutputKind.EMPTY,
        output_path=None,
        parsed=None,
        error_detail="test",
    )
    calls: list[dict[str, Any]] = []

    async def fake_openai_verify(**kwargs: Any):
        calls.append(kwargs)
        return expected

    monkeypatch.setattr(
        verify_runner,
        "_run_openai_verify_session",
        fake_openai_verify,
    )
    monkeypatch.setattr(
        verify_runner,
        "build_claude_settings",
        lambda *_a, **_k: pytest.fail("Claude settings should not be built"),
    )

    result = await verify_runner.run_verify_session(
        config=config,
        auth_token="sk-test",
        cwd=tmp_path,
        out_dir=tmp_path / "out",
        prompt="verify",
        log_path=tmp_path / "verify.log",
    )

    assert result is expected
    assert calls[0]["model"] == "gpt-5.6-sol"
