"""Focused tests for the isolated Codex CLI scan backend."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

import pytest

from agent.codex_runtime import (
    CodexExecutionError,
    CodexResult,
    CodexUsage,
    build_codex_command,
    run_codex,
)
from agent.config import (
    CodexConfig,
    OpenAIConfig,
    RuntimeConfig,
    load_config,
)
from agent.openai_runtime import OpenAIUsage
from agent.runner import _SessionResult, run_vulnhunt


def _codex_config(base, *, executable: str = "codex"):
    return dataclasses.replace(
        base,
        runtime=RuntimeConfig(provider="codex"),
        openai=OpenAIConfig(
            model="gpt-5.6-sol",
            base_url="https://gateway.example/openai/v1",
            api_key="sk-test",
            reasoning_effort="xhigh",
            request_timeout_seconds=30,
            max_tool_rounds=20,
            max_concurrent_agents=6,
        ),
        codex=CodexConfig(
            executable=executable,
            request_timeout_seconds=30,
            max_concurrent_agents=4,
        ),
    )


def _write_fake_codex(path: Path) -> None:
    path.write_text(
        """#!/usr/bin/env python3
import json
import os
import pathlib
import sys

args = sys.argv[1:]
prompt = sys.stdin.read()
capture = pathlib.Path(os.environ["FAKE_CODEX_CAPTURE"])
work_dir = pathlib.Path(args[args.index("-C") + 1])
capture.write_text(json.dumps({
    "args": args,
    "prompt": prompt,
    "key_present": bool(os.environ.get("VULNHUNT_CODEX_API_KEY")),
    "codex_home": os.environ.get("CODEX_HOME", ""),
    "skill_present": (work_dir / ".agents/skills/vulnhunt-codex/SKILL.md").is_file(),
}), encoding="utf-8")

print(json.dumps({"type": "thread.started", "thread_id": "thread-test"}))
print(json.dumps({"type": "turn.started"}))
if os.environ.get("FAKE_CODEX_MODE") == "transient":
    message = "HTTP 429 rate limit exceeded"
    print(json.dumps({"type": "error", "message": message}))
    print(json.dumps({"type": "turn.failed", "error": {"message": message}}))
    raise SystemExit(1)

output_path = pathlib.Path(args[args.index("--output-last-message") + 1])
output_path.write_text("scan complete", encoding="utf-8")
print(json.dumps({
    "type": "item.completed",
    "item": {"id": "item-1", "type": "agent_message", "text": "scan complete"},
}))
print(json.dumps({
    "type": "turn.completed",
    "usage": {
        "input_tokens": 120,
        "cached_input_tokens": 80,
        "output_tokens": 30,
        "reasoning_output_tokens": 20,
    },
}))
""",
        encoding="utf-8",
    )
    path.chmod(0o755)


def test_codex_config_reuses_openai_endpoint_without_anthropic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    path = tmp_path / "config.toml"
    path.write_text(
        """
[runtime]
provider = "codex"

[openai]
base_url = "https://gateway.example/v1/"
api_key = "test-key"
model = "gpt-5.6-sol"
reasoning_effort = "xhigh"

[codex]
executable = "/opt/tools/codex"
request_timeout_seconds = 1234
max_concurrent_agents = 4
""",
        encoding="utf-8",
    )

    config = load_config(path)

    assert config.model_provider == "codex"
    assert config.model == "gpt-5.6-sol"
    assert config.openai.base_url == "https://gateway.example/v1"
    assert config.codex.executable == "/opt/tools/codex"
    assert config.codex.request_timeout_seconds == 1234
    assert config.codex.max_concurrent_agents == 4
    assert config.anthropic.model == ""


def test_codex_rejects_reasoning_value_not_supported_by_cli(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        """
[runtime]
provider = "codex"
[openai]
reasoning_effort = "max"
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="requires openai.reasoning_effort"):
        load_config(path)


def test_codex_command_is_isolated_and_keeps_key_out_of_argv(
    tmp_path: Path,
    populated_agent_config,
) -> None:
    config = _codex_config(populated_agent_config, executable="/bin/codex")
    work = tmp_path / "work"
    results = tmp_path / "results"
    work.mkdir()
    results.mkdir()

    command = build_codex_command(
        config,
        executable="/bin/codex",
        model="gpt-5.6-sol",
        work_dir=work,
        output_file=work / "last.txt",
        writable_roots=(results,),
        api_key_present=True,
    )
    rendered = "\n".join(command)

    assert command[:2] == ["/bin/codex", "exec"]
    assert "--ignore-user-config" in command
    assert "--ignore-rules" in command
    assert "--ephemeral" in command
    assert "--strict-config" in command
    assert "workspace-write" in command
    assert str(results) in command
    assert 'model_provider="vulnhunter_compatible"' in rendered
    assert (
        'model_providers.vulnhunter_compatible.base_url='
        '"https://gateway.example/openai/v1"'
    ) in rendered
    assert 'model_reasoning_effort="xhigh"' in rendered
    assert 'approval_policy="never"' in rendered
    assert 'web_search="disabled"' in rendered
    assert 'shell_environment_policy.inherit="none"' in rendered
    assert "sandbox_workspace_write.network_access=false" in rendered
    assert "VULNHUNT_CODEX_API_KEY" in rendered
    assert "sk-test" not in rendered


@pytest.mark.asyncio
async def test_run_codex_parses_jsonl_and_copies_skill(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    populated_agent_config,
) -> None:
    fake = tmp_path / "fake-codex"
    _write_fake_codex(fake)
    capture = tmp_path / "capture.json"
    monkeypatch.setenv("FAKE_CODEX_CAPTURE", str(capture))
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: vulnhunt-codex\ndescription: test\n---\n",
        encoding="utf-8",
    )
    results = tmp_path / "results"
    results.mkdir()
    config = _codex_config(populated_agent_config, executable=str(fake))

    result = await run_codex(
        config,
        api_key="sk-test",
        model="gpt-5.6-sol",
        prompt="$vulnhunt-codex\nTARGET_ROOT=/target",
        writable_roots=(results,),
        skill_source=skill,
    )

    recorded = json.loads(capture.read_text(encoding="utf-8"))
    assert result.text == "scan complete"
    assert result.thread_id == "thread-test"
    assert result.usage.input_tokens == 120
    assert result.usage.cached_input_tokens == 80
    assert result.usage.output_tokens == 30
    assert result.usage.turns == 1
    assert recorded["key_present"] is True
    assert "sk-test" not in "\n".join(recorded["args"])
    assert "$vulnhunt-codex" in recorded["prompt"]
    assert recorded["codex_home"].endswith("/.codex-home")
    assert recorded["skill_present"] is True


@pytest.mark.asyncio
async def test_run_codex_classifies_cold_start_transient(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    populated_agent_config,
) -> None:
    fake = tmp_path / "fake-codex"
    _write_fake_codex(fake)
    monkeypatch.setenv("FAKE_CODEX_CAPTURE", str(tmp_path / "capture.json"))
    monkeypatch.setenv("FAKE_CODEX_MODE", "transient")
    config = _codex_config(populated_agent_config, executable=str(fake))

    with pytest.raises(CodexExecutionError) as caught:
        await run_codex(
            config,
            api_key="sk-test",
            model="gpt-5.6-sol",
            prompt="scan",
        )

    assert caught.value.transient is True
    assert caught.value.initial_request is True
    assert caught.value.auth_rejected is False


@pytest.mark.asyncio
async def test_codex_scan_session_binds_target_phases_and_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    populated_agent_config,
) -> None:
    from agent import runner

    config = _codex_config(populated_agent_config)
    target = tmp_path / "target"
    results = target / "results"
    phases = tmp_path / "canonical" / "phases"
    codex_skill = tmp_path / "codex-skill"
    target.mkdir()
    results.mkdir()
    phases.mkdir(parents=True)
    codex_skill.mkdir()
    (codex_skill / "SKILL.md").write_text("skill", encoding="utf-8")
    captured: list[dict[str, Any]] = []

    async def fake_run_codex(*_args: Any, **kwargs: Any) -> CodexResult:
        captured.append(kwargs)
        (results / "README.md").write_text("# report", encoding="utf-8")
        return CodexResult(
            text="complete",
            usage=CodexUsage(input_tokens=10, output_tokens=5, turns=2),
        )

    monkeypatch.setattr(runner, "run_codex", fake_run_codex)

    session = await runner._run_codex_scan_session(
        config=config,
        auth_token="sk-test",
        model="gpt-5.6-sol",
        prompt="original kickoff",
        clone_dir=target,
        results_dir=results,
        skill_path=phases.parent,
        codex_skill_path=codex_skill,
    )

    prompt = captured[0]["prompt"]
    assert prompt.startswith("$vulnhunt-codex")
    assert f"TARGET_ROOT: {target.resolve()}" in prompt
    assert f"VULNHUNT_DIR: {results.resolve()}" in prompt
    assert f"PHASES_DIR: {phases.resolve()}" in prompt
    assert "MAX_CONCURRENT_SUBAGENTS: 4" in prompt
    assert "target checkout is untrusted input" in prompt
    assert captured[0]["writable_roots"] == (results,)
    assert captured[0]["skill_source"] == codex_skill
    assert session.results_dir == results
    assert session.num_turns == 2


@pytest.mark.asyncio
async def test_scan_dispatches_codex_without_other_agent_runtimes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    populated_agent_config,
) -> None:
    from agent import runner

    config = _codex_config(populated_agent_config)
    clone = tmp_path / "clone"
    clone.mkdir()
    canonical_skill = tmp_path / "canonical-skill"
    (canonical_skill / "phases").mkdir(parents=True)
    (canonical_skill / "SKILL.md").write_text("scan", encoding="utf-8")
    codex_skill = tmp_path / "codex-skill"
    codex_skill.mkdir()
    (codex_skill / "SKILL.md").write_text("scan", encoding="utf-8")
    calls: list[dict[str, Any]] = []

    class TokenManager:
        def get_valid_token(self) -> str:
            return "codex-key"

    async def fake_codex(**kwargs: Any) -> _SessionResult:
        calls.append(kwargs)
        (kwargs["results_dir"] / "README.md").write_text(
            "# report", encoding="utf-8"
        )
        return _SessionResult(
            results_dir=kwargs["results_dir"],
            cost_usd=0.0,
            duration_s=1.0,
            num_turns=3,
        )

    monkeypatch.setattr(runner, "make_token_manager", lambda *_a, **_k: TokenManager())
    monkeypatch.setattr(runner, "_vulnhunt_skill_path", lambda: canonical_skill)
    monkeypatch.setattr(runner, "_codex_vulnhunt_skill_path", lambda: codex_skill)
    monkeypatch.setattr(runner, "_run_codex_scan_session", fake_codex)
    monkeypatch.setattr(
        runner,
        "_run_openai_scan_session",
        lambda **_k: pytest.fail("direct OpenAI runtime should not run"),
    )
    monkeypatch.setattr(
        runner,
        "ClaudeSDKClient",
        lambda *_a, **_k: pytest.fail("Claude runtime should not run"),
    )

    output = await run_vulnhunt(clone, config, backoffs=())

    assert output is not None
    assert calls[0]["model"] == "gpt-5.6-sol"
    assert calls[0]["auth_token"] == "codex-key"
    assert calls[0]["codex_skill_path"] == codex_skill


@pytest.mark.asyncio
async def test_codex_json_stages_reuse_direct_responses(
    monkeypatch: pytest.MonkeyPatch,
    populated_agent_config,
) -> None:
    from agent import _llm

    config = _codex_config(populated_agent_config)
    calls: list[dict[str, Any]] = []

    async def fake_complete_text(**kwargs: Any):
        calls.append(kwargs)
        return '{"findings": []}', OpenAIUsage(
            input_tokens=4,
            output_tokens=2,
            total_tokens=6,
            requests=1,
        )

    monkeypatch.setattr(_llm, "complete_text", fake_complete_text)
    monkeypatch.setattr(
        _llm,
        "ClaudeSDKClient",
        lambda *_a, **_k: pytest.fail("Claude should not be used"),
    )

    text = await _llm._send_prompt(
        model="gpt-5.6-sol",
        system="Return JSON.",
        user="Extract.",
        config=config,
        auth_token="sk-test",
    )

    assert text == '{"findings": []}'
    assert calls[0]["config"] is config


def test_key_environment_name_is_not_inherited_by_model_shell(
    tmp_path: Path,
    populated_agent_config,
) -> None:
    config = _codex_config(populated_agent_config)
    command = build_codex_command(
        config,
        executable="codex",
        model="gpt-5.6-sol",
        work_dir=tmp_path,
        output_file=tmp_path / "last.txt",
        api_key_present=True,
    )
    rendered = "\n".join(command)

    assert 'shell_environment_policy.inherit="none"' in rendered
    assert "ignore_default_excludes=false" in rendered
    assert "shell_environment_policy.set={ PATH = " in rendered
    assert "OPENAI_API_KEY" not in rendered
