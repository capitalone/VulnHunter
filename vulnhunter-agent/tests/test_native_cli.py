from __future__ import annotations

import asyncio
import json
import os
import subprocess
from pathlib import Path

from vulnhunter.cli import (
    _ask_level,
    _ask_model_count,
    _browse_model_list,
    _browse_provider_model_list,
    _configure_models_interactively,
    _configure_fresh_model_roster,
    _choose_team_aliases,
    _load_env_file,
    _live_scan_summary,
    _make_progress_handler,
    _choose_reasoning_effort,
    _render_progress,
    _resolve_target,
    _run_guided_init_scan,
    _set_color_mode,
    main,
)
from vulnhunter.config import load_engine_config, parse_engine_config, save_model_roster
from vulnhunter.inventory import build_inventory
from vulnhunter.models import ScanLevel


def _config():
    return parse_engine_config(
        {
            "providers": {
                "local": {
                    "kind": "openai_compatible",
                    "base_url": "http://local",
                    "remote": False,
                }
            },
            "models": {
                "a": {"provider": "local", "model": "a", "priority": 1},
                "b": {"provider": "local", "model": "b", "priority": 2},
            },
        }
    )


def test_scan_wizard_uses_two_questions(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hello')\n")
    answers = iter(["2", "2"])
    calls: list[str] = []

    def fake_input(prompt: str) -> str:
        calls.append(prompt)
        return next(answers)

    monkeypatch.setattr("builtins.input", fake_input)
    level = _ask_level()
    count = _ask_model_count(
        _config(), ["a", "b"], build_inventory(tmp_path), level, []
    )
    assert level == ScanLevel.STANDARD
    assert count == 2
    assert len(calls) == 2


def test_scan_subset_picker_chooses_specific_saved_model(monkeypatch) -> None:
    monkeypatch.setattr("builtins.input", lambda _prompt: "2")

    selected = _choose_team_aliases(_config(), ["a", "b"], 1)

    assert selected == ["b"]


def test_reasoning_picker_offers_auto_and_supported_levels(monkeypatch) -> None:
    monkeypatch.setattr("builtins.input", lambda _prompt: "3")

    selected = _choose_reasoning_effort(
        "vendor/reasoner",
        {"supported_reasoning_efforts": ["low", "medium", "high"]},
    )

    assert selected == "medium"


def test_incomplete_scan_offers_checkpoint_resume(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hello')\n")
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[providers.local]\n"
        'kind = "openai_compatible"\n'
        'base_url = "http://local"\n'
        "remote = false\n\n"
        "[models.local]\n"
        'provider = "local"\n'
        'model = "coder"\n'
        "remote = false\n",
        encoding="utf-8",
    )
    results = tmp_path / "results"
    calls = []

    class FakeEngine:
        def __init__(self, _config, *, progress=None):
            del progress

        async def scan(self, request):
            calls.append(request)
            status = "INCOMPLETE_COVERAGE" if len(calls) == 1 else "COMPLETE_CLEAN"
            return (
                {
                    "status": status,
                    "usage": {},
                    "coverage": {
                        "unfinished_assignments": ["hunt-1"] if len(calls) == 1 else []
                    },
                },
                results,
            )

    async def healthy(_config, *, progress=None):
        del progress
        return [("local", True, "ok")]

    monkeypatch.setattr("vulnhunter.cli.ScanEngine", FakeEngine)
    monkeypatch.setattr("vulnhunter.cli._model_health", healthy)
    monkeypatch.setattr("builtins.input", lambda _prompt: "y")

    code = main(
        [
            "scan",
            str(repo),
            "--config",
            str(config_path),
            "--level",
            "quick",
            "--models",
            "1",
        ]
    )

    assert code == 0
    assert len(calls) == 2
    assert calls[1].resume is True
    assert calls[1].results_dir == str(results)


def test_provider_env_file_loads_without_overriding_process_env(
    monkeypatch, tmp_path: Path
) -> None:
    env_file = tmp_path / "providers.env"
    env_file.write_text(
        "# provider credentials\n"
        "export OPENROUTER_API_KEY='from-file'\n"
        'GEMINI_API_KEY="gemini-file"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENROUTER_API_KEY", "from-process")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    _load_env_file(env_file, required=True)

    assert os.environ["OPENROUTER_API_KEY"] == "from-process"
    assert os.environ["GEMINI_API_KEY"] == "gemini-file"


def test_env_example_command_writes_template(tmp_path: Path) -> None:
    destination = tmp_path / "providers.env"

    assert main(["env-example", "--write", str(destination)]) == 0

    content = destination.read_text(encoding="utf-8")
    assert "OPENROUTER_API_KEY=" in content
    assert "GEMINI_API_KEY=" in content


def test_init_reuses_existing_config_without_force(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[providers.local]\n"
        'kind = "openai_compatible"\n'
        'base_url = "http://local"\n'
        "remote = false\n\n"
        "[models.local]\n"
        'provider = "local"\n'
        'model = "coder"\n'
        "remote = false\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)

    result = main(
        ["init", "--config", str(config_path), "--skip-model-picker"]
    )

    assert result == 0
    assert "Using existing VulnHunter config" in capsys.readouterr().out


def test_setup_only_init_adds_codex_without_starting_scan_wizard(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[providers.openrouter]\n"
        'kind = "openrouter"\n'
        'base_url = "https://openrouter.test/v1"\n'
        "remote = true\n\n"
        "[models.openrouter]\n"
        'provider = "openrouter"\n'
        'model = "vendor/model"\n'
        "remote = true\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "vulnhunter.cli.discover_codex_cli",
        lambda: {
            "model": "gpt-test",
            "context_tokens": 200_000,
            "supported_reasoning_efforts": ["low", "medium", "high"],
        },
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt: "y")

    async def healthy(_config, *, probe_models=True):
        del probe_models
        return []

    monkeypatch.setattr("vulnhunter.cli.doctor", healthy)

    assert main(["init", "--config", str(config_path), "--setup-only"]) == 0

    output = capsys.readouterr().out
    assert "Added Codex CLI provider" in output
    assert "[providers.codex-cli]" in config_path.read_text(encoding="utf-8")


def test_guided_init_collects_target_depth_team_and_confirmation(
    monkeypatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[providers.local]\n"
        'kind = "openai_compatible"\n'
        'base_url = "http://local"\n'
        "remote = false\n\n"
        "[models.local]\n"
        'provider = "local"\n'
        'model = "coder"\n'
        "remote = false\n",
        encoding="utf-8",
    )
    answers = iter([str(repo), "", "2", "1", ""])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))

    async def configure(config, *, discovered=None, target_count=None):
        del discovered
        assert target_count == 1
        save_model_roster(config, [next(iter(config.models.values()))])

    async def healthy(_config, *, probe_models=True):
        del probe_models
        return [
            {
                "alias": "local",
                "provider": "local",
                "model": "coder",
                "remote": False,
                "ok": True,
                "detail": "ok",
            }
        ]

    captured = {}

    async def scan(args):
        captured.update(vars(args))
        return 0

    monkeypatch.setattr("vulnhunter.cli._configure_fresh_model_roster", configure)
    monkeypatch.setattr("vulnhunter.cli.doctor", healthy)
    monkeypatch.setattr("vulnhunter.cli._run_scan", scan)

    assert asyncio.run(_run_guided_init_scan(config_path, instructions=None)) == 0
    assert captured["target"] == str(repo)
    assert captured["level"] == "standard"
    assert captured["models"] == 1
    assert captured["yes"] is True
    assert captured["ref"] is None


def test_guided_init_does_not_start_with_unhealthy_provider(
    monkeypatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[providers.local]\n"
        'kind = "openai_compatible"\n'
        'base_url = "http://local"\n'
        "remote = false\n\n"
        "[models.local]\n"
        'provider = "local"\n'
        'model = "coder"\n'
        "remote = false\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "vulnhunter.cli._ask_scan_target", lambda: (str(repo), None)
    )
    monkeypatch.setattr("vulnhunter.cli._ask_level", lambda: ScanLevel.QUICK)
    monkeypatch.setattr("vulnhunter.cli._ask_initial_model_count", lambda: 1)
    answers = iter(["", "n"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))

    async def configure(config, *, discovered=None, target_count=None):
        del discovered, target_count
        save_model_roster(config, [next(iter(config.models.values()))])

    async def unhealthy(_config, *, probe_models=True):
        del probe_models
        return [
            {
                "alias": "local",
                "provider": "local",
                "model": "coder",
                "remote": False,
                "ok": False,
                "detail": "preflight failed",
            }
        ]

    async def should_not_scan(_args):
        raise AssertionError("scan should not start")

    monkeypatch.setattr("vulnhunter.cli._configure_fresh_model_roster", configure)
    monkeypatch.setattr("vulnhunter.cli.doctor", unhealthy)
    monkeypatch.setattr("vulnhunter.cli._run_scan", should_not_scan)

    assert asyncio.run(_run_guided_init_scan(config_path, instructions=None)) == 0


def test_resolve_local_git_ref_uses_isolated_checkout(
    monkeypatch, tmp_path: Path
) -> None:
    repo = tmp_path / "source"
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    (repo / "app.py").write_text("print('v1')\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "app.py"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=VulnHunter Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-m",
            "fixture",
        ],
        check=True,
        capture_output=True,
    )
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

    checkout = _resolve_target(str(repo), resume=None, git_ref="HEAD")

    assert checkout != repo.resolve()
    assert (checkout / "app.py").read_text(encoding="utf-8") == "print('v1')\n"


def test_help_lists_commands_and_examples(capsys) -> None:
    assert main(["help"]) == 0

    output = capsys.readouterr().out
    assert "available commands" in output
    assert "vulnhunter scan ." in output
    assert "vulnhunter help COMMAND" in output


def test_help_topic_prints_command_options(capsys) -> None:
    assert main(["help", "scan"]) == 0

    output = capsys.readouterr().out
    assert "usage: vulnhunter scan" in output
    assert "--level" in output
    assert "--max-cost-usd" in output


def test_model_browser_searches_and_selects(monkeypatch) -> None:
    answers = iter(["/gemini", "2"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))

    selected = _browse_model_list(
        alias="router",
        provider="openrouter",
        current="openrouter/auto",
        models=[
            "openrouter/auto",
            "google/gemini-a",
            "google/gemini-b",
            "vendor/unrelated",
        ],
        metadata={"google/gemini-b": {"context_tokens": 1_048_576}},
    )

    assert selected == "google/gemini-b"


def test_unified_model_browser_groups_providers_with_continuous_numbers(
    monkeypatch, capsys
) -> None:
    monkeypatch.setattr("builtins.input", lambda _prompt: "3")

    selected = _browse_provider_model_list(
        title="Active model providers",
        discovered={
            "codex-cli": {
                "models": ["gpt-a", "gpt-b"],
                "metadata": {
                    "gpt-a": {"billing_label": "ChatGPT/Codex plan"},
                    "gpt-b": {"billing_label": "ChatGPT/Codex plan"},
                },
                "account": {},
                "error": "",
            },
            "openrouter": {
                "models": ["vendor/first", "vendor/second"],
                "metadata": {
                    "vendor/first": {
                        "context_tokens": 131_072,
                        "input_cost_per_million": 0.5,
                        "output_cost_per_million": 1.0,
                    }
                },
                "account": {},
                "error": "",
            },
        },
        provider_order=["codex-cli", "openrouter"],
        current_identities={("codex-cli", "gpt-a"): "codex-cli"},
        allow_done=True,
    )

    output = capsys.readouterr().out
    assert selected == ("openrouter", "vendor/first")
    assert "──── Codex CLI / ChatGPT plan ────" in output
    assert "   1. gpt-a" in output
    assert "   2. gpt-b" in output
    assert "──── openrouter ────" in output
    assert "   3. vendor/first" in output


def test_model_browser_explains_filter_and_page_boundaries(
    monkeypatch, capsys
) -> None:
    answers = iter(["/search", "n", "/", "1"])
    prompts: list[str] = []

    def fake_input(prompt: str) -> str:
        prompts.append(prompt)
        return next(answers)

    monkeypatch.setattr("builtins.input", fake_input)
    selected = _browse_model_list(
        alias="router",
        provider="openrouter",
        current="openrouter/auto",
        models=["openrouter/auto", "vendor/search-model", "vendor/chat-model"],
    )

    output = capsys.readouterr().out
    assert selected == "openrouter/auto"
    assert "filter: 'search'" in output
    assert "Already on the last page." in output
    assert "/text to filter" in prompts[0]
    assert "/ to clear" in prompts[0]


def test_model_browser_shows_context_window(monkeypatch, capsys) -> None:
    monkeypatch.setattr("builtins.input", lambda _prompt: "1")

    _browse_model_list(
        alias="router",
        provider="openrouter",
        current="vendor/model",
        models=["vendor/model", "vendor/unknown"],
        metadata={
            "vendor/model": {
                "context_tokens": 131_072,
                "input_cost_per_million": 0.05,
                "output_cost_per_million": 1.0,
            }
        },
    )

    output = capsys.readouterr().out
    assert "131k" in output
    assert "$.05/M in - $1/M out" in output
    assert "vendor/unknown — unknown — pricing unknown" in output
    assert "no input cache" in output


def test_model_browser_colors_name_context_and_pricing_separately(
    monkeypatch, capsys
) -> None:
    monkeypatch.setattr("builtins.input", lambda _prompt: "1")
    _set_color_mode("always")
    try:
        _browse_model_list(
            alias="router",
            provider="openrouter",
            current="vendor/model",
            models=["vendor/model"],
            metadata={
                "vendor/model": {
                    "context_tokens": 131_072,
                    "input_cost_per_million": 0.05,
                    "output_cost_per_million": 1.0,
                }
            },
        )
    finally:
        _set_color_mode("auto")

    output = capsys.readouterr().out
    assert "\033[1;36mvendor/model\033[0m" in output
    assert "\033[33m131k\033[0m" in output
    assert "\033[32m$.05/M in - $1/M out\033[0m" in output


def test_model_browser_hides_reasoning_until_after_selection(
    monkeypatch, capsys
) -> None:
    monkeypatch.setattr("builtins.input", lambda _prompt: "1")

    _browse_model_list(
        alias="router",
        provider="openrouter",
        current="vendor/reasoner",
        models=["vendor/reasoner"],
        metadata={
            "vendor/reasoner": {
                "context_tokens": 1_048_576,
                "supported_reasoning_efforts": [
                    "minimal",
                    "low",
                    "medium",
                    "high",
                    "xhigh",
                ],
                "default_reasoning_effort": "medium",
            }
        },
    )

    output = capsys.readouterr().out
    assert "1M" in output
    assert "thinking" not in output
    assert "minimal/low/medium/high/xhigh" not in output


def test_model_browser_pins_and_highlights_three_free_models(
    monkeypatch, capsys
) -> None:
    monkeypatch.setattr("builtins.input", lambda _prompt: "1")
    models = ["vendor/paid", "vendor/free-a", "vendor/free-b", "vendor/free-c"]
    metadata = {
        model_id: {
            "free": model_id != "vendor/paid",
            "input_cost_per_million": 0 if model_id != "vendor/paid" else 1,
            "output_cost_per_million": 0 if model_id != "vendor/paid" else 2,
        }
        for model_id in models
    }

    selected = _browse_model_list(
        alias="router",
        provider="openrouter",
        current="vendor/paid",
        models=models,
        metadata=metadata,
        account={"is_free_tier": False, "usage_daily": 0.25, "usage": 2.0},
    )

    output = capsys.readouterr().out
    assert selected == "vendor/free-a"
    assert "3 free models pinned" in output
    assert "1,000 free-model requests/day" in output
    assert "remaining request count unavailable" in output
    assert "OpenRouter usage: $.25 today, $2 total" in output
    assert "vendor/free-a" in output and "FREE" in output


def test_progress_uses_semantic_status_colors(capsys) -> None:
    _set_color_mode("always")
    try:
        _render_progress("phase_started", {"phase": "Independent hunts"})
        _render_progress(
            "assignment_complete",
            {
                "model": "model-a",
                "kind": "hunt",
                "input_tokens": 100,
                "output_tokens": 25,
                "cost_usd": 0.01,
                "duration_seconds": 2.5,
            },
        )
        _render_progress(
            "assignment_failed",
            {"model": "model-b", "kind": "review", "error": "timeout"},
        )
    finally:
        _set_color_mode("auto")

    output = capsys.readouterr().out
    assert "\033[1;34m" in output
    assert "\033[32m" in output
    assert "\033[1;31m" in output


def test_live_status_line_colorizes_independent_metrics() -> None:
    _set_color_mode("always")
    try:
        output = _live_scan_summary(
            {
                "run_elapsed_seconds": 596,
                "priced_requests": 49,
                "observed_cost_usd": 0.6379,
                "requests_so_far": 49,
                "tool_calls_so_far": 56,
                "adaptive_cost_low_usd": 0.6379,
                "adaptive_cost_high_usd": 0.7,
                "estimate": {"minutes_high": 16},
            }
        )
    finally:
        _set_color_mode("auto")

    assert "elapsed" in output and "9m 56s" in output
    assert "spent" in output and "$.63" in output
    assert "49" in output and "responses" in output
    assert "Est. ~$.70" in output and "ETA ~6m 4s" in output
    assert "56" in output and "tool calls" in output
    assert "\033[1;37m" in output  # elapsed value
    assert "\033[32m" in output  # spend
    assert "\033[1;35m" in output  # response count
    assert "\033[33m" in output  # projection
    assert "\033[1;34m" in output  # ETA


def test_progress_handler_writes_jsonl_when_console_is_quiet(tmp_path: Path) -> None:
    log_file = tmp_path / "scan-progress.jsonl"
    progress = _make_progress_handler(
        quiet=True, verbose=True, log_file=str(log_file)
    )

    progress("model_waiting", {"model": "model-a", "elapsed_seconds": 15})

    record = json.loads(log_file.read_text(encoding="utf-8"))
    assert record["event"] == "model_waiting"
    assert record["model"] == "model-a"
    assert record["timestamp"]


def test_live_progress_recalibrates_cost_from_provider_responses(capsys) -> None:
    progress = _make_progress_handler(quiet=False, verbose=False, log_file=None)
    progress(
        "scan_estimate",
        {
            "cost_known": True,
            "cost_low_usd": 1.0,
            "cost_high_usd": 3.0,
            "minutes_low": 10,
            "minutes_high": 30,
            "requests_low": 10,
            "requests_high": 30,
        },
    )
    progress(
        "model_request_complete",
        {
            "model": "model-a",
            "cost_usd": 0.5,
            "input_tokens": 10_000,
            "output_tokens": 1_000,
            "duration_seconds": 5,
            "tool_calls": 1,
        },
    )
    progress("tool_calls", {"model": "model-a", "count": 1, "tools": ["read_file"]})
    progress("model_waiting", {"model": "model-a", "elapsed_seconds": 6})

    output = capsys.readouterr().out
    assert "$.5 this response" in output
    assert "$.5 observed total" in output
    assert "spent $.50" in output
    assert "Est. ~$25.87" in output
    assert "1 tool calls" in output


def test_model_picker_builds_and_persists_multi_model_roster(
    monkeypatch, tmp_path: Path
) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[providers.router]\n"
        'kind = "openrouter"\n\n'
        "[models.router]\n"
        'provider = "router"\n'
        'model = "vendor/first"\n'
        "priority = 10\n",
        encoding="utf-8",
    )
    answers = iter(["", "y", "1", "n"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))

    asyncio.run(
        _configure_models_interactively(
            load_engine_config(config_path),
            discovered={
                "router": {
                    "models": ["vendor/first", "vendor/second"],
                    "error": "",
                }
            },
        )
    )

    reloaded = load_engine_config(config_path)
    assert [model.model for model in reloaded.models.values()] == [
        "vendor/first",
        "vendor/second",
    ]


def test_model_picker_counts_mixed_provider_core_models(monkeypatch, tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[providers.router]\n"
        'kind = "openrouter"\n\n'
        "[providers.codex-cli]\n"
        'kind = "codex_cli"\n\n'
        "[models.router]\n"
        'provider = "router"\n'
        'model = "vendor/first"\n\n'
        "[models.router-2]\n"
        'provider = "router"\n'
        'model = "vendor/second"\n\n'
        "[models.router-3]\n"
        'provider = "router"\n'
        'model = "vendor/third"\n\n'
        "[models.codex-cli]\n"
        'provider = "codex-cli"\n'
        'model = "gpt-test"\n',
        encoding="utf-8",
    )
    prompts: list[str] = []
    answers = iter(["", "n"])

    def answer(prompt: str) -> str:
        prompts.append(prompt)
        return next(answers)

    monkeypatch.setattr("builtins.input", answer)
    asyncio.run(
        _configure_models_interactively(
            load_engine_config(config_path),
            discovered={
                "router": {
                    "models": ["vendor/first", "vendor/second", "vendor/third"],
                    "error": "",
                },
                "codex-cli": {"models": ["gpt-test"], "error": ""},
            },
        )
    )

    assert "Add a fifth core model?" in prompts[-1]


def test_fresh_roster_picker_selects_exact_count_and_replaces_old_team(
    monkeypatch, tmp_path: Path
) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[providers.router]\n"
        'kind = "openrouter"\n\n'
        "[models.router]\n"
        'provider = "router"\n'
        'model = "vendor/first"\n',
        encoding="utf-8",
    )
    config = load_engine_config(config_path, apply_model_defaults=False)
    answers = iter(["2", "1", "1"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))

    asyncio.run(
        _configure_fresh_model_roster(
            config,
            discovered={
                "router": {
                    "models": ["vendor/first", "vendor/second", "vendor/third"],
                    "metadata": {},
                    "error": "",
                }
            },
        )
    )

    reloaded = load_engine_config(config_path)
    assert [model.model for model in reloaded.models.values()] == [
        "vendor/first",
        "vendor/second",
    ]
