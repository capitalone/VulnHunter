"""Standalone VulnHunter command-line interface."""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime
from dataclasses import replace
from pathlib import Path
from typing import Any

from .config import (
    DEFAULT_CONFIG_PATH,
    EngineConfig,
    choose_models,
    load_engine_config,
    save_additional_model,
    save_model_defaults,
)
from .engine import ScanEngine, estimate_scan
from .instructions import SUPPORTED_TOOLS, render_instructions
from .inventory import build_inventory
from .models import RunStatus, ScanLevel, ScanLimits, ScanRequest, SpecialistSpec
from .providers import create_provider
from .setup import (
    PROVIDER_ENV_EXAMPLE,
    append_codex_cli_config,
    discover_codex_cli,
    doctor,
    write_env_example,
    write_initial_config,
)


LEVEL_DESCRIPTIONS = {
    ScanLevel.QUICK: "Broad scan, minimal review                Lowest cost",
    ScanLevel.STANDARD: "Independent hunts + cross-review          Recommended",
    ScanLevel.DEEP: "Gap analysis + additional verification   Higher cost",
    ScanLevel.EXHAUSTIVE: "Maximum static coverage and evidence      Highest cost",
}

DEFAULT_ENV_PATH = Path.home() / ".vulnhunter" / "providers.env"
_COLOR_MODE = "auto"

_CYAN_BOLD = "1;36"
_YELLOW = "33"
_GREEN = "32"
_GREEN_BOLD = "1;32"
_BLUE_BOLD = "1;34"
_RED_BOLD = "1;31"
_MAGENTA_BOLD = "1;35"
_WHITE_BOLD = "1;37"
_DIM = "2"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnhunter",
        description="Provider-neutral, multi-model security scanner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  vulnhunter init
  vulnhunter doctor
  vulnhunter models --provider openrouter
  vulnhunter scan .
  vulnhunter scan . --level standard --models 2 --yes
  vulnhunter instructions codex

Run 'vulnhunter help COMMAND' for detailed command help.
""",
    )
    parser.add_argument("--version", action="version", version="%(prog)s 0.2.0")
    parser.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="terminal colors: auto, always, or never (default: auto)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    help_parser = subparsers.add_parser(
        "help", help="show available commands or detailed command help"
    )
    help_parser.add_argument(
        "topic",
        nargs="?",
        choices=("init", "doctor", "models", "scan", "instructions", "env-example"),
        help="command to explain",
    )

    env_parser = subparsers.add_parser(
        "env-example", help="print or write a provider credential template"
    )
    env_parser.add_argument("--write", help="write the template to this path")
    env_parser.add_argument(
        "--force", action="store_true", help="replace an existing template file"
    )

    models_parser = subparsers.add_parser(
        "models", help="browse provider models and save scanner defaults"
    )
    models_parser.add_argument("--config", default=None, help="config TOML path")
    models_parser.add_argument("--env-file", help="provider credential env file")
    models_parser.add_argument("--provider", help="only query this provider alias")
    models_parser.add_argument(
        "--list", action="store_true", help="print models without opening the picker"
    )
    models_parser.add_argument(
        "--json", action="store_true", help="print discovered models as JSON"
    )

    init_parser = subparsers.add_parser("init", help="detect providers and write config")
    init_parser.add_argument(
        "--config", default=str(DEFAULT_CONFIG_PATH), help="config TOML destination"
    )
    init_parser.add_argument("--env-file", help="provider credential env file")
    init_parser.add_argument(
        "--force", action="store_true", help="regenerate and replace existing config"
    )
    init_parser.add_argument(
        "--skip-model-picker", action="store_true", help="do not open model selection"
    )
    remote_group = init_parser.add_mutually_exclusive_group()
    remote_group.add_argument(
        "--allow-remote",
        action="store_true",
        help="record consent and configure detected remote providers",
    )
    remote_group.add_argument(
        "--local-only",
        action="store_true",
        help="do not configure detected remote providers",
    )
    init_parser.add_argument(
        "--instructions", choices=SUPPORTED_TOOLS, default=None
    )

    doctor_parser = subparsers.add_parser(
        "doctor", help="validate configured providers and local prerequisites"
    )
    doctor_parser.add_argument("--config", default=None, help="config TOML path")
    doctor_parser.add_argument("--env-file", help="provider credential env file")
    doctor_parser.add_argument(
        "--json", action="store_true", help="emit machine-readable diagnostics"
    )

    instructions_parser = subparsers.add_parser(
        "instructions", help="print a coding-tool walkthrough"
    )
    instructions_parser.add_argument(
        "tool", choices=SUPPORTED_TOOLS, help="coding tool to integrate"
    )

    scan_parser = subparsers.add_parser("scan", help="scan a local checkout or git URL")
    scan_parser.add_argument(
        "target", nargs="?", default=".", help="local checkout or Git clone URL"
    )
    scan_parser.add_argument("--config", default=None, help="config TOML path")
    scan_parser.add_argument("--env-file", help="provider credential env file")
    scan_parser.add_argument(
        "--level",
        choices=[row.value for row in ScanLevel],
        help="scan depth (wizard asks when omitted)",
    )
    scan_parser.add_argument(
        "--models", type=int, help="number of independent core models"
    )
    scan_parser.add_argument(
        "--team-model",
        action="append",
        default=[],
        help="explicit model alias; repeat to form a roster",
    )
    scan_parser.add_argument(
        "--specialist",
        action="append",
        default=[],
        help="supplemental profile or profile=model-alias; repeatable",
    )
    scan_parser.add_argument(
        "--max-cost-usd", type=float, help="stop before exceeding this API-cost cap"
    )
    scan_parser.add_argument(
        "--max-tokens", type=int, help="maximum total provider tokens"
    )
    scan_parser.add_argument(
        "--max-duration", help="wall-clock cap such as 30m or 4h"
    )
    scan_parser.add_argument(
        "--max-workers", type=int, default=4, help="maximum parallel assignments"
    )
    scan_parser.add_argument(
        "--execute",
        action="store_true",
        help="allow disclosed target commands in a configured sandbox",
    )
    scan_parser.add_argument(
        "--yes", action="store_true", help="non-interactive mode; accept shown roster"
    )
    scan_parser.add_argument(
        "--resume", help="resume an incomplete results directory"
    )
    scan_parser.add_argument(
        "--retry-incomplete",
        action="store_true",
        help="automatically retry failed/unfinished assignments once",
    )
    scan_parser.add_argument("--results-dir", help="custom artifact directory")
    scan_parser.add_argument(
        "--json", action="store_true", help="emit machine-readable final status"
    )
    scan_parser.add_argument(
        "--verbose",
        action="store_true",
        help="show provider rounds and repository-tool activity",
    )
    scan_parser.add_argument(
        "--log-file",
        help="append structured progress events to a JSONL file",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _set_color_mode(args.color)
    try:
        if args.command == "help":
            _print_command_help(parser, args.topic)
            return 0
        env_file = getattr(args, "env_file", None)
        if env_file:
            _load_env_file(Path(env_file).expanduser(), required=True)
        elif DEFAULT_ENV_PATH.is_file():
            _load_env_file(DEFAULT_ENV_PATH, required=False)
        if args.command == "init":
            return _run_init(args)
        if args.command == "env-example":
            if args.write:
                destination = Path(args.write).expanduser()
                write_env_example(destination, force=args.force)
                print(f"Wrote provider environment template: {destination}")
            else:
                print(PROVIDER_ENV_EXAMPLE, end="")
            return 0
        if args.command == "models":
            return asyncio.run(_run_models(args))
        if args.command == "instructions":
            print(render_instructions(args.tool))
            return 0
        if args.command == "doctor":
            return asyncio.run(_run_doctor(args))
        return asyncio.run(_run_scan(args))
    except KeyboardInterrupt:
        print(_paint("\nVulnHunter cancelled.", _YELLOW), file=sys.stderr)
        return 2
    except (FileNotFoundError, ValueError) as exc:
        print(_paint(f"error: {exc}", _RED_BOLD), file=sys.stderr)
        return 64
    except RuntimeError as exc:
        print(_paint(f"error: {exc}", _RED_BOLD), file=sys.stderr)
        return 4


def _print_command_help(
    parser: argparse.ArgumentParser, topic: str | None
) -> None:
    """Print top-level help or the help page for one subcommand."""
    if topic is None:
        parser.print_help()
        return
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            action.choices[topic].print_help()
            return
    raise ValueError(f"unknown help topic {topic!r}")


def _run_init(args: argparse.Namespace) -> int:
    path = Path(args.config).expanduser()
    if path.exists() and not args.force:
        print(f"Using existing VulnHunter config: {path}")
        print("Run with --force only if you want to regenerate and replace it.")
        config = load_engine_config(path)
        codex_added = False
        codex_detection = discover_codex_cli()
        if codex_detection and "codex-cli" not in config.providers:
            add_codex = bool(args.allow_remote)
            if not args.local_only and not args.allow_remote and sys.stdin.isatty():
                print(
                    "Authenticated Codex CLI detected. Codex can run as a remote "
                    "provider using its existing login; selected source is sent to OpenAI."
                )
                add_codex = input("Add the Codex CLI provider? [y/N]: ").strip().lower() in {
                    "y",
                    "yes",
                }
            if add_codex:
                append_codex_cli_config(path, config, codex_detection)
                print("Added Codex CLI provider without reading or storing OAuth tokens.")
                config = load_engine_config(path)
                codex_added = True
        elif codex_detection and "codex-cli" in config.providers:
            print(
                "Codex CLI provider is already configured. Its models are separate "
                "from OpenRouter; use 'vulnhunter models --provider codex-cli' "
                "to change the saved Codex model."
            )
        if not args.skip_model_picker and sys.stdin.isatty():
            if codex_added:
                print(
                    "\nChoose the Codex CLI model next. It is a separate provider "
                    "and will not appear in OpenRouter searches."
                )
                print(
                    "After setup, use 'vulnhunter models --provider codex-cli' "
                    "to change it again."
                )
                asyncio.run(
                    _configure_models_interactively(
                        config,
                        provider_filter="codex-cli",
                        offer_additional_models=False,
                    )
                )
            else:
                asyncio.run(_configure_models_interactively(config))
            config = load_engine_config(path)
        checks = asyncio.run(doctor(config, probe_models=False))
        for row in checks:
            marker = "✓" if row["ok"] else "✗"
            print(f"{marker} {row['alias']}: {row['detail']}")
        print("\nNext: vulnhunter doctor")
        return 0

    remote_detected = bool(discover_codex_cli()) or any(
        os.environ.get(name)
        for name in (
            "OPENROUTER_API_KEY",
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "GEMINI_API_KEY",
        )
    )
    if args.allow_remote:
        allow_remote = True
    elif args.local_only or not remote_detected:
        allow_remote = False
    else:
        print(
            "Detected credentials for one or more remote model providers. "
            "Selected repository source will be sent to each remote provider "
            "shown in the scan roster."
        )
        if not sys.stdin.isatty():
            raise ValueError(
                "non-interactive setup must specify --allow-remote or --local-only"
            )
        answer = input("Configure these remote providers? [y/N]: ").strip().lower()
        allow_remote = answer in {"y", "yes"}
    detections = write_initial_config(
        path,
        force=args.force,
        allow_remote=allow_remote,
    )
    print(f"Wrote provider-neutral config: {path}")
    for detection in detections:
        print(f"  ✓ {detection}")
    print("\nNo API keys were stored; the config references environment variables.")
    if allow_remote:
        print(
            "Remote-provider consent was recorded. Remote providers receive source "
            "only when selected and displayed at scan time."
        )
    else:
        print("Setup is local-only; no remote provider was configured.")
    config = load_engine_config(path)
    if not args.skip_model_picker and sys.stdin.isatty():
        asyncio.run(_configure_models_interactively(config))
        config = load_engine_config(path)
    checks = asyncio.run(doctor(config, probe_models=False))
    for row in checks:
        marker = "✓" if row["ok"] else "✗"
        print(
            f"{marker} {row['alias']}: {row['detail']}"
        )
    print("\nNext: vulnhunter doctor")
    if args.instructions:
        print()
        print(render_instructions(args.instructions))
    else:
        print(
            "Walkthroughs: vulnhunter instructions "
            "opencode|pi|codex|claude-code|generic"
        )
    return 0


async def _run_doctor(args: argparse.Namespace) -> int:
    config = load_engine_config(args.config)
    rows = await doctor(config)
    git_ok = shutil.which("git") is not None
    payload = {
        "config": str(config.source_path),
        "git": git_ok,
        "sandbox": config.sandbox.available,
        "models": rows,
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"Config: {config.source_path}")
        print(f"Git: {'ok' if git_ok else 'missing'}")
        print(
            "Execution sandbox: "
            + ("configured" if config.sandbox.available else "not configured (static scans work)")
        )
        for row in rows:
            marker = "✓" if row["ok"] else "✗"
            locality = "remote" if row["remote"] else "local"
            identity = _paint(
                f"{row['provider']}/{row['model']}", _CYAN_BOLD
            )
            print(
                f"{marker} {row['alias']}: {identity} "
                f"({locality}) — {row['detail']}"
            )
            if row.get("capabilities"):
                capabilities = row["capabilities"]
                print(
                    "    capabilities: "
                    + ", ".join(
                        f"{key}={value}"
                        for key, value in capabilities.items()
                    )
                )
    return 0 if git_ok and all(bool(row["ok"]) for row in rows) else 4


async def _run_scan(args: argparse.Namespace) -> int:
    config = load_engine_config(args.config)
    progress = _make_progress_handler(
        quiet=bool(args.json),
        verbose=bool(args.verbose),
        log_file=args.log_file,
    )
    if args.log_file:
        progress(
            "logging_started",
            {"path": str(Path(args.log_file).expanduser().resolve())},
        )
    progress("repository_prepare_started", {"target": args.target})
    repository = _resolve_target(args.target, resume=args.resume)
    progress("repository_prepare_complete", {"repository": str(repository)})
    progress("inventory_started", {"repository": str(repository)})
    inventory = build_inventory(repository)
    progress(
        "inventory_preflight_complete",
        {"files": len(inventory.files), "bytes": inventory.total_bytes},
    )
    progress("provider_check_started", {"models": len(config.models)})
    health = await _model_health(config, progress=progress)
    progress("provider_check_complete", {"models": len(health)})
    healthy_aliases = [alias for alias, ok, _detail in health if ok]
    failed_health = [
        f"{alias}: {detail}" for alias, ok, detail in health if not ok
    ]
    if not healthy_aliases:
        raise RuntimeError(
            "no configured models passed provider health checks"
            + (f" ({'; '.join(failed_health)})" if failed_health else "")
        )
    if failed_health:
        print(_paint("Unavailable models excluded from this scan:", _YELLOW))
        for failure in failed_health:
            print(_paint(f"  - {failure}", _YELLOW))

    prompted = 0
    if args.level:
        level = ScanLevel(args.level)
    elif args.yes:
        level = ScanLevel.QUICK
    else:
        level = _ask_level()
        prompted += 1

    specialists = _resolve_specialists(config, args.specialist)
    unavailable_specialists = [
        row.model_alias
        for row in specialists
        if row.enabled and row.model_alias not in healthy_aliases
    ]
    if unavailable_specialists:
        raise ValueError(
            "specialist models are unavailable: "
            + ", ".join(sorted(set(unavailable_specialists)))
        )

    if args.team_model:
        missing = [alias for alias in args.team_model if alias not in healthy_aliases]
        if missing:
            raise ValueError(f"requested models are unavailable: {', '.join(missing)}")
        selected_aliases = list(dict.fromkeys(args.team_model))
        if args.models and args.models != len(selected_aliases):
            raise ValueError("--models must match the number of --team-model values")
    elif args.models:
        if args.models > len(healthy_aliases):
            raise ValueError(
                f"requested {args.models} models, but only "
                f"{len(healthy_aliases)} passed preflight"
                + (f" ({'; '.join(failed_health)})" if failed_health else "")
            )
        selected_aliases = _select_aliases(config, healthy_aliases, args.models)
    elif args.yes:
        selected_aliases = _select_aliases(config, healthy_aliases, 1)
    else:
        count = _ask_model_count(
            config, healthy_aliases, inventory, level, specialists
        )
        prompted += 1
        if count == 0:
            await _configure_models_interactively(config)
            config = load_engine_config(args.config)
            health = await _model_health(config)
            healthy_aliases = [alias for alias, ok, _detail in health if ok]
            if not healthy_aliases:
                raise RuntimeError("no selected model passed provider health checks")
            specialists = _resolve_specialists(config, args.specialist)
            count = _ask_model_count(
                config, healthy_aliases, inventory, level, specialists
            )
            if count == 0:
                raise ValueError("model customization was already completed")
        selected_aliases = _select_aliases(config, healthy_aliases, count)

    selected = [config.models[alias] for alias in selected_aliases]
    specialist_models = [
        config.models[row.model_alias] for row in specialists if row.enabled
    ]
    estimate = estimate_scan(
        inventory,
        selected,
        level=level,
        specialist_models=specialist_models,
        max_workers=max(1, args.max_workers),
    )
    _print_preflight(
        config,
        level,
        selected,
        specialists,
        inventory,
        estimate,
        execute=bool(args.execute),
    )
    progress(
        "scan_estimate",
        {
            "cost_low_usd": estimate.get("cost_low_usd"),
            "cost_high_usd": estimate.get("cost_high_usd"),
            "cost_known": estimate.get("cost_usd") is not None,
            "minutes_low": estimate.get("minutes_low"),
            "minutes_high": estimate.get("minutes_high"),
            "requests_low": estimate.get("requests_low"),
            "requests_high": estimate.get("requests_high"),
            "assignments_low": estimate.get("assignments_low"),
            "assignments_high": estimate.get("assignments_high"),
            "partitions": estimate.get("partitions"),
            "basis": estimate.get("basis"),
            "confidence": estimate.get("confidence"),
        },
    )
    if (
        any(model.remote for model in [*selected, *specialist_models])
        and not args.yes
        and prompted == 0
    ):
        raise ValueError(
            "remote models require the interactive two-question flow or explicit --yes"
        )

    request = ScanRequest(
        repository=str(repository),
        level=level,
        model_aliases=selected_aliases,
        specialists=specialists,
        limits=ScanLimits(
            max_cost_usd=args.max_cost_usd,
            max_tokens=args.max_tokens,
            max_duration_seconds=_parse_duration(args.max_duration),
            max_workers=max(1, args.max_workers),
        ),
        execute=bool(args.execute),
        results_dir=args.resume or args.results_dir,
        resume=bool(args.resume),
    )
    retried_incomplete = False
    while True:
        manifest, results_dir = await ScanEngine(config, progress=progress).scan(request)
        incomplete = str(manifest["status"]).startswith("INCOMPLETE")
        automatic_retry_pending = (
            incomplete and not retried_incomplete and bool(args.retry_incomplete)
        )
        if args.json and not automatic_retry_pending:
            print(
                json.dumps(
                    {"results_dir": str(results_dir), "manifest": manifest}, indent=2
                )
            )
        elif not args.json:
            _print_scan_summary(manifest, results_dir)

        if not incomplete or retried_incomplete:
            break
        retry_now = bool(args.retry_incomplete)
        if not retry_now and not args.yes and not args.json:
            unfinished = len(
                (manifest.get("coverage") or {}).get("unfinished_assignments", [])
            )
            print(
                _paint(
                    f"Checkpoint available: {unfinished} failed or unfinished "
                    "assignment(s) can be retried without rerunning completed work.",
                    _YELLOW,
                )
            )
            retry_now = input("Resume incomplete work now? [y/N]: ").strip().lower() in {
                "y",
                "yes",
            }
        if not retry_now:
            break
        print(_paint("Resuming from the last checkpoint…", _BLUE_BOLD))
        request = replace(
            request,
            results_dir=str(results_dir),
            resume=True,
        )
        retried_incomplete = True
    return _status_exit(manifest["status"])


def _print_scan_summary(manifest: dict[str, Any], results_dir: Path) -> None:
    """Render a final or resumable scan summary."""
    status = str(manifest["status"])
    print(f"\nStatus:  {_paint_status(status)}")
    print(f"Results: {_paint(str(results_dir), _CYAN_BOLD)}")
    print(f"Report:  {_paint(str(results_dir / 'README.md'), _CYAN_BOLD)}")
    usage = manifest.get("usage", {})
    cost = usage.get("cost_usd")
    cost_label = _format_cost(float(cost)) if cost is not None else "unknown"
    print(
        "Usage:   "
        + _paint(
            f"{int(usage.get('requests', 0))} API requests; {cost_label} total",
            _GREEN,
        )
    )
    cached = int(usage.get("cached_input_tokens", 0))
    written = int(usage.get("cache_write_tokens", 0))
    retries = int(usage.get("rate_limit_retries", 0))
    cache_summary = (
        f"{cached:,} read / {written:,} written"
        if cached or written
        else "no cache usage reported"
    )
    print(f"Cache:   {_paint(cache_summary, _MAGENTA_BOLD)}")
    if retries:
        print(
            "Limits:  "
            + _paint(f"{retries} rate-limit retries during this scan", _YELLOW)
        )
    if status.startswith("INCOMPLETE"):
        status = str(manifest["status"])
        print(
            _paint(
                "WARNING: This scan is incomplete and must not be treated as clean.",
                _YELLOW,
            )
        )


async def _model_health(
    config: EngineConfig,
    *,
    progress: Any | None = None,
) -> list[tuple[str, bool, str]]:
    async def check(alias: str) -> tuple[str, bool, str]:
        model = config.models[alias]
        if progress is not None:
            progress(
                "model_preflight_started",
                {"model": alias, "provider": model.provider, "identity": model.model},
            )
        provider = create_provider(config.providers[model.provider])
        ok, detail = await provider.health(model)
        if progress is not None:
            progress(
                "model_preflight_complete",
                {
                    "model": alias,
                    "provider": model.provider,
                    "identity": model.model,
                    "ok": ok,
                    "detail": detail,
                },
            )
        return alias, ok, detail

    return list(await asyncio.gather(*(check(alias) for alias in config.models)))


def _ask_level() -> ScanLevel:
    print(_paint("Choose scan level:", _WHITE_BOLD))
    levels = list(ScanLevel)
    colors = (_GREEN, _CYAN_BOLD, _YELLOW, _MAGENTA_BOLD)
    for index, level in enumerate(levels, 1):
        name = _paint(f"{level.value.title():<12}", colors[index - 1])
        print(f"  {index}. {name} {LEVEL_DESCRIPTIONS[level]}")
    raw = input("Scan level [1]: ").strip() or "1"
    try:
        return levels[int(raw) - 1]
    except (ValueError, IndexError) as exc:
        raise ValueError("scan level must be 1, 2, 3, or 4") from exc


def _format_context(tokens: int | None) -> str:
    if not tokens:
        return "unknown"
    if tokens >= 1_000_000:
        millions = tokens / 1_000_000
        nearest = round(millions)
        value = (
            str(nearest)
            if abs(millions - nearest) < 0.1
            else f"{millions:.1f}".rstrip("0").rstrip(".")
        )
        return f"{value}M"
    if tokens >= 1_000:
        return f"{round(tokens / 1_000):,}k"
    return str(tokens)


def _format_price_value(value: float) -> str:
    rendered = f"{value:.4f}".rstrip("0").rstrip(".")
    if rendered.startswith("0."):
        rendered = rendered[1:]
    return f"${rendered}"


def _format_cost(value: float) -> str:
    if 0 < value < 0.0001:
        return "<$.0001"
    return _format_price_value(value)


def _format_status_cost(value: float) -> str:
    """Format live cumulative costs compactly without overstating them."""
    if 0 < value < 0.01:
        return "<$.01"
    truncated = math.floor(max(0.0, value) * 100) / 100
    rendered = f"{truncated:.2f}"
    if rendered.startswith("0."):
        rendered = rendered[1:]
    return f"${rendered}"


def _cost_source_label(value: Any) -> str:
    return {
        "provider": "provider-reported billing",
        "estimate": "catalog estimate",
        "mixed": "mixed reported/estimated billing",
    }.get(str(value), "billing source unknown")


def _format_elapsed(seconds: float) -> str:
    total = max(0, int(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def _live_scan_summary(details: dict[str, Any]) -> str:
    elapsed = float(details.get("run_elapsed_seconds", 0))
    priced = int(details.get("priced_requests", 0))
    spent = (
        _format_status_cost(float(details.get("observed_cost_usd", 0)))
        if priced
        else "awaiting provider usage"
    )
    estimate = details.get("estimate") or {}
    if details.get("adaptive_cost_high_usd") is not None:
        adaptive_high = float(details["adaptive_cost_high_usd"])
        forecast = f"Est. ~{_format_status_cost(adaptive_high)}"
    elif estimate.get("cost_known"):
        forecast = f"Est. ~{_format_status_cost(float(estimate.get('cost_high_usd', 0)))}"
    else:
        forecast = "Est. unknown"
    high_minutes = estimate.get("minutes_high")
    if high_minutes is not None:
        remaining = float(high_minutes) * 60 - elapsed
        eta = (
            f"ETA ~{_format_elapsed(remaining)}"
            if remaining > 0
            else "ETA window exceeded"
        )
    else:
        eta = "ETA unknown"
    requests = int(details.get("requests_so_far", 0))
    tool_calls = int(details.get("tool_calls_so_far", 0))
    separator = _paint("  |  ", _DIM)
    return separator.join(
        (
            f"{_paint('elapsed', _DIM)} "
            f"{_paint(_format_elapsed(elapsed), _WHITE_BOLD)} "
            f"{_paint(f'({eta})', _BLUE_BOLD)}",
            f"{_paint('spent', _DIM)} {_paint(spent, _GREEN)} "
            f"{_paint(f'({forecast})', _YELLOW)}",
            f"{_paint(str(requests), _MAGENTA_BOLD)} "
            f"{_paint('responses', _DIM)}",
            f"{_paint(str(tool_calls), _CYAN_BOLD)} "
            f"{_paint('tool calls', _DIM)}",
        )
    )


def _format_pricing(metadata: dict[str, Any], *, local: bool = False) -> str:
    if metadata.get("billing_label"):
        return str(metadata["billing_label"])
    if local:
        return "$0 API"
    input_price = metadata.get("input_cost_per_million")
    output_price = metadata.get("output_cost_per_million")
    if input_price is None or output_price is None:
        return "pricing unknown"
    return (
        f"{_format_price_value(float(input_price))}/M in - "
        f"{_format_price_value(float(output_price))}/M out"
    )


def _format_model_pricing(model: Any) -> str:
    if getattr(model, "billing_label", ""):
        return str(model.billing_label)
    return _format_pricing(
        {
            "input_cost_per_million": model.input_cost_per_million,
            "output_cost_per_million": model.output_cost_per_million,
        },
        local=not model.remote,
    )


def _format_cache(metadata: dict[str, Any]) -> str:
    if not metadata.get("input_cache_supported"):
        return "no input cache"
    read_price = metadata.get("cache_read_cost_per_million")
    if read_price is None:
        return "input cache supported"
    return f"cache {_format_price_value(float(read_price))}/M read"


def _format_reasoning(metadata: dict[str, Any]) -> str:
    efforts = metadata.get("supported_reasoning_efforts") or []
    if not efforts:
        return ""
    default = str(metadata.get("default_reasoning_effort") or "auto")
    return f"thinking {default} default ({'/'.join(str(row) for row in efforts)})"


def _print_free_model_notice(count: int, account: dict[str, Any]) -> None:
    is_free_tier = account.get("is_free_tier")
    if is_free_tier is True:
        limit = "about 50 free-model requests/day"
    elif is_free_tier is False:
        limit = "up to 1,000 free-model requests/day for eligible funded accounts"
    else:
        limit = "50/day by default or 1,000/day for eligible funded accounts"
    print(
        "  "
        + _paint(f"★ {min(3, count)} free models pinned", _GREEN_BOLD)
        + _paint(
            f" ({count} free available; {limit}; remaining request count unavailable)",
            _DIM,
        )
    )
    if account.get("usage_daily") is not None:
        usage_daily = _format_price_value(float(account["usage_daily"]))
        usage_total = _format_price_value(float(account.get("usage", 0)))
        remaining = account.get("limit_remaining")
        remaining_label = (
            f"; key spend limit remaining {_format_price_value(float(remaining))}"
            if remaining is not None
            else ""
        )
        print(
            "  "
            + _paint(
                f"OpenRouter usage: {usage_daily} today, {usage_total} total"
                f"{remaining_label}",
                _DIM,
            )
        )
    print(
        "  "
        + _paint(
            "Free models can be slower or unavailable; repeated 429s will trigger "
            "backoff and a paid-model recommendation.",
            _YELLOW,
        )
    )


def _set_color_mode(mode: str) -> None:
    global _COLOR_MODE
    _COLOR_MODE = mode


def _colors_enabled() -> bool:
    if _COLOR_MODE == "never" or "NO_COLOR" in os.environ:
        return False
    if _COLOR_MODE == "always":
        return True
    return bool(sys.stdout.isatty() and os.environ.get("TERM", "") != "dumb")


def _paint(value: str, code: str) -> str:
    return f"\033[{code}m{value}\033[0m" if _colors_enabled() else value


def _model_summary(model: Any, *, include_locality: bool = True) -> str:
    pieces = [
        _paint(f"{model.provider}/{model.model}", _CYAN_BOLD),
        _paint(_format_context(model.context_tokens), _YELLOW),
        _paint(_format_model_pricing(model), _GREEN),
    ]
    if getattr(model, "reasoning_effort", "auto") != "auto":
        pieces.append(f"reasoning {model.reasoning_effort}")
    if include_locality:
        pieces.append("remote" if model.remote else "local")
    return f"{pieces[0]} ({'; '.join(pieces[1:])})"


def _paint_status(status: str) -> str:
    if status == "COMPLETE_CLEAN":
        color = _GREEN
    elif status == "COMPLETE_FINDINGS":
        color = _MAGENTA_BOLD
    elif status in {"COMPLETE_CONDITIONAL", "INCOMPLETE_LIMIT", "INCOMPLETE_COVERAGE"}:
        color = _YELLOW
    elif status == "FAILED":
        color = _RED_BOLD
    else:
        color = _BLUE_BOLD
    return _paint(status, color)


def _make_progress_handler(
    *, quiet: bool, verbose: bool, log_file: str | None
) -> Any:
    log_path = Path(log_file).expanduser().resolve() if log_file else None
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
    telemetry: dict[str, Any] = {
        "started_at": None,
        "observed_cost_usd": 0.0,
        "priced_requests": 0,
        "requests": 0,
        "tool_calls": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "cached_input_tokens": 0,
        "estimate": {},
        "estimate_exceeded_reported": False,
    }

    def handle(event: str, details: dict[str, Any]) -> None:
        if event == "scan_estimate":
            telemetry["started_at"] = time.monotonic()
            telemetry["estimate"] = dict(details)
        elif event == "tool_calls":
            telemetry["tool_calls"] += int(details.get("count", 0))
        elif event == "model_request_complete":
            telemetry["requests"] += 1
            telemetry["input_tokens"] += int(details.get("input_tokens", 0))
            telemetry["output_tokens"] += int(details.get("output_tokens", 0))
            telemetry["cached_input_tokens"] += int(
                details.get("cached_input_tokens", 0)
            )
            if details.get("cost_usd") is not None:
                telemetry["observed_cost_usd"] += float(details["cost_usd"])
                telemetry["priced_requests"] += 1
        enriched = dict(details)
        started_at = telemetry.get("started_at")
        enriched.update(
            {
                "run_elapsed_seconds": (
                    time.monotonic() - float(started_at) if started_at else 0.0
                ),
                "observed_cost_usd": telemetry["observed_cost_usd"],
                "priced_requests": telemetry["priced_requests"],
                "requests_so_far": telemetry["requests"],
                "tool_calls_so_far": telemetry["tool_calls"],
                "input_tokens_so_far": telemetry["input_tokens"],
                "output_tokens_so_far": telemetry["output_tokens"],
                "cached_input_tokens_so_far": telemetry["cached_input_tokens"],
                "estimate": telemetry["estimate"],
            }
        )
        estimate = telemetry["estimate"]
        priced_requests = int(telemetry["priced_requests"])
        if priced_requests and estimate.get("requests_high") is not None:
            average_cost = telemetry["observed_cost_usd"] / priced_requests
            remaining_low = max(
                0, int(estimate.get("requests_low", 0)) - telemetry["requests"]
            )
            remaining_high = max(
                0, int(estimate.get("requests_high", 0)) - telemetry["requests"]
            )
            enriched["adaptive_cost_low_usd"] = telemetry["observed_cost_usd"] + (
                average_cost * remaining_low * 0.6
            )
            enriched["adaptive_cost_high_usd"] = telemetry["observed_cost_usd"] + (
                average_cost * remaining_high * 1.75
            )
        preflight_high = estimate.get("cost_high_usd")
        enriched["preflight_cost_exceeded"] = bool(
            preflight_high is not None
            and telemetry["observed_cost_usd"] > float(preflight_high)
        )
        enriched["preflight_cost_exceeded_just_now"] = bool(
            enriched["preflight_cost_exceeded"]
            and not telemetry["estimate_exceeded_reported"]
        )
        if enriched["preflight_cost_exceeded"]:
            telemetry["estimate_exceeded_reported"] = True
        if log_path is not None:
            record = {
                "timestamp": datetime.now(UTC).isoformat(),
                "event": event,
                **enriched,
            }
            with log_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record, sort_keys=True, default=str) + "\n")
        if not quiet:
            _render_progress(event, enriched, verbose=verbose)

    return handle


def _render_progress(
    event: str, details: dict[str, Any], *, verbose: bool = False
) -> None:
    """Render stable, line-oriented progress that remains readable in logs."""
    if event == "provider_check_started":
        print(
            _paint("◆ Checking provider and model availability", _BLUE_BOLD)
            + _paint(f" ({details['models']} configured)", _DIM)
        )
    elif event == "provider_check_complete":
        print(_paint("✓ Provider preflight complete", _GREEN))
    elif event == "model_preflight_started":
        print(
            f"  {_paint('→', _BLUE_BOLD)} checking "
            f"{_paint(str(details['model']), _CYAN_BOLD)} "
            + _paint(
                f"({details['provider']}/{details['identity']})", _DIM
            )
        )
    elif event == "model_preflight_complete":
        marker = _paint("✓", _GREEN) if details.get("ok") else _paint("✗", _RED_BOLD)
        detail_color = _DIM if details.get("ok") else _RED_BOLD
        print(
            f"  {marker} {_paint(str(details['model']), _CYAN_BOLD)}: "
            f"{_paint(str(details.get('detail', '')), detail_color)}"
        )
    elif event == "logging_started":
        print(
            _paint("◆ Structured progress log", _BLUE_BOLD)
            + f": {_paint(str(details['path']), _CYAN_BOLD)}"
        )
    elif event == "repository_prepare_started":
        print(
            _paint("◆ Preparing repository", _BLUE_BOLD)
            + _paint(f" ({details['target']})", _DIM)
        )
    elif event == "repository_prepare_complete":
        print(
            _paint("✓ Repository ready", _GREEN)
            + f": {_paint(str(details['repository']), _CYAN_BOLD)}"
        )
    elif event == "inventory_started":
        print(_paint("◆ Discovering production files", _BLUE_BOLD))
    elif event == "inventory_preflight_complete":
        print(
            _paint("✓ File discovery complete", _GREEN)
            + _paint(f" ({details['files']} production files)", _DIM)
        )
    elif event == "model_discovery_started":
        print(
            _paint("◆ Discovering provider model catalogs", _BLUE_BOLD)
            + _paint(f" ({details['providers']} providers)", _DIM)
        )
    elif event == "model_discovery_complete":
        print(
            _paint("✓ Model discovery complete", _GREEN)
            + _paint(f" ({details['models']} models)", _DIM)
        )
    elif event == "inventory_complete":
        print(
            "\n"
            + _paint("◆ Repository inventory ready", _BLUE_BOLD)
            + _paint(
                f" ({details['files']} files, {details['partitions']} partitions)",
                _DIM,
            )
        )
    elif event == "results_directory_ready":
        print(
            _paint("◆ Resumable state directory", _BLUE_BOLD)
            + f": {_paint(str(details['results_dir']), _CYAN_BOLD)}"
        )
    elif event == "scan_estimate":
        if details.get("cost_known"):
            cost = (
                f"{_format_cost(float(details['cost_low_usd']))}–"
                f"{_format_cost(float(details['cost_high_usd']))}"
            )
        else:
            cost = "cost unknown"
        print(
            "\n"
            + _paint("◆ Initial scan forecast", _BLUE_BOLD)
            + _paint(
                f" ({cost}; {details.get('minutes_low')}–"
                f"{details.get('minutes_high')} min; "
                f"{details.get('requests_low')}–{details.get('requests_high')} "
                "provider responses)",
                _DIM,
            )
        )
        print(
            "  "
            + _paint(
                "Based on repository partitions and expected agent/tool turns; "
                "live provider usage will recalibrate this range.",
                _YELLOW,
            )
        )
    elif event == "free_team_mode":
        print(
            "\n"
            + _paint("◆ Free-team pacing enabled", _YELLOW)
            + _paint(
                f" ({details['models']} free models; one assignment at a time; "
                f"at least {float(details['spacing_seconds']):g}s between requests)",
                _DIM,
            )
        )
        print(
            "  "
            + _paint(
                "This scan will be slower to stay below the shared 20 RPM free-model limit.",
                _YELLOW,
            )
        )
    elif event == "free_request_paced":
        print(
            f"  {_paint('…', _YELLOW)} pacing "
            f"{_paint(str(details['model']), _CYAN_BOLD)} for "
            f"{float(details['delay_seconds']):.1f}s"
        )
    elif event == "phase_started":
        print("\n" + _paint(f"◆ {details['phase']}", _BLUE_BOLD))
    elif event == "assignment_started":
        print(
            f"  {_paint('→', _BLUE_BOLD)} "
            f"{_paint(str(details['model']), _CYAN_BOLD)} running "
            f"{_paint(str(details['kind']), _MAGENTA_BOLD)} "
            f"{_paint(str(details['assignment']), _DIM)}"
        )
    elif event == "model_waiting":
        print(
            f"    {_paint('…', _BLUE_BOLD)} "
            f"{_paint(str(details['model']), _CYAN_BOLD)} is still generating "
            + _paint(
                f"({float(details['elapsed_seconds']):.0f}s elapsed)", _DIM
            )
        )
        print("      " + _live_scan_summary(details))
    elif event == "tool_calls":
        tools = ", ".join(str(row) for row in details.get("tools", []))
        print(
            f"    {_paint('↳', _MAGENTA_BOLD)} "
            f"{_paint(str(details['model']), _CYAN_BOLD)} requested "
            f"{_paint(tools or 'repository tools', _MAGENTA_BOLD)}"
        )
    elif event == "model_request_started" and verbose:
        print(
            f"    {_paint('·', _BLUE_BOLD)} sending provider request for "
            f"{_paint(str(details['model']), _CYAN_BOLD)} "
            + _paint(f"(attempt {details['attempt']})", _DIM)
        )
    elif event == "model_request_complete":
        request_cost = details.get("cost_usd")
        request_cost_label = (
            _format_cost(float(request_cost))
            if request_cost is not None
            else "cost not reported"
        )
        observed_total_label = (
            _format_cost(float(details["observed_cost_usd"]))
            if int(details.get("priced_requests", 0))
            else "cost unavailable"
        )
        print(
            f"    {_paint('$', _GREEN_BOLD)} provider response from "
            f"{_paint(str(details['model']), _CYAN_BOLD)} "
            + _paint(
                f"({request_cost_label} this response; "
                f"{observed_total_label} observed total; "
                f"{_cost_source_label(details.get('cost_source'))})",
                _DIM,
            )
        )
        print("      " + _live_scan_summary(details))
        if verbose:
            print(
                "      "
                + _paint(
                    f"{int(details.get('input_tokens', 0)):,} input + "
                    f"{int(details.get('output_tokens', 0)):,} output tokens; "
                    f"{float(details.get('duration_seconds', 0)):.1f}s; "
                    f"{details.get('tool_calls', 0)} tool calls",
                    _DIM,
                )
            )
        if details.get("preflight_cost_exceeded_just_now"):
            print(
                "      "
                + _paint(
                    "Observed spend has exceeded the initial high estimate. "
                    "Use the live estimate above; cancel with Ctrl-C if needed.",
                    _RED_BOLD,
                )
            )
    elif event == "model_output_retry":
        print(
            f"    {_paint('!', _YELLOW)} "
            f"{_paint(str(details['model']), _CYAN_BOLD)} returned invalid final JSON; "
            + _paint(
                f"repair attempt {details['attempt']}/{details['max_attempts']}",
                _YELLOW,
            )
        )
        if verbose and details.get("error"):
            print("      " + _paint(str(details["error"]), _DIM))
    elif event == "model_result_received" and verbose:
        suffix = " after schema repair" if details.get("repaired") else ""
        print(
            f"    {_paint('·', _GREEN)} structured result accepted for "
            f"{_paint(str(details['model']), _CYAN_BOLD)}{suffix}"
        )
    elif event == "assignment_complete":
        total_tokens = int(details.get("input_tokens", 0)) + int(
            details.get("output_tokens", 0)
        )
        cost = details.get("cost_usd")
        cost_label = (
            _format_cost(float(cost)) if cost is not None else "cost unknown"
        )
        if cost is not None:
            cost_label += f" ({_cost_source_label(details.get('cost_source'))})"
        duration = float(details.get("duration_seconds", 0))
        cached = int(details.get("cached_input_tokens", 0))
        cache_label = f", {cached:,} cached" if cached else ""
        retries = int(details.get("rate_limit_retries", 0))
        retry_label = f", {retries} rate-limit retries" if retries else ""
        print(
            f"  {_paint('✓', _GREEN)} "
            f"{_paint(str(details['model']), _CYAN_BOLD)} completed "
            f"{_paint(str(details['kind']), _MAGENTA_BOLD)} "
            + _paint(
                f"({total_tokens:,} tokens{cache_label}, {cost_label}, "
                f"{duration:.1f}s{retry_label})",
                _DIM,
            )
        )
    elif event == "assignment_failed":
        print(
            f"  {_paint('✗', _RED_BOLD)} "
            f"{_paint(str(details['model']), _CYAN_BOLD)} failed "
            f"{_paint(str(details['kind']), _MAGENTA_BOLD)}: "
            f"{_paint(str(details.get('error', 'unknown error')), _RED_BOLD)}"
        )
        failed_cost = details.get("cost_usd")
        if failed_cost is not None:
            failed_tokens = int(details.get("input_tokens", 0)) + int(
                details.get("output_tokens", 0)
            )
            print(
                "    "
                + _paint(
                    f"Billed work retained: {_format_cost(float(failed_cost))}, "
                    f"{failed_tokens:,} tokens, {int(details.get('requests', 0))} responses "
                    f"({_cost_source_label(details.get('cost_source'))})",
                    _YELLOW,
                )
            )
        error = str(details.get("error", "")).casefold()
        if "429" in error or "rate limit" in error:
            print(
                "    "
                + _paint(
                    "Repeated rate limiting exhausted retries. Consider switching "
                    "this team member to a paid model.",
                    _YELLOW,
                )
            )
    elif event == "rate_limited":
        print(
            f"  {_paint('!', _YELLOW)} "
            f"{_paint(str(details['model']), _CYAN_BOLD)} rate limited; "
            f"retrying in {float(details['delay_seconds']):g}s "
            + _paint(f"(attempt {details['attempt']}/2)", _DIM)
        )
    elif event == "assignment_resumed":
        print(
            f"  {_paint('↻', _YELLOW)} reused completed "
            f"{_paint(str(details['assignment']), _DIM)}"
        )
    elif event == "candidates_merged":
        print(
            _paint("◆ Candidate aggregation", _MAGENTA_BOLD)
            + _paint(f" ({details['candidates']} unique candidates)", _DIM)
        )
    elif event == "report_started":
        print("\n" + _paint("◆ Generating reports and manifests", _BLUE_BOLD))
    elif event == "scan_complete":
        print(
            _paint("✓ Scan workflow finished", _GREEN)
            + _paint(f" ({details['candidates']} candidates)", _DIM)
        )


def _ask_model_count(
    config: EngineConfig,
    healthy_aliases: list[str],
    inventory: Any,
    level: ScanLevel,
    specialists: list[SpecialistSpec],
) -> int:
    print("\nChoose number of core models:")
    if specialists:
        print("Configured supplemental specialists:")
        for specialist in specialists:
            model = config.models[specialist.model_alias]
            locality = "REMOTE — source will be sent" if model.remote else "local"
            print(
                f"  + {specialist.profile}: {specialist.model_alias} ({locality})"
            )
    for count in range(1, len(healthy_aliases) + 1):
        aliases = _select_aliases(config, healthy_aliases, count)
        models = [config.models[alias] for alias in aliases]
        estimate = estimate_scan(
            inventory,
            models,
            level=level,
            specialist_models=[
                config.models[row.model_alias]
                for row in specialists
                if row.enabled
            ],
        )
        roster = " + ".join(
            _model_summary(model)
            for model in models
        )
        cost = (
            f"${estimate['cost_low_usd']:.2f}–${estimate['cost_high_usd']:.2f}"
            if estimate["cost_usd"] is not None
            else "cost unknown"
        )
        print(
            f"  {count}. {count} model{'s' if count != 1 else ''}: {roster} — "
            f"{cost}, {estimate['minutes_low']}–{estimate['minutes_high']} min"
        )
    print("  m. Browse current provider models and change saved defaults")
    raw = input("Number of models [1], or m to change models: ").strip() or "1"
    if raw.lower() in {"m", "models", "change"}:
        return 0
    try:
        count = int(raw)
    except ValueError as exc:
        raise ValueError("model count must be a number") from exc
    if count < 1 or count > len(healthy_aliases):
        raise ValueError(f"model count must be between 1 and {len(healthy_aliases)}")
    return count


async def _run_models(args: argparse.Namespace) -> int:
    config = load_engine_config(args.config)
    if not args.json and not args.list and sys.stdin.isatty():
        _render_progress(
            "model_discovery_started",
            {"providers": 1 if args.provider else len(config.providers)},
        )
    discovered = await _discover_provider_models(config, args.provider)
    if not args.json and not args.list and sys.stdin.isatty():
        _render_progress(
            "model_discovery_complete",
            {"models": sum(len(row["models"]) for row in discovered.values())},
        )
    if args.list or args.json or not sys.stdin.isatty():
        if args.json:
            print(json.dumps(discovered, indent=2, sort_keys=True))
        else:
            for provider, row in discovered.items():
                if row["error"]:
                    print(
                        _paint(
                            f"{provider}: unavailable — {row['error']}", _RED_BOLD
                        )
                    )
                    continue
                print(f"{provider}: {len(row['models'])} models")
                for model_id in row["models"]:
                    details = row.get("metadata", {}).get(model_id, {})
                    context = details.get("context_tokens")
                    print(
                        f"  {_paint(model_id, _CYAN_BOLD)} — "
                        f"{_paint(_format_context(int(context) if context else None), _YELLOW)} — "
                        f"{_paint(_format_pricing(details, local=bool(details.get('local'))), _GREEN)}"
                        + (
                            f" — {_paint(_format_reasoning(details), _BLUE_BOLD)}"
                            if _format_reasoning(details)
                            else ""
                        )
                    )
        return 0 if all(not row["error"] for row in discovered.values()) else 4
    await _configure_models_interactively(
        config,
        provider_filter=args.provider,
        discovered=discovered,
    )
    return 0


async def _discover_provider_models(
    config: EngineConfig, provider_filter: str | None = None
) -> dict[str, dict[str, Any]]:
    names = [
        name
        for name in config.providers
        if provider_filter is None or name == provider_filter
    ]
    if provider_filter and not names:
        raise ValueError(f"unknown provider {provider_filter!r}")

    async def discover(
        name: str,
    ) -> tuple[str, list[str], dict[str, dict[str, Any]], dict[str, Any], str]:
        provider = create_provider(config.providers[name])
        try:
            metadata_method = getattr(provider, "list_model_metadata", None)
            if callable(metadata_method):
                metadata = await metadata_method()
                models = sorted(set(metadata), key=str.casefold)
            else:
                models = sorted(set(await provider.list_models()), key=str.casefold)
                metadata = {model_id: {} for model_id in models}
            for details in metadata.values():
                details["local"] = not config.providers[name].remote
            account_method = getattr(provider, "account_status", None)
            try:
                account = await account_method() if callable(account_method) else {}
            except Exception as exc:  # noqa: BLE001
                account = {"query_error": f"{type(exc).__name__}: {exc}"}
            return name, models, metadata, account, ""
        except Exception as exc:  # noqa: BLE001
            return name, [], {}, {}, f"{type(exc).__name__}: {exc}"

    rows = await asyncio.gather(*(discover(name) for name in names))
    return {
        name: {
            "models": models,
            "metadata": metadata,
            "account": account,
            "error": error,
        }
        for name, models, metadata, account, error in rows
    }


async def _configure_models_interactively(
    config: EngineConfig,
    *,
    provider_filter: str | None = None,
    discovered: dict[str, dict[str, Any]] | None = None,
    offer_additional_models: bool = True,
) -> None:
    discovered = discovered or await _discover_provider_models(
        config, provider_filter
    )
    selections = {alias: model.model for alias, model in config.models.items()}
    selection_contexts = {
        alias: model.context_tokens for alias, model in config.models.items()
    }
    selection_input_costs = {
        alias: model.input_cost_per_million
        for alias, model in config.models.items()
        if model.input_cost_per_million is not None
    }
    selection_output_costs = {
        alias: model.output_cost_per_million
        for alias, model in config.models.items()
        if model.output_cost_per_million is not None
    }
    selection_reasoning = {
        alias: model.reasoning_effort for alias, model in config.models.items()
    }
    changed = False
    provider_aliases: dict[str, list[str]] = {}
    for alias, model in sorted(
        config.models.items(), key=lambda item: item[1].priority
    ):
        if provider_filter and model.provider != provider_filter:
            continue
        provider_aliases.setdefault(model.provider, []).append(alias)
    provider_order = sorted(
        provider_aliases,
        key=lambda name: (
            0 if config.providers[name].kind == "codex_cli" else 1,
            0 if not config.providers[name].remote else 1,
            min(config.models[alias].priority for alias in provider_aliases[name]),
            name,
        ),
    )
    unavailable = [
        f"{provider}: {discovered[provider]['error']}"
        for provider in provider_order
        if discovered.get(provider, {}).get("error")
    ]
    for detail in unavailable:
        print(f"  {_paint('unavailable', _YELLOW)} — {detail}")
    selectable = {
        provider: discovered[provider]
        for provider in provider_order
        if provider in discovered
        and not discovered[provider].get("error")
        and discovered[provider].get("models")
    }
    print(
        "\nModel defaults (active providers share one numbered catalog; "
        "Enter finishes)"
    )
    while selectable:
        current_identities = {
            (model.provider, selections.get(alias, model.model)): alias
            for alias, model in config.models.items()
            if model.provider in selectable
        }
        choice = _browse_provider_model_list(
            title="Active model providers",
            discovered=selectable,
            provider_order=[row for row in provider_order if row in selectable],
            current_identities=current_identities,
            allow_done=True,
        )
        if choice is None:
            break
        provider_name, selected = choice
        alias = provider_aliases[provider_name][0]
        model = config.models[alias]
        row = selectable[provider_name]
        details = row.get("metadata", {}).get(selected, {})
        if selections.get(alias) != selected:
            selections[alias] = selected
            changed = True
        discovered_context = details.get("context_tokens")
        if discovered_context and int(discovered_context) != model.context_tokens:
            selection_contexts[alias] = int(discovered_context)
            changed = True
        selected_reasoning = _choose_reasoning_effort(
            selected,
            details,
            current=selection_reasoning.get(alias, "auto"),
        )
        if selected_reasoning != selection_reasoning.get(alias, "auto"):
            selection_reasoning[alias] = selected_reasoning
            changed = True
        for key, destination in (
            ("input_cost_per_million", selection_input_costs),
            ("output_cost_per_million", selection_output_costs),
        ):
            if details.get(key) is None:
                if alias in destination and selected != model.model:
                    destination.pop(alias)
                    changed = True
            elif destination.get(alias) != float(details[key]):
                destination[alias] = float(details[key])
                changed = True
        print(
            f"Selected {_paint(provider_name, _MAGENTA_BOLD)} / "
            f"{_paint(selected, _CYAN_BOLD)} for alias {alias}."
        )
        break
    if changed:
        path = save_model_defaults(
            config,
            selections,
            selection_contexts,
            selection_input_costs,
            selection_output_costs,
            selection_reasoning,
        )
        print(f"Saved model defaults: {path}")
    else:
        print("Model defaults unchanged.")

    if not offer_additional_models:
        return

    selected_identities = {
        (model.provider, selections.get(alias, model.model))
        for alias, model in config.models.items()
    }
    next_number = 2
    while any(alias.endswith(f"-{next_number}") for alias in config.models):
        next_number += 1
    ordinal = {2: "second", 3: "third"}.get(next_number, f"#{next_number}")
    while input(f"Add a {ordinal} core model? [y/N]: ").strip().lower() in {"y", "yes"}:
        available = {
            name: row
            for name, row in discovered.items()
            if not row["error"]
            and any(
                (name, model_id) not in selected_identities
                for model_id in row["models"]
            )
        }
        if not available:
            print("No provider model catalogs are available.")
            break
        unselected = {
            name: {
                **row,
                "models": [
                    model_id
                    for model_id in row["models"]
                    if (name, model_id) not in selected_identities
                ],
            }
            for name, row in available.items()
        }
        choice = _browse_provider_model_list(
            title=f"Choose core model {next_number}",
            discovered=unselected,
            provider_order=[row for row in provider_order if row in unselected],
            current_identities={},
            allow_done=False,
        )
        assert choice is not None
        provider_name, selected_model = choice
        template = next(
            model for model in config.models.values() if model.provider == provider_name
        )
        alias = f"{provider_name}-{next_number}"
        while alias in config.models:
            next_number += 1
            alias = f"{provider_name}-{next_number}"
        selected_details = (
            discovered[provider_name]
            .get("metadata", {})
            .get(selected_model, {})
        )
        selected_reasoning = _choose_reasoning_effort(
            selected_model,
            selected_details,
            current="auto",
        )
        extra = replace(
            template,
            alias=alias,
            model=selected_model,
            priority=max(model.priority for model in config.models.values()) + 1,
            context_tokens=int(
                discovered[provider_name]
                .get("metadata", {})
                .get(selected_model, {})
                .get("context_tokens")
                or template.context_tokens
            ),
            input_cost_per_million=(
                float(selected_details["input_cost_per_million"])
                if selected_details.get("input_cost_per_million") is not None
                else None
            ),
            output_cost_per_million=(
                float(selected_details["output_cost_per_million"])
                if selected_details.get("output_cost_per_million") is not None
                else None
            ),
            reasoning_effort=selected_reasoning,
            supported_reasoning_efforts=tuple(
                str(value)
                for value in selected_details.get(
                    "supported_reasoning_efforts", []
                )
            ),
            billing_label=str(selected_details.get("billing_label", "")),
        )
        path = save_additional_model(config, extra)
        config = replace(config, models={**config.models, alias: extra})
        selected_identities.add(extra.identity)
        print(
            f"Added {alias}: "
            f"{_paint(f'{provider_name}/{selected_model}', _CYAN_BOLD)}"
        )
        print(f"Saved core-team roster: {path}")
        next_number += 1
        ordinal = {2: "second", 3: "third"}.get(next_number, f"#{next_number}")


def _browse_provider_model_list(
    *,
    title: str,
    discovered: dict[str, dict[str, Any]],
    provider_order: list[str],
    current_identities: dict[tuple[str, str], str],
    allow_done: bool,
) -> tuple[str, str] | None:
    """Browse all active provider catalogs with continuous numbering."""
    catalog: list[tuple[str, str]] = []
    for provider in provider_order:
        row = discovered.get(provider, {})
        metadata = row.get("metadata", {})
        models = list(dict.fromkeys(str(value) for value in row.get("models", [])))
        free = [model_id for model_id in models if metadata.get(model_id, {}).get("free")]
        pinned = free[:3]
        ordered = [*pinned, *[model_id for model_id in models if model_id not in pinned]]
        catalog.extend((provider, model_id) for model_id in ordered)
    filtered = catalog
    filter_term = ""
    page = 0
    page_size = 20
    free_notices: set[str] = set()
    while True:
        pages = max(1, (len(filtered) + page_size - 1) // page_size)
        page = min(page, pages - 1)
        start = page * page_size
        visible = list(enumerate(filtered[start : start + page_size], start + 1))
        print(
            f"\n{title} (page {page + 1}/{pages}, {len(filtered)} models"
            f"{f', filter: {filter_term!r}' if filter_term else ''})"
        )
        previous_provider = ""
        for index, (provider, model_id) in visible:
            row = discovered[provider]
            details = row.get("metadata", {}).get(model_id, {})
            if provider != previous_provider:
                provider_kind = (
                    "Codex CLI / ChatGPT plan"
                    if provider == "codex-cli"
                    else provider
                )
                print(
                    "  "
                    + _paint(
                        f"──── {provider_kind} ────",
                        _MAGENTA_BOLD,
                    )
                )
                previous_provider = provider
                if (
                    not filter_term
                    and provider not in free_notices
                    and any(
                        row.get("metadata", {}).get(value, {}).get("free")
                        for value in row.get("models", [])
                    )
                ):
                    free_count = sum(
                        1
                        for value in row.get("models", [])
                        if row.get("metadata", {}).get(value, {}).get("free")
                    )
                    _print_free_model_notice(
                        free_count, dict(row.get("account", {}))
                    )
                    free_notices.add(provider)
            context = details.get("context_tokens")
            context_label = _format_context(int(context) if context else None)
            pricing_label = _format_pricing(
                details, local=bool(details.get("local"))
            )
            cache_label = _format_cache(details)
            current_alias = current_identities.get((provider, model_id))
            marker = f" * current: {current_alias}" if current_alias else ""
            free_badge = (
                " " + _paint("FREE", _GREEN_BOLD) if details.get("free") else ""
            )
            print(
                f"  {index:>4}. {_paint(model_id, _CYAN_BOLD)} — "
                f"{_paint(context_label, _YELLOW)} — "
                f"{_paint(pricing_label, _GREEN)} — "
                f"{_paint(cache_label, _MAGENTA_BOLD)}"
                f"{free_badge}{marker}"
            )
        finish = "finish" if allow_done else "select a model"
        raw = input(
            "Choose number, /text to filter all providers, / to clear, "
            f"n(ext), p(revious), or Enter to {finish}: "
        ).strip()
        if not raw:
            if allow_done:
                return None
            print("Select a displayed model number.")
            continue
        if raw.lower() in {"n", "next"}:
            if page >= pages - 1:
                print("Already on the last page.")
            else:
                page += 1
            continue
        if raw.lower() in {"p", "prev", "previous"}:
            if page == 0:
                print("Already on the first page.")
            else:
                page -= 1
            continue
        if raw.startswith("/"):
            term = raw[1:].strip().casefold()
            filtered = (
                [
                    item
                    for item in catalog
                    if term in item[0].casefold() or term in item[1].casefold()
                ]
                if term
                else catalog
            )
            page = 0
            if not filtered:
                print("No models matched that search.")
                filtered = catalog
                filter_term = ""
            else:
                filter_term = term
            continue
        try:
            choice = int(raw) - 1
        except ValueError:
            print("Enter a displayed number or one of the navigation commands.")
            continue
        if 0 <= choice < len(filtered):
            return filtered[choice]
        print("That model number is outside the filtered list.")


def _browse_model_list(
    *,
    alias: str,
    provider: str,
    current: str | None,
    models: list[str],
    metadata: dict[str, dict[str, Any]] | None = None,
    account: dict[str, Any] | None = None,
) -> str:
    metadata = metadata or {}
    account = account or {}
    if current is not None and current not in models:
        models = [current, *models]
    all_models = list(dict.fromkeys(models))
    free_models = [
        model_id for model_id in all_models if metadata.get(model_id, {}).get("free")
    ]
    pinned_free = free_models[:3]
    all_models = [*pinned_free, *[row for row in all_models if row not in pinned_free]]
    filtered = all_models
    filter_term = ""
    page = 0
    page_size = 15
    notice_shown = False
    while True:
        pages = max(1, (len(filtered) + page_size - 1) // page_size)
        page = min(page, pages - 1)
        start = page * page_size
        visible = filtered[start : start + page_size]
        print(
            f"\n{alias} — {provider}"
            f"{f' — current: {current}' if current is not None else ''} "
            f"(page {page + 1}/{pages}, {len(filtered)} models"
            f"{f', filter: {filter_term!r}' if filter_term else ''})"
        )
        if page == 0 and not filter_term and pinned_free and not notice_shown:
            _print_free_model_notice(len(free_models), account)
            notice_shown = True
        for index, model_id in enumerate(visible, start + 1):
            marker = " *" if model_id == current else ""
            context = metadata.get(model_id, {}).get("context_tokens")
            details = metadata.get(model_id, {})
            context_label = _format_context(int(context) if context else None)
            pricing_label = _format_pricing(
                details, local=bool(details.get("local"))
            )
            free_badge = (
                " " + _paint("FREE", _GREEN_BOLD) if details.get("free") else ""
            )
            cache_label = _format_cache(details)
            print(
                f"  {index:>4}. {_paint(model_id, _CYAN_BOLD)} — "
                f"{_paint(context_label, _YELLOW)} — "
                f"{_paint(pricing_label, _GREEN)} — "
                f"{_paint(cache_label, _MAGENTA_BOLD)}"
                + f"{free_badge}{marker}"
            )
        raw = input(
            "Choose number, /text to filter, / to clear, n(ext), "
            "p(revious), or Enter to keep: "
        ).strip()
        if not raw and current is not None:
            return current
        if not raw:
            print("Select a displayed model number.")
            continue
        if raw.lower() in {"n", "next"}:
            if page >= pages - 1:
                print("Already on the last page.")
            else:
                page += 1
            continue
        if raw.lower() in {"p", "prev", "previous"}:
            if page == 0:
                print("Already on the first page.")
            else:
                page -= 1
            continue
        if raw.startswith("/"):
            term = raw[1:].strip().casefold()
            filtered = (
                [row for row in all_models if term in row.casefold()]
                if term
                else all_models
            )
            page = 0
            if not filtered:
                print("No models matched that search.")
                filtered = all_models
                filter_term = ""
            else:
                filter_term = term
            continue
        try:
            choice = int(raw) - 1
        except ValueError:
            print("Enter a displayed number or one of the navigation commands.")
            continue
        if 0 <= choice < len(filtered):
            return filtered[choice]
        print("That model number is outside the filtered list.")


def _choose_reasoning_effort(
    model_id: str,
    metadata: dict[str, Any],
    *,
    current: str = "auto",
) -> str:
    efforts = [
        str(value).lower()
        for value in metadata.get("supported_reasoning_efforts", [])
    ]
    if not efforts:
        return current
    options = ["auto", *[value for value in efforts if value != "auto"]]
    default = current if current in options else "auto"
    print(f"Reasoning effort for {_paint(model_id, _CYAN_BOLD)}:")
    for index, effort in enumerate(options, 1):
        suffix = " — provider/model default" if effort == "auto" else ""
        marker = " *" if effort == default else ""
        print(f"  {index}. {_paint(effort, _YELLOW)}{suffix}{marker}")
    raw = input(f"Reasoning effort [{default}]: ").strip()
    if not raw:
        return default
    if raw.lower() in options:
        return raw.lower()
    try:
        return options[int(raw) - 1]
    except (ValueError, IndexError) as exc:
        raise ValueError("reasoning effort is outside the displayed list") from exc


def _select_aliases(
    config: EngineConfig, healthy_aliases: list[str], count: int
) -> list[str]:
    healthy_config = replace(
        config,
        models={alias: config.models[alias] for alias in healthy_aliases},
    )
    return [model.alias for model in choose_models(healthy_config, count)]


def _resolve_specialists(
    config: EngineConfig, values: list[str]
) -> list[SpecialistSpec]:
    if not values:
        return [row for row in config.specialists if row.enabled]
    resolved: list[SpecialistSpec] = []
    configured = {row.profile: row for row in config.specialists}
    for value in values:
        if "=" not in value:
            if value not in configured:
                raise ValueError(
                    f"unknown specialist profile {value!r}; use profile=model-alias"
                )
            resolved.append(configured[value])
            continue
        profile, alias = value.split("=", 1)
        if alias not in config.models:
            raise ValueError(f"unknown specialist model alias {alias!r}")
        prompt = configured.get(profile).prompt if profile in configured else ""
        resolved.append(
            SpecialistSpec(profile=profile, model_alias=alias, prompt=prompt)
        )
    return resolved


def _print_preflight(
    config: EngineConfig,
    level: ScanLevel,
    models: list[Any],
    specialists: list[SpecialistSpec],
    inventory: Any,
    estimate: dict[str, Any],
    *,
    execute: bool,
) -> None:
    print("\nVulnHunter preflight")
    print(f"  Level: {level.value}")
    print(
        f"  Repository: {inventory.root} "
        f"({len(inventory.files)} production files, {inventory.total_bytes} bytes)"
    )
    print(f"  Core hunters: {len(models)}")
    for model in models:
        exposure = "REMOTE — source is sent to this provider" if model.remote else "local"
        print(
            f"    - {model.alias}: {_model_summary(model, include_locality=False)}; "
            f"{exposure}"
        )
    print(f"  Additional specialists: {len(specialists)}")
    for specialist in specialists:
        model = config.models[specialist.model_alias]
        exposure = "REMOTE — source is sent to this provider" if model.remote else "local"
        print(
            f"    - {specialist.profile}: {specialist.model_alias} "
            f"({_model_summary(model, include_locality=False)}; {exposure})"
        )
    if estimate["cost_usd"] is None:
        print("  Estimated API cost: unknown (pricing is not configured)")
    else:
        print(
            f"  Estimated API cost: "
            f"{_format_cost(float(estimate['cost_low_usd']))}–"
            f"{_format_cost(float(estimate['cost_high_usd']))}"
        )
    print(
        f"  Estimated workload: {estimate.get('partitions', '?')} repository "
        f"partitions; {estimate.get('assignments_low', '?')}–"
        f"{estimate.get('assignments_high', '?')} assignments; "
        f"{estimate.get('requests_low', '?')}–{estimate.get('requests_high', '?')} "
        "provider responses"
    )
    print(
        f"  Estimate confidence: {estimate.get('confidence', 'unknown')}"
    )
    if estimate["hardware_cost_high_usd"] > 0:
        print(
            f"  Estimated local hardware cost: "
            f"${estimate['hardware_cost_low_usd']:.2f}–"
            f"${estimate['hardware_cost_high_usd']:.2f}"
        )
    print(
        f"  Estimated duration: {estimate['minutes_low']}–"
        f"{estimate['minutes_high']} minutes"
    )
    print(
        "  Execution: "
        + (
            "sandboxed target-code execution explicitly enabled"
            if execute
            else "static/read-only"
        )
    )


def _resolve_target(target: str, *, resume: str | None) -> Path:
    if resume:
        state_path = Path(resume).expanduser() / "run_state.json"
        if not state_path.is_file():
            raise FileNotFoundError(f"resume state not found: {state_path}")
        state = json.loads(state_path.read_text(encoding="utf-8"))
        return Path(state["repository"]).resolve()
    candidate = Path(target).expanduser()
    if candidate.is_dir():
        return candidate.resolve()
    if not _looks_like_git_url(target):
        raise FileNotFoundError(f"local repository not found: {candidate}")
    if shutil.which("git") is None:
        raise RuntimeError("git is required to scan a repository URL")
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", target.rstrip("/").split("/")[-1])
    slug = re.sub(r"\.git$", "", slug) or "repository"
    destination = Path.home() / ".vulnhunter" / "clones" / slug
    if destination.exists():
        suffix = 2
        while destination.with_name(f"{slug}-{suffix}").exists():
            suffix += 1
        destination = destination.with_name(f"{slug}-{suffix}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        ["git", "clone", "--depth", "1", target, str(destination)],
        capture_output=True,
        text=True,
        timeout=300,
        shell=False,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"git clone failed: {completed.stderr.strip()}")
    return destination.resolve()


def _looks_like_git_url(value: str) -> bool:
    return bool(
        re.match(r"^(?:https?|ssh)://", value)
        or re.match(r"^[\w.-]+@[\w.-]+:", value)
    )


def _parse_duration(value: str | None) -> float | None:
    if value is None:
        return None
    match = re.fullmatch(r"(\d+(?:\.\d+)?)(s|m|h)?", value.strip().lower())
    if not match:
        raise ValueError("duration must look like 90s, 30m, or 4h")
    amount = float(match.group(1))
    multiplier = {"s": 1, "m": 60, "h": 3600, None: 1}[match.group(2)]
    return amount * multiplier


def _status_exit(status: str) -> int:
    if status in {
        RunStatus.COMPLETE_CLEAN,
        RunStatus.COMPLETE_FINDINGS,
        RunStatus.COMPLETE_CONDITIONAL,
    }:
        return 0
    if str(status).startswith("INCOMPLETE"):
        return 2
    return 4


def _load_env_file(path: Path, *, required: bool) -> None:
    """Load a small dotenv subset without overriding the calling environment."""
    if not path.is_file():
        if required:
            raise FileNotFoundError(f"provider environment file not found: {path}")
        return
    for number, raw_line in enumerate(
        path.read_text(encoding="utf-8-sig").splitlines(), 1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise ValueError(f"invalid environment entry at {path}:{number}")
        name, value = line.split("=", 1)
        name = name.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ValueError(f"invalid environment name at {path}:{number}")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        os.environ.setdefault(name, value)


if __name__ == "__main__":
    raise SystemExit(main())
