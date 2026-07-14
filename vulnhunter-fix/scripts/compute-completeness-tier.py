#!/usr/bin/env python3
"""Deterministic completeness-tier classifier.

Implements REQ-HON-004: walks signals conservative-first
(WORKAROUND → MITIGATION → FULL → LLM_REVIEW) and NEVER silently selects
FULL. When no terminal signal matches, returns LLM_REVIEW so the calling
phase can escalate to the bounded LLM prompt (REQ-HON-013).

Signal definitions are documented in references/fix-completeness-rubric.md;
this file is the mechanical implementation.

Usage:
    compute-completeness-tier.py --diff <path> [--plan <path>] [--result <path>] [--phase plan|verify]
    compute-completeness-tier.py --diff - --plan <path>   # diff on stdin

Emits JSON on stdout:
    {"tier": "FULL"|"MITIGATION"|"WORKAROUND"|"LLM_REVIEW",
     "signals": ["signal_id", ...],
     "phase": "plan"|"verify",
     "reason": "human-readable summary"}

SCH-2 signal sourcing (post-Commit 3):
    `callers_routed_coverage` reads from `--plan` (fix_plan.json).
    `discrimination_evidence` reads from `--result` (worker result.json).
    In plan phase, `--result` is typically absent; `full.test_discriminates`
    stays false and the tier can't be FULL (correct — you haven't verified).
    In verify phase, both plan and result are available.
    For backward compat, `discrimination_evidence` on `--plan` is still
    accepted (falls through if not present on result).

Exit codes:
    0 — classification produced (any tier including LLM_REVIEW)
    2 — usage / IO error
    3 — malformed plan artifact
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


HAND_WAVE_PATTERNS = (
    "future work",
    "more work needed",
    "to be done",
    "tbd",
    "later",
)


def _read_diff(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8", errors="replace")


def _read_plan(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    text = Path(path).read_text(encoding="utf-8")
    return json.loads(text)


def _diff_added_lines(diff: str) -> list[str]:
    added = []
    for line in diff.splitlines():
        if line.startswith("+++"):
            continue
        if line.startswith("+"):
            added.append(line[1:])
    return added


def _diff_removed_lines(diff: str) -> list[str]:
    removed = []
    for line in diff.splitlines():
        if line.startswith("---"):
            continue
        if line.startswith("-"):
            removed.append(line[1:])
    return removed


def _files_changed(diff: str) -> list[str]:
    files = []
    for line in diff.splitlines():
        m = re.match(r"^\+\+\+ b/(.+)$", line)
        if m:
            files.append(m.group(1))
    return files


def _check_workaround_signals(diff: str, plan: dict) -> list[str]:
    signals: list[str] = []
    added = "\n".join(_diff_added_lines(diff)).lower()
    files = _files_changed(diff)

    if re.search(r"\b(ratelimit|rate_limit|token[_ ]?bucket|semaphore|circuitbreaker|circuit_breaker|throttl)", added):
        if not re.search(r"\bdef\s+\w+\s*\(|\bfunc\s+\w+\s*\(|\breturn\s+(?:new)?", added):
            signals.append("workaround.rate_limit_upstream_of_sink")

    if re.search(r"\b(feature[_ ]?flag|toggle|is_enabled\s*=\s*(false|False|0))", added):
        if all(f.endswith((".yaml", ".yml", ".json", ".toml", ".ini", ".env", ".conf")) for f in files) and files:
            signals.append("workaround.feature_flag_flipped_off")

    if files and all(f.endswith(".md") for f in files):
        signals.append("workaround.documentation_only")

    if re.search(r"logger\.(warn|error|info)|log\.(warn|error|info)|audit_log\(|x-warning", added):
        if not re.search(r"\braise\b|\breturn\s+[45]\d\d|abort\(|reject\(", added):
            signals.append("workaround.log_or_header_without_reject")

    return signals


def _check_mitigation_signals(diff: str, plan: dict) -> list[str]:
    signals: list[str] = []
    added = "\n".join(_diff_added_lines(diff)).lower()

    if re.search(r"if\s+len\(\w+\)\s*[<>]=?\s*\d+", added) or re.search(r"maxlength\s*[:=]\s*\d+", added):
        signals.append("mitigation.length_or_complexity_cap")

    if re.search(r"whitelist|allow[_ ]?list|allowed[_ ]?patterns", added) and re.search(r"else\s*:|elif\s", added):
        signals.append("mitigation.partial_input_sanitization")

    if plan.get("crypto_trust_chain"):
        tc = plan["crypto_trust_chain"]
        if any(tc.get(k) is False for k in ("algorithm_approved", "key_source_approved",
                                             "key_rotation_present", "transport_encrypted")):
            signals.append("mitigation.crypto_trust_chain_incomplete")

    return signals


def _check_full_signals(diff: str, plan: dict, result: dict) -> list[str]:
    signals: list[str] = []
    added_lines = _diff_added_lines(diff)
    removed_lines = _diff_removed_lines(diff)
    added_text = "\n".join(added_lines)
    removed_text = "\n".join(removed_lines)

    sig_change_added = re.search(r"^\s*(?:def|func|public|private|protected|fn)\s+\w+\s*\([^)]*\)", added_text, re.MULTILINE)
    sig_change_removed = re.search(r"^\s*(?:def|func|public|private|protected|fn)\s+\w+\s*\([^)]*\)", removed_text, re.MULTILINE)
    if sig_change_added and sig_change_removed:
        signals.append("full.sink_signature_changed")

    # SCH-2: callers_routed_coverage is a plan-level commitment (fix intent).
    # But "superset" over zero routed callers is vacuous (12-seg review S3):
    # require the result to actually enumerate a non-empty routed set. The
    # authoritative graph cross-check (routed ⊇ graph.callers_of) runs at
    # delivery in validate-verification.py column 7.
    routed = (result or {}).get("callers_routed_through_fix") or []
    if plan.get("callers_routed_coverage") == "superset" and routed:
        signals.append("full.callers_routed_through_fix")

    # SCH-2: discrimination_evidence is a result-level outcome (test proof).
    # Read from result first; fall back to plan for backward compat with
    # producers that emitted it on the plan before the schema split.
    disc = (result or {}).get("discrimination_evidence") or plan.get("discrimination_evidence") or {}
    # A two-field {pre:fail, post:pass} stub is not proof — require the method
    # and a concrete assertion_target too, matching the schema's FULL guard
    # (12-seg review S3: a stub earned the terminal FULL signal).
    if (
        disc.get("pre_fix_result") == "fail"
        and disc.get("post_fix_result") == "pass"
        and disc.get("method")
        and disc.get("assertion_target")
    ):
        signals.append("full.test_discriminates")

    return signals


def classify(diff: str, plan: dict, phase: str, result: dict | None = None) -> dict[str, Any]:
    result = result or {}
    workaround = _check_workaround_signals(diff, plan)
    if workaround:
        return {
            "tier": "WORKAROUND",
            "signals": workaround,
            "phase": phase,
            "reason": f"workaround signal(s) matched: {', '.join(workaround)}",
        }

    mitigation = _check_mitigation_signals(diff, plan)
    if mitigation:
        return {
            "tier": "MITIGATION",
            "signals": mitigation,
            "phase": phase,
            "reason": f"mitigation signal(s) matched: {', '.join(mitigation)}",
        }

    full = _check_full_signals(diff, plan, result)
    required_full = {
        "full.sink_signature_changed",
        "full.callers_routed_through_fix",
        "full.test_discriminates",
    }
    matched_full = set(full)
    if required_full.issubset(matched_full):
        return {
            "tier": "FULL",
            "signals": sorted(matched_full),
            "phase": phase,
            "reason": "all FULL signals matched cumulatively (per REQ-HON-004 conservative-first walk)",
        }

    missing = sorted(required_full - matched_full)
    return {
        "tier": "LLM_REVIEW",
        "signals": sorted(matched_full),
        "phase": phase,
        "reason": (
            "no terminal signal resolved; deterministic classifier declines to "
            f"pick FULL (missing signals: {', '.join(missing) or '<none>'}). "
            "Route to prompts/tier_judgment.md (REQ-HON-013)."
        ),
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Deterministic completeness-tier classifier.")
    ap.add_argument("--diff", required=True, help="Path to unified-diff text, or '-' for stdin.")
    ap.add_argument("--plan", default=None, help="Path to fix_plan JSON artifact (optional).")
    ap.add_argument("--result", default=None, help="Path to worker result JSON (optional; verify-phase only).")
    ap.add_argument("--phase", default="plan", choices=("plan", "verify"))
    args = ap.parse_args(argv[1:])

    try:
        diff = _read_diff(args.diff)
    except OSError as exc:
        print(json.dumps({"error": f"diff read failed: {exc}"}))
        return 2

    try:
        plan = _read_plan(args.plan)
    except OSError as exc:
        print(json.dumps({"error": f"plan read failed: {exc}"}))
        return 2
    except json.JSONDecodeError as exc:
        print(json.dumps({"error": f"plan parse failed: line {exc.lineno} col {exc.colno}: {exc.msg}"}))
        return 3

    try:
        result = _read_plan(args.result)
    except OSError as exc:
        print(json.dumps({"error": f"result read failed: {exc}"}))
        return 2
    except json.JSONDecodeError as exc:
        print(json.dumps({"error": f"result parse failed: line {exc.lineno} col {exc.colno}: {exc.msg}"}))
        return 3

    classification = classify(diff, plan, args.phase, result)
    print(json.dumps(classification, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
