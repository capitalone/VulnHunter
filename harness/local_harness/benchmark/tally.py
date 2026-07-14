"""Generate benchmark tally reports from state data."""

import os
from collections import defaultdict
from datetime import datetime

from local_harness.config import RESULTS_DIR, TALLY_FILE, TALLY_REPORT, atomic_write_json


def _fmt_duration(seconds):
    """Format seconds into human-readable duration like '43m 12s' or '1h 23m'."""
    if not seconds:
        return "0s"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        m, s = divmod(seconds, 60)
        return f"{m}m {s}s"
    h, remainder = divmod(seconds, 3600)
    m, s = divmod(remainder, 60)
    return f"{h}h {m}m"


def generate_tally(state):
    """Generate a benchmark tally from the state dict.

    Returns a tally dict with summary stats and per-finding results.
    """
    judgments = state.get("judgments", {})
    scan_targets = state.get("scan_targets", {})

    findings_list = []
    by_type = defaultdict(lambda: {"total": 0, "detected": 0, "missed": 0, "error": 0})

    for finding_id, judgment in judgments.items():
        detected = judgment.get("detected")
        finding_type = judgment.get("type", "Unknown")

        by_type[finding_type]["total"] += 1
        if detected is True:
            by_type[finding_type]["detected"] += 1
        elif detected is False:
            by_type[finding_type]["missed"] += 1
        else:
            by_type[finding_type]["error"] += 1

        findings_list.append({
            "finding_id": finding_id,
            "benchmark_file": judgment.get("benchmark_file", ""),
            "type": finding_type,
            "repo": judgment.get("repo_name", ""),
            "commit": judgment.get("commit_hash", "")[:8],
            "detected": detected,
            "confidence": judgment.get("confidence"),
            "reasoning": judgment.get("reasoning", ""),
            "matched_finding_id": judgment.get("matched_finding_id"),
        })

    total = len(findings_list)
    detected_count = sum(1 for f in findings_list if f["detected"] is True)
    missed_count = sum(1 for f in findings_list if f["detected"] is False)
    error_count = sum(1 for f in findings_list if f["detected"] is None)
    detection_rate = detected_count / total if total > 0 else 0.0

    scan_failures = sum(1 for t in scan_targets.values() if t.get("status") == "scan_failed")

    # Aggregate cost/time/token metrics across all scans
    total_cost_usd = 0.0
    total_elapsed_s = 0
    total_input_tokens = 0
    total_output_tokens = 0
    total_cache_read_tokens = 0
    total_cache_creation_tokens = 0
    total_num_turns = 0
    per_scan_costs = []

    for key, target_data in scan_targets.items():
        scan_cost = target_data.get("scan_total_cost_usd", 0) or 0
        scan_elapsed = target_data.get("scan_elapsed_s", 0) or 0
        total_cost_usd += scan_cost
        total_elapsed_s += scan_elapsed
        total_input_tokens += target_data.get("scan_input_tokens", 0) or 0
        total_output_tokens += target_data.get("scan_output_tokens", 0) or 0
        total_cache_read_tokens += target_data.get("scan_cache_read_tokens", 0) or 0
        total_cache_creation_tokens += target_data.get("scan_cache_creation_tokens", 0) or 0
        total_num_turns += target_data.get("scan_num_turns", 0) or 0
        if scan_cost or scan_elapsed:
            per_scan_costs.append({
                "target": key,
                "cost_usd": scan_cost,
                "elapsed_s": scan_elapsed,
                "input_tokens": target_data.get("scan_input_tokens", 0) or 0,
                "output_tokens": target_data.get("scan_output_tokens", 0) or 0,
                "cache_read_tokens": target_data.get("scan_cache_read_tokens", 0) or 0,
                "cache_creation_tokens": target_data.get("scan_cache_creation_tokens", 0) or 0,
                "num_turns": target_data.get("scan_num_turns", 0) or 0,
            })

    tally = {
        "generated_at": datetime.now().isoformat(),
        "model": state.get("model", "unknown"),
        "summary": {
            "total_findings": total,
            "detected": detected_count,
            "missed": missed_count,
            "errors": error_count,
            "detection_rate": round(detection_rate, 4),
            "scan_failures": scan_failures,
            "by_type": dict(by_type),
        },
        "cost": {
            "total_cost_usd": round(total_cost_usd, 2),
            "total_elapsed_s": total_elapsed_s,
            "total_input_tokens": total_input_tokens,
            "total_output_tokens": total_output_tokens,
            "total_cache_read_tokens": total_cache_read_tokens,
            "total_cache_creation_tokens": total_cache_creation_tokens,
            "total_num_turns": total_num_turns,
            "scans_counted": len(per_scan_costs),
            "avg_cost_per_scan_usd": round(total_cost_usd / len(per_scan_costs), 2) if per_scan_costs else 0,
            "avg_elapsed_per_scan_s": round(total_elapsed_s / len(per_scan_costs)) if per_scan_costs else 0,
            "per_scan": sorted(per_scan_costs, key=lambda x: x["cost_usd"], reverse=True),
        },
        "findings": sorted(findings_list, key=lambda f: (f["benchmark_file"], f["finding_id"])),
    }

    return tally


def write_tally_json(tally):
    """Write tally to JSON file."""
    atomic_write_json(TALLY_FILE, tally)
    print(f"  Tally JSON written to: {TALLY_FILE}")


def write_tally_markdown(tally):
    """Write a human-readable Markdown report."""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    summary = tally["summary"]
    cost = tally.get("cost", {})
    findings = tally["findings"]

    lines = []
    lines.append("# VulnHunter Benchmark Report\n")
    lines.append(f"**Generated**: {tally['generated_at']}")
    lines.append(f"**Model**: {tally['model']}")
    lines.append(f"**Benchmark**: {summary['total_findings']} findings\n")

    lines.append("## Summary\n")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Total Benchmark Findings | {summary['total_findings']} |")
    lines.append(f"| Detected (True Positives) | {summary['detected']} |")
    lines.append(f"| Missed (False Negatives) | {summary['missed']} |")
    lines.append(f"| Judge Errors | {summary['errors']} |")
    lines.append(f"| Detection Rate | {summary['detection_rate']:.1%} |")
    lines.append(f"| Scan Failures | {summary['scan_failures']} |")
    lines.append("")

    lines.append("## Detection by Vulnerability Type\n")
    lines.append("| Type | Total | Detected | Missed | Rate |")
    lines.append("|------|-------|----------|--------|------|")
    for vtype, counts in sorted(summary["by_type"].items()):
        total = counts["total"]
        det = counts["detected"]
        rate = f"{det/total:.0%}" if total > 0 else "N/A"
        lines.append(f"| {vtype} | {total} | {det} | {counts['missed']} | {rate} |")
    lines.append("")

    lines.append("## Per-Finding Results\n")
    lines.append("| # | Benchmark File | Finding ID | Type | Detected | Confidence |")
    lines.append("|---|---------------|-----------|------|----------|------------|")
    for i, f in enumerate(findings, 1):
        det_str = "YES" if f["detected"] is True else ("NO" if f["detected"] is False else "ERR")
        conf = f["confidence"] or "-"
        lines.append(f"| {i} | {f['benchmark_file']} | {f['finding_id']} | {f['type']} | {det_str} | {conf} |")
    lines.append("")

    missed = [f for f in findings if f["detected"] is False]
    if missed:
        lines.append("## Missed Findings (False Negatives)\n")
        for f in missed:
            lines.append(f"### {f['finding_id']} — {f['type']} in {f['repo']}")
            lines.append(f"**Reasoning**: {f['reasoning']}\n")

    if cost.get("total_cost_usd") or cost.get("total_elapsed_s"):
        lines.append("## Cost & Performance\n")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Total Cost | ${cost['total_cost_usd']:.2f} |")
        lines.append(f"| Avg Cost / Scan | ${cost.get('avg_cost_per_scan_usd', 0):.2f} |")
        total_elapsed = cost.get("total_elapsed_s", 0)
        lines.append(f"| Total Wall Time | {_fmt_duration(total_elapsed)} |")
        avg_elapsed = cost.get("avg_elapsed_per_scan_s", 0)
        lines.append(f"| Avg Time / Scan | {_fmt_duration(avg_elapsed)} |")
        lines.append(f"| Total Input Tokens | {cost.get('total_input_tokens', 0):,} |")
        lines.append(f"| Total Output Tokens | {cost.get('total_output_tokens', 0):,} |")
        lines.append(f"| Total Cache Read Tokens | {cost.get('total_cache_read_tokens', 0):,} |")
        lines.append(f"| Total Cache Creation Tokens | {cost.get('total_cache_creation_tokens', 0):,} |")
        lines.append(f"| Total Turns | {cost.get('total_num_turns', 0):,} |")
        lines.append(f"| Scans Counted | {cost.get('scans_counted', 0)} |")
        lines.append("")

        per_scan = cost.get("per_scan", [])
        if per_scan:
            lines.append("### Per-Scan Breakdown\n")
            lines.append("| Target | Cost | Time | Tokens (in/out) | Turns |")
            lines.append("|--------|------|------|-----------------|-------|")
            for s in per_scan:
                total_tokens = s["input_tokens"] + s["output_tokens"] + s["cache_read_tokens"] + s["cache_creation_tokens"]
                lines.append(
                    f"| {s['target']} | ${s['cost_usd']:.2f} | {_fmt_duration(s['elapsed_s'])} "
                    f"| {s['input_tokens']:,} / {s['output_tokens']:,} ({total_tokens:,} total) | {s['num_turns']} |"
                )
            lines.append("")

    with open(TALLY_REPORT, "w") as f:
        f.write("\n".join(lines))
    print(f"  Benchmark report written to: {TALLY_REPORT}")


def print_summary(tally):
    """Print a concise summary to stdout."""
    s = tally["summary"]
    cost = tally.get("cost", {})
    print(f"\n{'='*60}")
    print(f"BENCHMARK RESULTS: {s['detected']}/{s['total_findings']} detected "
          f"({s['detection_rate']:.1%})")
    print(f"{'='*60}")
    print(f"  Detected:  {s['detected']}")
    print(f"  Missed:    {s['missed']}")
    print(f"  Errors:    {s['errors']}")
    print(f"  Scan fails: {s['scan_failures']}")
    print()
    for vtype, counts in sorted(s["by_type"].items()):
        total = counts["total"]
        det = counts["detected"]
        rate = f"{det/total:.0%}" if total > 0 else "N/A"
        print(f"  {vtype:20s} {det}/{total} ({rate})")

    if cost.get("total_cost_usd") or cost.get("total_elapsed_s"):
        print(f"\n{'-'*60}")
        print(f"  COST & PERFORMANCE")
        print(f"{'-'*60}")
        print(f"  Total cost:        ${cost['total_cost_usd']:.2f}")
        print(f"  Avg cost/scan:     ${cost.get('avg_cost_per_scan_usd', 0):.2f}")
        print(f"  Total wall time:   {_fmt_duration(cost.get('total_elapsed_s', 0))}")
        print(f"  Avg time/scan:     {_fmt_duration(cost.get('avg_elapsed_per_scan_s', 0))}")
        total_all_tokens = (cost.get("total_input_tokens", 0) + cost.get("total_output_tokens", 0)
                           + cost.get("total_cache_read_tokens", 0) + cost.get("total_cache_creation_tokens", 0))
        print(f"  Total tokens:      {total_all_tokens:,} "
              f"(in: {cost.get('total_input_tokens', 0):,}, "
              f"out: {cost.get('total_output_tokens', 0):,}, "
              f"cache-read: {cost.get('total_cache_read_tokens', 0):,})")
        print(f"  Total turns:       {cost.get('total_num_turns', 0):,}")
        print(f"  Scans counted:     {cost.get('scans_counted', 0)}")

    print(f"{'='*60}")
    if s["missed"] > 0:
        print(f"\n  To analyze missed findings and get prompt tuning suggestions:")
        print(f"    python -m local_harness.benchmark.analyze_misses")
    print()
