#!/usr/bin/env python3
"""Benchmark test harness for VulnHunter.

Scans known-vulnerable repos at specific commits, then uses an LLM judge to check
whether each benchmark finding was detected. Outputs a detection-rate scorecard.

Usage:
    python -m local_harness.benchmark.run [OPTIONS]

Options:
    --scan-only         Clone and scan only, skip judging
    --judge-only        Skip scanning, only judge already-scanned results
    --tally-only        Skip scanning and judging, regenerate tally from state
    --force-rescan      Re-scan repos even if results exist
    --force-rejudge     Re-judge findings even if judgments exist
    --repos FILTER      Only process repos matching this substring
    --findings IDS      Re-run specific finding IDs (comma-separated)
    --max-workers N     Override parallel scan workers (default: 3)
"""

import argparse
import glob
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from local_harness.clone import clone_at_commit, parse_source_url, target_dir_name
from local_harness.config import (
    BENCHMARK_DIR,
    CLONE_BASE_DIR,
    MAX_SCAN_WORKERS,
    MODEL,
    STATE_FILE,
    atomic_write_json,
)
from .judge import judge_findings_batch, read_results_report
from local_harness.scan import clean_prior_results, extract_cost_from_log, find_results_dir, has_valid_results, scan_targets
from .tally import (
    generate_tally,
    print_summary,
    write_tally_json,
    write_tally_markdown,
)
from .finding_history import get_stable_findings, update_history


def load_all_benchmarks():
    """Load all benchmark JSON files.

    Returns list of (filename, findings_list) where each finding has parsed
    _repo_url, _repo_name, _commit_hash fields added.
    """
    results = []
    pattern = os.path.join(BENCHMARK_DIR, "*.json")
    for json_file in sorted(glob.glob(pattern)):
        with open(json_file) as f:
            findings = json.load(f)
        for finding in findings:
            repo_url, repo_name, commit_hash = parse_source_url(finding["source_code"])
            finding["_repo_url"] = repo_url
            finding["_repo_name"] = repo_name
            finding["_commit_hash"] = commit_hash
        results.append((os.path.basename(json_file), findings))
    return results


def deduplicate_targets(benchmarks):
    """Build unique (repo_url, commit_hash) scan targets from benchmark data.

    Returns dict keyed by target_key -> target info dict.
    """
    targets = {}
    for filename, findings in benchmarks:
        for finding in findings:
            key = target_dir_name(finding["_repo_name"], finding["_commit_hash"])
            if key not in targets:
                targets[key] = {
                    "key": key,
                    "repo_url": finding["_repo_url"],
                    "commit_hash": finding["_commit_hash"],
                    "repo_name": finding["_repo_name"],
                    "clone_dir": os.path.join(CLONE_BASE_DIR, key),
                    "findings": [],
                }
            targets[key]["findings"].append({
                "finding_id": finding["finding_id"],
                "type": finding["type"],
                "description": finding["description"],
                "benchmark_file": filename,
            })
    return targets


def load_state():
    """Load existing state or return empty state."""
    if os.path.isfile(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            print(f"  WARNING: {STATE_FILE} is corrupt, starting fresh")
    return {"scan_targets": {}, "judgments": {}, "model": MODEL}


def save_state(state):
    """Persist state to disk atomically."""
    atomic_write_json(STATE_FILE, state)


def phase_clone(targets, state):
    """Phase 1: Clone all repos at specific commits."""
    print(f"\n{'='*60}")
    print(f"PHASE 1: CLONE ({len(targets)} targets)")
    print(f"{'='*60}\n")

    for key, target in targets.items():
        if key in state["scan_targets"] and state["scan_targets"][key].get("status") in ("cloned", "scanned"):
            if os.path.isdir(target["clone_dir"]):
                print(f"  [skip] {key} — already cloned")
                continue

        target_dir, error = clone_at_commit(
            target["repo_url"], target["commit_hash"], target["clone_dir"]
        )

        if error:
            print(f"  [FAIL] {key}: {error}")
            state["scan_targets"][key] = {
                "repo_url": target["repo_url"],
                "commit_hash": target["commit_hash"],
                "clone_dir": target["clone_dir"],
                "status": "clone_failed",
                "error": error,
            }
        else:
            state["scan_targets"][key] = {
                "repo_url": target["repo_url"],
                "commit_hash": target["commit_hash"],
                "clone_dir": target["clone_dir"],
                "status": "cloned",
            }
        save_state(state)


def phase_scan(targets, state, force_rescan=False, max_workers=MAX_SCAN_WORKERS):
    """Phase 2: Scan all cloned repos in parallel."""
    to_scan = []
    for key, target in targets.items():
        target_state = state["scan_targets"].get(key, {})

        if target_state.get("status") == "clone_failed":
            continue

        if not force_rescan and target_state.get("status") == "scanned":
            results_dir = target_state.get("results_dir")
            if results_dir and os.path.isdir(results_dir):
                print(f"  [skip] {key} — already scanned")
                continue

        if not force_rescan and has_valid_results(target["clone_dir"]):
            results_dir = find_results_dir(target["clone_dir"])
            entry = state["scan_targets"].setdefault(key, {})
            entry["status"] = "scanned"
            entry["results_dir"] = results_dir
            save_state(state)
            print(f"  [skip] {key} — results already exist")
            continue

        to_scan.append(target)

    if not to_scan:
        print(f"\n  All targets already scanned. Use --force-rescan to re-run.")
        return

    # Clean prior results for targets about to be scanned
    for target in to_scan:
        removed = clean_prior_results(target["clone_dir"])
        if removed:
            print(f"  [clean] {target['key']} — removed {len(removed)} prior results dir(s)")

    # Invalidate stale state/judgments for targets being rescanned
    for target in to_scan:
        key = target["key"]
        if key in state["scan_targets"]:
            state["scan_targets"][key].pop("results_dir", None)
            state["scan_targets"][key]["status"] = "cloned"
        for finding in targets[key].get("findings", []):
            state["judgments"].pop(finding["finding_id"], None)
    save_state(state)

    print(f"\n{'='*60}")
    print(f"PHASE 2: SCAN ({len(to_scan)} targets, {max_workers} workers)")
    print(f"{'='*60}")

    results = scan_targets(to_scan, max_workers=max_workers)

    for target_key, r in results:
        if r.returncode == 0 and r.results_dir:
            state["scan_targets"][target_key] = {
                **state["scan_targets"].get(target_key, {}),
                "status": "scanned",
                "results_dir": r.results_dir,
                "scan_exit_code": r.returncode,
                "scan_elapsed_s": round(r.elapsed),
                "scan_event_count": r.event_count,
                **({f"scan_{k}": v for k, v in r.cost_data.items()} if r.cost_data else {}),
            }
        else:
            state["scan_targets"][target_key] = {
                **state["scan_targets"].get(target_key, {}),
                "status": "scan_failed",
                "scan_exit_code": r.returncode,
                "scan_elapsed_s": round(r.elapsed),
                "scan_event_count": r.event_count,
                "results_dir": r.results_dir,
                **({f"scan_{k}": v for k, v in r.cost_data.items()} if r.cost_data else {}),
            }
        save_state(state)


def phase_judge(targets, state, force_rejudge=False):
    """Phase 3: Judge each benchmark finding against scan results."""
    print(f"\n{'='*60}")
    print(f"PHASE 3: JUDGE")
    print(f"{'='*60}\n")

    total_judged = 0
    total_skipped = 0

    for key, target in targets.items():
        target_state = state["scan_targets"].get(key, {})
        results_dir = target_state.get("results_dir")

        if target_state.get("status") != "scanned" or not results_dir:
            for finding in target["findings"]:
                fid = finding["finding_id"]
                if fid not in state["judgments"] or force_rejudge:
                    state["judgments"][fid] = {
                        "scan_target": key,
                        "detected": None,
                        "confidence": None,
                        "reasoning": f"scan not available (status: {target_state.get('status', 'unknown')})",
                        "matched_finding_id": None,
                        "type": finding["type"],
                        "benchmark_file": finding["benchmark_file"],
                        "repo_name": target.get("repo_name", ""),
                        "commit_hash": target.get("commit_hash", ""),
                    }
            save_state(state)
            continue

        # Check which findings still need judging
        findings_to_judge = []
        for finding in target["findings"]:
            fid = finding["finding_id"]
            if force_rejudge or fid not in state["judgments"]:
                findings_to_judge.append(finding)
            else:
                total_skipped += 1

        if not findings_to_judge:
            continue

        report = read_results_report(results_dir)
        if not report:
            for finding in findings_to_judge:
                state["judgments"][finding["finding_id"]] = {
                    "scan_target": key,
                    "detected": None,
                    "confidence": None,
                    "reasoning": "no README.md in results directory",
                    "matched_finding_id": None,
                    "type": finding["type"],
                    "benchmark_file": finding["benchmark_file"],
                    "repo_name": target.get("repo_name", ""),
                    "commit_hash": target.get("commit_hash", ""),
                }
            save_state(state)
            continue

        print(f"  Judging {len(findings_to_judge)} findings for {key} ...", flush=True)
        judgments = judge_findings_batch(report, findings_to_judge)

        for judgment in judgments:
            fid = judgment["finding_id"]
            finding_meta = next((f for f in findings_to_judge if f["finding_id"] == fid), {})
            state["judgments"][fid] = {
                "scan_target": key,
                "detected": judgment.get("detected"),
                "confidence": judgment.get("confidence"),
                "reasoning": judgment.get("reasoning", ""),
                "matched_finding_id": judgment.get("matched_finding_id"),
                "type": finding_meta.get("type", ""),
                "benchmark_file": finding_meta.get("benchmark_file", ""),
                "repo_name": target.get("repo_name", ""),
                "commit_hash": target.get("commit_hash", ""),
            }
            total_judged += 1

        save_state(state)

    print(f"\n  Judged: {total_judged}, Skipped: {total_skipped}")


def phase_tally(state):
    """Phase 4: Generate tally report."""
    print(f"\n{'='*60}")
    print(f"PHASE 4: TALLY")
    print(f"{'='*60}\n")

    # Backfill cost data from logs for any scans missing it
    backfilled = 0
    for key, target_data in state.get("scan_targets", {}).items():
        if target_data.get("scan_total_cost_usd"):
            continue
        clone_dir = target_data.get("clone_dir")
        if not clone_dir:
            continue
        log_file = os.path.join(clone_dir, "benchmark_scan.log")
        cost_data = extract_cost_from_log(log_file)
        if cost_data:
            for k, v in cost_data.items():
                target_data[f"scan_{k}"] = v
            backfilled += 1
    if backfilled:
        print(f"  Backfilled cost data from logs for {backfilled} scan(s)")
        save_state(state)

    tally = generate_tally(state)
    write_tally_json(tally)
    write_tally_markdown(tally)
    print_summary(tally)


def filter_targets_by_findings(targets, finding_ids):
    """Filter targets to only those containing specified findings, trimming each findings list."""
    filtered = {}
    for key, target in targets.items():
        matching = [f for f in target["findings"] if f["finding_id"] in finding_ids]
        if matching:
            filtered[key] = {**target, "findings": matching}
    return filtered


def main():
    parser = argparse.ArgumentParser(description="VulnHunter Benchmark Test Harness")
    parser.add_argument("--scan-only", action="store_true",
                        help="Clone and scan only, skip judging")
    parser.add_argument("--judge-only", action="store_true",
                        help="Skip scanning, only judge already-scanned results")
    parser.add_argument("--tally-only", action="store_true",
                        help="Regenerate tally from existing state")
    parser.add_argument("--force-rescan", action="store_true",
                        help="Re-scan repos even if results exist")
    parser.add_argument("--force-rejudge", action="store_true",
                        help="Re-judge findings even if judgments exist")
    parser.add_argument("--repos", type=str, default=None,
                        help="Only process repos matching this substring")
    parser.add_argument("--findings", type=str, default=None,
                        help="Re-run specific finding IDs (comma-separated, e.g. VULN-001,VULN-002)")
    parser.add_argument("--max-workers", type=int, default=MAX_SCAN_WORKERS,
                        help=f"Parallel scan workers (default: {MAX_SCAN_WORKERS})")
    parser.add_argument("--skip-stable", action="store_true",
                        help="Skip findings detected in every one of the last 3 runs")
    args = parser.parse_args()

    # Load benchmarks
    benchmarks = load_all_benchmarks()
    if not benchmarks:
        print("Error: No benchmark files found in local_harness/benchmark/ground_truth/")
        sys.exit(1)

    total_findings = sum(len(findings) for _, findings in benchmarks)
    print(f"Loaded {len(benchmarks)} benchmark files with {total_findings} findings")

    # Deduplicate targets
    targets = deduplicate_targets(benchmarks)

    # Apply repo filter
    if args.repos:
        targets = {k: v for k, v in targets.items() if args.repos.lower() in k.lower()}
        if not targets:
            print(f"No targets match filter: {args.repos}")
            sys.exit(1)

    # Apply finding-level filter
    if args.findings:
        finding_ids = {fid.strip() for fid in args.findings.split(",")}
        targets = filter_targets_by_findings(targets, finding_ids)
        if not targets:
            all_fids = {f["finding_id"] for _, findings in benchmarks for f in findings}
            unknown = finding_ids - all_fids
            if unknown:
                print(f"Error: Unknown finding IDs: {', '.join(sorted(unknown))}")
            else:
                print(f"No targets remain after filtering (check --repos combination)")
            sys.exit(1)
        args.force_rescan = True
        args.force_rejudge = True
        matched = sum(len(t["findings"]) for t in targets.values())
        print(f"Finding filter: re-running {matched} finding(s) across {len(targets)} target(s)")

    # Apply --skip-stable filter (ignored when --findings is explicit)
    if args.skip_stable and not args.findings:
        stable_ids = get_stable_findings(threshold=3)
        if stable_ids:
            for key in list(targets.keys()):
                targets[key]["findings"] = [
                    f for f in targets[key]["findings"]
                    if f["finding_id"] not in stable_ids
                ]
                if not targets[key]["findings"]:
                    del targets[key]
            print(f"--skip-stable: Skipped {len(stable_ids)} findings stable across last 3 runs")
        if not targets:
            print("All findings are stable — nothing to run.")
            return

    print(f"Scan targets: {len(targets)} unique (repo, commit) pairs")
    for key in sorted(targets.keys()):
        n = len(targets[key]["findings"])
        print(f"  {key} ({n} findings)")

    # Load state
    state = load_state()
    state["model"] = MODEL

    # Execute phases based on flags
    if args.tally_only:
        phase_tally(state)
        return

    if not args.judge_only:
        phase_clone(targets, state)
        phase_scan(targets, state, force_rescan=args.force_rescan, max_workers=args.max_workers)

    if args.scan_only:
        print("\n  --scan-only: Skipping judge and tally phases.")
        save_state(state)
        return

    phase_judge(targets, state, force_rejudge=args.force_rejudge)
    phase_tally(state)

    # Record results to global history tracker
    recorded, skipped = update_history(state, targets)
    print(f"\n  History updated: {recorded} findings recorded, {skipped} skipped")


if __name__ == "__main__":
    main()
