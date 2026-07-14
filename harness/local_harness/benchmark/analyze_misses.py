#!/usr/bin/env python3
"""Analyze missed benchmark findings to identify pipeline loss points and suggest prompt tunings.

For each false negative, traces through scan artifacts to pinpoint where in the pipeline
the finding was lost, then invokes Claude to diagnose the root cause and suggest fixes.

Usage:
    python -m local_harness.benchmark.analyze_misses [OPTIONS]

Options:
    --finding FINDING_ID    Analyze a specific finding only
    --state-file PATH       Override state file path
    --verbose               Print full artifact excerpts
"""

import argparse
import glob
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from local_harness.config import BENCHMARK_DIR, MODEL, REPO_ROOT, RESULTS_DIR, STATE_FILE, atomic_write_json

PHASE_TO_PROMPT = {
    "phase1": ["skill/phases/phase1_recon.md"],
    "phase2_inj": ["skill/phases/phase2_shared.md", "skill/phases/phase2_class_inj.md"],
    "phase2_nav": ["skill/phases/phase2_shared.md", "skill/phases/phase2_class_nav.md"],
    "phase2_log": ["skill/phases/phase2_shared.md", "skill/phases/phase2_class_log.md"],
    "phase2b": ["skill/phases/phase2b_verify.md"],
    "unknown": ["skill/phases/phase2_hunt.md"],
}

ANALYSIS_JSON = os.path.join(RESULTS_DIR, "miss_analysis.json")
ANALYSIS_REPORT = os.path.join(RESULTS_DIR, "MISS_ANALYSIS.md")

DIAGNOSTIC_SYSTEM_PROMPT = """You are an expert security scanner prompt engineer investigating why a vulnerability scanner missed a known finding.

INVESTIGATION PROCESS:
1. Start with the ground truth vulnerability definition to understand exactly what should have been found
2. Read the scanner results in the VULNHUNT_RESULTS directory to see what WAS found and what wasn't
3. Dive into the scan log (benchmark_scan.log - JSONL format, one JSON object per line) to trace where the scanner's reasoning went wrong. Use grep to find relevant sections rather than reading the whole file.
4. Read the relevant prompt file(s) in skill/phases/ to identify what instruction gap led to the miss

DIAGNOSIS CONSTRAINTS:
- Identify the ROOT CAUSE in the scanner's prompts/instructions
- Suggest a MINIMAL fix: a single sentence, clause, or bullet point addition/edit/deletion
- Be GENERAL: the fix should catch an entire CLASS of similar misses, not just this specific finding
- Prefer adding to an existing list over restructuring sections
- Deletions and edits are acceptable if they remove an overly restrictive gate
- Conciseness is paramount — prompts must stay small

Output ONLY valid JSON:
{
  "root_cause": "Why the scanner missed this — be specific about which instruction/rule/gate caused the miss",
  "prompt_file": "The primary prompt file to change (relative path like skill/phases/phase2_shared.md)",
  "section_to_change": "Quote the relevant section heading or existing text",
  "suggested_change": "The specific text to add, modify, or delete — as short and general as possible",
  "change_type": "add|edit|delete",
  "false_positive_risk": "low|medium|high",
  "risk_explanation": "Why this change might or might not introduce false positives"
}"""


_CODE_EXTS = {
    "py", "js", "ts", "jsx", "tsx", "java", "go", "rb", "php", "c", "cpp", "cc",
    "h", "hpp", "cs", "kt", "kts", "scala", "rs", "swift", "m", "mm", "sh",
    "json", "yaml", "yml", "xml", "html", "sql", "tf", "gradle", "properties",
}


def extract_identifiers(description):
    """Extract file paths, function names, and endpoint patterns from a finding description."""
    identifiers = []

    # A token like `word.word` only counts as a file path if it contains a
    # directory separator or ends in a known code/config extension. Without
    # this filter, prose like "e.g." or version strings like "1.2.3" get
    # mistaken for files and produce spurious loss-phase evidence.
    for candidate in re.findall(r'[\w/.-]+\.\w{1,4}', description):
        ext = candidate.rsplit(".", 1)[-1].lower()
        if "/" in candidate or ext in _CODE_EXTS:
            identifiers.append(candidate)

    function_names = re.findall(r'(?:function|handler|endpoint|method)\s+(\w+)|(\w+)\(\)', description)
    for match in function_names:
        name = match[0] or match[1]
        if name and len(name) > 3:
            identifiers.append(name)

    route_patterns = re.findall(r'(?:GET|POST|PUT|DELETE|PATCH)\s+(/[\w/{}\-]+)', description)
    identifiers.extend(route_patterns)

    api_patterns = re.findall(r'/api/[\w/\-{}]+', description)
    identifiers.extend(api_patterns)

    camel_names = re.findall(r'\b[a-z]+(?:[A-Z][a-z]+){1,}\b', description)
    identifiers.extend([n for n in camel_names if len(n) > 5])

    return list(set(identifiers))


def search_file_for_identifiers(filepath, identifiers, context_lines=3):
    """Search a file for any of the given identifiers. Return matches with context."""
    if not os.path.isfile(filepath):
        return []

    with open(filepath, "r", errors="replace") as f:
        lines = f.readlines()

    matches = []
    for ident in identifiers:
        # For plain word identifiers (function/variable names) require a
        # word-boundary match so a short name doesn't match unrelated
        # substrings; path/route identifiers still use substring matching.
        if re.fullmatch(r"\w+", ident):
            pattern = re.compile(r"\b" + re.escape(ident) + r"\b", re.IGNORECASE)
            matcher = lambda line, p=pattern: p.search(line) is not None
        else:
            matcher = lambda line, i=ident: i.lower() in line.lower()
        for i, line in enumerate(lines):
            if matcher(line):
                start = max(0, i - context_lines)
                end = min(len(lines), i + context_lines + 1)
                context = "".join(lines[start:end])
                matches.append({
                    "identifier": ident,
                    "file": filepath,
                    "line": i + 1,
                    "context": context.strip(),
                })
                break
    return matches


def locate_loss_phase(results_dir, finding):
    """Determine which phase lost the finding.

    Returns (phase_key, evidence_excerpt).
    """
    identifiers = extract_identifiers(finding["description"])
    if not identifiers:
        return ("unknown", "Could not extract identifiers from finding description")

    # 1. Check phase2b — was it a candidate that got rejected?
    phase2b_path = os.path.join(results_dir, "phase2b_output.md")
    phase2b_matches = search_file_for_identifiers(phase2b_path, identifiers)
    if phase2b_matches:
        with open(phase2b_path, "r", errors="replace") as f:
            phase2b_content = f.read()
        reject_patterns = ["REJECTED", "FALSE POSITIVE", "false positive", "rejected"]
        for pattern in reject_patterns:
            if pattern in phase2b_content:
                for m in phase2b_matches:
                    if any(rp.lower() in m["context"].lower() for rp in reject_patterns):
                        return ("phase2b", m["context"])

    # 2. Check phase2 results — was input traced with non-candidate disposition?
    results_subdir = os.path.join(results_dir, "results")
    if os.path.isdir(results_subdir):
        for results_file in sorted(os.listdir(results_subdir)):
            filepath = os.path.join(results_subdir, results_file)
            matches = search_file_for_identifiers(filepath, identifiers)
            if matches:
                non_candidate = ["SAFE", "NO-MATCH", "NO MATCH", "DESIGN-INTENT", "DESIGN INTENT"]
                for m in matches:
                    for disposition in non_candidate:
                        if disposition.lower() in m["context"].lower():
                            class_agent = _infer_class_from_filename(results_file)
                            return (f"phase2_{class_agent}", m["context"])

    # 3. Check phase1 — was the input/endpoint even enumerated?
    phase1_path = os.path.join(results_dir, "phase1_output.md")
    phase1_matches = search_file_for_identifiers(phase1_path, identifiers)
    if not phase1_matches:
        return ("phase1", f"None of these identifiers found in phase1: {identifiers[:5]}")

    # 4. Input is in phase1 but not found in phase2 results — lost in dispatch/tracing
    # Check which class should have caught it based on finding type
    finding_type = finding.get("type", "")
    class_agent = _type_to_class(finding_type)

    # Gather what phase2 results exist for context
    evidence = f"Input enumerated in phase1 but not traced to a candidate in phase2. "
    evidence += f"Expected class agent: {class_agent}. "
    if phase1_matches:
        evidence += f"Phase1 match: {phase1_matches[0]['context'][:200]}"

    return (f"phase2_{class_agent}", evidence)


def _infer_class_from_filename(filename):
    """Infer class agent from results filename like sg-1_inj_results.md."""
    if "_inj_" in filename:
        return "inj"
    elif "_nav_" in filename:
        return "nav"
    elif "_log_" in filename:
        return "log"
    elif "sink_driven" in filename:
        return "inj"
    return "nav"


def _type_to_class(finding_type):
    """Map vulnerability type to the expected class agent."""
    type_map = {
        "SQLi": "inj", "PathTraversal": "inj", "SSRF": "inj",
        "CommandInjection": "inj", "XXE": "inj", "CodeEval": "inj",
        "XSS": "inj", "OpenRedirect": "inj",
        "CSRF": "nav", "IDOR": "nav", "AuthBypass": "nav",
        "MissingAuth": "nav", "AuditSpoofing": "nav",
        "IPSpoofing": "nav", "MassAssignment": "nav",
        "RaceCondition": "log", "DoS": "log", "CryptoWeakness": "log",
    }
    return type_map.get(finding_type, "nav")


def build_diagnostic_prompt(finding, phase_key, evidence, results_dir, repo_dir):
    """Build the investigative prompt for an agentic diagnostic session."""
    gt_files = glob.glob(os.path.join(BENCHMARK_DIR, f"{finding['repo_name']}*.json"))
    gt_path = gt_files[0] if gt_files else "unknown"
    prompt_files = PHASE_TO_PROMPT.get(phase_key, PHASE_TO_PROMPT["unknown"])
    prompt_paths = [os.path.join(REPO_ROOT, p) for p in prompt_files]
    scan_log_path = os.path.join(repo_dir, "benchmark_scan.log")

    return f"""Finding {finding['finding_id']} was NOT detected. Figure out where the scanner went amiss.

## Ground Truth Finding
- **ID**: {finding['finding_id']}
- **Type**: {finding['type']}
- **Description**: {finding['description']}

## Investigation Paths
- Ground truth file: {gt_path}
- Scanner results directory: {results_dir}/
- Scan log (JSONL, use grep): {scan_log_path}
- Relevant prompt file(s): {', '.join(prompt_paths)}
- All prompt files: {os.path.join(REPO_ROOT, 'skill', 'phases')}/

## Pre-analysis Hint (may be wrong — verify)
Lost at **{phase_key}** phase. Evidence: {evidence[:500]}

Come up with a plan of the minimal changes we could make, as concise as possible, to our prompts to mitigate this gap. Deletions/edits/additions are all acceptable, but bear in mind our goals of being concise and keeping prompts as small as possible, with generalized advice.

Output ONLY valid JSON as specified in your system prompt."""


def invoke_diagnostic(finding, phase_key, evidence, results_dir, repo_dir):
    """Invoke Claude in agentic mode to investigate the miss."""
    fid = finding["finding_id"]
    prompt = build_diagnostic_prompt(finding, phase_key, evidence, results_dir, repo_dir)

    print(f"    [{fid}] Invoking claude ({MODEL}) in agentic mode, timeout 1200s ...", flush=True)

    cmd = [
        "claude", "-p", prompt,
        "--output-format", "text",
        "--model", MODEL,
        "--system-prompt", DIAGNOSTIC_SYSTEM_PROMPT,
        "--allowedTools", "Read", "Bash(grep:*)", "Bash(wc:*)", "Bash(ls:*)",
        "Bash(find:*)", "Bash(head:*)", "Bash(tail:*)", "Bash(cat:*)",
        "--permission-mode", "acceptEdits",
        "--add-dir", repo_dir,
        "--add-dir", results_dir,
        "--add-dir", os.path.join(REPO_ROOT, "skill", "phases"),
        "--add-dir", BENCHMARK_DIR,
    ]

    start = time.time()
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=1200,
        )
    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        print(f"    [{fid}] TIMED OUT after {elapsed:.0f}s", flush=True)
        return {"root_cause": "diagnostic timed out", "prompt_file": "unknown",
                "section_to_change": "", "suggested_change": "",
                "change_type": "", "false_positive_risk": "unknown",
                "risk_explanation": ""}

    elapsed = time.time() - start
    if result.returncode != 0:
        print(f"    [{fid}] FAILED (exit {result.returncode}) after {elapsed:.0f}s", flush=True)
        if result.stderr:
            print(f"    [{fid}] stderr: {result.stderr.strip()[:200]}", flush=True)
        return {"root_cause": f"diagnostic failed: exit {result.returncode}",
                "prompt_file": "unknown", "section_to_change": "",
                "suggested_change": "", "change_type": "",
                "false_positive_risk": "unknown", "risk_explanation": ""}

    print(f"    [{fid}] Completed in {elapsed:.0f}s ({len(result.stdout):,} chars response)", flush=True)
    return _parse_diagnostic_output(result.stdout)


def _parse_diagnostic_output(raw_output):
    """Parse the diagnostic JSON output."""
    text = raw_output.strip()
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass
    return {"root_cause": "failed to parse diagnostic output",
            "prompt_file": "unknown", "section_to_change": text[:500],
            "suggested_change": "", "change_type": "",
            "false_positive_risk": "unknown", "risk_explanation": ""}


def write_analysis_json(analyses):
    """Write machine-readable analysis results."""
    atomic_write_json(ANALYSIS_JSON, analyses)
    print(f"  Analysis JSON written to: {ANALYSIS_JSON}")


def write_analysis_report(analyses):
    """Write human-readable Markdown analysis report."""
    os.makedirs(RESULTS_DIR, exist_ok=True)

    lines = []
    lines.append("# False Negative Analysis\n")
    lines.append(f"**Generated**: {datetime.now().isoformat()}")
    lines.append(f"**Model**: {MODEL}")
    lines.append(f"**Misses analyzed**: {len(analyses)}\n")

    for a in analyses:
        lines.append(f"## {a['finding_id']} — {a['type']} in {a['repo_name']}\n")
        lines.append(f"**Lost at phase**: {a['loss_phase']}")
        lines.append(f"**Responsible prompt(s)**: {', '.join(PHASE_TO_PROMPT.get(a['loss_phase'], ['unknown']))}")
        lines.append(f"**Evidence**: {a['evidence'][:300]}\n")

        diag = a.get("diagnostic", {})
        lines.append(f"**Root cause**: {diag.get('root_cause', 'unknown')}\n")
        lines.append(f"**Prompt file to change**: {diag.get('prompt_file', 'unknown')}")
        lines.append(f"**Section to change**: {diag.get('section_to_change', 'unknown')}\n")
        lines.append(f"**Suggested change** ({diag.get('change_type', 'add')}):\n```\n{diag.get('suggested_change', '')}\n```\n")
        lines.append(f"**FP risk**: {diag.get('false_positive_risk', 'unknown')} — {diag.get('risk_explanation', '')}\n")
        lines.append("---\n")

    with open(ANALYSIS_REPORT, "w") as f:
        f.write("\n".join(lines))
    print(f"  Analysis report written to: {ANALYSIS_REPORT}")


def main():
    parser = argparse.ArgumentParser(description="Analyze missed benchmark findings")
    parser.add_argument("--finding", type=str, default=None,
                        help="Analyze a specific finding ID only")
    parser.add_argument("--state-file", type=str, default=STATE_FILE,
                        help="Override state file path")
    parser.add_argument("--verbose", action="store_true",
                        help="Print full artifact excerpts")
    args = parser.parse_args()

    if not os.path.isfile(args.state_file):
        print(f"Error: State file not found: {args.state_file}")
        print("  Run the benchmark first: python -m local_harness.benchmark.run")
        sys.exit(1)

    with open(args.state_file) as f:
        state = json.load(f)

    # Filter to missed findings
    misses = []
    for fid, judgment in state.get("judgments", {}).items():
        if judgment.get("detected") is False:
            if args.finding and fid != args.finding:
                continue
            misses.append({
                "finding_id": fid,
                "type": judgment.get("type", ""),
                "description": _get_finding_description(fid, state),
                "repo_name": judgment.get("repo_name", ""),
                "scan_target": judgment.get("scan_target", ""),
                "results_dir": state["scan_targets"].get(
                    judgment.get("scan_target", ""), {}).get("results_dir"),
            })

    if not misses:
        if args.finding:
            print(f"Finding {args.finding} was not a miss (or doesn't exist in state).")
        else:
            print("No missed findings to analyze. All ground truth findings were detected!")
        sys.exit(0)

    print(f"\n{'='*60}")
    print(f"ANALYZING {len(misses)} MISSED FINDING(S) (3 workers)")
    print(f"{'='*60}\n")

    def _analyze_one(miss):
        """Analyze a single missed finding. Returns the analysis dict."""
        fid = miss["finding_id"]
        try:
            print(f"  [{fid}] {miss['type']} in {miss['repo_name']}")

            if not miss["results_dir"] or not os.path.isdir(miss["results_dir"]):
                print(f"    [{fid}] No results directory available, skipping")
                return {**miss, "loss_phase": "no_results", "evidence": "",
                        "diagnostic": {"root_cause": "scan produced no results"}}

            phase_key, evidence = locate_loss_phase(miss["results_dir"], miss)
            print(f"    [{fid}] Lost at: {phase_key}")

            if args.verbose:
                print(f"    [{fid}] Evidence: {evidence[:200]}")

            repo_dir = os.path.dirname(miss["results_dir"])
            print(f"    [{fid}] Running agentic diagnostic analysis ...", flush=True)
            diagnostic = invoke_diagnostic(miss, phase_key, evidence, miss["results_dir"], repo_dir)
            print(f"    [{fid}] Root cause: {diagnostic.get('root_cause', 'unknown')[:100]}")
            print(f"    [{fid}] FP risk: {diagnostic.get('false_positive_risk', 'unknown')}")

            return {**miss, "loss_phase": phase_key, "evidence": evidence, "diagnostic": diagnostic}
        except Exception as e:
            print(f"    [{fid}] ERROR: {e}", flush=True)
            return {**miss, "loss_phase": "error", "evidence": "",
                    "diagnostic": {"root_cause": f"analysis error: {e}"}}

    analyses = []
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {executor.submit(_analyze_one, miss): miss for miss in misses}
        for future in as_completed(futures):
            analyses.append(future.result())

    # Write outputs
    print()
    write_analysis_json(analyses)
    write_analysis_report(analyses)

    print(f"\n{'='*60}")
    print(f"ANALYSIS COMPLETE: {len(analyses)} miss(es) diagnosed")
    print(f"{'='*60}")
    print(f"  Report: {ANALYSIS_REPORT}")
    print(f"  JSON:   {ANALYSIS_JSON}\n")


def _get_finding_description(finding_id, state):
    """Retrieve the full finding description from ground truth files."""
    for json_file in glob.glob(os.path.join(BENCHMARK_DIR, "*.json")):
        with open(json_file) as f:
            findings = json.load(f)
        for finding in findings:
            if finding.get("finding_id") == finding_id:
                return finding.get("description", "")
    return ""


if __name__ == "__main__":
    main()
