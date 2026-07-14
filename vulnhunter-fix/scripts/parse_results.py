#!/usr/bin/env python3
"""Parse VulnHunter results directory into structured JSON.

Extracts:
- Code smells (regex-based — stable format, unlikely to drift)
- File discovery (PoC and exploit_test paths per VULN ID)
- README path for haiku-based findings extraction

Findings extraction is delegated to haiku at runtime (see the phase-2
parse prompts). The regex-based fallback is retained for offline/test
use but is NOT the primary path in production.
"""

import hashlib
import json
import re
import sys
from pathlib import Path


def primary_cwe(cwe_string: str) -> str:
    """Pick the canonical CWE when the report carries multiple.

    Reports sometimes record a finding with two related CWEs as
    `CWE-918 / CWE-74` (or comma-separated). The upstream agent's
    issue body templates emit only the first CWE in the marker, so
    that's the one our idempotency key must use to collide
    cross-tool. Empty input returns empty.
    """
    m = re.search(r"CWE-\d+", cwe_string or "")
    return m.group(0) if m else ""


def compute_vulnfix_key(location: str, cwe: str, root_cause: str) -> str:
    """SHA-256 prefix used as the cross-tool idempotency marker.

    Same definition vulnhunter, verify, and vulnhunter-fix all use,
    so the marker correlates across tools. For multi-CWE rows we key
    on the primary CWE (matching how issue bodies are written) — see
    `primary_cwe`.
    """
    raw = f"{location}|{primary_cwe(cwe)}|{root_cause}".encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def parse_summary_table(content: str) -> list[dict]:
    """Regex fallback: extract findings from the summary table.

    Used only when haiku extraction is unavailable (tests, offline).
    Handles multi-CWE columns (`CWE-918 / CWE-74`, `CWE-22, CWE-23`)
    and High+ severities.
    """
    findings = []
    # CWE column accepts: `CWE-918`, `CWE-918 / CWE-74`, `CWE-22, CWE-23`,
    # `CWE-918 | CWE-74` — anything word-y plus `/` and `,` between codes.
    table_pattern = re.compile(
        r'\|\s*\[?(VULN-\d+)\]?(?:\([^)]*\))?\s*\|'
        r'\s*(.+?)\s*\|'
        r'\s*(CWE-[\d,\s\w/-]+?)\s*\|'
        r'\s*(\w+\+?)\s*\|'
        r'\s*(.+?)\s*\|'
        r'\s*(\w+)\s*\|'
    )
    for match in table_pattern.finditer(content):
        findings.append({
            "id": match.group(1),
            "title": match.group(2).strip(),
            "cwe": match.group(3).strip(),
            "severity": match.group(4),
            "exploit_test": match.group(5).strip(),
            "status": match.group(6),
        })
    return findings


def parse_finding_detail(content: str, vuln_id: str) -> dict:
    """Extract detailed info for a specific finding from the README body."""
    detail = {}

    section_pattern = re.compile(
        rf'##\s*\[?{re.escape(vuln_id)}\]?[:\s]*(.+?)(?=\n##\s|\Z)',
        re.DOTALL
    )
    match = section_pattern.search(content)
    if not match:
        section_pattern = re.compile(
            rf'##\s*{re.escape(vuln_id)}[:\s]*(.+?)(?=\n##\s|\Z)',
            re.DOTALL
        )
        match = section_pattern.search(content)

    if not match:
        return detail

    section = match.group(0)

    location_match = re.search(r'\*\*Location\*\*\s*\|\s*`?([^`|]+)`?', section)
    if location_match:
        detail["location"] = location_match.group(1).strip()

    root_cause_match = re.search(r'\*\*Root Cause\*\*\s*\|\s*(.+)', section)
    if root_cause_match:
        detail["root_cause"] = root_cause_match.group(1).strip()

    entry_match = re.search(r'\*\*Entry Point\*\*\s*\|\s*(.+)', section)
    if entry_match:
        detail["entry_point"] = entry_match.group(1).strip()

    flow_match = re.search(r'\*\*Data Flow\*\*\s*\|\s*(.+)', section)
    if flow_match:
        detail["data_flow"] = flow_match.group(1).strip()

    fix_section = re.search(r'###\s*Proposed Fix(.+?)(?=\n###|\Z)', section, re.DOTALL)
    if fix_section:
        fix_text = fix_section.group(1)
        strategy_match = re.search(r'\*\*Strategy\*\*:\s*(.+)', fix_text)
        files_match = re.search(r'\*\*Files to change\*\*:\s*(.+)', fix_text)
        why_match = re.search(r'\*\*Why this works\*\*:\s*(.+)', fix_text)

        detail["proposed_fix"] = {
            "strategy": strategy_match.group(1).strip() if strategy_match else "",
            "files_to_change": files_match.group(1).strip() if files_match else "",
            "why": why_match.group(1).strip() if why_match else "",
        }

    return detail


def find_related_files(results_dir: Path, vuln_id: str) -> dict:
    """Locate PoC and exploit test files for a finding."""
    vuln_num = vuln_id.replace("VULN-", "")
    files = {}

    poc_dir = results_dir / "poc"
    if poc_dir.exists():
        for f in poc_dir.iterdir():
            if f"VULN-{vuln_num}" in f.name or f"vuln_{vuln_num}" in f.name.lower():
                files["poc"] = str(f)
                break

    tests_dir = results_dir / "exploit_tests"
    if tests_dir.exists():
        for f in tests_dir.iterdir():
            if f"vuln_{vuln_num}" in f.name.lower() or f"VULN-{vuln_num}" in f.name:
                files["exploit_test"] = str(f)
                break

    return files


def discover_all_vuln_files(results_dir: Path) -> dict[str, dict]:
    """Discover PoC and exploit test files for all VULN IDs in the directory."""
    all_files = {}
    poc_dir = results_dir / "poc"
    tests_dir = results_dir / "exploit_tests"

    vuln_pattern = re.compile(r"VULN-(\d+)", re.IGNORECASE)

    if poc_dir.exists():
        for f in poc_dir.iterdir():
            m = vuln_pattern.search(f.name)
            if m:
                vid = f"VULN-{m.group(1)}"
                all_files.setdefault(vid, {})["poc"] = str(f)

    if tests_dir.exists():
        for f in tests_dir.iterdir():
            m = vuln_pattern.search(f.name)
            if m:
                vid = f"VULN-{m.group(1)}"
                all_files.setdefault(vid, {})["exploit_test"] = str(f)

    return all_files


# Heading regex matching all observed code-smell section variants:
#   ## Code Quality / Defense in Depth
#   ## Code Quality / Defense in Depth — IAM Policy Observations
#   ## Code Smells
#   ## Observations (Informational)
#   ## Infrastructure Configuration Review (Informational)
#   ## Infrastructure Security Observations (Non-Findings)
#   ### Code Smells (Informational — not vulnerabilities)
SMELL_HEADING_RE = re.compile(
    r"^(#{2,3})\s+(?:Code\s+Quality(?:\s*[/—-]\s*Defense\s+in\s+Depth)?(?:\s*[—-].*)?|"
    r"Code\s+Smells?(?:\s*\(.+?\))?|"
    r"(?:Infrastructure\s+)?(?:Security\s+|Configuration\s+)?Observations?(?:\s*\(.+?\))?|"
    r"Defense\s+in\s+Depth(?:\s*[—-].*)?|"
    r"Infrastructure\s+Configuration\s+Review(?:\s*\(.+?\))?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)


def _extract_smell_section(content: str) -> str:
    """Find the first code-smell section and return its body up to the next H2 heading."""
    match = SMELL_HEADING_RE.search(content)
    if not match:
        return ""
    start = match.end()
    # Stop at the next H2 heading (any H2 ends the section, including new top-level sections)
    next_h2 = re.search(r"^##\s+\S", content[start:], re.MULTILINE)
    end = start + next_h2.start() if next_h2 else len(content)
    return content[start:end]


def _parse_smells_per_section_format(section: str) -> list[dict]:
    """Parse Format 1: per-smell `### Code Smell N: <title>` headings each with a field table."""
    smells = []
    # Split on `### Code Smell N: ...` or `### Smell N: ...`
    smell_pattern = re.compile(
        r"^###\s+(?:Code\s+Smell|Smell|Observation)\s*\d+\s*[:.\-]?\s*(.+?)$",
        re.IGNORECASE | re.MULTILINE,
    )
    matches = list(smell_pattern.finditer(section))
    for i, m in enumerate(matches):
        title = m.group(1).strip()
        body_start = m.end()
        body_end = matches[i + 1].start() if i + 1 < len(matches) else len(section)
        body = section[body_start:body_end]

        smell = {"title": title}
        # Extract fields from a 2-column markdown table: `| **Field** | Value |`
        for label, key in [
            ("Location", "location"),
            ("Pattern", "pattern"),
            ("Risk if conditions change", "risk_if_conditions_change"),
            ("Risk if Conditions Change", "risk_if_conditions_change"),
            ("Recommendation", "recommendation"),
            ("Downgrade reason", "downgrade_reason"),
            ("Downgrade Reason", "downgrade_reason"),
        ]:
            field_re = re.compile(
                rf"\*\*{re.escape(label)}\*\*\s*\|\s*([^\n|]+(?:\|[^\n|]+)*)\s*(?:\||$)",
                re.MULTILINE,
            )
            fm = field_re.search(body)
            if fm and key not in smell:
                smell[key] = fm.group(1).strip().strip("`")
        if smell.get("location") or smell.get("pattern"):
            smells.append(smell)
    return smells


def _parse_smells_table_format(section: str) -> list[dict]:
    """Parse Format 2: a single combined table with one row per smell."""
    smells = []
    # Find a markdown table with a header row that includes Location and Recommendation
    lines = section.splitlines()
    table_start = None
    for i, line in enumerate(lines):
        if "Location" in line and "Recommendation" in line and line.strip().startswith("|"):
            table_start = i
            break
    if table_start is None:
        return smells

    header = [c.strip().strip("*").lower() for c in lines[table_start].split("|")[1:-1]]
    # Find column positions
    def col_idx(*names):
        for n in names:
            try:
                return header.index(n.lower())
            except ValueError:
                pass
        return -1

    loc_i = col_idx("location")
    pat_i = col_idx("pattern", "observation")
    risk_i = col_idx("risk if conditions change", "risk-if-conditions-change", "risk")
    rec_i = col_idx("recommendation", "recommended action", "notes")

    # Skip header + separator row
    for line in lines[table_start + 2 :]:
        line = line.strip()
        if not line or not line.startswith("|"):
            break
        cells = [c.strip() for c in line.split("|")[1:-1]]
        if len(cells) < 2:
            continue
        smell = {}
        if loc_i >= 0 and loc_i < len(cells):
            smell["location"] = cells[loc_i].strip("`")
        if pat_i >= 0 and pat_i < len(cells):
            smell["pattern"] = cells[pat_i]
        if risk_i >= 0 and risk_i < len(cells):
            smell["risk_if_conditions_change"] = cells[risk_i]
        if rec_i >= 0 and rec_i < len(cells):
            smell["recommendation"] = cells[rec_i]
        if smell.get("location"):
            smells.append(smell)
    return smells


def parse_code_smells(content: str) -> list[dict]:
    """Extract code smells / defense-in-depth observations from the report.

    Per REQ-ING-003: distinguish smells from confirmed vulnerabilities.
    Per REQ-DEL-005: each smell needs location, risk_if_conditions_change, recommendation.

    Handles both observed report formats:
    - Format 1: per-smell `### Code Smell N: <title>` sections with field tables
    - Format 2: single combined table with one row per smell
    """
    section = _extract_smell_section(content)
    if not section:
        return []

    # Try per-section format first, fall back to table format
    smells = _parse_smells_per_section_format(section)
    if not smells:
        smells = _parse_smells_table_format(section)
    return smells


def parse_results(results_path: str) -> dict:
    """Main parser: reads results directory and returns structured output.

    The `findings` array uses regex extraction as a fallback. In production
    the Phase 2 parse orchestrator uses haiku to extract findings from the
    README and merges the file paths from `vuln_files` into the
    haiku-produced findings.
    """
    results_dir = Path(results_path)
    readme = results_dir / "README.md"

    if not readme.exists():
        return {"error": f"README.md not found in {results_path}"}

    content = readme.read_text()

    # Regex-based findings extraction (fallback)
    summary = parse_summary_table(content)
    confirmed = [f for f in summary if f["status"].lower() == "confirmed"]

    smells = parse_code_smells(content)

    for finding in confirmed:
        detail = parse_finding_detail(content, finding["id"])
        finding.update(detail)
        related = find_related_files(results_dir, finding["id"])
        finding["files"] = related
        # vulnfix_key joins findings ↔ issues across the toolchain.
        # Always emit one — empty location/root_cause still hash to a
        # stable value, just one that's unlikely to collide with the
        # upstream issue's key.
        finding["primary_cwe"] = primary_cwe(finding.get("cwe", ""))
        finding["vulnfix_key"] = compute_vulnfix_key(
            finding.get("location", ""),
            finding.get("cwe", ""),
            finding.get("root_cause", ""),
        )

    # Discover all VULN file paths (independent of regex parsing)
    vuln_files = discover_all_vuln_files(results_dir)

    return {
        "results_dir": str(results_dir),
        "readme_path": str(readme),
        "total_findings": len(summary),
        "confirmed_findings": len(confirmed),
        "findings": confirmed,
        "vuln_files": vuln_files,
        "code_smells_count": len(smells),
        "code_smells": smells,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: parse_results.py <results_directory>", file=sys.stderr)
        sys.exit(1)

    result = parse_results(sys.argv[1])
    print(json.dumps(result, indent=2))
