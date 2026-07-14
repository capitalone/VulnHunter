"""Convert a VulnHunter scan's extracted findings into audit-stream records.

Two-stage design so we don't double-run the (Haiku-cost) LLM extractor:

- ``count_findings_from_disk`` — cheap filesystem count of VULN-NNN
  artifacts (poc/exploit_tests) used to populate ``findings_count`` on
  ``scan_completed`` audit events. No LLM needed.
- ``build_finding_events`` — pure converter from an
  ``issues_extract.ExtractedReport`` (already produced by the issues
  stage) into a list of findings-event dicts.

The invoking module (``__main__`` for the scan path; ``verify_runner``
for the verify path) is responsible for calling
``issues_extract.extract_findings`` once and threading the result to
both the issues stage and here — that way a Haiku call is never
duplicated.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from . import audit
from .issues_extract import ExtractedReport, Finding
from .repo_properties import RepoProperties

logger = logging.getLogger(__name__)


# Match the same pattern issues_extract uses so we don't diverge on
# what a "VULN file" looks like.
_VULN_FILE_RE = re.compile(r"VULN[-_](\d+)", re.IGNORECASE)


def count_findings_from_disk(results_dir: Path) -> int:
    """Count distinct VULN-NNN identifiers under results_dir/{poc,exploit_tests}.

    Cheap enough to run inline; used to populate ``findings_count`` on
    ``scan_completed`` events without paying for a Haiku extract.
    Returns 0 when the directory is missing or empty. Same VULN found
    in both ``poc/`` and ``exploit_tests/`` counts once.
    """
    if not results_dir.is_dir():
        return 0
    seen: set[str] = set()
    for sub in ("poc", "exploit_tests"):
        d = results_dir / sub
        if not d.is_dir():
            continue
        for entry in d.iterdir():
            m = _VULN_FILE_RE.search(entry.name)
            if m:
                seen.add(f"VULN-{int(m.group(1)):03d}")
    return len(seen)


def build_finding_events(
    extracted: ExtractedReport,
    *,
    repo_slug: str,
    app_id: str,
    report_id: str,
    results_dir: Path,
    opened: bool = True,
    status: str = "OPEN",
    github_issue_url_by_vuln: dict[str, str] | None = None,
    repo_properties: RepoProperties | None = None,
) -> list[dict[str, Any]]:
    """Convert every Finding in ``extracted`` to a findings-event dict.

    - ``opened=True`` populates ``opened_at`` — use on the initial
      scan-side emission. ``opened=False`` on later transitions so
      the materialized view keeps the original open timestamp.
    - ``status`` is the finding-state-machine value for the emission.
    - ``github_issue_url_by_vuln`` maps ``VULN-NNN`` → issue URL when
      known (e.g. after the issues stage posts).
    - ``repo_properties`` carries the optional operator-defined metadata
      tags. Blank fields drop out of the JSON during serialization.
    """
    url_map = github_issue_url_by_vuln or {}
    props = repo_properties or RepoProperties()
    return [
        _one(
            finding=f,
            repo_slug=repo_slug,
            app_id=app_id,
            report_id=report_id,
            results_dir=results_dir,
            opened=opened,
            status=status,
            github_issue_url=url_map.get(f.id, ""),
            repo_properties=props,
        )
        for f in extracted.findings
    ]


def _one(
    *,
    finding: Finding,
    repo_slug: str,
    app_id: str,
    report_id: str,
    results_dir: Path,
    opened: bool,
    status: str,
    github_issue_url: str,
    repo_properties: RepoProperties,
) -> dict[str, Any]:
    return audit.build_finding_event(
        app_id=app_id,
        repo_slug=repo_slug,
        report_id=report_id,
        finding_id=audit.finding_id_for(report_id, finding.id),
        vuln_id=finding.id,
        title=finding.title,
        cwe=finding.cwe or "CWE-UNKNOWN",
        severity=finding.severity,
        status=status,
        location=finding.location,
        root_cause=finding.root_cause,
        entry_point=finding.entry_point,
        data_flow=finding.data_flow,
        # The Finding dataclass doesn't currently carry a one-liner
        # reproduction command — the exploit test lives as a file, not
        # a shell string. Leave the top-level ``exploit_test`` empty;
        # ``files.exploit_test`` still carries the path.
        exploit_test_cmd="",
        proposed_fix_strategy=finding.fix_strategy,
        # Not surfaced by issues_extract today; kept empty rather than
        # invented. Adding it would require a new field on Finding.
        proposed_fix_files="",
        # Reuse severity_rationale — it's the closest thing the
        # extractor gives us to a "why". Better than blank.
        proposed_fix_why=finding.severity_rationale,
        poc_file=relativize(finding.poc_path, results_dir),
        exploit_test_file=relativize(finding.exploit_test_path, results_dir),
        github_issue_url=github_issue_url,
        opened=opened,
        repo_properties=repo_properties.values,
    )


def relativize(path: str | None, root: Path) -> str:
    """Make ``path`` relative to ``root`` when possible.

    A findings event should be portable — absolute paths pin us to the
    scanning host's filesystem. Fall back to the original string when
    relativization fails (path outside root, or None).
    """
    if not path:
        return ""
    try:
        return str(Path(path).resolve().relative_to(root.resolve()))
    except (ValueError, OSError):
        return path
