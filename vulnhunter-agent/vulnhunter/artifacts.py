"""Typed artifact persistence and compatibility report rendering."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .models import Assignment, Candidate, Review, RunStatus, Usage


SCHEMA_VERSION = "1"


class ArtifactStore:
    def __init__(self, results_dir: Path) -> None:
        self.results_dir = results_dir.resolve()
        self.assignments_dir = self.results_dir / "assignments"
        self.candidates_dir = self.results_dir / "candidates"
        self.reviews_dir = self.results_dir / "reviews"
        self.disagreements_dir = self.results_dir / "disagreements"
        self.poc_dir = self.results_dir / "poc"
        self.exploit_tests_dir = self.results_dir / "exploit_tests"
        for directory in (
            self.results_dir,
            self.assignments_dir,
            self.candidates_dir,
            self.reviews_dir,
            self.disagreements_dir,
            self.poc_dir,
            self.exploit_tests_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)

    def write_assignment(self, assignment: Assignment, payload: dict[str, Any]) -> None:
        self._validate_named("assignment.schema.json", assignment.to_dict())
        document = {
            "schema_version": SCHEMA_VERSION,
            "assignment": assignment.to_dict(),
            "payload": payload,
        }
        self.write_json(self.assignments_dir / f"{assignment.assignment_id}.json", document)

    def read_assignment(self, assignment_id: str) -> dict[str, Any] | None:
        path = self.assignments_dir / f"{assignment_id}.json"
        return self.read_json(path) if path.is_file() else None

    def write_candidate(self, candidate: Candidate) -> None:
        self._validate_named("candidate.schema.json", candidate.to_dict())
        self.write_json(
            self.candidates_dir / f"{candidate.candidate_id}.json",
            {"schema_version": SCHEMA_VERSION, **candidate.to_dict()},
        )

    def write_review(self, review: Review) -> None:
        self._validate_named("review.schema.json", review.to_dict())
        self.write_json(
            self.reviews_dir / f"{review.review_id}.json",
            {"schema_version": SCHEMA_VERSION, **review.to_dict()},
        )

    def write_disagreement(
        self,
        *,
        candidate_id: str,
        review_ids: list[str],
        disputed_claims: list[str],
        resolution_status: str,
    ) -> None:
        payload = {
            "candidate_id": candidate_id,
            "review_ids": review_ids,
            "disputed_claims": disputed_claims,
            "resolution_status": resolution_status,
        }
        self._validate_named("disagreement.schema.json", payload)
        self.write_json(
            self.disagreements_dir / f"{candidate_id}.json",
            {"schema_version": SCHEMA_VERSION, **payload},
        )

    def write_state(self, state: dict[str, Any]) -> None:
        self.write_json(self.results_dir / "run_state.json", state)

    def read_state(self) -> dict[str, Any] | None:
        path = self.results_dir / "run_state.json"
        return self.read_json(path) if path.is_file() else None

    def finalize(
        self,
        *,
        run_id: str,
        repository: dict[str, Any],
        level: str,
        requested_models: list[dict[str, Any]],
        specialists: list[dict[str, Any]],
        status: RunStatus,
        candidates: list[Candidate],
        reviews: list[Review],
        assignments: list[Assignment],
        usage: Usage,
        coverage: dict[str, Any],
        limits: dict[str, Any],
        incomplete_reason: str = "",
    ) -> dict[str, Any]:
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "status": str(status),
            "repository": repository,
            "level": level,
            "models": requested_models,
            "specialists": specialists,
            "usage": asdict(usage),
            "limits": limits,
            "coverage": coverage,
            "assignments": {
                "total": len(assignments),
                "completed": sum(row.status == "COMPLETED" for row in assignments),
                "failed": sum(row.status == "FAILED" for row in assignments),
                "pending": sum(row.status == "PENDING" for row in assignments),
            },
            "findings": [
                {
                    "candidate_id": row.candidate_id,
                    "title": row.title,
                    "severity": row.severity,
                    "cwe": row.cwe,
                    "verdict": str(row.verdict),
                    "discovered_by": row.discovered_by,
                    "reviews": row.reviews,
                }
                for row in candidates
                if str(row.verdict) != "REJECTED"
            ],
            "reviews": len(reviews),
            "incomplete_reason": incomplete_reason,
        }
        self._validate_named("coverage.schema.json", coverage)
        self._validate_named("provider_usage.schema.json", asdict(usage))
        self._validate_manifest(manifest)
        self.write_json(self.results_dir / "run_manifest.json", manifest)
        self._write_pocs(candidates)
        self._write_report(manifest, candidates, reviews)
        self._write_legacy_manifest(run_id, status, candidates, usage)
        return manifest

    @staticmethod
    def write_json(path: Path, value: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(
            dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(value, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        except BaseException:
            try:
                os.remove(temporary)
            except OSError:
                pass
            raise

    @staticmethod
    def read_json(path: Path) -> dict[str, Any]:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"expected JSON object in {path}")
        return value

    def _validate_manifest(self, manifest: dict[str, Any]) -> None:
        self._validate_named("run_manifest.schema.json", manifest)

    def _validate_named(self, name: str, value: dict[str, Any]) -> None:
        schema_path = Path(__file__).with_name("schemas") / name
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        errors = sorted(
            Draft202012Validator(schema).iter_errors(value),
            key=lambda error: list(error.absolute_path),
        )
        if errors:
            raise ValueError(f"invalid {name}: {errors[0].message}")

    def _write_pocs(self, candidates: list[Candidate]) -> None:
        for index, candidate in enumerate(
            [row for row in candidates if str(row.verdict) == "CONFIRMED"], 1
        ):
            vuln_id = f"VULN-{index:03d}"
            slug = _slug(candidate.title)
            if candidate.poc:
                (self.poc_dir / f"{vuln_id}_{slug}.md").write_text(
                    candidate.poc.rstrip() + "\n", encoding="utf-8"
                )
            if candidate.exploit_test:
                (self.exploit_tests_dir / f"{vuln_id}_{slug}.txt").write_text(
                    candidate.exploit_test.rstrip() + "\n", encoding="utf-8"
                )

    def _write_report(
        self,
        manifest: dict[str, Any],
        candidates: list[Candidate],
        reviews: list[Review],
    ) -> None:
        confirmed = [row for row in candidates if str(row.verdict) == "CONFIRMED"]
        conditional = [row for row in candidates if str(row.verdict) == "CONDITIONAL"]
        unresolved = [row for row in candidates if str(row.verdict) == "UNRESOLVED"]
        lines = [
            "# VulnHunter Security Report",
            "",
            f"- Status: **{manifest['status']}**",
            f"- Scan level: **{manifest['level']}**",
            f"- Core models: **{len(manifest['models'])}**",
            f"- Confirmed findings: **{len(confirmed)}**",
            f"- Conditional findings: **{len(conditional)}**",
            f"- Unresolved findings: **{len(unresolved)}**",
            "",
        ]
        if len(manifest["models"]) == 1:
            lines.extend(
                [
                    "> [!NOTE]",
                    "> This run has no cross-model diversity. Review used a fresh, "
                    "isolated context, but the reviewer is not independently trained.",
                    "",
                ]
            )
        if str(manifest["status"]).startswith("INCOMPLETE"):
            lines.extend(
                [
                    "> [!WARNING]",
                    "> This scan is incomplete and must not be interpreted as clean.",
                    f"> Reason: {manifest['incomplete_reason'] or 'configured limit reached'}",
                    "",
                ]
            )
        elif manifest["status"] == RunStatus.COMPLETE_CONDITIONAL:
            lines.extend(
                [
                    "> [!CAUTION]",
                    "> Coverage completed, but one or more candidates remain "
                    "conditional or unresolved. This is not a clean result.",
                    "",
                ]
            )
        elif manifest["status"] == RunStatus.FAILED:
            lines.extend(
                [
                    "> [!WARNING]",
                    "> The scan failed and must not be interpreted as clean.",
                    f"> Reason: {manifest['incomplete_reason'] or 'engine failure'}",
                    "",
                ]
            )
        lines.extend(
            [
                "## Summary",
                "",
                "| ID | Severity | CWE | Title | Verdict |",
                "|---|---|---|---|---|",
            ]
        )
        reportable = confirmed + conditional + unresolved
        for index, candidate in enumerate(reportable, 1):
            lines.append(
                f"| VULN-{index:03d} | {candidate.severity} | {candidate.cwe} | "
                f"{candidate.title} | {candidate.verdict} |"
            )
        if not reportable:
            lines.append("| — | — | — | No reportable findings | — |")
        lines.append("")
        for index, candidate in enumerate(reportable, 1):
            lines.extend(_finding_markdown(f"VULN-{index:03d}", candidate, reviews))
        lines.extend(
            [
                "## Coverage",
                "",
                f"- Production files inventoried: {manifest['coverage'].get('files_total', 0)}",
                f"- Completed assignments: {manifest['assignments']['completed']}/"
                f"{manifest['assignments']['total']}",
                f"- Failed assignments: {manifest['assignments']['failed']}",
                f"- Unresolved files: {len(manifest['coverage'].get('unresolved_files', []))}",
                "",
                "## Model Provenance",
                "",
            ]
        )
        for model in manifest["models"]:
            location = "remote" if model.get("remote") else "local"
            lines.append(
                f"- `{model['alias']}`: {model['provider']}/{model['model']} ({location})"
            )
        lines.append("")
        (self.results_dir / "README.md").write_text(
            "\n".join(lines), encoding="utf-8"
        )

    def _write_legacy_manifest(
        self,
        run_id: str,
        status: RunStatus,
        candidates: list[Candidate],
        usage: Usage,
    ) -> None:
        confirmed = [row for row in candidates if str(row.verdict) == "CONFIRMED"]
        findings: list[dict[str, Any]] = []
        for index, candidate in enumerate(confirmed, 1):
            vuln_id = f"VULN-{index:03d}"
            slug = _slug(candidate.title)
            location = _location(candidate.sink) or _location(candidate.source)
            key_material = "\0".join([location, candidate.cwe, candidate.root_cause])
            findings.append(
                {
                    "id": vuln_id,
                    "title": candidate.title,
                    "cwe": candidate.cwe if re.fullmatch(r"CWE-\d+", candidate.cwe) else "",
                    "cwe_name": candidate.classification,
                    "severity": candidate.severity,
                    "location": location,
                    "root_cause": candidate.root_cause,
                    "data_flow": " -> ".join(
                        str(row.get("claim") or row.get("location") or "")
                        for row in candidate.trace
                    ),
                    "entry_point": _location(candidate.source),
                    "exploit_description": candidate.new_capability,
                    "exploit_impact": candidate.new_capability,
                    "fix_strategy": candidate.fix_strategy,
                    "severity_rationale": (
                        f"{candidate.severity}: {candidate.new_capability}"
                    ),
                    "vulnfix_key": hashlib.sha256(
                        key_material.encode("utf-8")
                    ).hexdigest()[:16],
                    "poc_path": (
                        f"poc/{vuln_id}_{slug}.md" if candidate.poc else None
                    ),
                    "exploit_test_path": (
                        f"exploit_tests/{vuln_id}_{slug}.txt"
                        if candidate.exploit_test
                        else None
                    ),
                }
            )
        if status == RunStatus.COMPLETE_FINDINGS:
            legacy_exit_code = 0
        elif status == RunStatus.COMPLETE_CLEAN:
            legacy_exit_code = 1
        else:
            # The v1 legacy contract has no incomplete/conditional status.
            # Use its failure code so an old consumer cannot report a clean scan.
            legacy_exit_code = 4
        legacy = {
            "schema_version": "1",
            "scan_id": run_id,
            "agent_exit_code": legacy_exit_code,
            "cost_usd": float(usage.cost_usd or 0.0),
            "findings": findings,
            "posted": [],
            "skipped": [],
            "failed": [],
        }
        self.write_json(self.results_dir / "scan_manifest.json", legacy)


def _finding_markdown(
    vuln_id: str, candidate: Candidate, reviews: list[Review]
) -> list[str]:
    matching = [row for row in reviews if row.candidate_id == candidate.candidate_id]
    lines = [
        f"## {vuln_id}: {candidate.title}",
        "",
        f"- **Severity:** {candidate.severity}",
        f"- **CWE:** {candidate.cwe}",
        f"- **Status:** {candidate.verdict}",
        f"- **Location:** {_location(candidate.sink)}",
        f"- **Entry Point:** {_location(candidate.source)}",
        f"- **Root Cause:** {candidate.root_cause}",
        f"- **Exploit Impact:** {candidate.new_capability}",
        f"- **Proposed Fix:** {candidate.fix_strategy}",
        "",
        "### Data Flow",
        "",
    ]
    for row in candidate.trace:
        lines.append(
            f"- {row.get('file', '')}:{row.get('line', '')} — "
            f"{row.get('claim', row.get('description', ''))}"
        )
    lines.extend(["", "### Independent Review", ""])
    if not matching:
        lines.append("- No completed independent review.")
    for review in matching:
        lines.append(
            f"- `{review.reviewer.get('alias', 'unknown')}`: "
            f"**{review.verdict}** — {review.rationale}"
        )
    lines.append("")
    return lines


def _location(value: dict[str, Any]) -> str:
    path = str(value.get("file") or value.get("path") or "")
    line = value.get("line")
    return f"{path}:{line}" if path and line else path


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:60] or "finding"
