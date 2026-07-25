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

from .methodology import (
    StaticSeed,
    SurfaceLedgerRow,
    ThreatModel,
    render_threat_model,
)
from .models import Assignment, Candidate, FindingDisposition, Review, RunStatus, Usage


SCHEMA_VERSION = "2"


class ArtifactStore:
    def __init__(self, results_dir: Path) -> None:
        self.results_dir = results_dir.resolve()
        self.assignments_dir = self.results_dir / "assignments"
        self.candidates_dir = self.results_dir / "candidates"
        self.reviews_dir = self.results_dir / "reviews"
        self.disagreements_dir = self.results_dir / "disagreements"
        self.validation_dir = self.results_dir / "validation"
        self.attack_paths_dir = self.results_dir / "attack_paths"
        self.validation_artifacts_dir = self.results_dir / "validation_artifacts"
        self.poc_dir = self.results_dir / "poc"
        self.exploit_tests_dir = self.results_dir / "exploit_tests"
        for directory in (
            self.results_dir,
            self.assignments_dir,
            self.candidates_dir,
            self.reviews_dir,
            self.disagreements_dir,
            self.validation_dir,
            self.attack_paths_dir,
            self.validation_artifacts_dir,
            self.poc_dir,
            self.exploit_tests_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)

    def write_threat_model(self, threat_model: ThreatModel) -> None:
        document = {"schema_version": SCHEMA_VERSION, **threat_model.to_dict()}
        self._validate_named("threat_model.schema.json", document)
        self.write_json(
            self.results_dir / "threat_model.json",
            document,
        )
        (self.results_dir / "threat_model.md").write_text(
            render_threat_model(threat_model), encoding="utf-8"
        )

    def write_surface_ledger(
        self,
        rows: list[SurfaceLedgerRow],
        candidates: list[Candidate] | None = None,
    ) -> None:
        surface_documents = [
            {"schema_version": SCHEMA_VERSION, **row.to_dict()} for row in rows
        ]
        for document in surface_documents:
            self._validate_named("security_surface.schema.json", document)
        self.write_jsonl(
            self.results_dir / "security_surfaces.jsonl",
            surface_documents,
        )
        coverage_rows = [
            {
                "schema_version": SCHEMA_VERSION,
                "record_type": "surface",
                **row.to_dict(),
            }
            for row in rows
        ]
        for candidate in candidates or []:
            instances = _candidate_instances(candidate)
            for index, instance in enumerate(instances, 1):
                coverage_rows.append(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "record_type": "candidate_instance",
                        "instance_id": (
                            f"{candidate.candidate_id}-INSTANCE-{index:03d}"
                        ),
                        "candidate_id": candidate.candidate_id,
                        "file": str(
                            instance.get("file") or instance.get("path") or ""
                        ),
                        "line": instance.get("line"),
                        "disposition": str(candidate.disposition),
                        "validation_path": (
                            f"validation/{candidate.candidate_id}.json"
                            if candidate.validation
                            else None
                        ),
                    }
                )
        self.write_jsonl(
            self.results_dir / "coverage_ledger.jsonl",
            coverage_rows,
        )

    def write_static_seeds(self, seeds: list[StaticSeed]) -> None:
        documents = [
            {"schema_version": SCHEMA_VERSION, **seed.to_dict()} for seed in seeds
        ]
        for document in documents:
            self._validate_named("static_seed.schema.json", document)
        self.write_jsonl(
            self.results_dir / "static_seeds.jsonl",
            documents,
        )

    def write_validation(self, candidate: Candidate) -> None:
        if not candidate.validation:
            return
        document = {
            "schema_version": SCHEMA_VERSION,
            "candidate_id": candidate.candidate_id,
            **candidate.validation,
        }
        self._validate_named("validation_report.schema.json", document)
        self.write_json(
            self.validation_dir / f"{candidate.candidate_id}.json", document
        )

    def write_attack_path(self, candidate: Candidate) -> None:
        if not candidate.attack_path:
            return
        document = {
            "schema_version": SCHEMA_VERSION,
            "candidate_id": candidate.candidate_id,
            **candidate.attack_path,
        }
        self._validate_named("attack_path_report.schema.json", document)
        self.write_json(
            self.attack_paths_dir / f"{candidate.candidate_id}.json", document
        )

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
        threat_model: ThreatModel | None = None,
        surface_ledger: list[SurfaceLedgerRow] | None = None,
        static_seeds: list[StaticSeed] | None = None,
        tooling: dict[str, Any] | None = None,
        sandbox: dict[str, Any] | None = None,
        incomplete_reason: str = "",
    ) -> dict[str, Any]:
        surface_ledger = surface_ledger or []
        static_seeds = static_seeds or []
        dispositions = {
            value: sum(str(row.disposition) == value for row in candidates)
            for value in (
                "REPORTABLE",
                "DEFERRED",
                "SUPPRESSED",
                "NOT_APPLICABLE",
                "UNRESOLVED",
            )
        }
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
            "phases": _phase_summary(assignments),
            "threat_model": {
                "path": "threat_model.json",
                "markdown_path": "threat_model.md",
                "repository_digest": (
                    threat_model.repository_digest if threat_model else ""
                ),
                "complete": bool(threat_model and threat_model.model_provenance),
            },
            "security_surfaces": {
                "total": len(surface_ledger),
                "mandatory": sum(row.mandatory for row in surface_ledger),
                "unresolved_mandatory": [
                    row.surface_id
                    for row in surface_ledger
                    if row.mandatory and str(row.disposition) == "UNRESOLVED"
                ],
                "path": "security_surfaces.jsonl",
                "coverage_ledger_path": "coverage_ledger.jsonl",
                "instance_rows": sum(
                    len(_candidate_instances(row))
                    for row in candidates
                ),
            },
            "tooling": tooling or {
                "native_rules": True,
                "native_seed_count": len(static_seeds),
                "optional_tools": [],
                "seed_path": "static_seeds.jsonl",
            },
            "sandbox": sandbox or {
                "enabled": False,
                "backend": "docker",
                "network": "none",
            },
            "dispositions": dispositions,
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
                    "disposition": str(row.disposition),
                    "discovered_by": row.discovered_by,
                    "reviews": row.reviews,
                    "validation_path": (
                        f"validation/{row.candidate_id}.json"
                        if row.validation
                        else None
                    ),
                    "attack_path": (
                        f"attack_paths/{row.candidate_id}.json"
                        if row.attack_path
                        else None
                    ),
                }
                for row in candidates
                if str(row.disposition) != "SUPPRESSED"
            ],
            "reviews": len(reviews),
            "incomplete_reason": incomplete_reason,
        }
        self._validate_named("coverage.schema.json", coverage)
        self._validate_named("provider_usage.schema.json", asdict(usage))
        self._validate_manifest(manifest)
        self.write_json(self.results_dir / "run_manifest.json", manifest)
        if threat_model:
            self.write_threat_model(threat_model)
        if surface_ledger:
            self.write_surface_ledger(surface_ledger, candidates)
        self.write_static_seeds(static_seeds)
        for candidate in candidates:
            self.write_validation(candidate)
            self.write_attack_path(candidate)
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
    def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(
            dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                for row in rows:
                    handle.write(json.dumps(row, sort_keys=True) + "\n")
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
            [
                row
                for row in candidates
                if str(row.disposition) == FindingDisposition.REPORTABLE
            ],
            1,
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
        confirmed = [
            row
            for row in candidates
            if str(row.disposition) == FindingDisposition.REPORTABLE
        ]
        conditional = [
            row for row in candidates if str(row.disposition) == "DEFERRED"
        ]
        unresolved = [
            row for row in candidates if str(row.disposition) == "UNRESOLVED"
        ]
        suppressed = [
            row for row in candidates if str(row.disposition) == "SUPPRESSED"
        ]
        lines = [
            "# VulnHunter Security Report",
            "",
            f"- Status: **{manifest['status']}**",
            f"- Scan level: **{manifest['level']}**",
            f"- Core models: **{len(manifest['models'])}**",
            f"- Confirmed findings: **{len(confirmed)}**",
            f"- Conditional findings: **{len(conditional)}**",
            f"- Unresolved findings: **{len(unresolved)}**",
            f"- Suppressed candidates: **{len(suppressed)}**",
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
                "| ID | Severity | CWE | Title | Disposition |",
                "|---|---|---|---|---|",
            ]
        )
        reportable = confirmed + conditional + unresolved
        for index, candidate in enumerate(reportable, 1):
            lines.append(
                f"| VULN-{index:03d} | {candidate.severity} | {candidate.cwe} | "
                f"{candidate.title} | {candidate.disposition} |"
            )
        if not reportable:
            lines.append("| — | — | — | No reportable findings | — |")
        lines.append("")
        for index, candidate in enumerate(reportable, 1):
            lines.extend(_finding_markdown(f"VULN-{index:03d}", candidate, reviews))
        lines.extend(["## Suppressed Candidates", ""])
        if not suppressed:
            lines.append("- None.")
        for candidate in suppressed:
            counterevidence = "; ".join(candidate.contradicting_evidence) or (
                "Independent validation found a blocking control or disproved "
                "a required exploitability claim."
            )
            lines.append(f"- **{candidate.title}** — {counterevidence}")
        lines.extend(
            [
                "",
                "## Coverage",
                "",
                f"- Production files inventoried: {manifest['coverage'].get('files_total', 0)}",
                f"- Completed assignments: {manifest['assignments']['completed']}/"
                f"{manifest['assignments']['total']}",
                f"- Failed assignments: {manifest['assignments']['failed']}",
                f"- Unresolved files: {len(manifest['coverage'].get('unresolved_files', []))}",
                f"- Mandatory security surfaces: "
                f"{manifest['security_surfaces'].get('mandatory', 0)}",
                f"- Unclosed mandatory surfaces: "
                f"{len(manifest['security_surfaces'].get('unresolved_mandatory', []))}",
                "- Threat model: [`threat_model.md`](threat_model.md)",
                "- Coverage ledger: [`coverage_ledger.jsonl`](coverage_ledger.jsonl)",
                "",
                "## Static Tools and Sandbox",
                "",
                f"- Native deterministic rules: "
                f"{'enabled' if manifest['tooling'].get('native_rules') else 'disabled'}",
                f"- Native seeds: {manifest['tooling'].get('native_seed_count', 0)}",
                f"- Optional scanner mode: "
                f"{manifest['tooling'].get('optional_mode', 'auto')}",
                f"- Docker execution: "
                f"{'enabled' if manifest['sandbox'].get('enabled') else 'disabled'}",
                f"- Sandbox network: {manifest['sandbox'].get('network', 'none')}",
                "",
                "## Usage",
                "",
                f"- Provider requests: {manifest['usage'].get('requests', 0)}",
                f"- Input tokens: {manifest['usage'].get('input_tokens', 0)}",
                f"- Output tokens: {manifest['usage'].get('output_tokens', 0)}",
                f"- Cached input tokens: "
                f"{manifest['usage'].get('cached_input_tokens', 0)}",
                f"- Observed cost: "
                f"{_display_cost(manifest['usage'].get('cost_usd'))}",
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
        confirmed = [
            row
            for row in candidates
            if str(row.disposition) == FindingDisposition.REPORTABLE
        ]
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
        f"- **Verdict:** {candidate.verdict}",
        f"- **Disposition:** {candidate.disposition}",
        f"- **Location:** {_location(candidate.sink)}",
        f"- **Entry Point:** {_location(candidate.source)}",
        f"- **Closest Control:** {_location(candidate.closest_control)} "
        f"{candidate.closest_control.get('description', '')}",
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
    lines.extend(["", "### Proof Gaps and Counterevidence", ""])
    if not candidate.proof_gaps and not candidate.contradicting_evidence:
        lines.append("- None recorded.")
    for gap in candidate.proof_gaps:
        lines.append(f"- Proof gap: {gap}")
    for evidence in candidate.contradicting_evidence:
        lines.append(f"- Counterevidence: {evidence}")
    if candidate.validation:
        lines.extend(
            [
                "",
                "### Validation",
                "",
                f"- Method: {candidate.validation.get('method', 'static')}",
                f"- Rationale: {candidate.validation.get('rationale', '')}",
            ]
        )
    if candidate.attack_path:
        lines.extend(
            [
                "",
                "### Attack Path",
                "",
                f"- Attacker position: "
                f"{candidate.attack_path.get('attacker_position', '')}",
                f"- Boundary crossed: "
                f"{candidate.attack_path.get('boundary_crossed', '')}",
                f"- Blast radius: {candidate.attack_path.get('blast_radius', '')}",
            ]
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


def _candidate_instances(candidate: Candidate) -> list[dict[str, Any]]:
    return candidate.affected_instances or [
        point
        for point in (candidate.source, candidate.sink)
        if point.get("file") or point.get("path")
    ]


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:60] or "finding"


def _display_cost(value: Any) -> str:
    if value is None:
        return "not reported"
    return f"${float(value):.4f}"


def _phase_summary(assignments: list[Assignment]) -> dict[str, dict[str, Any]]:
    phases: dict[str, dict[str, Any]] = {}
    for assignment in assignments:
        kind = str(assignment.kind)
        row = phases.setdefault(
            kind,
            {
                "total": 0,
                "completed": 0,
                "failed": 0,
                "pending": 0,
                "prompt_hashes": [],
            },
        )
        row["total"] += 1
        key = {
            "COMPLETED": "completed",
            "FAILED": "failed",
            "PENDING": "pending",
        }.get(assignment.status, "pending")
        row[key] += 1
        if (
            assignment.prompt_hash
            and assignment.prompt_hash not in row["prompt_hashes"]
        ):
            row["prompt_hashes"].append(assignment.prompt_hash)
    return phases
