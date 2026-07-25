"""Deterministic multi-model scanner orchestration."""

from __future__ import annotations

import asyncio
import hashlib
import json
import random
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Awaitable, Callable

from jsonschema import Draft202012Validator

from .artifacts import ArtifactStore
from .config import EngineConfig
from .inventory import Partition, RepositoryInventory, build_inventory, partition_inventory
from .methodology import (
    StaticSeed,
    SurfaceLedgerRow,
    ThreatModel,
    baseline_threat_model,
    initial_surface_ledger,
    optional_tool_status,
    run_optional_scanners,
    scan_native_seeds,
    seed_to_candidate,
)
from .models import (
    Assignment,
    AssignmentKind,
    Candidate,
    FindingDisposition,
    ModelResponse,
    ModelSpec,
    Review,
    RunStatus,
    ScanLevel,
    ScanRequest,
    Usage,
    Verdict,
)
from .prompts import (
    ATTACK_PATH_SCHEMA,
    CANDIDATE_SCHEMA,
    REVIEW_SCHEMA,
    SYSTEM_PROMPT,
    THREAT_MODEL_SCHEMA,
    VALIDATION_SCHEMA,
    attack_path_prompt,
    clean_challenge_prompt,
    hunt_prompt,
    json_tool_instruction,
    review_prompt,
    seed_review_prompt,
    threat_model_prompt,
    validation_prompt,
)
from .providers import ModelProvider, ProviderError, create_provider
from .sandbox import DockerSandbox, SandboxPolicy, docker_status
from .tools import RepositoryTools


class BudgetExceeded(RuntimeError):
    pass


class ModelOutputError(RuntimeError):
    """A model completed its calls but did not produce the required contract."""

    def __init__(self, message: str, usage: Usage) -> None:
        super().__init__(message)
        self.usage = usage


class ScanEngine:
    def __init__(
        self,
        config: EngineConfig,
        *,
        providers: dict[str, ModelProvider] | None = None,
        progress: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self.config = config
        self.providers = providers or {
            name: create_provider(provider)
            for name, provider in config.providers.items()
        }
        self._state_lock = asyncio.Lock()
        self._free_request_lock = asyncio.Lock()
        self._last_free_request_at = 0.0
        self._free_team_mode = False
        self._serial_provider_locks = {
            name: asyncio.Lock()
            for name, provider in config.providers.items()
            if provider.kind == "codex_cli"
        }
        self._provider_unavailable_errors: dict[str, ProviderError] = {}
        self._progress_callback = progress
        self._active_request: ScanRequest | None = None
        self._active_results_dir: Path | None = None

    def _progress(self, event: str, **details: Any) -> None:
        if self._progress_callback is None:
            return
        try:
            self._progress_callback(event, details)
        except Exception:  # noqa: BLE001
            # Presentation must never interrupt or invalidate a scan.
            return

    async def scan(self, request: ScanRequest) -> tuple[dict[str, Any], Path]:
        self._active_request = request
        source_root = Path(request.repository).expanduser().resolve()
        source_inventory = build_inventory(
            source_root, include_dormant=request.include_dormant
        )
        snapshot = tempfile.TemporaryDirectory(prefix="vulnhunter-snapshot-")
        root = Path(snapshot.name).resolve()
        for rel in sorted(
            set(
                source_inventory.production_files
                + source_inventory.dormant_files
                + source_inventory.support_files
            )
        ):
            source = source_root / rel
            destination = root / rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination, follow_symlinks=True)
        for provider in self.providers.values():
            set_root = getattr(provider, "set_repository_root", None)
            if callable(set_root):
                set_root(root)
        inventory = build_inventory(root, include_dormant=request.include_dormant)
        model_specs = [self.config.models[alias] for alias in request.model_aliases]
        self._free_team_mode = len(model_specs) > 1 and all(
            model.is_free for model in model_specs
        )
        if self._free_team_mode:
            self._progress(
                "free_team_mode",
                models=len(model_specs),
                spacing_seconds=3.2,
                max_workers=1,
            )
        self._validate_request(request, model_specs)
        context_models = [
            *model_specs,
            *[
                self.config.models[row.model_alias]
                for row in request.specialists
                if row.enabled
            ],
        ]
        usable_context = min(
            row.context_tokens - row.max_output_tokens - 4_096
            for row in context_models
        )
        target_bytes, max_files = _partition_limits(request.level, usable_context)
        partitions = partition_inventory(
            inventory,
            target_bytes=target_bytes,
            max_files=max_files,
        )
        self._progress(
            "inventory_complete",
            files=len(inventory.files),
            bytes=inventory.total_bytes,
            lines=inventory.line_count,
            symbols=inventory.symbol_count,
            partitions=len(partitions),
            production=len(inventory.production_files),
            dormant=len(inventory.dormant_files),
            support=len(inventory.support_files),
            excluded=len(inventory.excluded_files),
            snapshot_digest=inventory.snapshot_digest,
        )

        results_dir = self._resolve_results_dir(source_root, request)
        self._active_results_dir = results_dir
        self._progress("results_directory_ready", results_dir=str(results_dir))
        store = ArtifactStore(results_dir)
        run_id = results_dir.name
        state = store.read_state() if request.resume else None
        if state is None:
            state = self._new_state(run_id, request, inventory, model_specs)
            # Resume must reconstruct a fresh immutable snapshot from the
            # original checkout, not from this run's temporary snapshot path.
            state["repository"] = str(source_root)
            store.write_state(state)
        elif state.get("run_id") != run_id:
            raise ValueError("resume directory contains a different run_id")
        elif state.get("snapshot_digest") != inventory.snapshot_digest:
            raise ValueError(
                "repository snapshot changed since this run; resume would mix "
                "incompatible evidence"
            )
        elif state.get("engine_fingerprint") != _engine_fingerprint():
            raise ValueError(
                "scanner prompts or methodology changed since this run; start a "
                "new scan so incompatible completed phases are not reused"
            )

        budget = BudgetTracker(request, state)
        assignments: list[Assignment] = []
        candidates: list[Candidate] = []
        reviews: list[Review] = []
        threat_model = baseline_threat_model(inventory)
        reused_threat_model = False
        if request.threat_model_path:
            payload = json.loads(
                Path(request.threat_model_path)
                .expanduser()
                .read_text(encoding="utf-8")
            )
            if payload.get("repository_digest") != inventory.snapshot_digest:
                raise ValueError(
                    "reused threat model does not match the repository snapshot"
                )
            threat_model = ThreatModel(
                **{
                    key: value
                    for key, value in payload.items()
                    if key in ThreatModel.__dataclass_fields__
                }
            )
            if not threat_model.model_provenance:
                threat_model.model_provenance = [
                    {
                        "alias": "reused",
                        "provider": "artifact",
                        "model": str(request.threat_model_path),
                    }
                ]
            reused_threat_model = True
        cached_seed_path = results_dir / "static_seeds.jsonl"
        if (
            request.resume
            and state.get("static_tools_complete")
            and cached_seed_path.is_file()
        ):
            static_seeds = _load_static_seeds(cached_seed_path)
            native_seed_count = int(state.get("native_seed_count", 0))
            optional_results = _dict(state.get("optional_tools"))
            self._progress(
                "static_tools_resumed",
                seeds=len(static_seeds),
            )
        else:
            static_seeds = scan_native_seeds(inventory)
            native_seed_count = len(static_seeds)
            optional_results: dict[str, dict[str, Any]]
            if request.static_tools == "off":
                optional_results = {
                    name: {
                        "available": available,
                        "status": "disabled",
                        "seeds": 0,
                    }
                    for name, available in optional_tool_status().items()
                }
            else:
                self._progress("phase_started", phase="Optional static scanners")
                optional_seeds, optional_results = run_optional_scanners(inventory)
                static_seeds.extend(optional_seeds)
                if request.static_tools == "required":
                    failed_tools = [
                        name
                        for name, result in optional_results.items()
                        if result.get("status") != "completed"
                    ]
                    if failed_tools:
                        raise ValueError(
                            "--static-tools required but scanner execution failed: "
                            + ", ".join(failed_tools)
                        )
            state["static_tools_complete"] = True
            state["native_seed_count"] = native_seed_count
            state["optional_tools"] = optional_results
            store.write_state(state)
        surface_ledger = initial_surface_ledger(
            inventory.surfaces, request.model_aliases
        )
        store.write_threat_model(threat_model)
        store.write_static_seeds(static_seeds)
        store.write_surface_ledger(surface_ledger)
        coverage_reviewed: set[str] = set(state.get("coverage_reviewed", []))
        coverage_unresolved: set[str] = set(state.get("coverage_unresolved", []))
        evidence_gaps: list[str] = []
        incomplete_reason = ""

        try:
            threat_assignments = (
                []
                if reused_threat_model
                else self._threat_model_assignments(
                    model_specs, request.level, inventory
                )
            )
            self._progress(
                "phase_started",
                phase="Threat modeling",
                assignments=max(1, len(threat_assignments)),
            )
            assignments.extend(threat_assignments)
            threat_payloads = await self._run_methodology_assignments(
                threat_assignments,
                root=root,
                inventory=inventory,
                store=store,
                state=state,
                budget=budget,
                request=request,
                schema=THREAT_MODEL_SCHEMA,
                prompt_factory=lambda assignment: threat_model_prompt(
                    self._repository_summary(inventory),
                    [surface.to_dict() for surface in surface_ledger],
                ),
            )
            if reused_threat_model:
                reused_assignment = Assignment(
                    assignment_id="threat-model-reused",
                    kind=AssignmentKind.THREAT_MODEL,
                    model_alias=model_specs[0].alias,
                    provider=model_specs[0].provider,
                    model=model_specs[0].model,
                    status="COMPLETED",
                    prompt_hash=hashlib.sha256(
                        json.dumps(
                            threat_model.to_dict(),
                            sort_keys=True,
                        ).encode("utf-8")
                    ).hexdigest(),
                    coverage_quality="auditable",
                    evidence=[
                        {
                            "tool": "reused_artifact",
                            "path": str(request.threat_model_path),
                            "result_sha256": hashlib.sha256(
                                json.dumps(
                                    threat_model.to_dict(),
                                    sort_keys=True,
                                ).encode("utf-8")
                            ).hexdigest(),
                        }
                    ],
                )
                assignments.append(reused_assignment)
                store.write_assignment(
                    reused_assignment, threat_model.to_dict()
                )
                threat_payloads = [
                    (
                        reused_assignment,
                        threat_model.to_dict(),
                    )
                ]
            if threat_payloads and not reused_threat_model:
                threat_model = self._merge_threat_models(
                    threat_model, threat_payloads, model_specs
                )
            elif not reused_threat_model:
                coverage_unresolved.update(
                    rel
                    for surface in inventory.surfaces
                    if surface.mandatory
                    for rel in surface.files
                )
                threat_model.proof_gaps.append(
                    "Mandatory model-assisted threat modeling failed."
                )
            store.write_threat_model(threat_model)
            self._progress(
                "threat_model_complete",
                actors=len(threat_model.actors),
                boundaries=len(threat_model.trust_boundaries),
                invariants=len(threat_model.security_invariants),
            )

            self._progress(
                "static_seeds_complete",
                seeds=len(static_seeds),
                native_rules=True,
            )
            hunts = self._hunt_assignments(model_specs, partitions)
            self._progress(
                "phase_started",
                phase="Independent vulnerability hunts",
                assignments=len(hunts),
            )
            assignments.extend(hunts)
            hunt_payloads = await self._run_hunt_assignments(
                hunts,
                root=root,
                inventory=inventory,
                store=store,
                state=state,
                budget=budget,
                request=request,
            )
            for assignment, payload in hunt_payloads:
                coverage = payload.get("coverage", {})
                coverage_reviewed.update(coverage.get("files_reviewed", []))
                coverage_unresolved.update(coverage.get("unresolved_files", []))
                candidates.extend(
                    self._parse_candidates(payload, assignment, len(candidates))
                )

            specialist_assignments = self._specialist_assignments(
                request, partitions
            )
            if specialist_assignments:
                self._progress(
                    "phase_started",
                    phase="Specialist analysis",
                    assignments=len(specialist_assignments),
                )
            assignments.extend(specialist_assignments)
            specialist_payloads = await self._run_hunt_assignments(
                specialist_assignments,
                root=root,
                inventory=inventory,
                store=store,
                state=state,
                budget=budget,
                request=request,
            )
            for assignment, payload in specialist_payloads:
                candidates.extend(
                    self._parse_candidates(payload, assignment, len(candidates))
                )

            seed_assignments = self._seed_assignments(
                static_seeds, model_specs, threat_model
            )
            if seed_assignments:
                self._progress(
                    "phase_started",
                    phase="Deterministic seed review",
                    assignments=len(seed_assignments),
                )
                assignments.extend(seed_assignments)
                seed_payloads = await self._run_hunt_assignments(
                    seed_assignments,
                    root=root,
                    inventory=inventory,
                    store=store,
                    state=state,
                    budget=budget,
                    request=request,
                )
                for assignment, payload in seed_payloads:
                    candidates.extend(
                        self._parse_candidates(payload, assignment, len(candidates))
                    )
            for seed in static_seeds:
                if seed.confidence >= 0.7:
                    candidates.append(
                        seed_to_candidate(seed, f"CAND-{len(candidates) + 1:05d}")
                    )

            if request.level in {ScanLevel.DEEP, ScanLevel.EXHAUSTIVE}:
                gap_assignments = self._gap_assignments(
                    hunt_payloads, model_specs
                )
                if gap_assignments:
                    self._progress(
                        "phase_started",
                        phase="Coverage gap analysis",
                        assignments=len(gap_assignments),
                    )
                    assignments.extend(gap_assignments)
                    gap_payloads = await self._run_hunt_assignments(
                        gap_assignments,
                        root=root,
                        inventory=inventory,
                        store=store,
                        state=state,
                        budget=budget,
                        request=request,
                    )
                    for assignment, payload in gap_payloads:
                        coverage = payload.get("coverage", {})
                        reviewed = set(coverage.get("files_reviewed", []))
                        coverage_reviewed.update(reviewed)
                        coverage_unresolved.difference_update(reviewed)
                        coverage_unresolved.update(
                            coverage.get("unresolved_files", [])
                        )
                        candidates.extend(
                            self._parse_candidates(
                                payload, assignment, len(candidates)
                            )
                        )

            if request.level != ScanLevel.QUICK:
                sweeps = self._sweep_assignments(
                    model_specs,
                    inventory,
                    count=2 if request.level == ScanLevel.EXHAUSTIVE else 1,
                )
                self._progress(
                    "phase_started",
                    phase="Root-cause security sweep",
                    assignments=len(sweeps),
                )
                assignments.extend(sweeps)
                sweep_payloads = await self._run_hunt_assignments(
                    sweeps,
                    root=root,
                    inventory=inventory,
                    store=store,
                    state=state,
                    budget=budget,
                    request=request,
                    sweep=True,
                )
                for assignment, payload in sweep_payloads:
                    candidates.extend(
                        self._parse_candidates(payload, assignment, len(candidates))
                    )

            challenge_assignments = self._clean_challenge_assignments(
                surface_ledger,
                candidates,
                model_specs,
                threat_model,
                static_seeds,
            )
            if challenge_assignments:
                self._progress(
                    "phase_started",
                    phase="Clean-result challenge",
                    assignments=len(challenge_assignments),
                )
                assignments.extend(challenge_assignments)
                challenge_payloads = await self._run_hunt_assignments(
                    challenge_assignments,
                    root=root,
                    inventory=inventory,
                    store=store,
                    state=state,
                    budget=budget,
                    request=request,
                )
                for assignment, payload in challenge_payloads:
                    coverage = payload.get("coverage", {})
                    coverage_reviewed.update(coverage.get("files_reviewed", []))
                    coverage_unresolved.update(coverage.get("unresolved_files", []))
                    candidates.extend(
                        self._parse_candidates(payload, assignment, len(candidates))
                    )

            candidates = merge_candidates(
                candidates,
                semantic=state.get("candidate_merge_version") == "semantic-v2",
            )
            self._progress("candidates_merged", candidates=len(candidates))
            for candidate in candidates:
                store.write_candidate(candidate)

            review_assignments = self._review_assignments(
                request.level, model_specs, candidates
            )
            if review_assignments:
                self._progress(
                    "phase_started",
                    phase="Cross-model review",
                    assignments=len(review_assignments),
                )
            assignments.extend(review_assignments)
            reviews = await self._run_review_assignments(
                review_assignments,
                candidates=candidates,
                root=root,
                inventory=inventory,
                store=store,
                state=state,
                budget=budget,
                request=request,
            )
            self._apply_reviews(candidates, reviews)

            if request.level in {ScanLevel.DEEP, ScanLevel.EXHAUSTIVE}:
                resolver_assignments = self._resolver_assignments(
                    model_specs, candidates, reviews
                )
                if resolver_assignments:
                    self._progress(
                        "phase_started",
                        phase="Disagreement resolution",
                        assignments=len(resolver_assignments),
                    )
                    assignments.extend(resolver_assignments)
                    for resolver in resolver_assignments:
                        prior = [
                            row
                            for row in reviews
                            if row.candidate_id == resolver.candidate_id
                        ]
                        store.write_disagreement(
                            candidate_id=resolver.candidate_id,
                            review_ids=[row.review_id for row in prior],
                            disputed_claims=[
                                row.rationale for row in prior if row.rationale
                            ],
                            resolution_status="PENDING",
                        )
                    resolver_reviews = await self._run_review_assignments(
                        resolver_assignments,
                        candidates=candidates,
                        root=root,
                        inventory=inventory,
                        store=store,
                        state=state,
                        budget=budget,
                        request=request,
                    )
                    reviews.extend(resolver_reviews)
                    self._apply_reviews(candidates, reviews)
                    for resolver in resolver_assignments:
                        candidate = next(
                            row
                            for row in candidates
                            if row.candidate_id == resolver.candidate_id
                        )
                        matching = [
                            row
                            for row in reviews
                            if row.candidate_id == resolver.candidate_id
                        ]
                        store.write_disagreement(
                            candidate_id=resolver.candidate_id,
                            review_ids=[row.review_id for row in matching],
                            disputed_claims=[
                                row.rationale for row in matching if row.rationale
                            ],
                            resolution_status=str(candidate.verdict),
                        )

            validation_assignments = self._validation_assignments(
                candidates, model_specs
            )
            if validation_assignments:
                self._progress(
                    "phase_started",
                    phase="Candidate validation",
                    assignments=len(validation_assignments),
                )
                assignments.extend(validation_assignments)
                validation_payloads = await self._run_methodology_assignments(
                    validation_assignments,
                    root=root,
                    inventory=inventory,
                    store=store,
                    state=state,
                    budget=budget,
                    request=request,
                    schema=VALIDATION_SCHEMA,
                    prompt_factory=lambda assignment: validation_prompt(
                        next(
                            candidate.to_dict()
                            for candidate in candidates
                            if candidate.candidate_id == assignment.candidate_id
                        )
                    ),
                )
                for assignment, payload in validation_payloads:
                    candidate = next(
                        row
                        for row in candidates
                        if row.candidate_id == assignment.candidate_id
                    )
                    self._apply_validation(candidate, payload, assignment)
                    unknown_evidence = _candidate_unknown_paths(
                        candidate, inventory
                    )
                    if unknown_evidence:
                        candidate.verdict = Verdict.UNRESOLVED
                        candidate.disposition = FindingDisposition.UNRESOLVED
                        candidate.validation["verdict"] = Verdict.UNRESOLVED
                        candidate.validation["disposition"] = (
                            FindingDisposition.UNRESOLVED
                        )
                        candidate.proof_gaps.append(
                            "Candidate evidence references paths outside the "
                            "immutable inventory: "
                            + ", ".join(sorted(unknown_evidence))
                        )
                        candidate.validation["proof_gaps"] = list(
                            candidate.proof_gaps
                        )
                    if _candidate_is_dormant(candidate, inventory):
                        candidate.verdict = Verdict.CONDITIONAL
                        candidate.disposition = FindingDisposition.DEFERRED
                        candidate.validation["verdict"] = Verdict.CONDITIONAL
                        candidate.validation["disposition"] = (
                            FindingDisposition.DEFERRED
                        )
                        candidate.proof_gaps.append(
                            "The affected implementation is dormant/disabled in "
                            "this snapshot; deployment or reachability evidence is "
                            "required before it is reportable."
                        )
                        candidate.validation["proof_gaps"] = list(
                            candidate.proof_gaps
                        )
                    store.write_validation(candidate)
                    store.write_candidate(candidate)
                completed_validation_ids = {
                    assignment.candidate_id
                    for assignment, _payload in validation_payloads
                }
                for assignment in validation_assignments:
                    if assignment.candidate_id in completed_validation_ids:
                        continue
                    candidate = next(
                        row
                        for row in candidates
                        if row.candidate_id == assignment.candidate_id
                    )
                    candidate.verdict = Verdict.UNRESOLVED
                    candidate.disposition = FindingDisposition.UNRESOLVED
                    candidate.proof_gaps.append(
                        "Validation assignment did not complete: "
                        + (assignment.error or "provider/engine failure")
                    )
                    store.write_candidate(candidate)

            attack_assignments = self._attack_path_assignments(
                candidates, model_specs
            )
            if attack_assignments:
                self._progress(
                    "phase_started",
                    phase="Attack-path analysis",
                    assignments=len(attack_assignments),
                )
                assignments.extend(attack_assignments)
                attack_payloads = await self._run_methodology_assignments(
                    attack_assignments,
                    root=root,
                    inventory=inventory,
                    store=store,
                    state=state,
                    budget=budget,
                    request=request,
                    schema=ATTACK_PATH_SCHEMA,
                    prompt_factory=lambda assignment: attack_path_prompt(
                        next(
                            candidate.to_dict()
                            for candidate in candidates
                            if candidate.candidate_id == assignment.candidate_id
                        ),
                        next(
                            candidate.validation
                            for candidate in candidates
                            if candidate.candidate_id == assignment.candidate_id
                        ),
                    ),
                )
                for assignment, payload in attack_payloads:
                    candidate = next(
                        row
                        for row in candidates
                        if row.candidate_id == assignment.candidate_id
                    )
                    candidate.attack_path = {
                        **{
                            key: value
                            for key, value in payload.items()
                            if not key.startswith("_")
                        },
                        "analyst": assignment.model_alias,
                    }
                    if payload.get("severity") in {
                        "Critical", "High", "Medium", "Low"
                    }:
                        candidate.severity = str(payload["severity"])
                    store.write_attack_path(candidate)
                    store.write_candidate(candidate)

            self._close_surface_ledger(
                surface_ledger,
                candidates,
                assignments,
                inventory,
            )
            store.write_surface_ledger(surface_ledger)
            if request.level == ScanLevel.EXHAUSTIVE:
                evidence_gaps = [
                    candidate.candidate_id
                    for candidate in candidates
                    if str(candidate.disposition) == FindingDisposition.REPORTABLE
                    and (
                        not candidate.poc.strip()
                        or not candidate.exploit_test.strip()
                    )
                    and not candidate.proof_gaps
                ]
        except BudgetExceeded as exc:
            incomplete_reason = str(exc)
            status = RunStatus.INCOMPLETE_LIMIT
        except Exception as exc:  # noqa: BLE001
            status = RunStatus.FAILED
            incomplete_reason = f"{type(exc).__name__}: {exc}"
        else:
            failed = [assignment for assignment in assignments if assignment.status == "FAILED"]
            mandatory_unclosed = [
                row.surface_id
                for row in surface_ledger
                if row.mandatory
                and str(row.disposition)
                in {
                    FindingDisposition.UNRESOLVED,
                    "UNRESOLVED",
                }
            ]
            if failed or coverage_unresolved or evidence_gaps or mandatory_unclosed:
                status = RunStatus.INCOMPLETE_COVERAGE
                reasons = [
                    f"{len(failed)} assignment(s) failed",
                    f"{len(coverage_unresolved)} file(s) unresolved",
                ]
                if mandatory_unclosed:
                    reasons.append(
                        f"{len(mandatory_unclosed)} mandatory security surface(s) unclosed"
                    )
                if evidence_gaps:
                    reasons.append(
                        "missing exhaustive PoC/exploit-test evidence for "
                        + ", ".join(evidence_gaps)
                    )
                incomplete_reason = "; ".join(reasons)
            elif any(
                str(candidate.disposition) == FindingDisposition.REPORTABLE
                for candidate in candidates
            ):
                status = RunStatus.COMPLETE_FINDINGS
            elif any(
                str(candidate.disposition)
                in {FindingDisposition.DEFERRED, FindingDisposition.UNRESOLVED}
                for candidate in candidates
            ):
                status = RunStatus.COMPLETE_CONDITIONAL
            else:
                status = RunStatus.COMPLETE_CLEAN

        state.update(
            {
                "status": str(status),
                "usage": asdict(budget.usage),
                "coverage_reviewed": sorted(coverage_reviewed),
                "coverage_unresolved": sorted(coverage_unresolved),
                "incomplete_reason": incomplete_reason,
            }
        )
        store.write_state(state)
        for candidate in candidates:
            store.write_candidate(candidate)
        repository = repository_metadata(source_root, inventory)
        coverage_matrix = []
        for assignment in assignments:
            if assignment.kind not in {
                AssignmentKind.HUNT,
                AssignmentKind.SPECIALIST,
                AssignmentKind.SEED_REVIEW,
                AssignmentKind.CLEAN_CHALLENGE,
                AssignmentKind.SWEEP,
            }:
                continue
            stored = store.read_assignment(assignment.assignment_id) or {}
            assignment_coverage = stored.get("payload", {}).get("coverage", {})
            coverage_matrix.append(
                {
                    "assignment_id": assignment.assignment_id,
                    "model_alias": assignment.model_alias,
                    "kind": str(assignment.kind),
                    "files_assigned": assignment.files,
                    "files_reviewed": _list_of_strings(
                        assignment_coverage.get("files_reviewed")
                    ),
                    "unresolved_files": _list_of_strings(
                        assignment_coverage.get("unresolved_files")
                    ),
                    "status": assignment.status,
                    "coverage_quality": assignment.coverage_quality,
                    "evidence": assignment.evidence,
                }
            )
        self._progress("report_started", results_dir=str(results_dir))
        manifest = store.finalize(
            run_id=run_id,
            repository=repository,
            level=str(request.level),
            requested_models=[model_public_dict(row) for row in model_specs],
            specialists=[asdict(row) for row in request.specialists],
            status=status,
            candidates=candidates,
            reviews=reviews,
            assignments=assignments,
            usage=budget.usage,
            coverage={
                "files_total": len(inventory.files),
                "files_reviewed": sorted(coverage_reviewed),
                "unresolved_files": sorted(coverage_unresolved),
                "assignment_coverage": coverage_matrix,
                "unfinished_assignments": [
                    row.assignment_id
                    for row in assignments
                    if row.status != "COMPLETED"
                ],
                "complete": (
                    status
                    not in {
                        RunStatus.INCOMPLETE_LIMIT,
                        RunStatus.INCOMPLETE_COVERAGE,
                        RunStatus.FAILED,
                    }
                ),
            },
            limits=asdict(request.limits),
            threat_model=threat_model,
            surface_ledger=surface_ledger,
            static_seeds=static_seeds,
            tooling={
                "native_rules": True,
                "native_seed_count": native_seed_count,
                "optional_mode": request.static_tools,
                "optional_tools": optional_results,
                "seed_path": "static_seeds.jsonl",
            },
            sandbox={
                "enabled": request.execute,
                "backend": "docker",
                "image": request.sandbox_image or self.config.sandbox.image,
                "network": (
                    "private"
                    if request.allow_private_network
                    else "internet"
                    if request.allow_network
                    else "none"
                ),
            },
            incomplete_reason=incomplete_reason,
        )
        self._progress(
            "scan_complete",
            status=str(status),
            candidates=len(candidates),
            results_dir=str(results_dir),
        )
        snapshot.cleanup()
        return manifest, results_dir

    async def _pace_request(self, model: ModelSpec) -> None:
        """Keep free OpenRouter-style traffic below the documented 20 RPM."""
        if not model.is_free:
            return
        async with self._free_request_lock:
            minimum_interval = 3.2
            elapsed = time.monotonic() - self._last_free_request_at
            delay = max(0.0, minimum_interval - elapsed)
            if delay:
                self._progress(
                    "free_request_paced",
                    model=model.alias,
                    delay_seconds=delay,
                )
                await asyncio.sleep(delay)
            self._last_free_request_at = time.monotonic()

    def _validate_request(
        self, request: ScanRequest, models: list[ModelSpec]
    ) -> None:
        if not models:
            raise ValueError("at least one core model is required")
        identities = [row.identity for row in models]
        if len(set(identities)) != len(identities):
            raise ValueError("core model identities must be distinct")
        scan_models = [
            *models,
            *[
                self.config.models[row.model_alias]
                for row in request.specialists
                if row.enabled
            ],
        ]
        undersized = [
            row.alias
            for row in scan_models
            if row.context_tokens <= row.max_output_tokens + 4_096
        ]
        if undersized:
            raise ValueError(
                "model context is too small for scanner tools and output: "
                + ", ".join(undersized)
            )
        if request.static_tools not in {"auto", "off", "required"}:
            raise ValueError("--static-tools must be auto, off, or required")
        if request.static_tools == "required":
            missing_tools = [
                name for name, available in optional_tool_status().items()
                if not available
            ]
            if missing_tools:
                raise ValueError(
                    "--static-tools required but these tools are unavailable: "
                    + ", ".join(missing_tools)
                )
        if request.allow_network and not request.execute:
            raise ValueError("--allow-network requires --execute")
        if request.allow_private_network and not request.allow_network:
            raise ValueError("--allow-private-network requires --allow-network")
        if request.execute:
            status = docker_status(
                request.sandbox_image or self.config.sandbox.image
            )
            if not status["available"]:
                raise ValueError(f"--execute requires Docker: {status['detail']}")
            if not status["image_available"]:
                raise ValueError(
                    f"sandbox image {status['image']!r} is unavailable; "
                    "run `vulnhunter sandbox build`"
                )
            if request.allow_network and not request.allow_private_network:
                raise ValueError(
                    "this Docker host cannot enforce internet-only egress; "
                    "omit --allow-network or explicitly add --allow-private-network"
                )
        if request.limits.max_cost_usd is not None:
            unpriced = [row.alias for row in scan_models if not row.priced]
            if unpriced:
                raise ValueError(
                    "--max-cost-usd cannot be enforced because these remote models "
                    f"lack pricing: {', '.join(unpriced)}"
                )

    def _resolve_results_dir(self, root: Path, request: ScanRequest) -> Path:
        if request.results_dir:
            path = Path(request.results_dir).expanduser().resolve()
            if request.resume and not path.is_dir():
                raise FileNotFoundError(f"resume directory not found: {path}")
            return path
        timestamp = datetime.now(UTC).strftime("%Y-%m-%d-%H%M%S")
        return root / f"{root.name}_VULNHUNT_RESULTS_multi_{timestamp}"

    def _new_state(
        self,
        run_id: str,
        request: ScanRequest,
        inventory: RepositoryInventory,
        models: list[ModelSpec],
    ) -> dict[str, Any]:
        return {
            "schema_version": "2",
            "run_id": run_id,
            "status": RunStatus.RUNNING,
            "created_at": datetime.now(UTC).isoformat(),
            "repository": str(inventory.root),
            "snapshot_digest": inventory.snapshot_digest,
            "engine_fingerprint": _engine_fingerprint(),
            "candidate_merge_version": "semantic-v2",
            "level": str(request.level),
            "models": [row.alias for row in models],
            "completed_assignments": [],
            "failed_assignments": [],
            "coverage_reviewed": [],
            "coverage_unresolved": [],
            "usage": asdict(Usage()),
        }

    def _hunt_assignments(
        self, models: list[ModelSpec], partitions: list[Partition]
    ) -> list[Assignment]:
        return [
            Assignment(
                assignment_id=f"hunt-{model.alias}-{partition.partition_id.lower()}",
                kind=AssignmentKind.HUNT,
                model_alias=model.alias,
                provider=model.provider,
                model=model.model,
                partition_id=partition.partition_id,
                files=partition.files,
            )
            for model in models
            for partition in partitions
        ]

    @staticmethod
    def _repository_summary(inventory: RepositoryInventory) -> str:
        return (
            f"{len(inventory.production_files)} production files, "
            f"{len(inventory.dormant_files)} dormant files, "
            f"{inventory.total_bytes} bytes, languages={inventory.languages}, "
            f"snapshot={inventory.snapshot_digest}"
        )

    def _threat_model_assignments(
        self,
        models: list[ModelSpec],
        level: ScanLevel,
        inventory: RepositoryInventory,
    ) -> list[Assignment]:
        count = 2 if level in {ScanLevel.DEEP, ScanLevel.EXHAUSTIVE} else 1
        return [
            Assignment(
                assignment_id=f"threat-model-{index}-{models[(index - 1) % len(models)].alias}",
                kind=AssignmentKind.THREAT_MODEL,
                model_alias=models[(index - 1) % len(models)].alias,
                provider=models[(index - 1) % len(models)].provider,
                model=models[(index - 1) % len(models)].model,
                partition_id="THREAT-MODEL",
                files=sorted(
                    {
                        rel
                        for surface in inventory.surfaces
                        if surface.mandatory
                        for rel in surface.files
                    }
                ),
            )
            for index in range(1, count + 1)
        ]

    def _seed_assignments(
        self,
        seeds: list[Any],
        models: list[ModelSpec],
        threat_model: ThreatModel,
    ) -> list[Assignment]:
        assignments: list[Assignment] = []
        for index, seed in enumerate(seeds[:50]):
            model = models[index % len(models)]
            assignments.append(
                Assignment(
                    assignment_id=f"seed-review-{seed.seed_id.lower()}-{model.alias}",
                    kind=AssignmentKind.SEED_REVIEW,
                    model_alias=model.alias,
                    provider=model.provider,
                    model=model.model,
                    partition_id=seed.seed_id,
                    files=[seed.file],
                    context={
                        "seed": seed.to_dict(),
                        "threat_model": threat_model.to_dict(),
                    },
                )
            )
        return assignments

    def _clean_challenge_assignments(
        self,
        rows: list[SurfaceLedgerRow],
        candidates: list[Candidate],
        models: list[ModelSpec],
        threat_model: ThreatModel,
        seeds: list[StaticSeed] | None = None,
    ) -> list[Assignment]:
        covered = {
            str(point.get("file") or point.get("path") or "")
            for candidate in candidates
            for point in [
                candidate.source,
                candidate.sink,
                *candidate.trace,
                *candidate.affected_instances,
            ]
        }
        assignments: list[Assignment] = []
        for index, row in enumerate(row for row in rows if row.mandatory):
            if set(row.files) & covered:
                continue
            model = models[(index + 1) % len(models)] if len(models) > 1 else models[0]
            assignments.append(
                Assignment(
                    assignment_id=f"clean-challenge-{row.surface_id.lower()}-{model.alias}",
                    kind=AssignmentKind.CLEAN_CHALLENGE,
                    model_alias=model.alias,
                    provider=model.provider,
                    model=model.model,
                    partition_id=row.surface_id,
                    files=row.files,
                    context={
                        "surface": row.to_dict(),
                        "threat_model": threat_model.to_dict(),
                        "seeds": [
                            seed.to_dict()
                            for seed in (seeds or [])
                            if seed.file in row.files
                        ],
                    },
                )
            )
        return assignments

    def _validation_assignments(
        self, candidates: list[Candidate], models: list[ModelSpec]
    ) -> list[Assignment]:
        assignments: list[Assignment] = []
        for candidate in candidates:
            if str(candidate.verdict) == Verdict.REJECTED:
                candidate.disposition = FindingDisposition.SUPPRESSED
                continue
            origins = {
                row.get("alias")
                for row in candidate.discovered_by
                if row.get("alias") in {model.alias for model in models}
            }
            model = next((row for row in models if row.alias not in origins), models[0])
            assignments.append(
                Assignment(
                    assignment_id=f"validate-{candidate.candidate_id.lower()}-{model.alias}",
                    kind=AssignmentKind.VALIDATE,
                    model_alias=model.alias,
                    provider=model.provider,
                    model=model.model,
                    candidate_id=candidate.candidate_id,
                    files=sorted(
                        {
                            str(point.get("file") or point.get("path") or "")
                            for point in [
                                candidate.source,
                                candidate.sink,
                                *candidate.trace,
                                *candidate.affected_instances,
                            ]
                            if point.get("file") or point.get("path")
                        }
                    ),
                )
            )
        return assignments

    def _attack_path_assignments(
        self, candidates: list[Candidate], models: list[ModelSpec]
    ) -> list[Assignment]:
        assignments: list[Assignment] = []
        for index, candidate in enumerate(candidates):
            if not candidate.validation:
                # A review verdict is not a substitute for source/control/sink
                # validation. Failed validation remains an explicit proof gap.
                continue
            if str(candidate.disposition) not in {
                FindingDisposition.REPORTABLE,
                FindingDisposition.DEFERRED,
            }:
                continue
            model = models[(index + 1) % len(models)] if len(models) > 1 else models[0]
            assignments.append(
                Assignment(
                    assignment_id=f"attack-path-{candidate.candidate_id.lower()}-{model.alias}",
                    kind=AssignmentKind.ATTACK_PATH,
                    model_alias=model.alias,
                    provider=model.provider,
                    model=model.model,
                    candidate_id=candidate.candidate_id,
                )
            )
        return assignments

    def _specialist_assignments(
        self, request: ScanRequest, partitions: list[Partition]
    ) -> list[Assignment]:
        return [
            Assignment(
                assignment_id=(
                    f"specialist-{specialist.profile}-{specialist.model_alias}-"
                    f"{partition.partition_id.lower()}"
                ),
                kind=AssignmentKind.SPECIALIST,
                    model_alias=specialist.model_alias,
                    provider=self.config.models[specialist.model_alias].provider,
                    model=self.config.models[specialist.model_alias].model,
                partition_id=partition.partition_id,
                files=partition.files,
                specialist_profile=specialist.profile,
            )
            for specialist in request.specialists
            if specialist.enabled
            for partition in partitions
        ]

    def _gap_assignments(
        self,
        hunt_payloads: list[tuple[Assignment, dict[str, Any]]],
        models: list[ModelSpec],
    ) -> list[Assignment]:
        assignments: list[Assignment] = []
        for index, (original, payload) in enumerate(hunt_payloads):
            unresolved = payload.get("coverage", {}).get("unresolved_files", [])
            files = (
                original.files
                if original.status == "FAILED"
                else [str(row) for row in unresolved]
            )
            if not files:
                continue
            origin_index = next(
                (
                    position
                    for position, model in enumerate(models)
                    if model.alias == original.model_alias
                ),
                0,
            )
            model = models[(origin_index + 1) % len(models)]
            assignments.append(
                Assignment(
                    assignment_id=(
                        f"gap-{model.alias}-{original.partition_id.lower()}-{index + 1}"
                    ),
                    kind=AssignmentKind.HUNT,
                    model_alias=model.alias,
                    provider=model.provider,
                    model=model.model,
                    partition_id=original.partition_id,
                    files=files,
                )
            )
        return assignments

    def _sweep_assignments(
        self,
        models: list[ModelSpec],
        inventory: RepositoryInventory,
        *,
        count: int,
    ) -> list[Assignment]:
        selected = [models[index % len(models)] for index in range(count)]
        return [
            Assignment(
                assignment_id=f"sweep-{index}-{model.alias}",
                kind=AssignmentKind.SWEEP,
                model_alias=model.alias,
                provider=model.provider,
                model=model.model,
                partition_id=f"SWEEP-{index}",
                files=inventory.files,
            )
            for index, model in enumerate(selected, 1)
        ]

    async def _run_hunt_assignments(
        self,
        assignments: list[Assignment],
        *,
        root: Path,
        inventory: RepositoryInventory,
        store: ArtifactStore,
        state: dict[str, Any],
        budget: "BudgetTracker",
        request: ScanRequest,
        sweep: bool = False,
    ) -> list[tuple[Assignment, dict[str, Any]]]:
        effective_workers = 1 if self._free_team_mode else request.limits.max_workers
        semaphore = asyncio.Semaphore(effective_workers)

        async def run(assignment: Assignment) -> tuple[Assignment, dict[str, Any]]:
            existing = store.read_assignment(assignment.assignment_id)
            if existing and existing.get("assignment", {}).get("status") == "COMPLETED":
                _restore_assignment(assignment, existing)
                self._progress(
                    "assignment_resumed",
                    assignment=assignment.assignment_id,
                    model=assignment.model_alias,
                    kind=str(assignment.kind),
                )
                return assignment, existing.get("payload", {})
            async with semaphore:
                reservation: tuple[int, float] | None = None
                try:
                    reservation = await budget.reserve(
                        self.config.models[assignment.model_alias],
                        estimated_input_tokens=max(
                            2_000,
                            sum(
                                (root / rel).stat().st_size
                                for rel in assignment.files
                                if (root / rel).is_file()
                            )
                            // 4,
                        ),
                    )
                    async def perform_worker() -> tuple[dict[str, Any], Usage]:
                        self._progress(
                            "assignment_started",
                            assignment=assignment.assignment_id,
                            model=assignment.model_alias,
                            kind=str(assignment.kind),
                        )
                        return await self._run_task_with_output_retries(
                            assignment,
                            lambda: self._hunt_worker(
                                assignment,
                                root=root,
                                inventory=inventory,
                                request=request,
                                sweep=(
                                    sweep
                                    or assignment.kind == AssignmentKind.SWEEP
                                ),
                            ),
                        )

                    worker = self._run_with_provider_limit(
                        assignment.provider,
                        perform_worker,
                    )
                    remaining = budget.remaining_duration()
                    payload, usage = await (
                        asyncio.wait_for(worker, timeout=remaining)
                        if remaining is not None
                        else worker
                    )
                    self._normalize_assignment_coverage(assignment, payload)
                    assignment.status = "COMPLETED"
                    assignment.usage = usage
                    await budget.record(usage, reservation)
                    store.write_assignment(assignment, payload)
                    await self._checkpoint(
                        store, state, assignment, budget, success=True
                    )
                    self._progress(
                        "assignment_complete",
                        assignment=assignment.assignment_id,
                        model=assignment.model_alias,
                        kind=str(assignment.kind),
                        input_tokens=usage.input_tokens,
                        output_tokens=usage.output_tokens,
                        cached_input_tokens=usage.cached_input_tokens,
                        cache_write_tokens=usage.cache_write_tokens,
                        requests=usage.requests,
                        rate_limit_retries=usage.rate_limit_retries,
                        cost_usd=usage.cost_usd,
                        cost_source=usage.cost_source,
                        duration_seconds=usage.duration_seconds,
                    )
                    return assignment, payload
                except TimeoutError as exc:
                    if reservation is not None:
                        await budget.release(reservation)
                    raise BudgetExceeded("maximum scan duration reached") from exc
                except BudgetExceeded:
                    if reservation is not None:
                        await budget.release(reservation)
                    raise
                except Exception as exc:  # noqa: BLE001
                    if isinstance(exc, ModelOutputError) and reservation is not None:
                        assignment.usage = exc.usage
                        await budget.record(exc.usage, reservation)
                    elif reservation is not None:
                        await budget.release(reservation)
                    assignment.status = "FAILED"
                    assignment.error = f"{type(exc).__name__}: {exc}"
                    store.write_assignment(
                        assignment, {"candidates": [], "coverage": {
                            "files_reviewed": [],
                            "unresolved_files": assignment.files,
                            "notes": assignment.error,
                        }}
                    )
                    await self._checkpoint(
                        store, state, assignment, budget, success=False
                    )
                    self._progress(
                        "assignment_failed",
                        assignment=assignment.assignment_id,
                        model=assignment.model_alias,
                        kind=str(assignment.kind),
                        error=assignment.error,
                        input_tokens=assignment.usage.input_tokens,
                        output_tokens=assignment.usage.output_tokens,
                        cached_input_tokens=assignment.usage.cached_input_tokens,
                        requests=assignment.usage.requests,
                        cost_usd=assignment.usage.cost_usd,
                        cost_source=assignment.usage.cost_source,
                        duration_seconds=assignment.usage.duration_seconds,
                    )
                    return assignment, {
                        "candidates": [],
                        "coverage": {
                            "files_reviewed": [],
                            "unresolved_files": assignment.files,
                            "notes": assignment.error,
                        },
                    }

        gathered = await asyncio.gather(
            *(run(row) for row in assignments),
            return_exceptions=True,
        )
        budget_failures = [
            row for row in gathered if isinstance(row, BudgetExceeded)
        ]
        if budget_failures:
            raise budget_failures[0]
        unexpected = [row for row in gathered if isinstance(row, BaseException)]
        if unexpected:
            raise unexpected[0]
        return [row for row in gathered if isinstance(row, tuple)]

    async def _run_methodology_assignments(
        self,
        assignments: list[Assignment],
        *,
        root: Path,
        inventory: RepositoryInventory,
        store: ArtifactStore,
        state: dict[str, Any],
        budget: "BudgetTracker",
        request: ScanRequest,
        schema: dict[str, Any],
        prompt_factory: Callable[[Assignment], str],
    ) -> list[tuple[Assignment, dict[str, Any]]]:
        effective_workers = 1 if self._free_team_mode else request.limits.max_workers
        if (
            len(assignments) > 1
            and effective_workers > 1
            and any(
                assignment.provider not in self._serial_provider_locks
                for assignment in assignments
            )
        ):
            semaphore = asyncio.Semaphore(effective_workers)

            async def run_one(
                assignment: Assignment,
            ) -> list[tuple[Assignment, dict[str, Any]]]:
                async with semaphore:
                    return await self._run_methodology_assignments(
                        [assignment],
                        root=root,
                        inventory=inventory,
                        store=store,
                        state=state,
                        budget=budget,
                        request=request,
                        schema=schema,
                        prompt_factory=prompt_factory,
                    )

            batches = await asyncio.gather(
                *(run_one(assignment) for assignment in assignments)
            )
            return [row for batch in batches for row in batch]

        results: list[tuple[Assignment, dict[str, Any]]] = []
        for assignment in assignments:
            existing = store.read_assignment(assignment.assignment_id)
            if existing and existing.get("assignment", {}).get("status") == "COMPLETED":
                _restore_assignment(assignment, existing)
                results.append((assignment, existing.get("payload", {})))
                self._progress(
                    "assignment_resumed",
                    assignment=assignment.assignment_id,
                    model=assignment.model_alias,
                    kind=str(assignment.kind),
                )
                continue
            reservation: tuple[int, float] | None = None
            try:
                reservation = await budget.reserve(
                    self.config.models[assignment.model_alias],
                    estimated_input_tokens=max(
                        2_000,
                        sum(
                            (root / rel).stat().st_size
                            for rel in assignment.files
                            if (root / rel).is_file()
                        )
                        // 4,
                    ),
                )
                prompt = prompt_factory(assignment)
                assignment.prompt_hash = hashlib.sha256(
                    (SYSTEM_PROMPT + "\n" + prompt).encode("utf-8")
                ).hexdigest()
                assignment.context["prompt_metrics"] = _prompt_metrics(
                    SYSTEM_PROMPT, prompt
                )
                self._progress(
                    "assignment_prompt_ready",
                    assignment=assignment.assignment_id,
                    model=assignment.model_alias,
                    kind=str(assignment.kind),
                    **assignment.context["prompt_metrics"],
                )
                self._progress(
                    "assignment_started",
                    assignment=assignment.assignment_id,
                    model=assignment.model_alias,
                    kind=str(assignment.kind),
                )

                async def perform() -> tuple[dict[str, Any], Usage]:
                    return await self._run_task_with_output_retries(
                        assignment,
                        lambda: self._tool_loop(
                            self.config.models[assignment.model_alias],
                            root=root,
                            allowed_files=set(inventory.files),
                            user_prompt=prompt,
                            schema=schema,
                            execute=(
                                request.execute
                                and assignment.kind == AssignmentKind.VALIDATE
                            ),
                        ),
                    )

                worker = self._run_with_provider_limit(assignment.provider, perform)
                remaining = budget.remaining_duration()
                payload, usage = await (
                    asyncio.wait_for(worker, timeout=remaining)
                    if remaining is not None
                    else worker
                )
                provenance_calls = _list_of_dicts(
                    _dict(payload.get("_provenance")).get("tool_calls")
                )
                assignment.evidence = _normalized_tool_evidence(
                    provenance_calls, assignment.files
                )
                evidenced_paths = {
                    str(row.get("path", ""))
                    for row in assignment.evidence
                    if str(row.get("path", ""))
                    and row.get("tool")
                    in {
                        "assignment_packet",
                        "read_file",
                        "search_text",
                        "find_symbol",
                        "run_command_path",
                    }
                }
                assignment.coverage_quality = (
                    "auditable"
                    if set(assignment.files) <= evidenced_paths
                    else "self_reported"
                )
                assignment.status = "COMPLETED"
                assignment.usage = usage
                await budget.record(usage, reservation)
                store.write_assignment(assignment, payload)
                await self._checkpoint(store, state, assignment, budget, success=True)
                results.append((assignment, payload))
                self._progress(
                    "assignment_complete",
                    assignment=assignment.assignment_id,
                    model=assignment.model_alias,
                    kind=str(assignment.kind),
                    input_tokens=usage.input_tokens,
                    output_tokens=usage.output_tokens,
                    requests=usage.requests,
                    cost_usd=usage.cost_usd,
                    duration_seconds=usage.duration_seconds,
                )
            except TimeoutError as exc:
                if reservation is not None:
                    await budget.release(reservation)
                raise BudgetExceeded("maximum scan duration reached") from exc
            except BudgetExceeded:
                if reservation is not None:
                    await budget.release(reservation)
                raise
            except Exception as exc:  # noqa: BLE001
                if isinstance(exc, ModelOutputError) and reservation is not None:
                    assignment.usage = exc.usage
                    await budget.record(exc.usage, reservation)
                elif reservation is not None:
                    await budget.release(reservation)
                assignment.status = "FAILED"
                assignment.error = f"{type(exc).__name__}: {exc}"
                store.write_assignment(assignment, {"error": assignment.error})
                await self._checkpoint(store, state, assignment, budget, success=False)
                self._progress(
                    "assignment_failed",
                    assignment=assignment.assignment_id,
                    model=assignment.model_alias,
                    kind=str(assignment.kind),
                    error=assignment.error,
                    input_tokens=assignment.usage.input_tokens,
                    output_tokens=assignment.usage.output_tokens,
                    cached_input_tokens=assignment.usage.cached_input_tokens,
                    requests=assignment.usage.requests,
                    cost_usd=assignment.usage.cost_usd,
                    cost_source=assignment.usage.cost_source,
                    duration_seconds=assignment.usage.duration_seconds,
                )
        return results

    @staticmethod
    def _merge_threat_models(
        baseline: ThreatModel,
        payloads: list[tuple[Assignment, dict[str, Any]]],
        models: list[ModelSpec],
    ) -> ThreatModel:
        def merged(name: str) -> list[str]:
            rows = list(getattr(baseline, name))
            for _assignment, payload in payloads:
                rows.extend(str(row) for row in payload.get(name, []) if str(row).strip())
            return list(dict.fromkeys(rows))

        baseline.product_surfaces = merged("product_surfaces")
        baseline.actors = merged("actors")
        baseline.external_entrypoints = merged("external_entrypoints")
        baseline.privileged_workflows = merged("privileged_workflows")
        baseline.assets = merged("assets")
        baseline.dependency_attackers = merged("dependency_attackers")
        baseline.trust_boundaries = merged("trust_boundaries")
        baseline.security_invariants = merged("security_invariants")
        baseline.external_controls = merged("external_controls")
        baseline.proof_gaps = merged("proof_gaps")
        baseline.model_provenance = [
            {
                "alias": assignment.model_alias,
                "provider": assignment.provider,
                "model": assignment.model,
            }
            for assignment, _payload in payloads
        ]
        return baseline

    @staticmethod
    def _apply_validation(
        candidate: Candidate, payload: dict[str, Any], assignment: Assignment
    ) -> None:
        candidate.validation = {
            **{
                key: value
                for key, value in payload.items()
                if not key.startswith("_") and key != "sandbox_commands"
            },
            "validator": {
                "alias": assignment.model_alias,
                "provider": assignment.provider,
                "model": assignment.model,
            },
            "artifacts": [
                str(row.get("artifact"))
                for row in assignment.evidence
                if row.get("artifact")
            ],
        }
        candidate.verdict = str(payload.get("verdict", Verdict.UNRESOLVED))
        candidate.disposition = str(
            payload.get("disposition", FindingDisposition.UNRESOLVED)
        )
        candidate.proof_gaps = _list_of_strings(payload.get("proof_gaps"))
        candidate.contradicting_evidence = _list_of_strings(
            payload.get("counterevidence")
        )
        severity = payload.get("recommended_severity")
        if severity in {"Critical", "High", "Medium", "Low"}:
            candidate.severity = str(severity)

    @staticmethod
    def _close_surface_ledger(
        rows: list[SurfaceLedgerRow],
        candidates: list[Candidate],
        assignments: list[Assignment],
        inventory: RepositoryInventory,
    ) -> None:
        for row in rows:
            relevant = []
            for candidate in candidates:
                paths = {
                    str(point.get("file") or point.get("path") or "")
                    for point in [
                        candidate.source,
                        candidate.sink,
                        *candidate.trace,
                        *candidate.affected_instances,
                    ]
                }
                if paths & set(row.files):
                    relevant.append(candidate)
            if relevant:
                row.candidate_ids = [candidate.candidate_id for candidate in relevant]
                dispositions = {str(candidate.disposition) for candidate in relevant}
                if str(FindingDisposition.REPORTABLE) in dispositions:
                    row.disposition = FindingDisposition.REPORTABLE
                elif str(FindingDisposition.DEFERRED) in dispositions:
                    row.disposition = FindingDisposition.DEFERRED
                elif str(FindingDisposition.UNRESOLVED) in dispositions:
                    row.disposition = FindingDisposition.UNRESOLVED
                else:
                    row.disposition = FindingDisposition.SUPPRESSED
                row.closure_reason = "Closed through candidate validation."
                continue
            challenger = next(
                (
                    assignment
                    for assignment in assignments
                    if assignment.kind == AssignmentKind.CLEAN_CHALLENGE
                    and assignment.partition_id == row.surface_id
                ),
                None,
            )
            evidence_paths = (
                {
                    str(point.get("path", ""))
                    for point in challenger.evidence
                    if str(point.get("path", ""))
                }
                if challenger
                else set()
            )
            if (
                challenger
                and challenger.status == "COMPLETED"
                and challenger.coverage_quality == "auditable"
                and set(row.files) <= evidence_paths
            ):
                row.disposition = FindingDisposition.SUPPRESSED
                row.closure_reason = (
                    "Fresh-context challenger found no reportable path and returned "
                    "complete auditable surface coverage."
                )
                row.evidence = challenger.evidence
            elif challenger and challenger.status == "COMPLETED":
                row.closure_reason = (
                    "The challenger completed, but critical-surface coverage was "
                    "self-reported or lacked exact file evidence."
                )
            elif not row.mandatory:
                row.disposition = FindingDisposition.NOT_APPLICABLE
                row.closure_reason = "Non-mandatory general surface completed by broad hunts."

    async def _run_with_provider_limit(
        self,
        provider_name: str,
        factory: Callable[[], Awaitable[tuple[dict[str, Any], Usage]]],
    ) -> tuple[dict[str, Any], Usage]:
        """Serialize providers whose local session state is not concurrency-safe."""
        unavailable = self._provider_unavailable_errors.get(provider_name)
        if unavailable is not None:
            raise ProviderError(
                f"provider disabled for the remainder of this run after a "
                f"non-retryable failure: {unavailable}",
                status_code=unavailable.status_code,
            )

        async def invoke() -> tuple[dict[str, Any], Usage]:
            disabled = self._provider_unavailable_errors.get(provider_name)
            if disabled is not None:
                raise ProviderError(
                    "provider disabled for the remainder of this run after a "
                    f"non-retryable failure: {disabled}",
                    status_code=disabled.status_code,
                )
            try:
                return await factory()
            except ProviderError as exc:
                if not _provider_error_retryable(exc):
                    self._provider_unavailable_errors[provider_name] = exc
                raise

        lock = self._serial_provider_locks.get(provider_name)
        if lock is None:
            return await invoke()
        async with lock:
            return await invoke()

    async def _run_task_with_output_retries(
        self,
        assignment: Assignment,
        factory: Callable[[], Awaitable[tuple[dict[str, Any], Usage]]],
    ) -> tuple[dict[str, Any], Usage]:
        """Retry a malformed final result in a completely fresh model context."""

        accumulated = Usage()
        last_error = "model did not return a valid structured result"
        for attempt in range(1, 5):
            try:
                payload, usage = await factory()
            except ModelOutputError as exc:
                accumulated.add(exc.usage)
                last_error = str(exc)
                if attempt <= 3:
                    self._progress(
                        "assignment_output_retry",
                        assignment=assignment.assignment_id,
                        model=assignment.model_alias,
                        retry=attempt,
                        max_retries=3,
                        error=last_error,
                    )
                    continue
                raise ModelOutputError(
                    f"{last_error}; exhausted 3 complete task retries",
                    accumulated,
                ) from exc
            accumulated.add(usage)
            return payload, accumulated
        raise ModelOutputError(last_error, accumulated)

    async def _hunt_worker(
        self,
        assignment: Assignment,
        *,
        root: Path,
        inventory: RepositoryInventory,
        request: ScanRequest,
        sweep: bool,
    ) -> tuple[dict[str, Any], Usage]:
        model = self.config.models[assignment.model_alias]
        specialist = next(
            (
                row
                for row in request.specialists
                if row.profile == assignment.specialist_profile
                and row.model_alias == assignment.model_alias
            ),
            None,
        )
        summary = self._repository_summary(inventory)
        if assignment.kind == AssignmentKind.SEED_REVIEW:
            prompt = seed_review_prompt(
                assignment.context.get("seed", {}),
                assignment.context.get("threat_model", {}),
            )
        elif assignment.kind == AssignmentKind.CLEAN_CHALLENGE:
            surface = dict(assignment.context.get("surface", {}))
            nearby_seeds = assignment.context.get("seeds", [])
            if nearby_seeds:
                surface["deterministic_seeds"] = nearby_seeds
            delivered: list[dict[str, Any]] = []
            delivered_bytes = 0
            for rel in assignment.files:
                path = root / rel
                try:
                    size = path.stat().st_size
                except OSError:
                    continue
                if size > 32_000 or delivered_bytes + size > 64_000:
                    continue
                try:
                    content = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                delivered.append({"path": rel, "content": content})
                delivered_bytes += size
                assignment.evidence.append(
                    {
                        "tool": "assignment_packet",
                        "path": rel,
                        "result_sha256": hashlib.sha256(
                            content.encode("utf-8")
                        ).hexdigest(),
                    }
                )
            if delivered:
                surface["delivered_files"] = delivered
            prompt = clean_challenge_prompt(
                surface=surface,
                files=assignment.files,
                threat_model=assignment.context.get("threat_model", {}),
            )
        else:
            prompt = hunt_prompt(
                partition_id=assignment.partition_id,
                files=assignment.files,
                repository_summary=summary,
                scan_level=str(request.level),
                specialist_profile=assignment.specialist_profile,
                specialist_prompt=specialist.prompt if specialist else "",
                sweep=sweep,
            )
        assignment.prompt_hash = hashlib.sha256(
            (SYSTEM_PROMPT + "\n" + prompt).encode("utf-8")
        ).hexdigest()
        assignment.context["prompt_metrics"] = _prompt_metrics(
            SYSTEM_PROMPT, prompt
        )
        self._progress(
            "assignment_prompt_ready",
            assignment=assignment.assignment_id,
            model=assignment.model_alias,
            kind=str(assignment.kind),
            **assignment.context["prompt_metrics"],
        )
        return await self._tool_loop(
            model,
            root=root,
            allowed_files=set(inventory.files),
            user_prompt=prompt,
            schema=CANDIDATE_SCHEMA,
            # Repository commands during discovery would blur static evidence
            # with execution. Only VALIDATE assignments may use Docker.
            execute=False,
        )

    @staticmethod
    def _normalize_assignment_coverage(
        assignment: Assignment, payload: dict[str, Any]
    ) -> None:
        calls = _list_of_dicts(
            _dict(payload.get("_provenance")).get("tool_calls")
        )
        normalized_evidence = _normalized_tool_evidence(calls, assignment.files)
        assignment.evidence.extend(
            row for row in normalized_evidence if row not in assignment.evidence
        )
        coverage = payload.setdefault("coverage", {})
        assigned = set(assignment.files)
        aliases: dict[str, list[str]] = {}
        for path in assigned:
            aliases.setdefault(_coverage_path_key(path), []).append(path)

        def normalize_claims(value: Any) -> tuple[set[str], set[str]]:
            primary: set[str] = set()
            supplemental: set[str] = set()
            for claimed in _list_of_strings(value):
                normalized = claimed.replace("\\", "/").removeprefix("./")
                matches = aliases.get(_coverage_path_key(normalized), [])
                if len(matches) == 1:
                    primary.add(matches[0])
                elif normalized in assigned:
                    primary.add(normalized)
                else:
                    supplemental.add(normalized)
            return primary, supplemental

        reviewed, supplemental_reviewed = normalize_claims(
            coverage.get("files_reviewed")
        )
        unresolved, supplemental_unresolved = normalize_claims(
            coverage.get("unresolved_files")
        )
        reviewed.difference_update(unresolved)
        unresolved.update(assigned - reviewed - unresolved)
        coverage["files_reviewed"] = sorted(reviewed)
        coverage["unresolved_files"] = sorted(unresolved)
        coverage["notes"] = str(coverage.get("notes", ""))
        if supplemental_reviewed:
            assignment.evidence.append(
                {
                    "tool": "supplemental_coverage_claim",
                    "paths": sorted(supplemental_reviewed),
                    "note": (
                        "Paths outside the primary shard are preserved as "
                        "supplemental claims and cannot close assigned coverage."
                    ),
                }
            )
        if supplemental_unresolved:
            assignment.evidence.append(
                {
                    "tool": "supplemental_unresolved_claim",
                    "paths": sorted(supplemental_unresolved),
                }
            )
        evidenced_paths = {
            str(row.get("path", ""))
            for row in assignment.evidence
            if str(row.get("path", ""))
            and row.get("tool")
            in {
                "assignment_packet",
                "read_file",
                "search_text",
                "find_symbol",
                "run_command_path",
            }
        }
        assignment.coverage_quality = (
            "auditable"
            if reviewed <= evidenced_paths and not supplemental_reviewed
            else "self_reported"
        )

    def _parse_candidates(
        self,
        payload: dict[str, Any],
        assignment: Assignment,
        offset: int,
    ) -> list[Candidate]:
        candidates: list[Candidate] = []
        for index, row in enumerate(payload.get("candidates", []), 1):
            candidates.append(
                Candidate(
                    candidate_id=f"CAND-{offset + index:05d}",
                    title=str(row.get("title", "Untitled candidate")),
                    classification=str(row.get("classification", "")),
                    severity=_severity(str(row.get("severity", "Medium"))),
                    cwe=_cwe(str(row.get("cwe", ""))),
                    source=_dict(row.get("source")),
                    sink=_dict(row.get("sink")),
                    trace=_list_of_dicts(row.get("trace")),
                    root_cause=str(row.get("root_cause", "")),
                    attacker_prerequisites=_list_of_strings(
                        row.get("attacker_prerequisites")
                    ),
                    new_capability=str(row.get("new_capability", "")),
                    contradicting_evidence=_list_of_strings(
                        row.get("contradicting_evidence")
                    ),
                    fix_strategy=str(row.get("fix_strategy", "")),
                    confidence=_optional_float(row.get("confidence")),
                    affected_resource=str(row.get("affected_resource", "")),
                    security_boundary=str(row.get("security_boundary", "")),
                    closest_control=_dict(row.get("closest_control")),
                    reachable_path=_list_of_dicts(
                        row.get("reachable_path") or row.get("trace")
                    ),
                    proof_gaps=_list_of_strings(row.get("proof_gaps")),
                    affected_instances=_list_of_dicts(
                        row.get("affected_instances")
                    ),
                    poc=str(row.get("poc", "")),
                    exploit_test=str(row.get("exploit_test", "")),
                    discovered_by=[
                        {
                            "alias": assignment.model_alias,
                            "provider": self.config.models[
                                assignment.model_alias
                            ].provider,
                            "assignment": assignment.assignment_id,
                            "kind": str(assignment.kind),
                        }
                    ],
                )
            )
        return candidates

    def _review_assignments(
        self,
        level: ScanLevel,
        models: list[ModelSpec],
        candidates: list[Candidate],
    ) -> list[Assignment]:
        assignments: list[Assignment] = []
        aliases = [row.alias for row in models]
        for candidate in candidates:
            origins = {
                row["alias"] for row in candidate.discovered_by if row.get("alias")
            }
            eligible = [alias for alias in aliases if alias not in origins] or aliases
            reviewers: list[str]
            if level == ScanLevel.EXHAUSTIVE:
                reviewers = eligible
            else:
                first_origin = next(
                    (alias for alias in aliases if alias in origins),
                    aliases[0],
                )
                origin_index = aliases.index(first_origin) if first_origin in aliases else 0
                ring = aliases[(origin_index + 1) % len(aliases)]
                reviewers = [ring]
                needs_second = (
                    level == ScanLevel.DEEP
                    and (
                        len(origins) == 1
                        or candidate.severity in {"High", "Critical"}
                        or bool(candidate.proof_gaps)
                        or bool(candidate.contradicting_evidence)
                    )
                )
                if needs_second:
                    second = next(
                        (alias for alias in eligible if alias != ring),
                        next((alias for alias in aliases if alias != ring), ring),
                    )
                    reviewers.append(second)
            for number, reviewer in enumerate(reviewers, 1):
                assignments.append(
                    Assignment(
                        assignment_id=(
                            f"review-{candidate.candidate_id.lower()}-{number}-{reviewer}"
                        ),
                        kind=AssignmentKind.REVIEW,
                        model_alias=reviewer,
                        provider=self.config.models[reviewer].provider,
                        model=self.config.models[reviewer].model,
                        candidate_id=candidate.candidate_id,
                    )
                )
        return assignments

    def _resolver_assignments(
        self,
        models: list[ModelSpec],
        candidates: list[Candidate],
        reviews: list[Review],
    ) -> list[Assignment]:
        assignments: list[Assignment] = []
        for candidate in candidates:
            verdicts = {
                row.verdict
                for row in reviews
                if row.candidate_id == candidate.candidate_id
            }
            if len(verdicts) <= 1:
                continue
            used = {
                row.reviewer.get("alias", "")
                for row in reviews
                if row.candidate_id == candidate.candidate_id
            }
            model = next(
                (row for row in models if row.alias not in used),
                models[0],
            )
            assignments.append(
                Assignment(
                    assignment_id=f"resolve-{candidate.candidate_id.lower()}-{model.alias}",
                    kind=AssignmentKind.RESOLVE,
                    model_alias=model.alias,
                    provider=model.provider,
                    model=model.model,
                    candidate_id=candidate.candidate_id,
                )
            )
        return assignments

    async def _run_review_assignments(
        self,
        assignments: list[Assignment],
        *,
        candidates: list[Candidate],
        root: Path,
        inventory: RepositoryInventory,
        store: ArtifactStore,
        state: dict[str, Any],
        budget: "BudgetTracker",
        request: ScanRequest,
    ) -> list[Review]:
        effective_workers = 1 if self._free_team_mode else request.limits.max_workers
        if (
            len(assignments) > 1
            and effective_workers > 1
            and any(
                assignment.provider not in self._serial_provider_locks
                for assignment in assignments
            )
        ):
            semaphore = asyncio.Semaphore(effective_workers)

            async def run_one(assignment: Assignment) -> list[Review]:
                async with semaphore:
                    return await self._run_review_assignments(
                        [assignment],
                        candidates=candidates,
                        root=root,
                        inventory=inventory,
                        store=store,
                        state=state,
                        budget=budget,
                        request=request,
                    )

            batches = await asyncio.gather(
                *(run_one(assignment) for assignment in assignments)
            )
            return [row for batch in batches for row in batch]

        by_id = {row.candidate_id: row for row in candidates}
        reviews: list[Review] = []
        for assignment in assignments:
            reservation: tuple[int, float] | None = None
            existing = store.read_assignment(assignment.assignment_id)
            if existing and existing.get("assignment", {}).get("status") == "COMPLETED":
                _restore_assignment(assignment, existing)
                review = _review_from_payload(
                    assignment,
                    existing.get("payload", {}),
                    self.config.models[assignment.model_alias],
                )
                reviews.append(review)
                self._progress(
                    "assignment_resumed",
                    assignment=assignment.assignment_id,
                    model=assignment.model_alias,
                    kind=str(assignment.kind),
                )
                continue
            candidate = by_id[assignment.candidate_id]
            model = self.config.models[assignment.model_alias]
            packet = candidate_review_packet(candidate)
            try:
                self._progress(
                    "assignment_started",
                    assignment=assignment.assignment_id,
                    model=assignment.model_alias,
                    kind=str(assignment.kind),
                )
                reservation = await budget.reserve(
                    model, estimated_input_tokens=8_000
                )
                assignment.prompt_hash = hashlib.sha256(
                    (SYSTEM_PROMPT + "\n" + review_prompt(packet)).encode("utf-8")
                ).hexdigest()
                assignment.context["prompt_metrics"] = _prompt_metrics(
                    SYSTEM_PROMPT, review_prompt(packet)
                )
                self._progress(
                    "assignment_prompt_ready",
                    assignment=assignment.assignment_id,
                    model=assignment.model_alias,
                    kind=str(assignment.kind),
                    **assignment.context["prompt_metrics"],
                )
                worker = self._run_with_provider_limit(
                    assignment.provider,
                    lambda: self._run_task_with_output_retries(
                        assignment,
                        lambda: self._tool_loop(
                            model,
                            root=root,
                            allowed_files=set(inventory.files),
                            user_prompt=review_prompt(packet),
                            schema=REVIEW_SCHEMA,
                            execute=False,
                        ),
                    ),
                )
                remaining = budget.remaining_duration()
                payload, usage = await (
                    asyncio.wait_for(worker, timeout=remaining)
                    if remaining is not None
                    else worker
                )
                assignment.status = "COMPLETED"
                assignment.usage = usage
                await budget.record(usage, reservation)
                store.write_assignment(assignment, payload)
                review = _review_from_payload(assignment, payload, model, usage)
                store.write_review(review)
                reviews.append(review)
                await self._checkpoint(
                    store, state, assignment, budget, success=True
                )
                self._progress(
                    "assignment_complete",
                    assignment=assignment.assignment_id,
                    model=assignment.model_alias,
                    kind=str(assignment.kind),
                    input_tokens=usage.input_tokens,
                    output_tokens=usage.output_tokens,
                    cached_input_tokens=usage.cached_input_tokens,
                    cache_write_tokens=usage.cache_write_tokens,
                    requests=usage.requests,
                    rate_limit_retries=usage.rate_limit_retries,
                    cost_usd=usage.cost_usd,
                    cost_source=usage.cost_source,
                    duration_seconds=usage.duration_seconds,
                )
            except TimeoutError as exc:
                if reservation is not None:
                    await budget.release(reservation)
                raise BudgetExceeded("maximum scan duration reached") from exc
            except BudgetExceeded:
                if reservation is not None:
                    await budget.release(reservation)
                raise
            except Exception as exc:  # noqa: BLE001
                if isinstance(exc, ModelOutputError) and reservation is not None:
                    assignment.usage = exc.usage
                    await budget.record(exc.usage, reservation)
                elif reservation is not None:
                    await budget.release(reservation)
                assignment.status = "FAILED"
                assignment.error = f"{type(exc).__name__}: {exc}"
                store.write_assignment(
                    assignment,
                    {
                        "verdict": Verdict.UNRESOLVED,
                        "source_reachable": None,
                        "attacker_controlled": None,
                        "trace_complete": None,
                        "blocking_control_found": None,
                        "new_capability_proven": None,
                        "rationale": assignment.error,
                        "incorrect_claims": [],
                        "missing_evidence": ["review assignment failed"],
                    },
                )
                await self._checkpoint(
                    store, state, assignment, budget, success=False
                )
                self._progress(
                    "assignment_failed",
                    assignment=assignment.assignment_id,
                    model=assignment.model_alias,
                    kind=str(assignment.kind),
                    error=assignment.error,
                    input_tokens=assignment.usage.input_tokens,
                    output_tokens=assignment.usage.output_tokens,
                    cached_input_tokens=assignment.usage.cached_input_tokens,
                    requests=assignment.usage.requests,
                    cost_usd=assignment.usage.cost_usd,
                    cost_source=assignment.usage.cost_source,
                    duration_seconds=assignment.usage.duration_seconds,
                )
        return reviews

    async def _tool_loop(
        self,
        model: ModelSpec,
        *,
        root: Path,
        allowed_files: set[str] | None,
        user_prompt: str,
        schema: dict[str, Any],
        execute: bool,
    ) -> tuple[dict[str, Any], Usage]:
        provider = self.providers[model.provider]
        provider_manages_tools = bool(
            getattr(provider, "manages_repository_tools", False)
        )
        tools = RepositoryTools(
            root,
            allowed_files=allowed_files,
            execute=execute,
            artifact_dir=(
                (self._active_results_dir or root) / "validation_artifacts"
            ),
            sandbox=(
                DockerSandbox(
                    root,
                    (self._active_results_dir or root) / "validation_artifacts",
                    SandboxPolicy(
                        image=(
                            (self._active_request.sandbox_image if self._active_request else None)
                            or self.config.sandbox.image
                        ),
                        memory=self.config.sandbox.memory,
                        cpus=self.config.sandbox.cpus,
                        pids_limit=self.config.sandbox.pids_limit,
                        allow_network=bool(
                            self._active_request and self._active_request.allow_network
                        ),
                        allow_private_network=bool(
                            self._active_request
                            and self._active_request.allow_private_network
                        ),
                    ),
                )
                if execute
                else None
            ),
        )
        system = SYSTEM_PROMPT
        if model.tool_mode == "json" and not provider_manages_tools:
            system += json_tool_instruction(tools.definitions)
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system},
            {
                "role": "user",
                "content": (
                    user_prompt
                    + (
                        "\n\nDocker execution is authorized for this validation. "
                        "Request bounded reproduction commands only through the "
                        "sandbox_commands field; the engine will execute them and "
                        "return their redacted results."
                        if execute
                        else "\n\nDocker execution is not authorized for this task."
                    )
                    + "\n\nEfficiency requirements: batch independent repository "
                    "tool calls in the same response. Do not repeat an identical "
                    "tool call. Return the final JSON as soon as the assigned "
                    "evidence is sufficient."
                ),
            },
        ]
        total_usage = Usage()
        tool_evidence: list[dict[str, Any]] = []
        tool_result_cache: dict[str, tuple[str, str]] = {}
        final_error = "model did not return a JSON final result"
        invalid_final_content = ""
        max_tool_rounds = 24
        sandbox_batches = 0
        sandbox_command_signatures: set[str] = set()
        for _turn in range(max_tool_rounds):
            response = await _complete_with_retry(
                provider,
                model=model,
                messages=messages,
                tools=(
                    tools.definitions
                    if model.tool_mode == "native" and not provider_manages_tools
                    else []
                ),
                response_schema=schema if provider_manages_tools else None,
                on_retry=lambda attempt, delay, error: self._progress(
                    "rate_limited",
                    model=model.alias,
                    attempt=attempt,
                    delay_seconds=delay,
                    error=error,
                ),
                before_request=lambda: self._pace_request(model),
                on_activity=lambda event, details: self._progress(
                    event, model=model.alias, **details
                ),
            )
            total_usage.add(response.usage)
            provider_events = (
                response.raw.get("tool_events", [])
                if isinstance(response.raw, dict)
                else []
            )
            if isinstance(provider_events, list):
                normalized_provider_events = [
                    event for event in provider_events if isinstance(event, dict)
                ]
                if normalized_provider_events:
                    self._progress(
                        "tool_calls",
                        model=model.alias,
                        count=len(normalized_provider_events),
                        tools=[
                            str(event.get("name", "codex_tool"))
                            for event in normalized_provider_events
                        ],
                        provider_managed=True,
                    )
                for event in normalized_provider_events:
                    if event not in tool_evidence:
                        tool_evidence.append(event)
            if model.tool_mode == "json" and not response.tool_calls:
                response = _decode_json_tool_response(response)
            if response.tool_calls:
                self._progress(
                    "tool_calls",
                    model=model.alias,
                    count=len(response.tool_calls),
                    tools=[call.name for call in response.tool_calls],
                )
                messages.append(
                    {
                        "role": "assistant",
                        "content": response.content,
                        "tool_calls": [
                            {
                                "id": call.id,
                                "type": "function",
                                "function": {
                                    "name": call.name,
                                    "arguments": json.dumps(call.arguments),
                                },
                            }
                            for call in response.tool_calls
                        ],
                    }
                )
                for call in response.tool_calls:
                    signature = json.dumps(
                        [call.name, call.arguments],
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    cached = tool_result_cache.get(signature)
                    if cached is None:
                        result = tools.execute_call(call.name, call.arguments)
                        result_hash = hashlib.sha256(
                            result.encode("utf-8")
                        ).hexdigest()
                        tool_result_cache[signature] = (call.id, result_hash)
                    else:
                        previous_id, result_hash = cached
                        result = json.dumps(
                            {
                                "ok": True,
                                "duplicate": True,
                                "previous_tool_call_id": previous_id,
                                "message": (
                                    "Identical result is already present earlier "
                                    "in this conversation; use that result."
                                ),
                            }
                        )
                        self._progress(
                            "duplicate_tool_call",
                            model=model.alias,
                            tool=call.name,
                        )
                    evidence_record = {
                        "name": call.name,
                        "arguments": call.arguments,
                        "result_sha256": result_hash,
                    }
                    try:
                        result_payload = json.loads(result)
                    except ValueError:
                        result_payload = {}
                    tool_result = (
                        result_payload.get("result")
                        if isinstance(result_payload, dict)
                        else {}
                    )
                    if (
                        isinstance(tool_result, dict)
                        and tool_result.get("command_log")
                    ):
                        evidence_record["artifact"] = str(
                            tool_result["command_log"]
                        )
                    tool_evidence.append(evidence_record)
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": call.id,
                            "name": call.name,
                            "content": result,
                        }
                    )
                completed_rounds = _turn + 1
                if completed_rounds in {12, 20}:
                    remaining = max_tool_rounds - completed_rounds
                    messages.append(
                        {
                            "role": "user",
                            "content": (
                                f"You have {remaining} repository-tool rounds "
                                "remaining. Batch any necessary independent calls "
                                "now, then return the required final JSON. Do not "
                                "re-read evidence already in the conversation."
                            ),
                        }
                    )
                continue
            parsed = _parse_final_json(response.content)
            if parsed is not None:
                _prune_schema_extras(parsed, schema)
                _add_safe_schema_defaults(parsed, schema)
            errors = (
                list(Draft202012Validator(schema).iter_errors(parsed))
                if parsed is not None
                else []
            )
            if parsed is not None and not errors:
                sandbox_commands = _list_of_dicts(
                    parsed.get("sandbox_commands")
                )
                if sandbox_commands and execute and sandbox_batches < 2:
                    sandbox_results: list[dict[str, Any]] = []
                    for command in sandbox_commands:
                        signature = json.dumps(
                            command, sort_keys=True, separators=(",", ":")
                        )
                        if signature in sandbox_command_signatures:
                            sandbox_results.append(
                                {
                                    "command": command,
                                    "ok": False,
                                    "error": (
                                        "duplicate sandbox command was not rerun"
                                    ),
                                }
                            )
                            continue
                        sandbox_command_signatures.add(signature)
                        self._progress(
                            "sandbox_command_started",
                            model=model.alias,
                            argv=command.get("argv", []),
                        )
                        result_text = tools.execute_call(
                            "run_command", command
                        )
                        try:
                            result_payload = json.loads(result_text)
                        except ValueError:
                            result_payload = {
                                "ok": False,
                                "error": "sandbox returned invalid JSON",
                            }
                        result = (
                            result_payload.get("result", {})
                            if isinstance(result_payload, dict)
                            else {}
                        )
                        evidence_record = {
                            "name": "run_command",
                            "arguments": command,
                            "result_sha256": hashlib.sha256(
                                result_text.encode("utf-8")
                            ).hexdigest(),
                        }
                        if (
                            isinstance(result, dict)
                            and result.get("command_log")
                        ):
                            evidence_record["artifact"] = str(
                                result["command_log"]
                            )
                        tool_evidence.append(evidence_record)
                        sandbox_results.append(
                            {
                                "command": command,
                                "response": result_payload,
                            }
                        )
                        self._progress(
                            "sandbox_command_complete",
                            model=model.alias,
                            argv=command.get("argv", []),
                            ok=bool(
                                isinstance(result_payload, dict)
                                and result_payload.get("ok")
                            ),
                            artifact=evidence_record.get("artifact", ""),
                        )
                    sandbox_batches += 1
                    messages.append(
                        {"role": "assistant", "content": response.content}
                    )
                    messages.append(
                        {
                            "role": "user",
                            "content": (
                                "Sandbox execution results (engine-generated, "
                                "redacted, and authoritative):\n"
                                + json.dumps(sandbox_results, indent=2)
                                + "\nReturn the final validation JSON now. Set "
                                "sandbox_commands to [] and base runtime claims "
                                "only on these results."
                            ),
                        }
                    )
                    continue
                if sandbox_commands:
                    parsed["sandbox_commands"] = []
                    proof_gaps = parsed.setdefault("proof_gaps", [])
                    reason = (
                        "Sandbox execution was not authorized; requested commands "
                        "were not run."
                        if not execute
                        else "Sandbox command round limit reached; additional "
                        "requested commands were not run."
                    )
                    if reason not in proof_gaps:
                        proof_gaps.append(reason)
                parsed["_provenance"] = {
                    "provider": model.provider,
                    "model": model.model,
                    "tool_calls": tool_evidence,
                }
                self._progress("model_result_received", model=model.alias)
                return parsed, total_usage
            if errors:
                final_error = f"model result failed schema: {errors[0].message}"
            if response.content:
                invalid_final_content = response.content
            break

        # A repair is deliberately constrained to the existing response. If it
        # still fails, the assignment runner retries the whole task in a fresh
        # context up to three times.
        # Schema repair is safe only when there is an actual final object to
        # repair. If the model spends its whole budget calling tools, retry the
        # assignment in a fresh context instead of asking a context-free repair
        # model to invent a result.
        max_repairs = 1 if invalid_final_content else 0
        for repair_attempt in range(1, max_repairs + 1):
            self._progress(
                "model_output_retry",
                model=model.alias,
                attempt=repair_attempt,
                max_attempts=max_repairs,
                error=final_error,
            )
            repair_prompt = (
                "Your previous final answer was invalid. Correct this error: "
                f"{final_error}. Return only a corrected JSON object. Do not call "
                "tools.\nSchema:\n"
                + json.dumps(schema, separators=(",", ":"))
                + "\nInvalid final answer:\n"
                + invalid_final_content
            )
            repair_messages = [
                {
                    "role": "system",
                    "content": (
                        "Repair a JSON object to match the supplied schema. "
                        "Preserve its security claims and evidence. Return JSON only."
                    ),
                },
                {"role": "user", "content": repair_prompt},
            ]
            repaired = await _complete_with_retry(
                provider,
                model=model,
                messages=repair_messages,
                tools=[],
                response_schema=(
                    schema if model.capabilities.structured_output else None
                ),
                on_retry=lambda attempt, delay, error: self._progress(
                    "rate_limited",
                    model=model.alias,
                    attempt=attempt,
                    delay_seconds=delay,
                    error=error,
                ),
                before_request=lambda: self._pace_request(model),
                on_activity=lambda event, details: self._progress(
                    event, model=model.alias, **details
                ),
            )
            total_usage.add(repaired.usage)
            payload = _parse_final_json(repaired.content)
            if payload is not None:
                _prune_schema_extras(payload, schema)
                _add_safe_schema_defaults(payload, schema)
            errors = (
                list(Draft202012Validator(schema).iter_errors(payload))
                if payload is not None
                else []
            )
            if payload is not None and not errors:
                payload["_provenance"] = {
                    "provider": model.provider,
                    "model": model.model,
                    "tool_calls": tool_evidence,
                }
                self._progress(
                    "model_result_received",
                    model=model.alias,
                    repaired=True,
                    repair_attempt=repair_attempt,
                )
                return payload, total_usage
            final_error = (
                f"model result failed schema: {errors[0].message}"
                if errors
                else "model did not return a JSON final result"
            )
        if final_error.startswith("model result failed schema:"):
            message = final_error.replace(
                "model result failed schema:",
                f"model result failed schema after {max_repairs} repair attempts:",
                1,
            )
        else:
            message = f"{final_error} after {max_repairs} repair attempts"
        raise ModelOutputError(message, total_usage)

    def _apply_reviews(
        self, candidates: list[Candidate], reviews: list[Review]
    ) -> None:
        for candidate in candidates:
            matching = [
                row for row in reviews if row.candidate_id == candidate.candidate_id
            ]
            candidate.reviews = [row.review_id for row in matching]
            verdicts = {row.verdict for row in matching}
            if not verdicts:
                candidate.verdict = Verdict.UNRESOLVED
                candidate.disposition = FindingDisposition.UNRESOLVED
            elif verdicts == {Verdict.REJECTED}:
                candidate.verdict = Verdict.REJECTED
                candidate.disposition = FindingDisposition.SUPPRESSED
            elif verdicts == {Verdict.CONFIRMED}:
                candidate.verdict = Verdict.CONFIRMED
                candidate.disposition = FindingDisposition.REPORTABLE
            elif Verdict.CONFIRMED in verdicts and Verdict.REJECTED not in verdicts:
                candidate.verdict = Verdict.CONFIRMED
                candidate.disposition = FindingDisposition.REPORTABLE
            elif Verdict.CONDITIONAL in verdicts and Verdict.REJECTED not in verdicts:
                candidate.verdict = Verdict.CONDITIONAL
                candidate.disposition = FindingDisposition.DEFERRED
            else:
                candidate.verdict = Verdict.UNRESOLVED
                candidate.disposition = FindingDisposition.UNRESOLVED

    async def _checkpoint(
        self,
        store: ArtifactStore,
        state: dict[str, Any],
        assignment: Assignment,
        budget: "BudgetTracker",
        *,
        success: bool,
    ) -> None:
        async with self._state_lock:
            target = (
                state.setdefault("completed_assignments", [])
                if success
                else state.setdefault("failed_assignments", [])
            )
            if assignment.assignment_id not in target:
                target.append(assignment.assignment_id)
            opposite = state.setdefault(
                "failed_assignments" if success else "completed_assignments", []
            )
            if assignment.assignment_id in opposite:
                opposite.remove(assignment.assignment_id)
            state["usage"] = asdict(budget.usage)
            store.write_state(state)


class BudgetTracker:
    def __init__(self, request: ScanRequest, state: dict[str, Any]) -> None:
        self.limits = request.limits
        self.started = time.monotonic()
        self._lock = asyncio.Lock()
        self._reserved_tokens = 0
        self._reserved_cost = 0.0
        prior = state.get("usage") or {}
        self.usage = Usage(
            input_tokens=int(prior.get("input_tokens", 0)),
            output_tokens=int(prior.get("output_tokens", 0)),
            cached_input_tokens=int(prior.get("cached_input_tokens", 0)),
            cache_write_tokens=int(prior.get("cache_write_tokens", 0)),
            requests=int(prior.get("requests", 0)),
            rate_limit_retries=int(prior.get("rate_limit_retries", 0)),
            cost_usd=prior.get("cost_usd"),
            cost_source=str(prior.get("cost_source", "unknown")),
            duration_seconds=float(prior.get("duration_seconds", 0)),
        )

    async def reserve(
        self, model: ModelSpec, *, estimated_input_tokens: int
    ) -> tuple[int, float]:
        async with self._lock:
            elapsed = time.monotonic() - self.started
            if (
                self.limits.max_duration_seconds is not None
                and elapsed >= self.limits.max_duration_seconds
            ):
                raise BudgetExceeded("maximum scan duration reached")
            reserve_tokens = estimated_input_tokens + model.max_output_tokens
            if (
                self.limits.max_tokens is not None
                and self.usage.total_tokens
                + self._reserved_tokens
                + reserve_tokens
                > self.limits.max_tokens
            ):
                raise BudgetExceeded(
                    "next assignment would exceed the configured token limit"
                )
            reserve_cost = (
                estimate_model_cost(
                    model, estimated_input_tokens, model.max_output_tokens
                )
                or 0.0
            )
            if self.limits.max_cost_usd is not None:
                if (
                    (self.usage.cost_usd or 0.0)
                    + self._reserved_cost
                    + reserve_cost
                    > self.limits.max_cost_usd
                ):
                    raise BudgetExceeded(
                        "next assignment would exceed the configured USD limit"
                    )
            self._reserved_tokens += reserve_tokens
            self._reserved_cost += reserve_cost
            return reserve_tokens, reserve_cost

    def remaining_duration(self) -> float | None:
        if self.limits.max_duration_seconds is None:
            return None
        return max(
            0.001,
            self.limits.max_duration_seconds - (time.monotonic() - self.started),
        )

    async def record(
        self, usage: Usage, reservation: tuple[int, float]
    ) -> None:
        async with self._lock:
            self._reserved_tokens -= reservation[0]
            self._reserved_cost -= reservation[1]
            self.usage.add(usage)

    async def release(self, reservation: tuple[int, float]) -> None:
        async with self._lock:
            self._reserved_tokens = max(0, self._reserved_tokens - reservation[0])
            self._reserved_cost = max(0.0, self._reserved_cost - reservation[1])


def _partition_limits(
    level: ScanLevel, usable_context: int
) -> tuple[int, int]:
    """Size tool-driven Quick shards without changing deeper-tier rigor."""

    if level == ScanLevel.QUICK:
        return (
            min(750_000, max(100_000, usable_context * 3)),
            min(40, max(15, usable_context // 6_000)),
        )
    return (min(200_000, max(16_000, usable_context * 3)), 15)


def estimate_scan(
    inventory: RepositoryInventory,
    models: list[ModelSpec],
    *,
    level: ScanLevel,
    specialist_models: list[ModelSpec] | None = None,
    max_workers: int = 4,
) -> dict[str, Any]:
    specialist_models = specialist_models or []
    source_tokens = max(1_000, inventory.total_bytes // 4)
    structural_factor = min(
        1.75,
        1.0
        + min(inventory.line_count, 500_000) / 2_000_000
        + min(inventory.symbol_count, 25_000) / 100_000,
    )
    all_models = [*models, *specialist_models]
    usable_context = min(
        (
            model.context_tokens - model.max_output_tokens - 4_096
            for model in all_models
        ),
        default=128_000,
    )
    target_bytes, max_files = _partition_limits(level, usable_context)
    partitions = partition_inventory(
        inventory,
        target_bytes=target_bytes,
        max_files=max_files,
    )
    partition_count = max(1, len(partitions))
    threat_assignments = 2 if level in {ScanLevel.DEEP, ScanLevel.EXHAUSTIVE} else 1
    base_assignments = (
        threat_assignments
        + partition_count * (len(models) + len(specialist_models))
    )
    sweep_assignments = {
        ScanLevel.QUICK: 0,
        ScanLevel.STANDARD: 1,
        ScanLevel.DEEP: 1,
        ScanLevel.EXHAUSTIVE: 2,
    }[level]
    base_assignments += sweep_assignments
    deterministic_seed_assignments = min(50, len(scan_native_seeds(inventory)))
    base_assignments += deterministic_seed_assignments
    possible_gap_assignments = (
        partition_count * len(models)
        if level in {ScanLevel.DEEP, ScanLevel.EXHAUSTIVE}
        else 0
    )
    # Findings drive review/resolution work and cannot be known before discovery.
    possible_candidates = max(
        1,
        min(
            40,
            round(
                (
                    (len(inventory.files) + 49) // 50
                    + len(inventory.surfaces) / 2
                    + inventory.symbol_count / 500
                )
                * structural_factor
            ),
        ),
    )
    reviews_per_candidate = {
        ScanLevel.QUICK: 1,
        ScanLevel.STANDARD: 1,
        ScanLevel.DEEP: 2,
        ScanLevel.EXHAUSTIVE: max(1, len(models) - 1),
    }[level]
    possible_reviews = possible_candidates * reviews_per_candidate
    possible_validations = possible_candidates
    possible_attack_paths = possible_candidates
    possible_clean_challenges = sum(
        surface.mandatory for surface in inventory.surfaces
    )
    possible_resolvers = (
        possible_candidates
        if level in {ScanLevel.DEEP, ScanLevel.EXHAUSTIVE}
        else 0
    )
    assignments_low = max(1, base_assignments)
    assignments_high = max(
        assignments_low,
        base_assignments
        + possible_gap_assignments
        + possible_clean_challenges
        + possible_reviews
        + possible_validations
        + possible_attack_paths
        + possible_resolvers,
    )
    turns_low, turns_high = {
        ScanLevel.QUICK: (3, 8),
        ScanLevel.STANDARD: (4, 12),
        ScanLevel.DEEP: (5, 16),
        ScanLevel.EXHAUSTIVE: (6, 22),
    }[level]
    requests_low = assignments_low * turns_low
    requests_high = assignments_high * turns_high
    partition_tokens = max(1_000, source_tokens // partition_count)
    base_prompt_tokens = max(1, (len(SYSTEM_PROMPT) + 3) // 4)
    average_input_low = max(
        2_500, int(partition_tokens * 0.30 * structural_factor) + 2_000
    )
    average_input_high = min(
        max(8_000, int(partition_tokens * 1.5 * structural_factor) + 10_000),
        max(8_000, int(usable_context * 0.80)),
    )
    input_tokens_low = requests_low * average_input_low
    input_tokens_high = requests_high * average_input_high
    reasoning_factors = {
        "none": 0.8,
        "minimal": 0.9,
        "low": 1.0,
        "auto": 1.0,
        "medium": 1.25,
        "high": 1.6,
        "xhigh": 2.0,
        "max": 2.5,
        "ultra": 3.0,
    }
    reasoning_factor = sum(
        reasoning_factors.get(model.reasoning_effort, 1.0) for model in all_models
    ) / max(len(all_models), 1)
    output_tokens_low = int(requests_low * 400 * reasoning_factor)
    output_tokens_high = int(requests_high * 2_500 * reasoning_factor)
    divisor = max(len(all_models), 1)
    costs_low = [
        estimate_model_cost(
            model,
            input_tokens_low // divisor,
            output_tokens_low // divisor,
            cached_input_tokens=(
                int(input_tokens_low * 0.60) // divisor
                if model.cache_read_cost_per_million is not None
                else 0
            ),
        )
        for model in all_models
    ]
    costs_high = [
        estimate_model_cost(
            model,
            input_tokens_high // divisor,
            output_tokens_high // divisor,
            cached_input_tokens=(
                int(input_tokens_high * 0.20) // divisor
                if model.cache_read_cost_per_million is not None
                else 0
            ),
        )
        for model in all_models
    ]
    cost_known = all(cost is not None for cost in [*costs_low, *costs_high])
    cost_low = sum(cost or 0.0 for cost in costs_low) if cost_known else None
    cost_high = sum(cost or 0.0 for cost in costs_high) if cost_known else None
    effective_workers = (
        1
        if len(models) > 1 and all(model.is_free for model in models)
        else max(1, max_workers)
    )
    minutes_low = max(2, int(requests_low * 12 / effective_workers / 60))
    minutes_high = max(
        minutes_low + 5,
        int(requests_high * 120 * reasoning_factor / effective_workers / 60),
    )
    hourly_hardware_cost = sum(
        model.hourly_hardware_cost or 0.0
        for model in [*models, *specialist_models]
        if not model.remote
    )
    return {
        "input_tokens": (input_tokens_low + input_tokens_high) // 2,
        "output_tokens": (output_tokens_low + output_tokens_high) // 2,
        "input_tokens_low": input_tokens_low,
        "input_tokens_high": input_tokens_high,
        "output_tokens_low": output_tokens_low,
        "output_tokens_high": output_tokens_high,
        "cost_usd": (
            (cost_low + cost_high) / 2
            if cost_low is not None and cost_high is not None
            else None
        ),
        "cost_low_usd": cost_low,
        "cost_high_usd": cost_high,
        "minutes_low": minutes_low,
        "minutes_high": minutes_high,
        "partitions": partition_count,
        "assignments_low": assignments_low,
        "assignments_high": assignments_high,
        "requests_low": requests_low,
        "requests_high": requests_high,
        "effective_workers": effective_workers,
        "repository_lines": inventory.line_count,
        "repository_symbols": inventory.symbol_count,
        "base_system_prompt_tokens": base_prompt_tokens,
        "structural_factor": round(structural_factor, 3),
        "basis": (
            "threat modeling + boundary shards + deterministic seed reviews + "
            "clean challengers + validation/attack paths + possible peer reviews; "
            f"{inventory.line_count:,} lines + ~{inventory.symbol_count:,} callable "
            f"symbols; reasoning factor {reasoning_factor:.2f}x"
        ),
        "confidence": "low until live provider usage is observed",
        "hardware_cost_low_usd": hourly_hardware_cost * minutes_low / 60,
        "hardware_cost_high_usd": hourly_hardware_cost * minutes_high / 60,
    }


def estimate_model_cost(
    model: ModelSpec,
    input_tokens: int,
    output_tokens: int,
    *,
    cached_input_tokens: int = 0,
    cache_write_tokens: int = 0,
) -> float | None:
    if not model.remote:
        return 0.0
    if (
        model.input_cost_per_million is None
        or model.output_cost_per_million is None
    ):
        return None
    cached = min(max(0, cached_input_tokens), max(0, input_tokens))
    written = min(
        max(0, cache_write_tokens), max(0, input_tokens - cached)
    )
    if model.cache_read_cost_per_million is None:
        cached = 0
    if model.cache_write_cost_per_million is None:
        written = 0
    regular = max(0, input_tokens - cached - written)
    return (
        regular * model.input_cost_per_million
        + cached
        * (
            model.cache_read_cost_per_million
            if model.cache_read_cost_per_million is not None
            else model.input_cost_per_million
        )
        + written
        * (
            model.cache_write_cost_per_million
            if model.cache_write_cost_per_million is not None
            else model.input_cost_per_million
        )
        + output_tokens * model.output_cost_per_million
    ) / 1_000_000


def _prompt_metrics(system_prompt: str, user_prompt: str) -> dict[str, int]:
    """Return transparent tokenizer-independent prompt-size estimates."""

    system_chars = len(system_prompt)
    user_chars = len(user_prompt)
    return {
        "system_prompt_chars": system_chars,
        "system_prompt_tokens_estimate": max(1, (system_chars + 3) // 4),
        "task_prompt_chars": user_chars,
        "task_prompt_tokens_estimate": max(1, (user_chars + 3) // 4),
        "initial_prompt_tokens_estimate": max(
            1, (system_chars + user_chars + 3) // 4
        ),
    }


def merge_candidates(
    candidates: list[Candidate], *, semantic: bool = True
) -> list[Candidate]:
    merged: list[Candidate] = []
    by_key: dict[str, Candidate] = {}
    for candidate in candidates:
        key = candidate_merge_key(candidate)
        existing = by_key.get(key)
        if existing is None and semantic:
            existing = next(
                (
                    row
                    for row in merged
                    if _same_candidate_mechanism(row, candidate)
                ),
                None,
            )
        if existing is None:
            by_key[key] = candidate
            merged.append(candidate)
            continue
        by_key[key] = existing
        existing.discovered_by.extend(
            row for row in candidate.discovered_by if row not in existing.discovered_by
        )
        existing.duplicate_candidate_ids.append(candidate.candidate_id)
        existing.trace.extend(row for row in candidate.trace if row not in existing.trace)
        existing.reachable_path.extend(
            row for row in candidate.reachable_path if row not in existing.reachable_path
        )
        existing.affected_instances.extend(
            row
            for row in candidate.affected_instances
            if row not in existing.affected_instances
        )
        existing.proof_gaps.extend(
            row for row in candidate.proof_gaps if row not in existing.proof_gaps
        )
        existing.contradicting_evidence.extend(
            row
            for row in candidate.contradicting_evidence
            if row not in existing.contradicting_evidence
        )
        if _severity_rank(candidate.severity) > _severity_rank(existing.severity):
            existing.severity = candidate.severity
        if not existing.poc and candidate.poc:
            existing.poc = candidate.poc
        if not existing.exploit_test and candidate.exploit_test:
            existing.exploit_test = candidate.exploit_test
        if not existing.closest_control and candidate.closest_control:
            existing.closest_control = candidate.closest_control
    for index, candidate in enumerate(merged, 1):
        candidate.candidate_id = f"CAND-{index:05d}"
    return merged


def candidate_merge_key(candidate: Candidate) -> str:
    sink = _location(candidate.sink)
    root = re.sub(r"\W+", " ", candidate.root_cause.lower()).strip()
    resource = candidate.affected_resource.lower().strip()
    boundary = candidate.security_boundary.lower().strip()
    return hashlib.sha256(
        "\0".join([sink, root, resource, boundary]).encode("utf-8")
    ).hexdigest()


def _same_candidate_mechanism(left: Candidate, right: Candidate) -> bool:
    """Consolidate paraphrases while preserving separate concrete instances."""

    family = _candidate_family(left)
    if family != _candidate_family(right):
        return False
    left_source = _location_parts(left.source)
    right_source = _location_parts(right.source)
    left_sink = _location_parts(left.sink)
    right_sink = _location_parts(right.sink)
    source_distance = _line_distance(left_source, right_source)
    sink_distance = _line_distance(left_sink, right_sink)
    if source_distance == 0 or sink_distance == 0:
        return True
    if family == "log-exposure":
        return sink_distance is not None and sink_distance <= 32
    if family in {"resource-exhaustion", "mobile-component"}:
        return source_distance is not None and source_distance <= 8
    return bool(
        source_distance is not None
        and source_distance <= 12
        and sink_distance is not None
        and sink_distance <= 64
    )


def _candidate_family(candidate: Candidate) -> str:
    text = " ".join(
        [
            candidate.cwe,
            candidate.classification,
            candidate.title,
            candidate.root_cause,
        ]
    ).lower()
    if (
        ("cache" in text or "idempot" in text)
        and any(word in text for word in ("tenant", "principal", "user", "account"))
    ):
        return "principal-isolation-cache"
    if (
        "log" in text
        and any(word in text for word in ("disclos", "expos", "authorization"))
        and any(word in text for word in ("global", "shared", "tenant", "user"))
    ):
        return "log-exposure"
    if any(word in text for word in ("upload", "multipart", "body")) and any(
        word in text
        for word in ("resource", "memory", "unbounded", "exhaust", "limit")
    ):
        return "resource-exhaustion"
    if any(
        phrase in text
        for phrase in (
            "resource exhaustion",
            "resource consumption",
            "memory exhaustion",
            "disk exhaustion",
            "memory amplification",
            "disk amplification",
        )
    ):
        return "resource-exhaustion"
    if any(word in text for word in ("receiver", "exported component", "intent")):
        return "mobile-component"
    if any(word in text for word in ("command injection", "shell injection")):
        return "command-injection"
    if any(
        word in text
        for word in (
            "idor",
            "bola",
            "cross-tenant",
            "authorization",
            "ownership",
            "service-role",
        )
    ):
        return "authorization"
    cwe = _cwe(candidate.cwe)
    return cwe or re.sub(
        r"\W+", "-", candidate.classification.lower()
    ).strip("-")


def _location_parts(value: dict[str, Any]) -> tuple[str, int | None]:
    path = str(value.get("file") or value.get("path") or "").replace("\\", "/")
    line_value = value.get("line")
    match = re.search(r"\d+", str(line_value)) if line_value is not None else None
    return path.casefold(), int(match.group(0)) if match else None


def _line_distance(
    left: tuple[str, int | None], right: tuple[str, int | None]
) -> int | None:
    if not left[0] or left[0] != right[0]:
        return None
    if left[1] is None or right[1] is None:
        return 0
    return abs(left[1] - right[1])


def candidate_review_packet(candidate: Candidate) -> dict[str, Any]:
    return {
        "candidate_id": candidate.candidate_id,
        "classification": candidate.classification,
        "severity": candidate.severity,
        "cwe": candidate.cwe,
        "source": candidate.source,
        "sink": candidate.sink,
        "closest_control": candidate.closest_control,
        "trace": candidate.trace,
        "reachable_path": candidate.reachable_path,
        "root_cause": candidate.root_cause,
        "attacker_prerequisites": candidate.attacker_prerequisites,
        "claimed_new_capability": candidate.new_capability,
        "contradicting_evidence": candidate.contradicting_evidence,
        "proof_gaps": candidate.proof_gaps,
        "affected_instances": candidate.affected_instances,
        "affected_resource": candidate.affected_resource,
        "security_boundary": candidate.security_boundary,
    }


def repository_metadata(
    root: Path, inventory: RepositoryInventory
) -> dict[str, Any]:
    def git(*args: str) -> str:
        try:
            result = subprocess.run(
                ["git", "-C", str(root), *args],
                capture_output=True,
                text=True,
                timeout=10,
                shell=False,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return ""
        return result.stdout.strip() if result.returncode == 0 else ""

    return {
        "path": str(root),
        "name": root.name,
        "url": git("remote", "get-url", "origin"),
        "commit": git("rev-parse", "HEAD"),
        "branch": git("branch", "--show-current"),
        "dirty": bool(git("status", "--porcelain")),
        "snapshot_digest": inventory.snapshot_digest,
        "files": len(inventory.files),
        "production_files": len(inventory.production_files),
        "dormant_files": len(inventory.dormant_files),
        "support_files": len(inventory.support_files),
        "bytes": inventory.total_bytes,
        "lines": inventory.line_count,
        "symbols": inventory.symbol_count,
        "languages": inventory.languages,
    }


def _engine_fingerprint() -> str:
    """Hash workflow and prompt sources used to decide resume compatibility."""

    digest = hashlib.sha256()
    package = Path(__file__).resolve().parent
    for name in ("engine.py", "prompts.py", "methodology.py", "inventory.py"):
        path = package / name
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def model_public_dict(model: ModelSpec) -> dict[str, Any]:
    return {
        "alias": model.alias,
        "provider": model.provider,
        "model": model.model,
        "remote": model.remote,
        "tool_mode": model.tool_mode,
        "reasoning_effort": model.reasoning_effort,
        "context_tokens": model.context_tokens,
    }


def _review_from_payload(
    assignment: Assignment,
    payload: dict[str, Any],
    model: ModelSpec,
    usage: Usage | None = None,
) -> Review:
    return Review(
        review_id=assignment.assignment_id,
        candidate_id=assignment.candidate_id,
        reviewer={
            "alias": assignment.model_alias,
            "provider": model.provider,
            "model": model.model,
            "kind": str(assignment.kind),
        },
        verdict=str(payload.get("verdict", Verdict.UNRESOLVED)),
        source_reachable=payload.get("source_reachable"),
        attacker_controlled=payload.get("attacker_controlled"),
        trace_complete=payload.get("trace_complete"),
        blocking_control_found=payload.get("blocking_control_found"),
        new_capability_proven=payload.get("new_capability_proven"),
        rationale=str(payload.get("rationale", "")),
        incorrect_claims=_list_of_strings(payload.get("incorrect_claims")),
        missing_evidence=_list_of_strings(payload.get("missing_evidence")),
        usage=usage or assignment.usage,
    )


def _decode_json_tool_response(response: ModelResponse) -> ModelResponse:
    payload = _parse_final_json(response.content)
    if payload is None:
        return response
    raw_calls = payload.get("tool_calls")
    if isinstance(raw_calls, list):
        from .models import ToolCall

        response.tool_calls = [
            ToolCall(
                id=str(row.get("id") or uuid.uuid4()),
                name=str(row.get("name", "")),
                arguments=_dict(row.get("arguments")),
            )
            for row in raw_calls
            if isinstance(row, dict)
        ]
        response.content = ""
    elif "final" in payload:
        response.content = json.dumps(payload["final"])
    return response


async def _complete_with_retry(
    provider: ModelProvider,
    *,
    model: ModelSpec,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    response_schema: dict[str, Any] | None,
    on_retry: Callable[[int, float, str], None] | None = None,
    before_request: Callable[[], Awaitable[None]] | None = None,
    on_activity: Callable[[str, dict[str, Any]], None] | None = None,
) -> ModelResponse:
    last_error: ProviderError | None = None
    rate_limit_retries = 0
    for attempt in range(3):
        try:
            if before_request is not None:
                await before_request()
            if on_activity is not None:
                on_activity("model_request_started", {"attempt": attempt + 1})
            response = await _await_provider_response(
                provider.complete(
                    model=model,
                    messages=messages,
                    tools=tools,
                    response_schema=response_schema,
                ),
                on_wait=(
                    lambda elapsed: on_activity(
                        "model_waiting",
                        {"attempt": attempt + 1, "elapsed_seconds": elapsed},
                    )
                    if on_activity is not None
                    else None
                ),
            )
            response.usage.rate_limit_retries += rate_limit_retries
            if on_activity is not None:
                on_activity(
                    "model_request_complete",
                    {
                        "attempt": attempt + 1,
                        "duration_seconds": response.usage.duration_seconds,
                        "tool_calls": len(response.tool_calls),
                        "input_tokens": response.usage.input_tokens,
                        "output_tokens": response.usage.output_tokens,
                        "cached_input_tokens": response.usage.cached_input_tokens,
                        "cost_usd": response.usage.cost_usd,
                        "cost_source": response.usage.cost_source,
                    },
                )
            return response
        except ProviderError as exc:
            last_error = exc
            if not _provider_error_retryable(exc):
                break
            if attempt < 2:
                base_delay = max(float(2**attempt), exc.retry_after or 0.0)
                jitter = random.uniform(0.0, min(1.0, base_delay * 0.25))
                delay = min(60.0, base_delay + jitter)
                if exc.status_code == 429:
                    rate_limit_retries += 1
                    if on_retry is not None:
                        on_retry(attempt + 1, delay, str(exc))
                await asyncio.sleep(delay)
    assert last_error is not None
    raise last_error


def _provider_error_retryable(error: ProviderError) -> bool:
    """Retry transient transport/capacity failures, never hard account errors."""

    message = str(error).casefold()
    hard_failure_markers = (
        "usage limit",
        "quota exceeded",
        "insufficient_quota",
        "billing",
        "purchase more credits",
        "invalid api key",
        "authentication",
        "unauthorized",
        "invalid_request_error",
        "invalid schema",
        "model not found",
    )
    if any(marker in message for marker in hard_failure_markers):
        return False
    if error.status_code is not None:
        return (
            error.status_code in {408, 409, 425, 429}
            or error.status_code >= 500
        )
    return any(
        marker in message
        for marker in (
            "timeout",
            "timed out",
            "temporarily unavailable",
            "connection",
            "disconnected",
            "transport",
            "no such host",
            "name resolution",
            "dns",
            "network",
            "socket",
            "reconnecting",
            "rate limit",
            "too many requests",
        )
    )


async def _await_provider_response(
    response: Awaitable[ModelResponse],
    *,
    on_wait: Callable[[float], None] | None,
    heartbeat_seconds: float = 15.0,
) -> ModelResponse:
    task = asyncio.ensure_future(response)
    started = time.monotonic()
    try:
        while True:
            done, _pending = await asyncio.wait(
                {task}, timeout=heartbeat_seconds
            )
            if task in done:
                return task.result()
            if on_wait is not None:
                on_wait(time.monotonic() - started)
    finally:
        if not task.done():
            task.cancel()


def _parse_final_json(content: str) -> dict[str, Any] | None:
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None
    return payload if isinstance(payload, dict) else None


def _prune_schema_extras(value: Any, schema: dict[str, Any]) -> None:
    """Remove fields a strict schema would force a repair model to remove."""

    schema_types = schema.get("type")
    is_object = schema_types == "object" or (
        isinstance(schema_types, list) and "object" in schema_types
    )
    if isinstance(value, dict) and is_object:
        properties = schema.get("properties")
        if not isinstance(properties, dict):
            return
        if schema.get("additionalProperties") is False:
            for key in list(value):
                if key not in properties:
                    del value[key]
        for key, child in list(value.items()):
            child_schema = properties.get(key)
            if isinstance(child_schema, dict):
                _prune_schema_extras(child, child_schema)
        return
    is_array = schema_types == "array" or (
        isinstance(schema_types, list) and "array" in schema_types
    )
    item_schema = schema.get("items")
    if isinstance(value, list) and is_array and isinstance(item_schema, dict):
        for child in value:
            _prune_schema_extras(child, item_schema)


def _add_safe_schema_defaults(value: Any, schema: dict[str, Any]) -> None:
    """Fill presentation-only omissions without inventing security conclusions."""

    schema_types = schema.get("type")
    is_object = schema_types == "object" or (
        isinstance(schema_types, list) and "object" in schema_types
    )
    if isinstance(value, dict) and is_object:
        properties = schema.get("properties")
        if not isinstance(properties, dict):
            return
        if (
            {"files_reviewed", "unresolved_files", "notes"} <= set(properties)
            and "notes" not in value
        ):
            value["notes"] = ""
        for key, child in value.items():
            child_schema = properties.get(key)
            if isinstance(child_schema, dict):
                _add_safe_schema_defaults(child, child_schema)
        return
    is_array = schema_types == "array" or (
        isinstance(schema_types, list) and "array" in schema_types
    )
    item_schema = schema.get("items")
    if isinstance(value, list) and is_array and isinstance(item_schema, dict):
        for child in value:
            _add_safe_schema_defaults(child, item_schema)


def _coverage_path_key(path: str) -> str:
    """Match harmless model path variants without inventing repository paths."""

    normalized = path.replace("\\", "/").removeprefix("./")
    return "/".join(part.removeprefix(".").casefold() for part in normalized.split("/"))


def _location(value: dict[str, Any]) -> str:
    path = str(value.get("file") or value.get("path") or "")
    line = value.get("line")
    return f"{path}:{line}" if path and line else path


def _severity(value: str) -> str:
    normalized = value.title()
    return normalized if normalized in {"Critical", "High", "Medium", "Low"} else "Medium"


def _severity_rank(value: str) -> int:
    return {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}.get(value, 0)


def _cwe(value: str) -> str:
    match = re.search(r"CWE-\d+", value.upper())
    return match.group(0) if match else ""


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list_of_dicts(value: Any) -> list[dict[str, Any]]:
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def _normalized_tool_evidence(
    calls: list[dict[str, Any]],
    expected_paths: list[str] | None = None,
) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    expected_paths = expected_paths or []
    for call in calls:
        name = str(call.get("name", ""))
        if name not in {
            "read_file",
            "search_text",
            "find_symbol",
            "write_artifact",
            "run_command",
        }:
            continue
        arguments = _dict(call.get("arguments"))
        record = {
            "tool": str(call.get("name", "")),
            "path": str(arguments.get("path", "")),
            "arguments": arguments,
            "result_sha256": str(call.get("result_sha256", "")),
            "artifact": str(call.get("artifact", "")),
        }
        evidence.append(record)
        if name != "run_command" or not _successful_command_event(call):
            continue
        command_value = arguments.get("command") or arguments.get("argv")
        command = (
            command_value
            if isinstance(command_value, str)
            else " ".join(str(part) for part in command_value)
            if isinstance(command_value, list)
            else ""
        )
        if not re.search(
            r"(?i)\b(?:get-content|cat|type|sed)\b", command
        ):
            continue
        normalized_command = command.replace("\\", "/").casefold()
        for path in expected_paths:
            normalized_path = path.replace("\\", "/").casefold()
            if normalized_path not in normalized_command:
                continue
            evidence.append(
                {
                    "tool": "run_command_path",
                    "path": path,
                    "arguments": arguments,
                    "result_sha256": str(call.get("result_sha256", "")),
                    "artifact": str(call.get("artifact", "")),
                    "source_tool": "run_command",
                }
            )
    return evidence


def _successful_command_event(call: dict[str, Any]) -> bool:
    status = str(call.get("status", "completed")).casefold()
    if status in {"failed", "error", "cancelled", "canceled"}:
        return False
    exit_code = call.get("exit_code")
    return exit_code in {None, 0, "0"}


def _candidate_is_dormant(
    candidate: Candidate, inventory: RepositoryInventory
) -> bool:
    dormant = set(inventory.dormant_files)
    paths = {
        str(point.get("file") or point.get("path") or "")
        for point in [
            candidate.source,
            candidate.sink,
            *candidate.trace,
            *candidate.affected_instances,
        ]
        if point.get("file") or point.get("path")
    }
    return bool(paths) and paths <= dormant


def _candidate_unknown_paths(
    candidate: Candidate, inventory: RepositoryInventory
) -> set[str]:
    known = set(
        inventory.production_files
        + inventory.dormant_files
        + inventory.support_files
    )
    return {
        str(point.get("file") or point.get("path") or "")
        for point in [
            candidate.source,
            candidate.sink,
            *candidate.trace,
            *candidate.affected_instances,
        ]
        if (point.get("file") or point.get("path"))
        and str(point.get("file") or point.get("path")) not in known
    }


def _load_static_seeds(path: Path) -> list[StaticSeed]:
    seeds: list[StaticSeed] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        seeds.append(
            StaticSeed(
                **{
                    key: value
                    for key, value in payload.items()
                    if key in StaticSeed.__dataclass_fields__
                }
            )
        )
    return seeds


def _restore_assignment(
    assignment: Assignment, document: dict[str, Any]
) -> None:
    stored = _dict(document.get("assignment"))
    assignment.status = "COMPLETED"
    assignment.prompt_hash = str(stored.get("prompt_hash", ""))
    assignment.error = str(stored.get("error", ""))
    assignment.evidence = _list_of_dicts(stored.get("evidence"))
    assignment.coverage_quality = str(
        stored.get("coverage_quality", "self_reported")
    )
    usage = _dict(stored.get("usage"))
    assignment.usage = Usage(
        input_tokens=int(usage.get("input_tokens", 0)),
        output_tokens=int(usage.get("output_tokens", 0)),
        cached_input_tokens=int(usage.get("cached_input_tokens", 0)),
        cache_write_tokens=int(usage.get("cache_write_tokens", 0)),
        requests=int(usage.get("requests", 0)),
        rate_limit_retries=int(usage.get("rate_limit_retries", 0)),
        cost_usd=usage.get("cost_usd"),
        cost_source=str(usage.get("cost_source", "unknown")),
        duration_seconds=float(usage.get("duration_seconds", 0.0)),
    )


def _list_of_strings(value: Any) -> list[str]:
    return [str(row) for row in value] if isinstance(value, list) else []


def _optional_float(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None
