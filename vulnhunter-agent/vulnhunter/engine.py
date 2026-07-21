"""Deterministic multi-model scanner orchestration."""

from __future__ import annotations

import asyncio
import hashlib
import json
import random
import re
import subprocess
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
from .models import (
    Assignment,
    AssignmentKind,
    Candidate,
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
    CANDIDATE_SCHEMA,
    REVIEW_SCHEMA,
    SYSTEM_PROMPT,
    hunt_prompt,
    json_tool_instruction,
    review_prompt,
)
from .providers import ModelProvider, ProviderError, create_provider
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
        self._progress_callback = progress

    def _progress(self, event: str, **details: Any) -> None:
        if self._progress_callback is None:
            return
        try:
            self._progress_callback(event, details)
        except Exception:  # noqa: BLE001
            # Presentation must never interrupt or invalidate a scan.
            return

    async def scan(self, request: ScanRequest) -> tuple[dict[str, Any], Path]:
        root = Path(request.repository).expanduser().resolve()
        for provider in self.providers.values():
            set_root = getattr(provider, "set_repository_root", None)
            if callable(set_root):
                set_root(root)
        inventory = build_inventory(root)
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
        partitions = partition_inventory(
            inventory,
            target_bytes=min(200_000, max(16_000, usable_context * 3)),
        )
        self._progress(
            "inventory_complete",
            files=len(inventory.files),
            bytes=inventory.total_bytes,
            partitions=len(partitions),
        )

        results_dir = self._resolve_results_dir(root, request)
        self._progress("results_directory_ready", results_dir=str(results_dir))
        store = ArtifactStore(results_dir)
        run_id = results_dir.name
        state = store.read_state() if request.resume else None
        if state is None:
            state = self._new_state(run_id, request, inventory, model_specs)
            store.write_state(state)
        elif state.get("run_id") != run_id:
            raise ValueError("resume directory contains a different run_id")

        budget = BudgetTracker(request, state)
        assignments: list[Assignment] = []
        candidates: list[Candidate] = []
        reviews: list[Review] = []
        coverage_reviewed: set[str] = set(state.get("coverage_reviewed", []))
        coverage_unresolved: set[str] = set(state.get("coverage_unresolved", []))
        evidence_gaps: list[str] = []
        incomplete_reason = ""

        try:
            hunts = self._hunt_assignments(model_specs, partitions)
            self._progress("phase_started", phase="Independent vulnerability hunts")
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
                self._progress("phase_started", phase="Specialist analysis")
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

            if request.level in {ScanLevel.DEEP, ScanLevel.EXHAUSTIVE}:
                gap_assignments = self._gap_assignments(
                    hunt_payloads, model_specs
                )
                if gap_assignments:
                    self._progress("phase_started", phase="Coverage gap analysis")
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
                self._progress("phase_started", phase="Root-cause security sweep")
                sweeps = self._sweep_assignments(
                    model_specs,
                    inventory,
                    count=2 if request.level == ScanLevel.EXHAUSTIVE else 1,
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

            candidates = merge_candidates(candidates)
            self._progress("candidates_merged", candidates=len(candidates))
            for candidate in candidates:
                store.write_candidate(candidate)

            review_assignments = self._review_assignments(
                request.level, model_specs, candidates
            )
            if review_assignments:
                self._progress("phase_started", phase="Cross-model review")
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
                    self._progress("phase_started", phase="Disagreement resolution")
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
            if request.level == ScanLevel.EXHAUSTIVE:
                evidence_gaps = [
                    candidate.candidate_id
                    for candidate in candidates
                    if str(candidate.verdict) == Verdict.CONFIRMED
                    and (not candidate.poc.strip() or not candidate.exploit_test.strip())
                ]
        except BudgetExceeded as exc:
            incomplete_reason = str(exc)
            status = RunStatus.INCOMPLETE_LIMIT
        except Exception as exc:  # noqa: BLE001
            status = RunStatus.FAILED
            incomplete_reason = f"{type(exc).__name__}: {exc}"
        else:
            failed = [assignment for assignment in assignments if assignment.status == "FAILED"]
            if failed or coverage_unresolved or evidence_gaps:
                status = RunStatus.INCOMPLETE_COVERAGE
                reasons = [
                    f"{len(failed)} assignment(s) failed",
                    f"{len(coverage_unresolved)} file(s) unresolved",
                ]
                if evidence_gaps:
                    reasons.append(
                        "missing exhaustive PoC/exploit-test evidence for "
                        + ", ".join(evidence_gaps)
                    )
                incomplete_reason = "; ".join(reasons)
            elif any(str(candidate.verdict) == Verdict.CONFIRMED for candidate in candidates):
                status = RunStatus.COMPLETE_FINDINGS
            elif any(
                str(candidate.verdict)
                in {Verdict.CONDITIONAL, Verdict.UNRESOLVED}
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
        repository = repository_metadata(root, inventory)
        coverage_matrix = []
        for assignment in assignments:
            if assignment.kind not in {
                AssignmentKind.HUNT,
                AssignmentKind.SPECIALIST,
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
            incomplete_reason=incomplete_reason,
        )
        self._progress(
            "scan_complete",
            status=str(status),
            candidates=len(candidates),
            results_dir=str(results_dir),
        )
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
        if request.execute and not self.config.sandbox.available:
            raise ValueError(
                "--execute requires sandbox.command_prefix in the engine config"
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
            "schema_version": "1",
            "run_id": run_id,
            "status": RunStatus.RUNNING,
            "created_at": datetime.now(UTC).isoformat(),
            "repository": str(inventory.root),
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
                assignment.status = "COMPLETED"
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
                        return await self._hunt_worker(
                            assignment,
                            root=root,
                            inventory=inventory,
                            request=request,
                            sweep=(
                                sweep or assignment.kind == AssignmentKind.SWEEP
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

    async def _run_with_provider_limit(
        self,
        provider_name: str,
        factory: Callable[[], Awaitable[tuple[dict[str, Any], Usage]]],
    ) -> tuple[dict[str, Any], Usage]:
        """Serialize providers whose local session state is not concurrency-safe."""
        lock = self._serial_provider_locks.get(provider_name)
        if lock is None:
            return await factory()
        async with lock:
            return await factory()

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
        summary = (
            f"{len(inventory.files)} production files, "
            f"{inventory.total_bytes} bytes, languages={inventory.languages}"
        )
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
        return await self._tool_loop(
            model,
            root=root,
            allowed_files=set(inventory.files),
            user_prompt=prompt,
            schema=CANDIDATE_SCHEMA,
            execute=request.execute,
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
                first_origin = next(iter(origins), aliases[0])
                origin_index = aliases.index(first_origin) if first_origin in aliases else 0
                ring = aliases[(origin_index + 1) % len(aliases)]
                reviewers = [ring]
                needs_second = (
                    level == ScanLevel.DEEP
                    and (len(origins) == 1 or candidate.severity in {"High", "Critical"})
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
        by_id = {row.candidate_id: row for row in candidates}
        reviews: list[Review] = []
        for assignment in assignments:
            reservation: tuple[int, float] | None = None
            existing = store.read_assignment(assignment.assignment_id)
            if existing and existing.get("assignment", {}).get("status") == "COMPLETED":
                assignment.status = "COMPLETED"
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
                worker = self._tool_loop(
                    model,
                    root=root,
                    allowed_files=set(inventory.files),
                    user_prompt=review_prompt(packet),
                    schema=REVIEW_SCHEMA,
                    execute=False,
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
            sandbox_prefix=self.config.sandbox.command_prefix,
        )
        system = SYSTEM_PROMPT
        if model.tool_mode == "json" and not provider_manages_tools:
            system += json_tool_instruction(tools.definitions)
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system},
            {"role": "user", "content": user_prompt},
        ]
        total_usage = Usage()
        tool_evidence: list[dict[str, Any]] = []
        final_error = "model did not return a JSON final result"
        for _turn in range(30):
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
                    result = tools.execute_call(call.name, call.arguments)
                    tool_evidence.append(
                        {
                            "name": call.name,
                            "arguments": call.arguments,
                            "result_sha256": hashlib.sha256(
                                result.encode("utf-8")
                            ).hexdigest(),
                        }
                    )
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": call.id,
                            "name": call.name,
                            "content": result,
                        }
                    )
                continue
            parsed = _parse_final_json(response.content)
            errors = (
                list(Draft202012Validator(schema).iter_errors(parsed))
                if parsed is not None
                else []
            )
            if parsed is not None and not errors:
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
                messages.append({"role": "assistant", "content": response.content})
            break

        max_repairs = 3
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
            )
            messages.append({"role": "user", "content": repair_prompt})
            repaired = await _complete_with_retry(
                provider,
                model=model,
                messages=messages,
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
            if repaired.content:
                messages.append({"role": "assistant", "content": repaired.content})

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
            elif verdicts == {Verdict.REJECTED}:
                candidate.verdict = Verdict.REJECTED
            elif verdicts == {Verdict.CONFIRMED}:
                candidate.verdict = Verdict.CONFIRMED
            elif Verdict.CONFIRMED in verdicts and Verdict.REJECTED not in verdicts:
                candidate.verdict = Verdict.CONFIRMED
            elif Verdict.CONDITIONAL in verdicts and Verdict.REJECTED not in verdicts:
                candidate.verdict = Verdict.CONDITIONAL
            else:
                candidate.verdict = Verdict.UNRESOLVED

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
    all_models = [*models, *specialist_models]
    usable_context = min(
        (
            model.context_tokens - model.max_output_tokens - 4_096
            for model in all_models
        ),
        default=128_000,
    )
    partitions = partition_inventory(
        inventory,
        target_bytes=min(200_000, max(16_000, usable_context * 3)),
    )
    partition_count = max(1, len(partitions))
    base_assignments = partition_count * (len(models) + len(specialist_models))
    sweep_assignments = {
        ScanLevel.QUICK: 0,
        ScanLevel.STANDARD: 1,
        ScanLevel.DEEP: 1,
        ScanLevel.EXHAUSTIVE: 2,
    }[level]
    base_assignments += sweep_assignments
    possible_gap_assignments = (
        partition_count * len(models)
        if level in {ScanLevel.DEEP, ScanLevel.EXHAUSTIVE}
        else 0
    )
    # Findings drive review/resolution work and cannot be known before discovery.
    possible_candidates = max(1, min(20, (len(inventory.files) + 49) // 50))
    reviews_per_candidate = {
        ScanLevel.QUICK: 1,
        ScanLevel.STANDARD: 1,
        ScanLevel.DEEP: 2,
        ScanLevel.EXHAUSTIVE: max(1, len(models) - 1),
    }[level]
    possible_reviews = possible_candidates * reviews_per_candidate
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
        + possible_reviews
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
    average_input_low = max(2_500, int(partition_tokens * 0.30) + 2_000)
    average_input_high = min(
        max(8_000, int(partition_tokens * 1.5) + 10_000),
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
        )
        for model in all_models
    ]
    costs_high = [
        estimate_model_cost(
            model,
            input_tokens_high // divisor,
            output_tokens_high // divisor,
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
        "basis": (
            "repository partitions × agent tool rounds + possible reviews; "
            f"reasoning factor {reasoning_factor:.2f}x"
        ),
        "confidence": "low until live provider usage is observed",
        "hardware_cost_low_usd": hourly_hardware_cost * minutes_low / 60,
        "hardware_cost_high_usd": hourly_hardware_cost * minutes_high / 60,
    }


def estimate_model_cost(
    model: ModelSpec, input_tokens: int, output_tokens: int
) -> float | None:
    if not model.remote:
        return 0.0
    if (
        model.input_cost_per_million is None
        or model.output_cost_per_million is None
    ):
        return None
    return (
        input_tokens * model.input_cost_per_million
        + output_tokens * model.output_cost_per_million
    ) / 1_000_000


def merge_candidates(candidates: list[Candidate]) -> list[Candidate]:
    merged: list[Candidate] = []
    by_key: dict[str, Candidate] = {}
    for candidate in candidates:
        key = candidate_merge_key(candidate)
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = candidate
            merged.append(candidate)
            continue
        existing.discovered_by.extend(
            row for row in candidate.discovered_by if row not in existing.discovered_by
        )
        existing.duplicate_candidate_ids.append(candidate.candidate_id)
        existing.trace.extend(row for row in candidate.trace if row not in existing.trace)
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


def candidate_review_packet(candidate: Candidate) -> dict[str, Any]:
    return {
        "candidate_id": candidate.candidate_id,
        "classification": candidate.classification,
        "severity": candidate.severity,
        "cwe": candidate.cwe,
        "source": candidate.source,
        "sink": candidate.sink,
        "trace": candidate.trace,
        "root_cause": candidate.root_cause,
        "attacker_prerequisites": candidate.attacker_prerequisites,
        "claimed_new_capability": candidate.new_capability,
        "contradicting_evidence": candidate.contradicting_evidence,
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
        "files": len(inventory.files),
        "bytes": inventory.total_bytes,
        "languages": inventory.languages,
    }


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


def _list_of_strings(value: Any) -> list[str]:
    return [str(row) for row in value] if isinstance(value, list) else []


def _optional_float(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None
