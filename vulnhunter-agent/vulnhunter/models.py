"""Provider-neutral data contracts used by the standalone scanner."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class ScanLevel(StrEnum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"
    EXHAUSTIVE = "exhaustive"


class RunStatus(StrEnum):
    RUNNING = "RUNNING"
    COMPLETE_CLEAN = "COMPLETE_CLEAN"
    COMPLETE_FINDINGS = "COMPLETE_FINDINGS"
    COMPLETE_CONDITIONAL = "COMPLETE_CONDITIONAL"
    INCOMPLETE_LIMIT = "INCOMPLETE_LIMIT"
    INCOMPLETE_COVERAGE = "INCOMPLETE_COVERAGE"
    FAILED = "FAILED"


class AssignmentKind(StrEnum):
    HUNT = "hunt"
    SPECIALIST = "specialist"
    REVIEW = "review"
    RESOLVE = "resolve"
    SWEEP = "sweep"


class Verdict(StrEnum):
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    CONDITIONAL = "CONDITIONAL"
    UNRESOLVED = "UNRESOLVED"


@dataclass(frozen=True)
class ModelCapabilities:
    native_tools: bool = True
    structured_output: bool = True
    streaming: bool = False
    usage_reporting: bool = True


@dataclass(frozen=True)
class ModelSpec:
    alias: str
    provider: str
    model: str
    remote: bool
    priority: int = 100
    context_tokens: int = 128_000
    max_output_tokens: int = 8_192
    tool_mode: str = "native"
    reasoning_effort: str = "auto"
    supported_reasoning_efforts: tuple[str, ...] = ()
    billing_label: str = ""
    input_cost_per_million: float | None = None
    output_cost_per_million: float | None = None
    hourly_hardware_cost: float | None = None
    capabilities: ModelCapabilities = field(default_factory=ModelCapabilities)

    @property
    def identity(self) -> tuple[str, str]:
        return (self.provider, self.model)

    @property
    def priced(self) -> bool:
        if not self.remote:
            return True
        return (
            self.input_cost_per_million is not None
            and self.output_cost_per_million is not None
        )

    @property
    def is_free(self) -> bool:
        return bool(
            self.remote
            and self.input_cost_per_million == 0
            and self.output_cost_per_million == 0
        )


@dataclass(frozen=True)
class SpecialistSpec:
    profile: str
    model_alias: str
    prompt: str = ""
    enabled: bool = True


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cached_input_tokens: int = 0
    cache_write_tokens: int = 0
    requests: int = 0
    rate_limit_retries: int = 0
    cost_usd: float | None = None
    # ``provider`` is an amount reported by the billing provider;
    # ``estimate`` is token arithmetic using catalog prices.
    cost_source: str = "unknown"
    duration_seconds: float = 0.0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def add(self, other: "Usage") -> None:
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.cached_input_tokens += other.cached_input_tokens
        self.cache_write_tokens += other.cache_write_tokens
        self.requests += other.requests
        self.rate_limit_retries += other.rate_limit_retries
        self.duration_seconds += other.duration_seconds
        if other.cost_usd is not None:
            self.cost_usd = (self.cost_usd or 0.0) + other.cost_usd
            if self.cost_source == "unknown":
                self.cost_source = other.cost_source
            elif other.cost_source not in {"unknown", self.cost_source}:
                self.cost_source = "mixed"


@dataclass
class ModelResponse:
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)
    finish_reason: str = ""
    raw: dict[str, Any] | None = None


@dataclass
class Candidate:
    candidate_id: str
    title: str
    classification: str
    severity: str
    cwe: str
    source: dict[str, Any]
    sink: dict[str, Any]
    trace: list[dict[str, Any]]
    root_cause: str
    attacker_prerequisites: list[str]
    new_capability: str
    contradicting_evidence: list[str]
    fix_strategy: str
    confidence: float | None = None
    affected_resource: str = ""
    security_boundary: str = ""
    poc: str = ""
    exploit_test: str = ""
    discovered_by: list[dict[str, str]] = field(default_factory=list)
    duplicate_candidate_ids: list[str] = field(default_factory=list)
    verdict: str = Verdict.UNRESOLVED
    reviews: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["verdict"] = str(self.verdict)
        return data


@dataclass
class Review:
    review_id: str
    candidate_id: str
    reviewer: dict[str, str]
    verdict: str
    source_reachable: bool | None
    attacker_controlled: bool | None
    trace_complete: bool | None
    blocking_control_found: bool | None
    new_capability_proven: bool | None
    rationale: str
    incorrect_claims: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["usage"] = asdict(self.usage)
        return data


@dataclass
class Assignment:
    assignment_id: str
    kind: str
    model_alias: str
    partition_id: str = ""
    files: list[str] = field(default_factory=list)
    candidate_id: str = ""
    specialist_profile: str = ""
    provider: str = ""
    model: str = ""
    prompt_hash: str = ""
    status: str = "PENDING"
    error: str = ""
    usage: Usage = field(default_factory=Usage)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["usage"] = asdict(self.usage)
        return data


@dataclass
class ScanLimits:
    max_cost_usd: float | None = None
    max_tokens: int | None = None
    max_duration_seconds: float | None = None
    max_workers: int = 4


@dataclass
class ScanRequest:
    repository: str
    level: ScanLevel
    model_aliases: list[str]
    specialists: list[SpecialistSpec] = field(default_factory=list)
    limits: ScanLimits = field(default_factory=ScanLimits)
    execute: bool = False
    results_dir: str | None = None
    resume: bool = False
