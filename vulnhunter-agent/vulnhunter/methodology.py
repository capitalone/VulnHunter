"""Threat-model, deterministic seed, surface-ledger, and validation helpers."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .inventory import RepositoryInventory, SecuritySurface
from .models import Candidate, FindingDisposition, Verdict


@dataclass
class ThreatModel:
    repository_digest: str
    product_surfaces: list[str] = field(default_factory=list)
    actors: list[str] = field(default_factory=list)
    external_entrypoints: list[str] = field(default_factory=list)
    privileged_workflows: list[str] = field(default_factory=list)
    assets: list[str] = field(default_factory=list)
    dependency_attackers: list[str] = field(default_factory=list)
    trust_boundaries: list[str] = field(default_factory=list)
    security_invariants: list[str] = field(default_factory=list)
    external_controls: list[str] = field(default_factory=list)
    proof_gaps: list[str] = field(default_factory=list)
    model_provenance: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class StaticSeed:
    seed_id: str
    rule_id: str
    title: str
    classification: str
    severity: str
    cwe: str
    file: str
    line: int
    source: str
    closest_control: str
    sink: str
    impact: str
    evidence: list[dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.7
    tool: str = "vulnhunter-native"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SurfaceLedgerRow:
    surface_id: str
    boundary: str
    family: str
    priority: str
    mandatory: bool
    files: list[str]
    assigned_models: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    candidate_ids: list[str] = field(default_factory=list)
    disposition: str = FindingDisposition.UNRESOLVED
    closure_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def baseline_threat_model(inventory: RepositoryInventory) -> ThreatModel:
    surfaces = sorted({surface.boundary for surface in inventory.surfaces})
    actors = ["untrusted external user", "authenticated malicious user"]
    assets = ["application data", "credentials and tokens", "build and deployment integrity"]
    invariants = [
        "Untrusted input must not reach dangerous operations without validation.",
        "Protected actions and objects require authentication, authorization, and tenant binding.",
        "Remote build and deployment content must be authenticated before execution.",
        "Secrets must not cross into untrusted code, logs, or client-visible artifacts.",
    ]
    if any(surface.family == "supply-chain" for surface in inventory.surfaces):
        actors.append("dependency or build-system attacker")
    if any(surface.family == "mobile" for surface in inventory.surfaces):
        actors.append("malicious local application or website")
        assets.append("device-local private data and component authority")
    return ThreatModel(
        repository_digest=inventory.snapshot_digest,
        product_surfaces=surfaces,
        actors=actors,
        external_entrypoints=[
            surface.boundary for surface in inventory.surfaces
            if surface.family in {"api", "network", "mobile"}
        ],
        privileged_workflows=[
            surface.boundary for surface in inventory.surfaces
            if surface.family in {"supply-chain", "authorization", "authentication"}
        ],
        assets=assets,
        dependency_attackers=(
            ["malicious dependency publisher or compromised build origin"]
            if any(surface.family == "supply-chain" for surface in inventory.surfaces)
            else []
        ),
        trust_boundaries=[
            f"untrusted input to {surface.boundary}" for surface in inventory.surfaces
            if surface.mandatory
        ],
        security_invariants=invariants,
        external_controls=[
            "Deployment, identity-provider, database-policy, and infrastructure controls outside the repository are proof gaps until evidenced."
        ],
        proof_gaps=[],
    )


def initial_surface_ledger(
    surfaces: list[SecuritySurface], model_aliases: list[str]
) -> list[SurfaceLedgerRow]:
    return [
        SurfaceLedgerRow(
            surface_id=surface.surface_id,
            boundary=surface.boundary,
            family=surface.family,
            priority=surface.priority,
            mandatory=surface.mandatory,
            files=surface.files,
            assigned_models=list(model_aliases),
        )
        for surface in surfaces
    ]


def scan_native_seeds(inventory: RepositoryInventory) -> list[StaticSeed]:
    seeds: list[StaticSeed] = []
    texts: dict[str, str] = {}
    for rel in inventory.files:
        path = inventory.root / rel
        try:
            if path.stat().st_size > 2_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        texts[rel] = text
        lines = text.splitlines()
        seeds.extend(_installer_seeds(rel, lines))
        seeds.extend(_downloaded_installer_seeds(rel, lines))
        seeds.extend(_pattern_seeds(rel, lines))
        seeds.extend(_contextual_pattern_seeds(rel, text))
    seeds.extend(_repository_absence_seeds(texts))
    seeds = _deduplicate_native_seeds(seeds)
    for index, seed in enumerate(seeds, 1):
        seed.seed_id = f"SEED-{index:05d}"
    return seeds


def optional_tool_status() -> dict[str, bool]:
    return {
        "semgrep": shutil.which("semgrep") is not None,
        "gitleaks": shutil.which("gitleaks") is not None,
        "trivy": shutil.which("trivy") is not None,
        "ast-grep": _ast_grep_executable() is not None,
    }


def run_optional_scanners(
    inventory: RepositoryInventory,
) -> tuple[list[StaticSeed], dict[str, dict[str, Any]]]:
    """Run installed optional scanners in offline, read-only modes.

    Optional scanner output is deliberately converted to seeds rather than
    findings. A model validator still has to establish reachability, controls,
    and impact.
    """

    available = optional_tool_status()
    seeds: list[StaticSeed] = []
    results: dict[str, dict[str, Any]] = {}
    runners = {
        "semgrep": _run_semgrep,
        "gitleaks": _run_gitleaks,
        "trivy": _run_trivy,
        "ast-grep": _run_ast_grep,
    }
    for name, runner in runners.items():
        if not available[name]:
            results[name] = {
                "available": False,
                "status": "unavailable",
                "version": "",
                "seeds": 0,
            }
            continue
        executable = (
            _ast_grep_executable()
            if name == "ast-grep"
            else shutil.which(name)
        )
        try:
            rows = runner(inventory.root)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            results[name] = {
                "available": True,
                "status": "failed",
                "version": _tool_version(executable),
                "error": f"{type(exc).__name__}: {exc}",
                "seeds": 0,
            }
            continue
        seeds.extend(rows)
        results[name] = {
            "available": True,
            "status": "completed",
            "version": _tool_version(executable),
            "seeds": len(rows),
        }
    for index, seed in enumerate(seeds, 1):
        seed.seed_id = f"TOOL-SEED-{index:05d}"
    return seeds, results


def seed_to_candidate(seed: StaticSeed, candidate_id: str) -> Candidate:
    point = {
        "file": seed.file,
        "line": seed.line,
        "description": seed.source,
        "claim": seed.source,
    }
    evidence = seed.evidence or [point]
    return Candidate(
        candidate_id=candidate_id,
        title=seed.title,
        classification=seed.classification,
        severity=seed.severity,
        cwe=seed.cwe,
        source=point,
        closest_control={
            "file": seed.file,
            "line": seed.line,
            "description": seed.closest_control,
        },
        sink={
            "file": seed.file,
            "line": seed.line,
            "description": seed.sink,
            "claim": seed.sink,
        },
        trace=evidence,
        reachable_path=evidence,
        root_cause=seed.closest_control,
        attacker_prerequisites=["Satisfy the external-control precondition described by the seed."],
        new_capability=seed.impact,
        contradicting_evidence=[],
        proof_gaps=["Independent model validation has not completed."],
        fix_strategy="Restore the missing security control at the cited boundary.",
        confidence=seed.confidence,
        affected_resource=seed.file,
        security_boundary=seed.classification,
        affected_instances=[{"file": seed.file, "line": seed.line}],
        discovered_by=[
            {
                "alias": seed.tool,
                "provider": "deterministic",
                "assignment": seed.seed_id,
                "kind": "seed",
            }
        ],
        verdict=Verdict.UNRESOLVED,
        disposition=FindingDisposition.UNRESOLVED,
    )


def render_threat_model(model: ThreatModel) -> str:
    def section(title: str, rows: list[str]) -> list[str]:
        return [f"## {title}", "", *[f"- {row}" for row in rows], ""]

    lines = ["# VulnHunter Threat Model", ""]
    lines += section("Product Surfaces", model.product_surfaces)
    lines += section("Actors", model.actors)
    lines += section("External Entrypoints", model.external_entrypoints)
    lines += section("Privileged Workflows", model.privileged_workflows)
    lines += section("Assets", model.assets)
    lines += section("Dependency and Build Attackers", model.dependency_attackers)
    lines += section("Trust Boundaries", model.trust_boundaries)
    lines += section("Security Invariants", model.security_invariants)
    lines += section("External Controls", model.external_controls)
    lines += section("Proof Gaps", model.proof_gaps)
    lines += [f"Repository snapshot: `{model.repository_digest}`", ""]
    return "\n".join(lines)


def prompt_hash(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _installer_seeds(relative: str, lines: list[str]) -> list[StaticSeed]:
    seeds: list[StaticSeed] = []
    pipe_re = re.compile(
        r"(?:curl|wget)\b[^\n|]*(?:\||\s+-O-\s*\|)\s*(?:sudo\s+)?(?:ba)?sh\b",
        re.IGNORECASE,
    )
    secret_re = re.compile(
        r"(?:secret|token|password|api[_-]?key|credential|\$\{\{\s*secrets\.)",
        re.IGNORECASE,
    )
    privileged_re = re.compile(
        r"(?:deploy|publish|release|login|push|apply|kubectl|terraform)",
        re.IGNORECASE,
    )
    integrity_re = re.compile(
        r"(?:sha(?:256|512)sum|checksum|cosign|gpg\s+--verify|signature)",
        re.IGNORECASE,
    )
    for number, line in enumerate(lines, 1):
        if not pipe_re.search(line):
            continue
        before = "\n".join(lines[:number])
        after_lines = lines[number:]
        later_secret = next(
            ((number + i + 1, row) for i, row in enumerate(after_lines) if secret_re.search(row)),
            None,
        )
        later_privileged = next(
            ((number + i + 1, row) for i, row in enumerate(after_lines) if privileged_re.search(row)),
            None,
        )
        has_integrity = bool(integrity_re.search(before))
        evidence = [
            {
                "file": relative,
                "line": number,
                "claim": "Mutable remote response is executed by a shell.",
            }
        ]
        if later_secret:
            evidence.append(
                {
                    "file": relative,
                    "line": later_secret[0],
                    "claim": "A later step exposes a credential to installer-controlled state.",
                }
            )
        if later_privileged:
            evidence.append(
                {
                    "file": relative,
                    "line": later_privileged[0],
                    "claim": "The workflow later performs a privileged operation.",
                }
            )
        severity = "Medium" if later_secret or later_privileged else "Low"
        seeds.append(
            StaticSeed(
                seed_id="",
                rule_id="VH-CI-001",
                title="Mutable remote installer executes before privileged workflow operations",
                classification="Supply-chain code execution",
                severity=severity,
                cwe="CWE-494",
                file=relative,
                line=number,
                source="Mutable response bytes from a remote installer endpoint.",
                closest_control=(
                    "No immutable digest or signature is verified before execution."
                    if not has_integrity
                    else "An integrity-like command exists earlier; validation must prove it authenticates these exact bytes."
                ),
                sink="Remote bytes execute in a shell and may persist into later workflow steps.",
                impact=(
                    "Upstream compromise can execute in the job and reach later credentials or deployment authority."
                    if later_secret or later_privileged
                    else "Upstream compromise can execute code in the job."
                ),
                evidence=evidence,
                confidence=0.9 if (later_secret and later_privileged and not has_integrity) else 0.72,
            )
        )
    return seeds


def _pattern_seeds(relative: str, lines: list[str]) -> list[StaticSeed]:
    rules = [
        (
            "VH-AUTH-001", re.compile(r"--no-verify-jwt\b"),
            "JWT verification is explicitly disabled", "Authentication control disabled",
            "CWE-306", "Medium", "A deployment or route disables JWT verification.",
        ),
        (
            "VH-EXEC-001",
            re.compile(r"(?<![\w.])(?:os\.system|eval|exec)\s*\("),
            "Potential dynamic code or shell execution", "Code execution",
            "CWE-94", "High", "Dynamic execution API is present.",
        ),
        (
            "VH-DESER-001", re.compile(r"\b(?:pickle\.loads?|yaml\.load)\s*\("),
            "Potential unsafe deserialization", "Unsafe deserialization",
            "CWE-502", "High", "A general-purpose deserializer is present.",
        ),
        (
            "VH-CI-002", re.compile(r"^\s*uses:\s*[^@\s]+@(?![0-9a-f]{40}\b)[^\s#]+"),
            "CI action is referenced by a mutable tag", "Supply-chain integrity",
            "CWE-829", "Low", "A third-party CI action is not pinned to a full commit digest.",
        ),
        (
            "VH-EXEC-002",
            re.compile(
                r"\bsubprocess\.(?:run|call|Popen|check_output)\s*\([^#\n]*"
                r"shell\s*=\s*True"
            ),
            "Subprocess invocation enables a command shell",
            "Shell command injection",
            "CWE-78",
            "High",
            "A subprocess API explicitly enables shell parsing.",
        ),
        (
            "VH-ARCHIVE-001",
            re.compile(r"\b(?:extractall|ZipFile\([^)]*\)\.extract|TarFile\([^)]*\)\.extract)\s*\("),
            "Archive extraction requires path-containment validation",
            "Archive path traversal",
            "CWE-22",
            "High",
            "An archive extraction API writes member-controlled paths.",
        ),
        (
            "VH-NET-001",
            re.compile(
                r"\b(?:requests|httpx)\.(?:get|post|put|delete|request)\s*\("
                r"\s*(?:request\.|req\.|params\[|args\[|body\[|payload\[)"
            ),
            "Request-derived URL reaches an outbound HTTP client",
            "Server-side request forgery",
            "CWE-918",
            "High",
            "A request-derived value appears to select an outbound URL.",
        ),
        (
            "VH-MOBILE-001",
            re.compile(r"android:exported\s*=\s*[\"']true[\"']", re.IGNORECASE),
            "Android component is explicitly exported",
            "Mobile component exposure",
            "CWE-926",
            "Medium",
            "An Android component is callable by other applications.",
        ),
        (
            "VH-MOBILE-002",
            re.compile(
                r"<(?:root-path|external-path)\b[^>]*\bpath\s*=\s*[\"']"
                r"(?:\.|/)?[\"']",
                re.IGNORECASE,
            ),
            "FileProvider exposes a broad filesystem root",
            "Mobile file sharing",
            "CWE-200",
            "High",
            "A FileProvider path mapping exposes an unrestricted root.",
        ),
        (
            "VH-SECRET-001",
            re.compile(
                r"(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|"
                r"password)\b\s*[:=]\s*[\"'][A-Za-z0-9_./+=-]{16,}[\"']"
            ),
            "Potential hardcoded privileged secret",
            "Credential exposure",
            "CWE-798",
            "High",
            "A credential-shaped literal is assigned to a privileged field.",
        ),
    ]
    seeds: list[StaticSeed] = []
    for number, line in enumerate(lines, 1):
        for rule_id, pattern, title, classification, cwe, severity, source in rules:
            if not pattern.search(line):
                continue
            seeds.append(
                StaticSeed(
                    seed_id="",
                    rule_id=rule_id,
                    title=title,
                    classification=classification,
                    severity=severity,
                    cwe=cwe,
                    file=relative,
                    line=number,
                    source=source,
                    closest_control="No complete blocking control is proven by the matched line.",
                    sink=line.strip()[:500],
                    impact="Requires focused source/control/sink validation.",
                    confidence=0.55,
                )
            )
    return seeds


def _contextual_pattern_seeds(relative: str, text: str) -> list[StaticSeed]:
    """Find security-sensitive relationships that commonly span several lines.

    These rules deliberately produce validation seeds, not findings.  Their job
    is to make a reviewer inspect lifecycle and containment controls that a
    line-oriented matcher cannot see.
    """

    seeds: list[StaticSeed] = []
    lines = text.splitlines()

    # Multiline subprocess calls with shell parsing enabled.
    subprocess_call = re.compile(
        r"\bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\(",
        re.IGNORECASE,
    )
    for match in subprocess_call.finditer(text):
        window = text[match.start() : match.start() + 2_500]
        closing = _bounded_call_text(window)
        if not re.search(r"\bshell\s*=\s*True\b", closing):
            continue
        line = _line_number(text, match.start())
        seeds.append(
            StaticSeed(
                seed_id="",
                rule_id="VH-EXEC-002",
                title="Subprocess invocation enables a command shell",
                classification="Shell command injection",
                severity="High",
                cwe="CWE-78",
                file=relative,
                line=line,
                source=(
                    "A subprocess call enables shell parsing across a multiline "
                    "argument list."
                ),
                closest_control=(
                    "Validation must prove that every interpolated command fragment "
                    "is fixed or safely encoded for the selected shell."
                ),
                sink=" ".join(closing.split())[:500],
                impact="Attacker-controlled command fragments may execute with process authority.",
                confidence=0.7,
            )
        )

    # Custom archive extraction loops are often missed because they do not call
    # extract()/extractall().  Look for member-derived paths followed by writes.
    archive_iteration = re.compile(
        r"(?:\.infolist\s*\(\)|\.namelist\s*\(\)|\.getmembers\s*\(\)|"
        r"\b(?:ZipFile|TarFile)\s*\()",
        re.IGNORECASE,
    )
    member_path = re.compile(
        r"(?:member|entry|info|item|name)\s*\.\s*(?:filename|name)|"
        r"\b(?:member|entry|info|item)_?(?:name|path)\b",
        re.IGNORECASE,
    )
    write_sink = re.compile(
        r"\b(?:open|write|copyfileobj|copy|move|rename|mkdir|makedirs)\s*\(|"
        r"\.(?:write_bytes|write_text|open|mkdir)\s*\(",
        re.IGNORECASE,
    )
    containment = re.compile(
        r"\b(?:commonpath|realpath|resolve|is_relative_to|relative_to|"
        r"startsWith|startswith|abspath|canonicalPath)\b",
        re.IGNORECASE,
    )
    if archive_iteration.search(text):
        for match in member_path.finditer(text):
            start = max(0, match.start() - 800)
            end = min(len(text), match.end() + 2_500)
            window = text[start:end]
            if not write_sink.search(window) or containment.search(window):
                continue
            seeds.append(
                StaticSeed(
                    seed_id="",
                    rule_id="VH-ARCHIVE-002",
                    title="Custom archive extraction needs destination containment",
                    classification="Archive path traversal",
                    severity="High",
                    cwe="CWE-22",
                    file=relative,
                    line=_line_number(text, match.start()),
                    source="An archive member name contributes to a filesystem destination.",
                    closest_control=(
                        "No canonical-path containment check is visible in the "
                        "bounded extraction flow."
                    ),
                    sink="A member-derived destination is opened, created, copied, or moved.",
                    impact="A crafted archive may write outside the intended extraction root.",
                    confidence=0.68,
                )
            )

    # Process-global request caches need both tenant-safe keys and all-path
    # retention controls.  This intentionally asks a model to examine success,
    # rejection, early-return, and cancellation paths.
    global_cache = re.compile(
        r"(?m)^(?:export\s+)?(?:const|let|var)\s+"
        r"(?P<name>[A-Za-z_$][\w$]*(?:cache|cached|requests|entries|results)[\w$]*)"
        r"\s*(?::[^=\n]+)?=\s*new\s+Map\b",
        re.IGNORECASE,
    )
    request_context = re.compile(
        r"\b(?:req(?:uest)?\.|router\.|app\.(?:get|post|put|patch|delete)|"
        r"client[_-]?request[_-]?id|idempotency[_-]?key|user[_-]?id|tenant[_-]?id)\b",
        re.IGNORECASE,
    )
    for match in global_cache.finditer(text):
        name = match.group("name")
        server_request = re.search(
            r"\b(?:req(?:uest)?\.|router\.|app\.(?:get|post|put|patch|delete))",
            text,
            re.IGNORECASE,
        )
        if not request_context.search(text) or (
            not server_request and not _looks_server_side(relative)
        ):
            continue
        if not re.search(rf"\b{re.escape(name)}\.set\s*\(", text):
            continue
        has_lookup = bool(re.search(rf"\b{re.escape(name)}\.(?:get|has)\s*\(", text))
        if not has_lookup:
            continue
        lifecycle_tokens = bool(
            re.search(
                rf"\b{re.escape(name)}\.delete\s*\(|\b(?:ttl|maxSize|maxEntries|"
                r"lru|evict|expire|setTimeout)\b",
                text,
                re.IGNORECASE,
            )
        )
        seeds.append(
            StaticSeed(
                seed_id="",
                rule_id="VH-CACHE-001",
                title="Shared request cache needs identity and lifecycle validation",
                classification="Cross-request state isolation",
                severity="High",
                cwe="CWE-664",
                file=relative,
                line=_line_number(text, match.start()),
                source=(
                    f"Process-global map '{name}' stores and reuses request-associated state."
                ),
                closest_control=(
                    "A cleanup mechanism exists, but validation must prove tenant-scoped "
                    "keys and eviction on success, failure, early return, and cancellation."
                    if lifecycle_tokens
                    else "No bounded retention or complete eviction mechanism is visible."
                ),
                sink="Cached promises or results are returned to later requests.",
                impact=(
                    "Key collisions can cross identity boundaries, while missed terminal "
                    "paths can retain attacker-created entries for process lifetime."
                ),
                confidence=0.67 if lifecycle_tokens else 0.78,
            )
        )

    # Common in-memory upload/body APIs buffer content before application logic.
    body_buffer = re.compile(
        r"\b(?:memoryStorage\s*\(|req(?:uest)?\.(?:body|file|files)|"
        r"\.(?:arrayBuffer|formData)\s*\(|readFile\s*\(|Buffer\.from\s*\()",
        re.IGNORECASE,
    )
    upload_context = re.compile(
        r"\b(?:upload|multipart|form-data|audio|video|archive|attachment|file)\b",
        re.IGNORECASE,
    )
    size_control = re.compile(
        r"\b(?:fileSize|content-length|max(?:imum)?[_-]?(?:size|bytes|length)|"
        r"bodyLimit|limits\s*:|limit\s*:|413|payload too large)\b",
        re.IGNORECASE,
    )
    if (
        _looks_server_side(relative)
        and body_buffer.search(text)
        and upload_context.search(text)
        and not size_control.search(text)
    ):
        match = body_buffer.search(text)
        assert match is not None
        seeds.append(
            StaticSeed(
                seed_id="",
                rule_id="VH-RESOURCE-001",
                title="Buffered request content lacks a visible size limit",
                classification="Resource exhaustion",
                severity="High",
                cwe="CWE-770",
                file=relative,
                line=_line_number(text, match.start()),
                source="A request-facing path buffers uploaded or request-derived content.",
                closest_control="No explicit byte or body-size limit is visible in this file.",
                sink="Request content is retained in process memory or passed to downstream processing.",
                impact="Repeated oversized requests may exhaust memory or downstream paid capacity.",
                confidence=0.66,
            )
        )
    return seeds


def _bounded_call_text(window: str) -> str:
    depth = 0
    opened = False
    quote = ""
    escaped = False
    for index, character in enumerate(window):
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
            continue
        if character in {"'", '"'}:
            quote = character
        elif character == "(":
            depth += 1
            opened = True
        elif character == ")" and opened:
            depth -= 1
            if depth <= 0:
                return window[: index + 1]
    return window


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _looks_server_side(relative: str) -> bool:
    lowered = f"/{relative.lower().replace(chr(92), '/')}/"
    return any(
        marker in lowered
        for marker in (
            "/backend/",
            "/server/",
            "/api/",
            "/functions/",
            "/routes/",
            "/controllers/",
            "/handlers/",
        )
    )


def _deduplicate_native_seeds(seeds: list[StaticSeed]) -> list[StaticSeed]:
    """Keep one focused assignment per rule and file while retaining evidence."""

    unique: dict[tuple[str, str], StaticSeed] = {}
    for seed in seeds:
        key = (seed.rule_id, seed.file)
        existing = unique.get(key)
        if existing is None:
            unique[key] = seed
            continue
        point = {
            "file": seed.file,
            "line": seed.line,
            "claim": seed.source,
        }
        if point not in existing.evidence:
            existing.evidence.append(point)
        existing.confidence = max(existing.confidence, seed.confidence)
        if _severity_rank(seed.severity) > _severity_rank(existing.severity):
            existing.severity = seed.severity
    return list(unique.values())


def _severity_rank(value: str) -> int:
    return {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}.get(value, 0)


def _downloaded_installer_seeds(
    relative: str, lines: list[str]
) -> list[StaticSeed]:
    """Find downloaded executables that lack a trusted immutable verifier."""

    download = re.compile(
        r"\bcurl\b[^\n]*(?:-o\s+(?P<file>[^\s]+)\s+(?P<url>https?://[^\s]+)"
        r"|-O\s+(?P<url_only>https?://[^\s]+))",
        re.IGNORECASE,
    )
    digest = re.compile(r"\b[0-9a-fA-F]{64}\b")
    secret_or_privileged = re.compile(
        r"(?i)(?:secret|token|password|api[_-]?key|deploy|publish|release|push|apply)"
    )
    seeds: list[StaticSeed] = []
    for index, line in enumerate(lines):
        match = download.search(line)
        if not match:
            continue
        url = match.group("url") or match.group("url_only") or ""
        filename = (match.group("file") or Path(url).name).strip("\"'")
        if not filename:
            continue
        window = lines[index + 1 : index + 16]
        filename_leaf = Path(filename).name
        execution_index = next(
            (
                offset
                for offset, row in enumerate(window, 1)
                if filename_leaf in row
                and re.search(
                    r"(?i)(?:chmod\s+\+x|(?:^|[\s;&])(?:\./|/tmp/|/work/|bash\s+))",
                    row,
                )
            ),
            None,
        )
        if execution_index is None:
            continue
        preceding = "\n".join(window[:execution_index])
        trusted_digest = bool(
            digest.search(preceding)
            and re.search(r"(?i)sha(?:256|512)sum\s+(?:--check|-c)", preceding)
        )
        if trusted_digest:
            continue
        checksum_same_origin = any(
            "curl" in row.lower()
            and ("sha256" in row.lower() or "checksum" in row.lower())
            for row in window[:execution_index]
        )
        later_privileged = next(
            (
                (index + offset + 1, row)
                for offset, row in enumerate(window[execution_index:], execution_index + 1)
                if secret_or_privileged.search(row)
            ),
            None,
        )
        evidence = [
            {
                "file": relative,
                "line": index + 1,
                "claim": "An executable artifact is downloaded from a mutable origin.",
            },
            {
                "file": relative,
                "line": index + execution_index + 1,
                "claim": "The downloaded artifact is later executed.",
            },
        ]
        if later_privileged:
            evidence.append(
                {
                    "file": relative,
                    "line": later_privileged[0],
                    "claim": "A later operation uses secrets or privileged authority.",
                }
            )
        seeds.append(
            StaticSeed(
                seed_id="",
                rule_id="VH-CI-003",
                title="Downloaded executable lacks trusted immutable verification",
                classification="Supply-chain code execution",
                severity="Medium" if later_privileged else "Low",
                cwe="CWE-494",
                file=relative,
                line=index + 1,
                source="Executable bytes are selected by a mutable remote origin.",
                closest_control=(
                    "A checksum is fetched from the same mutable workflow origin; "
                    "it does not authenticate the artifact."
                    if checksum_same_origin
                    else "Version output or transport security does not authenticate "
                    "the downloaded bytes; no pinned digest/signature is verified."
                ),
                sink="The downloaded executable is invoked by the workflow.",
                impact=(
                    "Origin compromise can execute before a later privileged action."
                    if later_privileged
                    else "Origin compromise can execute in the workflow with its current authority."
                ),
                evidence=evidence,
                confidence=0.8 if later_privileged else 0.7,
            )
        )
    return seeds


def _repository_absence_seeds(texts: dict[str, str]) -> list[StaticSeed]:
    seeds: list[StaticSeed] = []
    supabase_files = [
        path
        for path, text in texts.items()
        if "supabase" in path.lower() or "supabase" in text.lower()
    ]
    policy_evidence = any(
        re.search(
            r"\b(?:enable\s+row\s+level\s+security|create\s+policy|"
            r"auth\.uid\(\)|row[_ -]?level[_ -]?security)\b",
            text,
            re.IGNORECASE,
        )
        for text in texts.values()
    )
    if supabase_files and not policy_evidence:
        path = sorted(supabase_files)[0]
        seeds.append(
            StaticSeed(
                seed_id="",
                rule_id="VH-AUTHZ-002",
                title="Repository lacks evidence for database row-level authorization",
                classification="Authorization proof gap",
                severity="Medium",
                cwe="CWE-862",
                file=path,
                line=1,
                source="The repository references Supabase-backed data access.",
                closest_control=(
                    "No RLS enablement, policy definition, or auth.uid()-bound "
                    "database policy was found in the immutable snapshot."
                ),
                sink="Database rows may rely on an external, unverified policy.",
                impact=(
                    "Authorization cannot be closed from repository evidence; "
                    "deployment-side policies require explicit validation."
                ),
                confidence=0.65,
            )
        )

    unscoped_lookup = re.compile(
        r"(?i)\b(?:find|get|fetch|select|load)(?:_|\w)*(?:by_?id|id)\s*\("
    )
    ownership = re.compile(r"(?i)\b(?:tenant|owner|user|account|organization|org)_?id\b")
    for path, text in texts.items():
        lowered_path = path.lower()
        request_facing = any(
            marker in lowered_path
            for marker in ("controller", "handler", "route", "repository")
        ) or (
            "service" in lowered_path
            and any(
                marker in lowered_path
                for marker in ("/backend/", "/server/", "/api/", "/src/services/")
            )
        )
        if not request_facing:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if unscoped_lookup.search(line) and not ownership.search(line):
                seeds.append(
                    StaticSeed(
                        seed_id="",
                        rule_id="VH-AUTHZ-001",
                        title="Identifier lookup lacks visible ownership or tenant scope",
                        classification="Object-level authorization",
                        severity="High",
                        cwe="CWE-639",
                        file=path,
                        line=number,
                        source="A request-facing layer appears to perform an ID lookup.",
                        closest_control=(
                            "No ownership, account, organization, user, or tenant "
                            "predicate is visible at the lookup."
                        ),
                        sink=line.strip()[:500],
                        impact=(
                            "A caller may be able to select an object outside its "
                            "authorization boundary."
                        ),
                        confidence=0.6,
                    )
                )

    # Resolve repository-defined privileged data-client aliases, then inspect
    # their consumers for caller-selected identity joins.  This is intentionally
    # framework-neutral: service-role, admin, root, system, and RLS-bypass
    # credentials all represent the same trust-boundary transition.
    privileged_aliases: set[str] = set()
    privileged_definition = re.compile(
        r"(?i)(?:service[\s_-]?(?:role|key|token|client)|"
        r"admin[\s_-]?(?:key|token|client)|"
        r"root[\s_-]?(?:key|token|client)|bypass[\s_-]?(?:rls|auth)|"
        r"system[\s_-]?(?:key|token|client))"
    )
    declaration = re.compile(
        r"(?m)(?:export\s+)?(?:const|let|var)\s+"
        r"(?P<name>[A-Za-z_$][\w$]*)[^=\n]*="
    )
    for text in texts.values():
        for marker in privileged_definition.finditer(text):
            start = max(0, marker.start() - 1_500)
            end = min(len(text), marker.end() + 1_500)
            for match in declaration.finditer(text[start:end]):
                privileged_aliases.add(match.group("name"))

    identity_selector = re.compile(
        r"(?i)\b(?:phone(?:_number)?|email|username|handle|external[_-]?id|"
        r"account[_-]?number|customer[_-]?id|subject[_-]?id|record[_-]?id|"
        r"prospect[_-]?id|resource[_-]?id)\b"
    )
    caller_context = re.compile(
        r"(?i)\b(?:req(?:uest)?\.(?:body|params|query)|body\.|params\.|"
        r"payload\.|input\.|updates?\.|data\.)"
    )
    read_operation = re.compile(
        r"(?i)\.(?:from|table|collection|select|find|where|eq|or|filter)\s*\("
    )
    write_operation = re.compile(
        r"(?i)\.(?:insert|update|upsert|create|save|delete)\s*\("
    )
    tenant_binding = re.compile(
        r"(?i)\b(?:user|owner|tenant|account|organization|org)_?id\b"
    )
    for path, text in texts.items():
        lowered = path.lower()
        if not any(
            marker in lowered
            for marker in (
                "/backend/",
                "/server/",
                "/functions/",
                "/services/",
                "/routes/",
                "/controllers/",
                "/repositories/",
            )
        ):
            continue
        uses_privileged_client = privileged_definition.search(text) is not None or any(
            re.search(rf"\b{re.escape(alias)}\b", text)
            and re.search(
                rf"(?:import|require)[^\n]*\b{re.escape(alias)}\b", text
            )
            for alias in privileged_aliases
        )
        if not uses_privileged_client:
            continue
        collections = {
            match.group("name")
            for match in re.finditer(
                r"(?i)\.(?:from|table|collection)\s*\(\s*[\"']"
                r"(?P<name>[^\"']+)[\"']",
                text,
            )
        }
        if (
            len(collections) < 2
            or not caller_context.search(text)
            or not write_operation.search(text)
        ):
            continue
        selectors = list(identity_selector.finditer(text))
        if not selectors:
            continue
        for selector in selectors:
            start = max(0, selector.start() - 1_500)
            end = min(len(text), selector.end() + 4_000)
            window = text[start:end]
            if not read_operation.search(window):
                continue
            has_caller_selector = bool(caller_context.search(window))
            has_cross_record_write = bool(write_operation.search(window))
            if not has_cross_record_write:
                continue
            # A user_id elsewhere in a large service does not prove that the
            # privileged source query is scoped.  Only treat it as a weak signal
            # and leave the focused model to validate the exact fluent chain.
            local_binding = bool(tenant_binding.search(window))
            seeds.append(
                StaticSeed(
                    seed_id="",
                    rule_id="VH-AUTHZ-003",
                    title="Privileged data access needs caller-identity binding",
                    classification="Cross-tenant authorization",
                    severity="High",
                    cwe="CWE-639",
                    file=path,
                    line=_line_number(text, selector.start()),
                    source=(
                        "A privileged data client reads using an external identity "
                        "or object selector."
                    ),
                    closest_control=(
                        "A tenant-like identifier is nearby, but validation must prove "
                        "it constrains the same privileged source query."
                        if local_binding
                        else "No caller-derived owner or tenant predicate is visible "
                        "near the privileged lookup."
                    ),
                    sink=(
                        "Selected records are subsequently written, linked, or mutated."
                        if has_cross_record_write
                        else "Selected records cross a privileged data boundary."
                    ),
                    impact=(
                        "A caller-selected identifier may disclose, relink, import, or "
                        "mutate records belonging to another security principal."
                    ),
                    confidence=0.73 if (has_caller_selector and has_cross_record_write) else 0.61,
                )
            )
            break
    return seeds


def _run_semgrep(root: Path) -> list[StaticSeed]:
    executable = shutil.which("semgrep")
    if not executable:
        return []
    rules = Path(__file__).with_name("rules") / "semgrep.yml"
    payload = _run_json_command(
        [
            executable,
            "scan",
            "--config",
            str(rules),
            "--json",
            "--metrics",
            "off",
            "--disable-version-check",
            str(root),
        ]
    )
    rows: list[StaticSeed] = []
    for result in payload.get("results", []) if isinstance(payload, dict) else []:
        if not isinstance(result, dict):
            continue
        extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
        start = result.get("start") if isinstance(result.get("start"), dict) else {}
        path = _relative_tool_path(root, result.get("path"))
        if not path:
            continue
        rows.append(
            _tool_seed(
                tool="semgrep",
                rule=str(result.get("check_id") or "semgrep"),
                title=str(extra.get("message") or "Semgrep security seed"),
                path=path,
                line=int(start.get("line") or 1),
                severity=str(extra.get("severity") or "WARNING"),
            )
        )
    return rows


def _run_gitleaks(root: Path) -> list[StaticSeed]:
    executable = shutil.which("gitleaks")
    if not executable:
        return []
    with tempfile.TemporaryDirectory(prefix="vulnhunter-gitleaks-") as temp:
        report = Path(temp) / "report.json"
        _run_command(
            [
                executable,
                "detect",
                "--no-git",
                "--source",
                str(root),
                "--report-format",
                "json",
                "--report-path",
                str(report),
                "--exit-code",
                "0",
            ]
        )
        payload = json.loads(report.read_text(encoding="utf-8")) if report.is_file() else []
    rows: list[StaticSeed] = []
    for result in payload if isinstance(payload, list) else []:
        if not isinstance(result, dict):
            continue
        path = _relative_tool_path(root, result.get("File"))
        if not path:
            continue
        rows.append(
            _tool_seed(
                tool="gitleaks",
                rule=str(result.get("RuleID") or "gitleaks"),
                title=str(result.get("Description") or "Potential repository secret"),
                path=path,
                line=int(result.get("StartLine") or 1),
                severity="High",
                classification="Credential exposure",
                cwe="CWE-798",
            )
        )
    return rows


def _run_trivy(root: Path) -> list[StaticSeed]:
    executable = shutil.which("trivy")
    if not executable:
        return []
    with tempfile.TemporaryDirectory(prefix="vulnhunter-trivy-") as temp:
        report = Path(temp) / "report.json"
        _run_command(
            [
                executable,
                "fs",
                "--offline-scan",
                "--skip-db-update",
                "--scanners",
                "secret,misconfig",
                "--format",
                "json",
                "--output",
                str(report),
                str(root),
            ]
        )
        payload = json.loads(report.read_text(encoding="utf-8")) if report.is_file() else {}
    rows: list[StaticSeed] = []
    for result in payload.get("Results", []) if isinstance(payload, dict) else []:
        if not isinstance(result, dict):
            continue
        target = _relative_tool_path(root, result.get("Target"))
        for finding in [
            *(result.get("Misconfigurations") or []),
            *(result.get("Secrets") or []),
        ]:
            if not isinstance(finding, dict) or not target:
                continue
            rows.append(
                _tool_seed(
                    tool="trivy",
                    rule=str(finding.get("ID") or finding.get("RuleID") or "trivy"),
                    title=str(finding.get("Title") or "Trivy security seed"),
                    path=target,
                    line=int(finding.get("StartLine") or 1),
                    severity=str(finding.get("Severity") or "UNKNOWN"),
                )
            )
    return rows


def _run_ast_grep(root: Path) -> list[StaticSeed]:
    executable = _ast_grep_executable()
    if not executable:
        return []
    rules = Path(__file__).with_name("rules") / "ast-grep.yml"
    payload = _run_json_command(
        [executable, "scan", "--json=stream", "--rule", str(rules), str(root)],
        json_lines=True,
    )
    rows: list[StaticSeed] = []
    values = payload if isinstance(payload, list) else []
    for result in values:
        if not isinstance(result, dict):
            continue
        path = _relative_tool_path(
            root, result.get("file") or result.get("path")
        )
        if not path:
            continue
        start = result.get("range", {}).get("start", {}) if isinstance(result.get("range"), dict) else {}
        rows.append(
            _tool_seed(
                tool="ast-grep",
                rule=str(result.get("ruleId") or "ast-grep"),
                title=str(result.get("message") or "AST security seed"),
                path=path,
                line=int(start.get("line") or 0) + 1,
                severity=str(result.get("severity") or "WARNING"),
            )
        )
    return rows


def _ast_grep_executable() -> str | None:
    explicit = shutil.which("ast-grep")
    if explicit:
        return explicit
    short = shutil.which("sg")
    if not short:
        return None
    try:
        result = subprocess.run(
            [short, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            shell=False,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return short if "ast-grep" in (result.stdout + result.stderr).lower() else None


def _tool_version(executable: str | None) -> str:
    if not executable:
        return ""
    try:
        result = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            shell=False,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    output = result.stdout.strip() or result.stderr.strip()
    return output.splitlines()[0][:200] if output else "unknown"


def _run_json_command(
    arguments: list[str], *, json_lines: bool = False
) -> Any:
    output = _run_command(arguments)
    if json_lines:
        return [
            json.loads(line)
            for line in output.splitlines()
            if line.strip().startswith(("{", "["))
        ]
    return json.loads(output or "{}")


def _run_command(arguments: list[str]) -> str:
    result = subprocess.run(
        arguments,
        capture_output=True,
        text=True,
        timeout=120,
        shell=False,
        check=False,
    )
    if result.returncode not in {0, 1}:
        raise subprocess.CalledProcessError(
            result.returncode, arguments, result.stdout, result.stderr
        )
    return result.stdout


def _relative_tool_path(root: Path, value: Any) -> str:
    if not isinstance(value, str) or not value:
        return ""
    try:
        path = Path(value)
        resolved = path.resolve() if path.is_absolute() else (root / path).resolve()
        return resolved.relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return ""


def _tool_seed(
    *,
    tool: str,
    rule: str,
    title: str,
    path: str,
    line: int,
    severity: str,
    classification: str = "Static scanner candidate",
    cwe: str = "",
) -> StaticSeed:
    normalized_severity = {
        "CRITICAL": "Critical",
        "ERROR": "High",
        "HIGH": "High",
        "WARNING": "Medium",
        "MEDIUM": "Medium",
        "LOW": "Low",
        "INFO": "Low",
    }.get(severity.upper(), "Medium")
    return StaticSeed(
        seed_id="",
        rule_id=rule,
        title=title,
        classification=classification,
        severity=normalized_severity,
        cwe=cwe,
        file=path,
        line=max(1, line),
        source=f"{tool} matched rule {rule}.",
        closest_control="The scanner match requires source/control/sink validation.",
        sink=title,
        impact="Potential security impact; not yet independently validated.",
        confidence=0.6,
        tool=tool,
    )
