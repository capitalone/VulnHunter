"""Deterministic repository inventory, security surfaces, and partitioning."""

from __future__ import annotations

import hashlib
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


SOURCE_EXTENSIONS = {
    ".c", ".cc", ".cfg", ".conf", ".cpp", ".cs", ".gradle", ".go", ".h",
    ".hcl", ".hpp", ".java", ".js", ".json", ".jsx", ".kt", ".kts", ".lock",
    ".php", ".properties", ".proto", ".py", ".rb", ".rs", ".scala", ".sh",
    ".sol", ".sql", ".swift", ".tf", ".toml", ".ts", ".tsx", ".vue", ".xml",
    ".yaml", ".yml",
}

HARD_EXCLUDED_PARTS = {
    ".claude", ".git", ".gradle", ".idea", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".vscode",
    ".tox", ".venv", "__pycache__", "build", "coverage", "deps", "dist",
    "external", "generated", "node_modules", "target", "third_party", "tmp",
    "third-party", "vendor",
}

SUPPORT_PARTS = {"doc", "docs", "example", "examples", "fixture", "fixtures", "test", "tests"}
DORMANT_PARTS = {"disabled", "remote_disabled", "dormant"}
RESULT_MARKERS = ("_vulnhunt_results_", "vulnhunt-results", ".vulnhunter")

INCLUDED_NAMES = {
    "AGENTS.md", "Containerfile", "Dockerfile", "Gemfile", "Makefile",
    "Procfile", "Rakefile", "SECURITY.md", "go.mod", "go.sum", "package.json",
    "package-lock.json", "pnpm-lock.yaml", "requirements.txt", "uv.lock",
}

CRITICAL_PREFIXES = (
    ".azure/",
    ".buildkite/",
    ".circleci/",
    ".github/",
    ".github/workflows/",
    ".gitlab/",
    "deploy/",
    "deployment/",
    "infra/",
    "k8s/",
    "kubernetes/",
    "migrations/",
    "terraform/",
)


@dataclass(frozen=True)
class SecuritySurface:
    surface_id: str
    boundary: str
    family: str
    priority: str
    files: list[str]
    mandatory: bool = True
    entrypoints: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RepositoryInventory:
    root: Path
    files: list[str]
    total_bytes: int
    languages: dict[str, int]
    production_files: list[str] = field(default_factory=list)
    dormant_files: list[str] = field(default_factory=list)
    support_files: list[str] = field(default_factory=list)
    excluded_files: list[str] = field(default_factory=list)
    surfaces: list[SecuritySurface] = field(default_factory=list)
    snapshot_digest: str = ""
    line_count: int = 0
    symbol_count: int = 0


@dataclass(frozen=True)
class Partition:
    partition_id: str
    files: list[str]
    total_bytes: int
    boundary: str = "general"
    surface_ids: list[str] = field(default_factory=list)


def build_inventory(root: Path, *, include_dormant: bool = False) -> RepositoryInventory:
    resolved = root.resolve()
    if not resolved.is_dir():
        raise FileNotFoundError(f"repository directory not found: {root}")

    production: list[str] = []
    dormant: list[str] = []
    support: list[str] = []
    excluded: list[str] = []
    sizes: dict[str, int] = {}
    languages: dict[str, int] = {}
    line_count = 0
    symbol_count = 0
    digest = hashlib.sha256()
    ignored = _git_ignored_paths(resolved)

    for path in resolved.rglob("*"):
        if not path.is_file():
            continue
        rel_path = path.relative_to(resolved)
        rel = rel_path.as_posix()
        lowered = rel.lower()
        parts = {part.lower() for part in rel_path.parts}
        try:
            path.resolve().relative_to(resolved)
        except (OSError, ValueError):
            excluded.append(rel)
            continue

        if (
            parts & HARD_EXCLUDED_PARTS
            or any(marker in lowered for marker in RESULT_MARKERS)
            or _is_generated_mobile_web_asset(rel)
            or path.name in {"run_manifest.json", "run_state.json", "scan_manifest.json"}
            or _looks_secret(path.name)
            or rel in ignored
        ):
            excluded.append(rel)
            continue

        security_config = _is_security_config(rel)
        extension = path.suffix.lower()
        recognized = (
            extension in SOURCE_EXTENSIONS
            or path.name in INCLUDED_NAMES
            or security_config
            or _recognized_dormant_name(path.name)
        )
        if not recognized:
            excluded.append(rel)
            continue

        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        sizes[rel] = size

        if _is_dormant(rel_path):
            dormant.append(rel)
            continue
        if parts & SUPPORT_PARTS or _is_test_file(path.name):
            support.append(rel)
            continue
        production.append(rel)

    selected = sorted(production + (dormant if include_dormant else []))
    # Snapshot identity includes all classified repository inputs, even support
    # files and dormant files that are outside the current production scope.
    for rel in sorted(production + dormant + support):
        source_path = resolved / rel
        extension = source_path.suffix.lower().lstrip(".") or "config"
        languages[extension] = languages.get(extension, 0) + 1
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        try:
            with source_path.open("rb") as handle:
                content = bytearray()
                newlines = 0
                last_byte: int | None = None
                while chunk := handle.read(1024 * 1024):
                    digest.update(chunk)
                    if rel in selected:
                        newlines += chunk.count(b"\n")
                        last_byte = chunk[-1]
                        if len(content) < 2_000_000:
                            content.extend(chunk[: 2_000_000 - len(content)])
            if rel in selected:
                text = bytes(content).decode("utf-8", errors="ignore")
                line_count += newlines + bool(last_byte is not None and last_byte != 10)
                symbol_count += _approximate_symbol_count(text, source_path.suffix)
        except OSError:
            digest.update(b"<unreadable>")
        digest.update(b"\0")

    surfaces = classify_security_surfaces(resolved, selected)
    return RepositoryInventory(
        root=resolved,
        files=selected,
        total_bytes=sum(sizes.get(rel, 0) for rel in selected),
        languages=dict(sorted(languages.items())),
        production_files=sorted(production),
        dormant_files=sorted(dormant),
        support_files=sorted(support),
        excluded_files=sorted(excluded),
        surfaces=surfaces,
        snapshot_digest=digest.hexdigest(),
        line_count=line_count,
        symbol_count=symbol_count,
    )


def _approximate_symbol_count(text: str, extension: str) -> int:
    """Count likely callable declarations for workload estimation, not analysis."""

    suffix = extension.lower()
    patterns = [
        r"(?m)^\s*(?:async\s+)?def\s+[A-Za-z_]\w*\s*\(",
        r"(?m)^\s*func\s+(?:\([^)]*\)\s*)?[A-Za-z_]\w*\s*\(",
        r"(?m)^\s*(?:public|private|protected|internal|static|final|abstract|"
        r"suspend|override|open|\s)+\s*[A-Za-z_$][\w$<>, ?\[\]]*\s+"
        r"[A-Za-z_$][\w$]*\s*\([^;]*\)\s*(?:\{|=>)",
        r"(?m)^\s*(?:export\s+)?(?:async\s+)?function\s+[A-Za-z_$][\w$]*\s*\(",
        r"(?m)^\s*(?:export\s+)?(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*"
        r"=\s*(?:async\s*)?\([^)]*\)\s*=>",
    ]
    if suffix not in {
        ".c", ".cc", ".cpp", ".cs", ".go", ".h", ".hpp", ".java", ".js",
        ".jsx", ".kt", ".kts", ".php", ".py", ".rb", ".rs", ".scala",
        ".swift", ".ts", ".tsx",
    }:
        return 0
    return sum(len(re.findall(pattern, text)) for pattern in patterns)


def classify_security_surfaces(root: Path, files: list[str]) -> list[SecuritySurface]:
    grouped: dict[tuple[str, str, str], list[str]] = {}
    for rel in files:
        boundary, family, priority = _boundary_for(rel, root / rel)
        grouped.setdefault((boundary, family, priority), []).append(rel)
    surfaces: list[SecuritySurface] = []
    for index, ((boundary, family, priority), members) in enumerate(
        sorted(grouped.items()), 1
    ):
        surfaces.append(
            SecuritySurface(
                surface_id=f"SURF-{index:04d}",
                boundary=boundary,
                family=family,
                priority=priority,
                files=sorted(members),
                mandatory=priority in {"critical", "high"},
            )
        )
    return surfaces


def partition_inventory(
    inventory: RepositoryInventory,
    *,
    target_bytes: int = 150_000,
    max_files: int = 15,
) -> list[Partition]:
    """Build coherent boundary shards rather than lexicographic byte buckets."""
    partitions: list[Partition] = []
    surfaces = inventory.surfaces or [
        SecuritySurface("SURF-0001", "general", "general", "normal", inventory.files)
    ]
    for surface in surfaces:
        current: list[str] = []
        current_bytes = 0
        for rel in surface.files:
            try:
                size = (inventory.root / rel).stat().st_size
            except OSError:
                size = 0
            if current and (
                current_bytes + size > target_bytes or len(current) >= max_files
            ):
                partitions.append(
                    _partition(partitions, surface, current, current_bytes)
                )
                current, current_bytes = [], 0
            current.append(rel)
            current_bytes += size
        if current:
            partitions.append(_partition(partitions, surface, current, current_bytes))
    if not partitions:
        partitions.append(Partition("SG-1", [], 0))
    return partitions


def _partition(
    existing: list[Partition],
    surface: SecuritySurface,
    files: list[str],
    total_bytes: int,
) -> Partition:
    return Partition(
        partition_id=f"SG-{len(existing) + 1}",
        files=list(files),
        total_bytes=total_bytes,
        boundary=surface.boundary,
        surface_ids=[surface.surface_id],
    )


def _boundary_for(relative: str, path: Path) -> tuple[str, str, str]:
    rel = relative.lower()
    name = path.name.lower()
    content = ""
    try:
        if path.stat().st_size <= 500_000:
            content = path.read_text(encoding="utf-8", errors="replace").lower()
    except OSError:
        pass
    if rel.startswith(".github/workflows/") or any(
        token in rel for token in ("deploy", "release", "jenkins", "circleci")
    ):
        return ("ci-deployment-supply-chain", "supply-chain", "critical")
    if any(token in rel for token in ("auth", "session", "oauth", "saml", "jwt")):
        return ("authentication-session", "authentication", "critical")
    if any(token in rel for token in ("permission", "policy", "rls", "iam", "role")):
        return ("authorization-tenant-isolation", "authorization", "critical")
    if (
        any(token in rel for token in ("service", "repository", "data"))
        and any(
            token in content
            for token in (
                "service_role",
                "service-role",
                "bypass rls",
                "admin client",
                "privileged client",
            )
        )
    ) or (
        any(token in rel for token in ("service", "repository"))
        and any(
            token in content
            for token in (
                "phone_number",
                "external_id",
                "customer_id",
                "subject_id",
                "account_number",
            )
        )
        and any(token in content for token in (".select(", ".find(", ".where(", ".from("))
        and any(token in content for token in (".insert(", ".update(", ".upsert(", ".save("))
    ):
        return ("authorization-tenant-isolation", "authorization", "critical")
    if rel.endswith("androidmanifest.xml") or any(
        token in rel for token in ("deeplink", "intent", "fileprovider")
    ):
        return ("mobile-exported-local-data", "mobile", "high")
    if any(token in rel for token in ("route", "controller", "handler", "function")):
        return ("public-api-parser", "api", "high")
    if any(token in rel for token in ("upload", "archive", "storage", "file", "path")):
        return ("file-storage-archive", "filesystem", "high")
    if any(token in rel for token in ("http", "client", "request", "webhook", "callback")):
        return ("network-ssrf-callback", "network", "high")
    if name in INCLUDED_NAMES or path.suffix.lower() in {
        ".cfg", ".conf", ".gradle", ".hcl", ".kts", ".lock", ".properties",
        ".tf", ".toml", ".yaml", ".yml",
    }:
        return ("secrets-configuration", "configuration", "high")
    return ("language-dangerous-sinks", "general", "normal")


def _is_security_config(relative: str) -> bool:
    rel = relative.lower().replace("\\", "/")
    return (
        rel.startswith(CRITICAL_PREFIXES)
        or rel.endswith(("dockerfile", "containerfile"))
        or any(
            token in rel
            for token in (
                "security",
                "policy",
                "permissions",
                "signing",
                "sigstore",
                "release",
                "deploy",
                "iam",
            )
        )
    )


def _is_generated_mobile_web_asset(relative: str) -> bool:
    """Exclude copied/minified web build output embedded in mobile packages."""

    rel = relative.lower().replace("\\", "/")
    return (
        "/android/app/src/main/assets/public/assets/" in f"/{rel}"
        or "/ios/app/app/public/assets/" in f"/{rel}"
    )


def _is_dormant(path: Path) -> bool:
    parts = {part.lower() for part in path.parts}
    name = path.name.lower()
    return bool(
        parts & DORMANT_PARTS
        or name.endswith((".bak", ".disabled", ".off", ".old"))
    )


def _recognized_dormant_name(name: str) -> bool:
    lowered = name.lower()
    for suffix in (".bak", ".disabled", ".off", ".old"):
        if lowered.endswith(suffix):
            return Path(lowered[: -len(suffix)]).suffix in SOURCE_EXTENSIONS
    return False


def _looks_secret(name: str) -> bool:
    lowered = name.lower()
    return lowered == ".env" or lowered.startswith(".env.") or lowered in {
        "id_rsa", "id_ed25519", "credentials.json",
    }


def _is_test_file(name: str) -> bool:
    lowered = name.lower()
    return (
        lowered.startswith("test_")
        or lowered.endswith("_test.go")
        or ".test." in lowered
        or ".spec." in lowered
        or lowered.endswith("test.java")
        or lowered.endswith("spec.scala")
    )


def _git_ignored_paths(root: Path) -> set[str]:
    """Return ignored, untracked files without making Git a hard dependency."""

    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "ls-files",
                "--others",
                "--ignored",
                "--exclude-standard",
                "-z",
            ],
            capture_output=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    if result.returncode != 0:
        return set()
    return {
        value.decode("utf-8", errors="surrogateescape").replace("\\", "/")
        for value in result.stdout.split(b"\0")
        if value
    }
