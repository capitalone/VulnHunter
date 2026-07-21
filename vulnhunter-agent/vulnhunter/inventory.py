"""Deterministic repository inventory and partitioning."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


SOURCE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cfg",
    ".conf",
    ".cpp",
    ".cs",
    ".gradle",
    ".go",
    ".h",
    ".hcl",
    ".hpp",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".kts",
    ".php",
    ".properties",
    ".proto",
    ".py",
    ".rb",
    ".rs",
    ".scala",
    ".sh",
    ".sol",
    ".sql",
    ".swift",
    ".tf",
    ".ts",
    ".tsx",
    ".vue",
    ".xml",
    ".yaml",
    ".yml",
}

EXCLUDED_PARTS = {
    ".git",
    ".venv",
    "build",
    "coverage",
    "deps",
    "dist",
    "docs",
    "examples",
    "external",
    "generated",
    "node_modules",
    "test",
    "tests",
    "third_party",
    "third-party",
    "vendor",
}

INCLUDED_NAMES = {
    "Containerfile",
    "Dockerfile",
    "Gemfile",
    "Makefile",
    "Procfile",
    "Rakefile",
    "go.mod",
    "package.json",
    "requirements.txt",
}


@dataclass(frozen=True)
class RepositoryInventory:
    root: Path
    files: list[str]
    total_bytes: int
    languages: dict[str, int]


@dataclass(frozen=True)
class Partition:
    partition_id: str
    files: list[str]
    total_bytes: int


def build_inventory(root: Path) -> RepositoryInventory:
    resolved = root.resolve()
    if not resolved.is_dir():
        raise FileNotFoundError(f"repository directory not found: {root}")
    files: list[str] = []
    total_bytes = 0
    languages: dict[str, int] = {}
    for path in resolved.rglob("*"):
        if not path.is_file():
            continue
        rel_path = path.relative_to(resolved)
        rel_parts = {part.lower() for part in rel_path.parts}
        if rel_parts & EXCLUDED_PARTS:
            continue
        if _is_test_file(path.name):
            continue
        extension = path.suffix.lower()
        if extension not in SOURCE_EXTENSIONS and path.name not in INCLUDED_NAMES:
            continue
        rel = rel_path.as_posix()
        files.append(rel)
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        total_bytes += size
        languages[extension.lstrip(".")] = languages.get(extension.lstrip("."), 0) + 1
    return RepositoryInventory(
        root=resolved,
        files=sorted(files),
        total_bytes=total_bytes,
        languages=dict(sorted(languages.items())),
    )


def partition_inventory(
    inventory: RepositoryInventory,
    *,
    target_bytes: int = 200_000,
    max_files: int = 80,
) -> list[Partition]:
    partitions: list[Partition] = []
    current: list[str] = []
    current_bytes = 0
    for rel in inventory.files:
        path = inventory.root / rel
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        if current and (current_bytes + size > target_bytes or len(current) >= max_files):
            partitions.append(
                Partition(
                    partition_id=f"SG-{len(partitions) + 1}",
                    files=current,
                    total_bytes=current_bytes,
                )
            )
            current = []
            current_bytes = 0
        current.append(rel)
        current_bytes += size
    if current or not partitions:
        partitions.append(
            Partition(
                partition_id=f"SG-{len(partitions) + 1}",
                files=current,
                total_bytes=current_bytes,
            )
        )
    return partitions


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
