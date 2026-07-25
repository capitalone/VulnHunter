"""Bounded repository tools exposed to model workers."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .sandbox import DockerSandbox


MAX_FILE_BYTES = 1_000_000
MAX_TOOL_OUTPUT_CHARS = 100_000
MAX_SEARCH_MATCHES = 500


TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "list_files",
        "description": "List repository-relative files matching an optional glob.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 2000},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "search_text",
        "description": "Search production files using a regular expression.",
        "input_schema": {
            "type": "object",
            "required": ["pattern"],
            "properties": {
                "pattern": {"type": "string", "maxLength": 1000},
                "paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "maxItems": 200,
                },
                "case_sensitive": {"type": "boolean"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 500},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "read_file",
        "description": "Read a bounded line range from a repository file.",
        "input_schema": {
            "type": "object",
            "required": ["path"],
            "properties": {
                "path": {"type": "string"},
                "start_line": {"type": "integer", "minimum": 1},
                "end_line": {"type": "integer", "minimum": 1},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "find_symbol",
        "description": "Find likely definitions and references for a symbol.",
        "input_schema": {
            "type": "object",
            "required": ["symbol"],
            "properties": {
                "symbol": {"type": "string", "maxLength": 200},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "write_artifact",
        "description": (
            "Write a bounded scanner artifact outside the source snapshot. "
            "This never modifies repository files."
        ),
        "input_schema": {
            "type": "object",
            "required": ["path", "content"],
            "properties": {
                "path": {"type": "string", "maxLength": 240},
                "content": {"type": "string", "maxLength": 100000},
            },
            "additionalProperties": False,
        },
    },
]


class RepositoryTools:
    def __init__(
        self,
        root: Path,
        *,
        allowed_files: set[str] | None = None,
        execute: bool = False,
        sandbox: DockerSandbox | None = None,
        artifact_dir: Path | None = None,
    ) -> None:
        self.root = root.resolve()
        self.allowed_files = allowed_files
        self.execute = execute
        self.sandbox = sandbox
        self.artifact_dir = artifact_dir.resolve() if artifact_dir else None

    @property
    def definitions(self) -> list[dict[str, Any]]:
        definitions = list(TOOL_DEFINITIONS)
        if self.execute:
            definitions.append(
                {
                    "name": "run_command",
                    "description": (
                        "Run an argument-array command through the configured sandbox."
                    ),
                    "input_schema": {
                        "type": "object",
                        "required": ["argv"],
                        "properties": {
                            "argv": {
                                "type": "array",
                                "items": {"type": "string"},
                                "minItems": 1,
                                "maxItems": 100,
                            },
                            "timeout_seconds": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 300,
                            },
                        },
                        "additionalProperties": False,
                    },
                }
            )
        return definitions

    def execute_call(self, name: str, arguments: dict[str, Any]) -> str:
        try:
            if name == "list_files":
                result = self.list_files(
                    str(arguments.get("pattern", "**/*")),
                    int(arguments.get("limit", 1000)),
                )
            elif name == "search_text":
                result = self.search_text(
                    str(arguments["pattern"]),
                    paths=arguments.get("paths"),
                    case_sensitive=bool(arguments.get("case_sensitive", False)),
                    limit=int(arguments.get("limit", 200)),
                )
            elif name == "read_file":
                result = self.read_file(
                    str(arguments["path"]),
                    start_line=int(arguments.get("start_line", 1)),
                    end_line=int(arguments.get("end_line", 400)),
                )
            elif name == "find_symbol":
                result = self.find_symbol(
                    str(arguments["symbol"]),
                    limit=int(arguments.get("limit", 100)),
                )
            elif name == "write_artifact":
                result = self.write_artifact(
                    str(arguments["path"]),
                    str(arguments["content"]),
                )
            elif name == "run_command":
                result = self.run_command(
                    arguments.get("argv", []),
                    timeout_seconds=int(arguments.get("timeout_seconds", 60)),
                )
            else:
                return json.dumps({"error": f"unknown tool {name!r}"})
            return _bounded(json.dumps({"ok": True, "result": result}))
        except Exception as exc:  # noqa: BLE001
            return _bounded(
                json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
            )

    def list_files(self, pattern: str = "**/*", limit: int = 1000) -> list[str]:
        limit = min(max(limit, 1), 2000)
        files: list[str] = []
        for path in self.root.glob(pattern):
            if not path.is_file():
                continue
            rel = path.relative_to(self.root).as_posix()
            if self._allowed(rel):
                files.append(rel)
            if len(files) >= limit:
                break
        return sorted(files)

    def search_text(
        self,
        pattern: str,
        *,
        paths: list[str] | None = None,
        case_sensitive: bool = False,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        flags = 0 if case_sensitive else re.IGNORECASE
        regex = re.compile(pattern, flags)
        limit = min(max(limit, 1), MAX_SEARCH_MATCHES)
        candidates = (
            [self._resolve(path) for path in paths]
            if paths
            else [self._resolve(path) for path in self.list_files(limit=2000)]
        )
        matches: list[dict[str, Any]] = []
        for path in candidates:
            if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
                continue
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for number, line in enumerate(lines, 1):
                if regex.search(line):
                    matches.append(
                        {
                            "path": path.relative_to(self.root).as_posix(),
                            "line": number,
                            "text": line[:500],
                        }
                    )
                    if len(matches) >= limit:
                        return matches
        return matches

    def read_file(self, path: str, *, start_line: int = 1, end_line: int = 400) -> str:
        target = self._resolve(path)
        if not target.is_file():
            raise FileNotFoundError(path)
        if target.stat().st_size > MAX_FILE_BYTES:
            raise ValueError(f"file exceeds {MAX_FILE_BYTES} byte tool limit")
        start = max(start_line, 1)
        end = min(max(end_line, start), start + 999)
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        selected = [
            f"{number}: {lines[number - 1]}"
            for number in range(start, min(end, len(lines)) + 1)
        ]
        return "\n".join(selected)

    def find_symbol(self, symbol: str, *, limit: int = 100) -> list[dict[str, Any]]:
        escaped = re.escape(symbol)
        definition = (
            rf"\b(?:def|class|function|func|fn|interface|struct|type)\s+{escaped}\b"
            rf"|\b{escaped}\s*[:=]\s*(?:function|\()"
        )
        results = self.search_text(definition, limit=max(1, limit // 2))
        if len(results) < limit:
            references = self.search_text(rf"\b{escaped}\b", limit=limit - len(results))
            seen = {(row["path"], row["line"]) for row in results}
            results.extend(
                row
                for row in references
                if (row["path"], row["line"]) not in seen
            )
        return results[:limit]

    def run_command(self, argv: list[str], *, timeout_seconds: int = 60) -> dict[str, Any]:
        if not self.execute:
            raise PermissionError("target code execution was not enabled")
        if self.sandbox is None:
            raise PermissionError("no Docker sandbox is configured")
        if not argv or not all(isinstance(item, str) and item for item in argv):
            raise ValueError("argv must be a non-empty string array")
        return self.sandbox.run(argv, timeout_seconds=timeout_seconds)

    def write_artifact(self, path: str, content: str) -> str:
        if self.artifact_dir is None:
            raise PermissionError("artifact writing is unavailable")
        if len(content) > MAX_TOOL_OUTPUT_CHARS:
            raise ValueError(
                f"artifact exceeds {MAX_TOOL_OUTPUT_CHARS} character limit"
            )
        if not path or "\x00" in path:
            raise ValueError("invalid artifact path")
        destination = (self.artifact_dir / path).resolve()
        try:
            destination.relative_to(self.artifact_dir)
        except ValueError as exc:
            raise PermissionError(f"artifact path escapes output root: {path}") from exc
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
        return destination.relative_to(self.artifact_dir).as_posix()

    def _allowed(self, relative: str) -> bool:
        return self.allowed_files is None or relative in self.allowed_files

    def _resolve(self, relative: str) -> Path:
        if not relative or "\x00" in relative:
            raise ValueError("invalid empty or NUL-containing path")
        candidate = (self.root / relative).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise PermissionError(f"path escapes repository root: {relative}") from exc
        rel = candidate.relative_to(self.root).as_posix()
        if not self._allowed(rel):
            raise PermissionError(f"path is outside this assignment scope: {relative}")
        return candidate

def _bounded(value: str) -> str:
    if len(value) <= MAX_TOOL_OUTPUT_CHARS:
        return value
    return value[:MAX_TOOL_OUTPUT_CHARS] + "\n...[tool output truncated]"
