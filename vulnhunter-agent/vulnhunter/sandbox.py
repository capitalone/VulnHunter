"""Built-in Docker validation sandbox."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_IMAGE = "vulnhunter-sandbox:0.3.0"


@dataclass(frozen=True)
class SandboxPolicy:
    image: str = DEFAULT_IMAGE
    memory: str = "2g"
    cpus: float = 2.0
    pids_limit: int = 256
    allow_network: bool = False
    allow_private_network: bool = False


def docker_status(image: str = DEFAULT_IMAGE) -> dict[str, Any]:
    executable = shutil.which("docker")
    desktop = docker_desktop_executable()
    if executable is None:
        return {
            "available": False,
            "installed": False,
            "daemon_running": False,
            "desktop_installed": desktop is not None,
            "desktop_executable": str(desktop) if desktop else None,
            "image": image,
            "image_available": False,
            "detail": "docker executable not found",
        }
    try:
        version = subprocess.run(
            [executable, "version", "--format", "{{json .Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "available": False,
            "installed": True,
            "daemon_running": False,
            "desktop_installed": desktop is not None,
            "desktop_executable": str(desktop) if desktop else None,
            "image": image,
            "image_available": False,
            "detail": f"Docker daemon check failed: {exc}",
        }
    if version.returncode != 0:
        return {
            "available": False,
            "installed": True,
            "daemon_running": False,
            "desktop_installed": desktop is not None,
            "desktop_executable": str(desktop) if desktop else None,
            "image": image,
            "image_available": False,
            "detail": version.stderr.strip() or "Docker daemon unavailable",
        }
    inspect = subprocess.run(
        [executable, "image", "inspect", image],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    return {
        "available": True,
        "installed": True,
        "daemon_running": True,
        "desktop_installed": desktop is not None,
        "desktop_executable": str(desktop) if desktop else None,
        "version": version.stdout.strip().strip('"'),
        "image": image,
        "image_available": inspect.returncode == 0,
        "resource_policy_supported": True,
        "network_isolation": {
            "disabled_by_default": True,
            "public_only_supported": False,
            "private_network_requires_explicit_opt_in": True,
        },
        "detail": "ok",
    }


def docker_desktop_executable() -> Path | None:
    """Locate Docker Desktop without assuming its daemon is already running."""

    candidates: list[Path] = []
    if sys.platform == "win32":
        for variable in ("ProgramFiles", "LOCALAPPDATA"):
            base = os.environ.get(variable)
            if base:
                candidates.append(
                    Path(base) / "Docker" / "Docker" / "Docker Desktop.exe"
                )
    elif sys.platform == "darwin":
        candidates.append(Path("/Applications/Docker.app"))
    else:
        candidates.extend(
            [
                Path("/opt/docker-desktop/bin/docker-desktop"),
                Path("/usr/bin/docker-desktop"),
            ]
        )
    return next((path for path in candidates if path.exists()), None)


def start_docker_desktop() -> tuple[bool, str]:
    """Start Docker Desktop without waiting for the daemon to become ready."""

    desktop = docker_desktop_executable()
    if desktop is None:
        return False, "Docker Desktop installation was not found"
    try:
        if sys.platform == "darwin":
            command = ["open", "-a", "Docker"]
        else:
            command = [str(desktop)]
        creationflags = 0
        if sys.platform == "win32":
            creationflags = (
                subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
            )
        subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            creationflags=creationflags,
        )
    except OSError as exc:
        return False, f"could not start Docker Desktop: {exc}"
    return True, f"started {desktop}"


def build_sandbox_image(context: Path, image: str = DEFAULT_IMAGE) -> None:
    executable = shutil.which("docker")
    if executable is None:
        raise RuntimeError("docker executable not found")
    completed = subprocess.run(
        [executable, "build", "--tag", image, str(context.resolve())],
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"Docker sandbox build failed ({completed.returncode})")


class DockerSandbox:
    def __init__(
        self,
        source: Path,
        artifacts: Path,
        policy: SandboxPolicy,
    ) -> None:
        self.source = source.resolve()
        self.artifacts = artifacts.resolve()
        self.policy = policy

    def run(self, argv: list[str], *, timeout_seconds: int = 60) -> dict[str, Any]:
        if not argv or not all(isinstance(item, str) and item for item in argv):
            raise ValueError("argv must be a non-empty string array")
        status = docker_status(self.policy.image)
        if not status["available"]:
            raise PermissionError(str(status["detail"]))
        if not status["image_available"]:
            raise PermissionError(
                f"sandbox image {self.policy.image!r} is not built; "
                "run `vulnhunter sandbox build`"
            )
        if self.policy.allow_network and not self.policy.allow_private_network:
            raise PermissionError(
                "restricted internet-only Docker egress is unavailable on this host; "
                "use the default network-disabled sandbox or explicitly add "
                "--allow-private-network"
            )

        docker = shutil.which("docker")
        assert docker is not None
        self.artifacts.mkdir(parents=True, exist_ok=True)
        command = [
            docker,
            "run",
            "--rm",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            f"--pids-limit={max(32, self.policy.pids_limit)}",
            f"--memory={self.policy.memory}",
            f"--cpus={max(0.25, self.policy.cpus)}",
            "--network",
            "bridge" if self.policy.allow_network else "none",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=256m",
            "--tmpfs",
            "/work:rw,exec,nosuid,size=1g,uid=10001,gid=10001,mode=0700",
            "--mount",
            f"type=bind,source={self.source},target=/source,readonly",
            "--mount",
            f"type=bind,source={self.artifacts},target=/artifacts",
            self.policy.image,
            *argv,
        ]
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=min(max(timeout_seconds, 1), 300),
            shell=False,
            check=False,
        )
        result = {
            "returncode": completed.returncode,
            "stdout": _redact(completed.stdout[:50_000]),
            "stderr": _redact(completed.stderr[:50_000]),
            "sandbox": {
                "backend": "docker",
                "image": self.policy.image,
                "network": "private" if self.policy.allow_network else "none",
            },
        }
        command_id = hashlib.sha256(
            ("\0".join(argv) + datetime.now(UTC).isoformat()).encode("utf-8")
        ).hexdigest()[:16]
        log_name = f"command-{command_id}.json"
        log = {
            "schema_version": "2",
            "timestamp": datetime.now(UTC).isoformat(),
            "argv": [_redact(value) for value in argv],
            **result,
        }
        _write_json_atomic(self.artifacts / log_name, log)
        result["command_log"] = f"validation_artifacts/{log_name}"
        return result


def _redact(value: str) -> str:
    """Redact common credential-shaped command output without storing secrets."""
    import re

    patterns = [
        r"(?i)(token|password|secret|api[_-]?key)\s*[:=]\s*([^\s,;]+)",
        r"\b(?:sk|ghp|github_pat)_[A-Za-z0-9_-]{12,}\b",
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    ]
    redacted = value
    for pattern in patterns:
        redacted = re.sub(
            pattern,
            lambda match: (
                f"{match.group(1)}=[REDACTED]" if match.lastindex else "[REDACTED]"
            ),
            redacted,
        )
    return redacted


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        temporary = Path(handle.name)
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
    temporary.replace(path)
