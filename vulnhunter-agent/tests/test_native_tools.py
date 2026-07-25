from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnhunter.inventory import build_inventory
from vulnhunter.sandbox import DockerSandbox, SandboxPolicy, docker_status
from vulnhunter.tools import RepositoryTools


def test_repository_tools_are_bounded_to_root(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def handler(value):\n    return value\n")
    outside = tmp_path / "secret.txt"
    outside.write_text("secret")
    tools = RepositoryTools(repo)

    assert tools.list_files() == ["app.py"]
    assert "def handler" in tools.read_file("app.py")
    result = json.loads(tools.execute_call("read_file", {"path": "../secret.txt"}))
    assert result["ok"] is False
    assert "escapes repository root" in result["error"]


def test_symlink_escape_rejected(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("secret = True")
    link = repo / "link.py"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")
    tools = RepositoryTools(repo)
    with pytest.raises(PermissionError):
        tools.read_file("link.py")


def test_command_requires_explicit_sandbox(tmp_path: Path) -> None:
    tools = RepositoryTools(tmp_path, execute=True)
    with pytest.raises(PermissionError, match="sandbox"):
        tools.run_command(["python", "-V"])


def test_docker_status_distinguishes_installed_but_stopped(monkeypatch) -> None:
    class Completed:
        returncode = 1
        stdout = ""
        stderr = "daemon unavailable"

    monkeypatch.setattr("vulnhunter.sandbox.shutil.which", lambda _name: "docker")
    monkeypatch.setattr(
        "vulnhunter.sandbox.docker_desktop_executable",
        lambda: Path("Docker Desktop.exe"),
    )
    monkeypatch.setattr(
        "vulnhunter.sandbox.subprocess.run",
        lambda *_args, **_kwargs: Completed(),
    )

    status = docker_status("test-image")

    assert status["installed"] is True
    assert status["daemon_running"] is False
    assert status["desktop_installed"] is True
    assert status["available"] is False
    assert status["detail"] == "daemon unavailable"


def test_inventory_includes_security_relevant_manifests(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    (tmp_path / "package.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "policy.yaml").write_text("allow: false\n", encoding="utf-8")
    (tmp_path / ".env").write_text("SECRET=do-not-index\n", encoding="utf-8")

    inventory = build_inventory(tmp_path)

    assert inventory.files == ["Dockerfile", "package.json", "policy.yaml"]


def test_tool_scope_blocks_non_inventory_files(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('safe')\n", encoding="utf-8")
    (tmp_path / ".env").write_text("SECRET=hidden\n", encoding="utf-8")
    tools = RepositoryTools(tmp_path, allowed_files={"app.py"})

    assert tools.list_files() == ["app.py"]
    with pytest.raises(PermissionError, match="outside this assignment scope"):
        tools.read_file(".env")


def test_artifact_writes_are_bounded_outside_source(tmp_path: Path) -> None:
    source = tmp_path / "source"
    artifacts = tmp_path / "artifacts"
    source.mkdir()
    tools = RepositoryTools(source, artifact_dir=artifacts)

    result = tools.write_artifact("poc/reproduction.md", "static proof\n")

    assert result == "poc/reproduction.md"
    assert (artifacts / result).read_text() == "static proof\n"
    assert not (source / result).exists()
    with pytest.raises(PermissionError, match="escapes"):
        tools.write_artifact("../outside.txt", "blocked")


def test_docker_sandbox_uses_read_only_isolated_argument_array(
    monkeypatch, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    artifacts = tmp_path / "artifacts"
    source.mkdir()
    seen: dict[str, object] = {}

    class Completed:
        returncode = 0
        stdout = "token=super-secret-value\nok"
        stderr = ""

    def fake_run(command, **kwargs):
        seen["command"] = command
        seen["kwargs"] = kwargs
        return Completed()

    monkeypatch.setattr(
        "vulnhunter.sandbox.docker_status",
        lambda _image: {
            "available": True,
            "image_available": True,
            "detail": "ok",
        },
    )
    monkeypatch.setattr("vulnhunter.sandbox.shutil.which", lambda _name: "docker")
    monkeypatch.setattr("vulnhunter.sandbox.subprocess.run", fake_run)

    result = DockerSandbox(
        source,
        artifacts,
        SandboxPolicy(image="test-image", memory="1g", cpus=1, pids_limit=64),
    ).run(["python", "-m", "pytest"], timeout_seconds=30)

    command = seen["command"]
    assert command[:3] == ["docker", "run", "--rm"]
    assert "--read-only" in command
    assert "--cap-drop=ALL" in command
    assert "--security-opt=no-new-privileges" in command
    assert "--network" in command
    assert command[command.index("--network") + 1] == "none"
    assert (
        "/work:rw,exec,nosuid,size=1g,uid=10001,gid=10001,mode=0700"
        in command
    )
    assert "--pids-limit=64" in command
    assert "--memory=1g" in command
    assert command[-4:] == ["test-image", "python", "-m", "pytest"]
    assert seen["kwargs"]["shell"] is False
    assert "super-secret-value" not in result["stdout"]


def test_docker_sandbox_refuses_unenforceable_public_only_network(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        "vulnhunter.sandbox.docker_status",
        lambda _image: {
            "available": True,
            "image_available": True,
            "detail": "ok",
        },
    )
    sandbox = DockerSandbox(
        tmp_path,
        tmp_path / "artifacts",
        SandboxPolicy(allow_network=True, allow_private_network=False),
    )

    with pytest.raises(PermissionError, match="internet-only"):
        sandbox.run(["true"])
