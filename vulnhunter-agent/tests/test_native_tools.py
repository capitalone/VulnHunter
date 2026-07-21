from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnhunter.inventory import build_inventory
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
