"""Tests for the committed-test-naming gate (REQ-GAT-013).

scripts/check-committed-test-naming.py fails delivery if a verify_/exploit_
scaffold was committed instead of being promoted to a discoverable,
repo-convention test name.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"


def _load(name: str, mod: str):
    spec = importlib.util.spec_from_file_location(mod, SCRIPTS / name)
    module = importlib.util.module_from_spec(spec)
    # Register before exec so dataclasses in the module can resolve their
    # own __module__ during annotation processing (run-gates.py GateContext).
    sys.modules[mod] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gate():
    return _load("check-committed-test-naming.py", "cctn")


@pytest.fixture(scope="module")
def rg():
    return _load("run-gates.py", "rg")


# ---- pure naming rule: offending_files ----

def test_flags_verify_scaffold(gate):
    assert gate.offending_files(["tests/verify_VULN_005_dom_xss.py"]) == [
        "tests/verify_VULN_005_dom_xss.py"
    ]


def test_flags_exploit_scaffold(gate):
    assert gate.offending_files(["tests/exploit_VULN_009.py"]) == [
        "tests/exploit_VULN_009.py"
    ]


def test_flags_hyphenated_vuln_id(gate):
    assert gate.offending_files(["a/verify_VULN-9.ts"]) == ["a/verify_VULN-9.ts"]


def test_promoted_name_is_clean(gate):
    clean = [
        "tests/test_dom_xss_pr_list.py",
        "web/hotels.security.test.ts",
        "internal/auth/auth_test.go",
        "c1_MOAP/web/index.html",
    ]
    assert gate.offending_files(clean) == []


def test_target_repo_verify_file_not_flagged(gate):
    # A target repo's own verify_email.py / exploit_utils.go must NOT trip the
    # gate — only the tool's VULN-anchored scaffolds do.
    assert gate.offending_files(["src/verify_email.py", "pkg/exploit_utils.go"]) == []


# ---- git integration: RED then GREEN ----

def _init_repo(root: Path) -> None:
    subprocess.run(["git", "init", "-b", "main", str(root)], check=True, capture_output=True)
    for k, v in [("user.email", "t@x.com"), ("user.name", "T"), ("commit.gpgsign", "false")]:
        subprocess.run(["git", "-C", str(root), "config", k, v], check=True, capture_output=True)
    (root / "seed.txt").write_text("seed\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(root), "commit", "-m", "base"], check=True, capture_output=True)


def _branch_commit(root: Path, rel: str) -> None:
    subprocess.run(["git", "-C", str(root), "checkout", "-b", "vulnfix/x"],
                   check=True, capture_output=True)
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("def test_x():\n    assert True\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(root), "commit", "-m", "fix"], check=True, capture_output=True)


def _commit_file(root: Path, rel: str, msg: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("def test_y():\n    assert True\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(root), "commit", "-m", msg], check=True, capture_output=True)


def test_gate_fails_on_committed_scaffold(gate, tmp_path):
    _init_repo(tmp_path)
    _branch_commit(tmp_path, "tests/verify_VULN_005_dom_xss.py")
    rc = gate.main(["check-committed-test-naming.py", "--repo-root", str(tmp_path)])
    assert rc == 1


def test_gate_passes_on_promoted_name(gate, tmp_path):
    _init_repo(tmp_path)
    _branch_commit(tmp_path, "tests/test_dom_xss_pr_list.py")
    rc = gate.main(["check-committed-test-naming.py", "--repo-root", str(tmp_path)])
    assert rc == 0


def test_gate_catches_scaffold_in_earlier_commit(gate, tmp_path):
    # Multi-finding cluster PR: scaffold leaked in commit 1, clean file is HEAD.
    # A HEAD-only scan would miss it; the base...HEAD diff catches it.
    _init_repo(tmp_path)
    _branch_commit(tmp_path, "tests/verify_VULN_005_dom_xss.py")   # earlier commit
    _commit_file(tmp_path, "tests/test_second_finding.py", "second")  # HEAD
    rc = gate.main(["check-committed-test-naming.py", "--repo-root", str(tmp_path),
                    "--base", "main"])
    assert rc == 1


def test_gate_auto_detects_master_default(gate, tmp_path):
    # Repo defaults to master, not main. With --base defaulting to "main" (which
    # does not resolve), the gate must auto-detect master and still catch the leak.
    subprocess.run(["git", "init", "-b", "master", str(tmp_path)], check=True, capture_output=True)
    for k, v in [("user.email", "t@x.com"), ("user.name", "T"), ("commit.gpgsign", "false")]:
        subprocess.run(["git", "-C", str(tmp_path), "config", k, v], check=True, capture_output=True)
    (tmp_path / "seed.txt").write_text("seed\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-m", "base"], check=True, capture_output=True)
    _branch_commit(tmp_path, "tests/verify_VULN_007.py")
    rc = gate.main(["check-committed-test-naming.py", "--repo-root", str(tmp_path)])
    assert rc == 1


def test_head_only_fallback_warns(gate, tmp_path, capsys):
    # No base resolves (single detached commit, no main/master). The gate must
    # still return based on HEAD's files, but WARN loudly so a pass in this mode
    # is not mistaken for a clean full-branch scan (multi-finding cluster PR case).
    subprocess.run(["git", "init", "-b", "wip", str(tmp_path)], check=True, capture_output=True)
    for k, v in [("user.email", "t@x.com"), ("user.name", "T"), ("commit.gpgsign", "false")]:
        subprocess.run(["git", "-C", str(tmp_path), "config", k, v], check=True, capture_output=True)
    (tmp_path / "tests" / "verify_VULN_001.py").parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / "tests" / "verify_VULN_001.py").write_text("x\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-m", "only"], check=True, capture_output=True)
    rc = gate.main(["check-committed-test-naming.py", "--repo-root", str(tmp_path),
                    "--base", "nonexistent-base"])
    assert rc == 1  # HEAD's added scaffold is still caught
    assert "WARNING" in capsys.readouterr().err


def test_gate_returns_2_on_git_error(gate, tmp_path):
    # A repo-root that isn't a git repo makes every git call fail; the gate must
    # surface that as exit code 2 (usage/git error), not a traceback or a false
    # clean pass. Also exercises the _git() TimeoutExpired/OSError guard's
    # returncode=2 contract downstream.
    not_a_repo = tmp_path / "plain"
    not_a_repo.mkdir()
    rc = gate.main(["check-committed-test-naming.py", "--repo-root", str(not_a_repo)])
    assert rc == 2


# ---- routing registration (mirrors test_gate6_verification_registered_in_routing) ----

def test_gate7_registered_in_routing(rg):
    assert "gate7_committed_test_naming" in rg.GATE_ROUTING
    assert rg.GATE_ROUTING["gate7_committed_test_naming"]["script"].name == (
        "check-committed-test-naming.py"
    )


def test_gate7_is_required(rg):
    assert "gate7_committed_test_naming" in rg.REQUIRED_GATES


def test_gate7_builder_passes_repo_root(rg):
    ctx = rg.GateContext(
        pr_body=Path("/tmp/pr.md"), issue_body=None, result={}, sidecar={},
        branch="vulnfix/x", repo_root=Path("/tmp/repo"),
    )
    argv = rg._build_gate7_invocations(ctx)[0]
    assert argv == ["--repo-root", "/tmp/repo"]


def test_gate7_builder_threads_default_branch(rg):
    # When the orchestrator knows the target repo's base branch, the builder
    # must pass it as --base so Gate 7 diffs the whole branch (base...HEAD).
    ctx = rg.GateContext(
        pr_body=Path("/tmp/pr.md"), issue_body=None, result={}, sidecar={},
        branch="vulnfix/x", repo_root=Path("/tmp/repo"), default_branch="master",
    )
    argv = rg._build_gate7_invocations(ctx)[0]
    assert argv == ["--repo-root", "/tmp/repo", "--base", "master"]
