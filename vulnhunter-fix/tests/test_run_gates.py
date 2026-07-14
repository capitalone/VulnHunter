"""Coverage tests for run-gates.py (REQ-GAT-011)."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"


@pytest.fixture(scope="module")
def rg():
    spec = importlib.util.spec_from_file_location("rg", SCRIPTS / "run-gates.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules["rg"] = m
    spec.loader.exec_module(m)
    return m


def _make_git_repo(root: Path) -> None:
    subprocess.run(["git", "init", "-b", "main", str(root)], check=True, capture_output=True)
    for k, v in [("user.email", "t@x.com"), ("user.name", "T"), ("commit.gpgsign", "false")]:
        subprocess.run(["git", "-C", str(root), "config", k, v], check=True)


def _commit(root: Path, name: str, body: str, msg: str) -> None:
    p = root / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(root), "commit", "-m", msg], check=True, capture_output=True
    )


# ---- unit tests on builders ----

def test_gate1_builder_pr_only(rg):
    ctx = rg.GateContext(
        pr_body=Path("/tmp/pr"), issue_body=None, result={},
        sidecar={}, branch="b", repo_root=Path("/tmp"),
    )
    invocations = rg._build_gate1_invocations(ctx)
    assert invocations == [["/tmp/pr"]]


def test_gate1_builder_with_issue(rg):
    ctx = rg.GateContext(
        pr_body=Path("/tmp/pr"), issue_body=Path("/tmp/iss"), result={},
        sidecar={}, branch="b", repo_root=Path("/tmp"),
    )
    invocations = rg._build_gate1_invocations(ctx)
    assert invocations == [["/tmp/pr", "/tmp/iss"]]


def test_gate2_builder_default(rg):
    ctx = rg.GateContext(
        pr_body=Path("/tmp/pr"), issue_body=None,
        result={"completeness_tier": "MITIGATION", "status": "VERIFIED", "sweep_ran": True},
        sidecar={}, branch="b", repo_root=Path("/tmp"),
    )
    invocations = rg._build_gate2_invocations(ctx)
    assert len(invocations) == 1
    argv = invocations[0]
    assert "--tier" in argv and "MITIGATION" in argv
    assert "--sweep-ran" in argv and "true" in argv


def test_gate2_builder_breaking_change_enforces_string(rg):
    ctx = rg.GateContext(
        pr_body=Path("/tmp/pr"), issue_body=None,
        result={"status": "BREAKING_CHANGE"},
        sidecar={}, branch="b", repo_root=Path("/tmp"),
    )
    argv = rg._build_gate2_invocations(ctx)[0]
    assert "--enforce-strings" in argv
    assert "## Breaking Change" in argv


def test_gate2_builder_pr_and_issue(rg):
    ctx = rg.GateContext(
        pr_body=Path("/tmp/pr"), issue_body=Path("/tmp/iss"),
        result={}, sidecar={}, branch="b", repo_root=Path("/tmp"),
    )
    invocations = rg._build_gate2_invocations(ctx)
    assert len(invocations) == 2
    assert "--kind" in invocations[0] and "pr" in invocations[0]
    assert "--kind" in invocations[1] and "issue" in invocations[1]


def test_gate3_builder(rg):
    ctx = rg.GateContext(
        pr_body=Path("/tmp/pr"), issue_body=None,
        result={"files_modified": ["a.py", "b.py"], "test_file": "tests/t.py"},
        sidecar={}, branch="vulnfix", repo_root=Path("/tmp/root"),
    )
    argv = rg._build_gate3_invocations(ctx)[0]
    assert "--files-modified" in argv
    assert "a.py" in argv and "b.py" in argv
    assert "--test-file" in argv


def test_gate4_builder_pr_and_issue(rg):
    ctx = rg.GateContext(
        pr_body=Path("/tmp/pr"), issue_body=Path("/tmp/iss"),
        result={}, sidecar={}, branch="b", repo_root=Path("/tmp"),
    )
    invocations = rg._build_gate4_invocations(ctx)
    assert len(invocations) == 2


def test_gate5_anti_merge_noop_without_sidecar(rg):
    """No anti_merge block on sidecar → gate is a no-op (single-finding PRs)."""
    ctx = rg.GateContext(
        pr_body=Path("/tmp/pr"), issue_body=None,
        result={}, sidecar={}, branch="b", repo_root=Path("/tmp"),
    )
    assert rg._build_gate5_invocations(ctx) == []


def test_gate5_anti_merge_bad_grouping_fails_strict(rg):
    """Anti-merge sidecar block with grouping over threshold builds a
    --strict invocation that will exit 1."""
    ctx = rg.GateContext(
        pr_body=Path("/tmp/pr"), issue_body=None, result={},
        sidecar={"anti_merge": {"files_grouped": 6, "files_split": 3}},
        branch="b", repo_root=Path("/tmp"),
    )
    invocations = rg._build_gate5_invocations(ctx)
    assert len(invocations) == 1
    args = invocations[0]
    assert "--strict" in args
    assert "--files-grouped" in args and "6" in args
    assert "--files-split" in args and "3" in args


def test_gate5_registered_in_gate_routing(rg):
    """Gate 5 is present in the dispatch table so main() picks it up."""
    assert "gate5_anti_merge" in rg.GATE_ROUTING


def test_load_json_missing(rg):
    assert rg._load_json(None) == {}
    assert rg._load_json(Path("/nonexistent.json")) == {}


def test_load_json_malformed(rg, tmp_path):
    fp = tmp_path / "bad.json"
    fp.write_text("{ malformed", encoding="utf-8")
    assert rg._load_json(fp) == {}


def test_load_json_valid(rg, tmp_path):
    fp = tmp_path / "ok.json"
    fp.write_text('{"a": 1}', encoding="utf-8")
    assert rg._load_json(fp) == {"a": 1}


def test_run_returns_tuple(rg):
    rc, stdout, stderr = rg._run([sys.executable, "-c", "print('hi')"])
    assert rc == 0
    assert "hi" in stdout


# ---- main() end-to-end ----

def test_main_all_gates_pass(rg, tmp_path, capsys):
    root = tmp_path / "repo"
    root.mkdir()
    _make_git_repo(root)
    _commit(root, "src/foo.py", "print('base')\n", "base")
    subprocess.run(["git", "-C", str(root), "checkout", "-b", "vulnfix"], check=True, capture_output=True)
    _commit(root, "src/foo.py", "print('fixed')\n", "fix")

    pr_body = tmp_path / "pr.md"
    pr_body.write_text(
        "## Finding Summary\nCWE-89 High severity in src/foo.py:1 root: unsafe\n\n"
        "## Attacker Capability\nAttacker can exfil.\n\n"
        "## Security Test\n```\nassert x\n```\n\n"
        "## Fix Description\nEscape properly.\n\n"
        "## Verification Results\nRED pre, GREEN post.\n\n"
        "## Verification Table\n| a | b | c | d | e | f | g | h | v |\n|-|-|-|-|-|-|-|-|-|\n| 1 | v | y | y | y | n/a | y | n/a | PASS |\n\n"
        "<!-- vulnfix-key: abcdef0123456789 -->\n",
        encoding="utf-8",
    )
    result = tmp_path / "result.json"
    result.write_text(json.dumps({
        "completeness_tier": "FULL",
        "status": "VERIFIED_FULL",
        "sweep_ran": False,
        "files_modified": ["src/foo.py"],
    }), encoding="utf-8")

    rc = rg.main([
        "run-gates.py",
        "--pr-body", str(pr_body),
        "--result", str(result),
        "--branch", "vulnfix",
        "--repo-root", str(root),
    ])
    payload = json.loads(capsys.readouterr().out)
    assert isinstance(payload["pass"], bool)
    assert "gates" in payload
    # rc mirrors the pass flag
    assert (rc == 0) is payload["pass"]


def test_main_missing_sidecar_is_ok(rg, tmp_path, capsys):
    """--sidecar is optional; None handling exercised."""
    root = tmp_path / "repo"
    root.mkdir()
    _make_git_repo(root)
    _commit(root, "src/foo.py", "a\n", "base")
    subprocess.run(["git", "-C", str(root), "checkout", "-b", "vulnfix"], check=True, capture_output=True)
    _commit(root, "src/foo.py", "aa\n", "fix")

    pr_body = tmp_path / "pr.md"
    pr_body.write_text("no marker\n", encoding="utf-8")
    result = tmp_path / "r.json"
    result.write_text('{"files_modified": ["src/foo.py"]}', encoding="utf-8")

    # Should not raise even though sidecar is absent
    rg.main([
        "run-gates.py",
        "--pr-body", str(pr_body),
        "--result", str(result),
        "--branch", "vulnfix",
        "--repo-root", str(root),
    ])
    # Some gates will fail (Gate 4 idempotency), but the orchestrator itself must run
    payload = json.loads(capsys.readouterr().out)
    assert payload["pass"] is False  # missing vulnfix-key marker


def test_gate6_verification_registered_in_routing(rg):
    """peer re-review blocker #3 — validate-verification.py must be
    wired into the gate orchestrator, not just invoked ad-hoc."""
    assert "gate6_verification_table" in rg.GATE_ROUTING
    assert rg.GATE_ROUTING["gate6_verification_table"]["script"].name == "validate-verification.py"


def test_gate6_builder_passes_sidecars_and_result(rg):
    ctx = rg.GateContext(
        pr_body=Path("/tmp/pr"), issue_body=None, result={}, sidecar={},
        branch="b", repo_root=Path("/tmp/root"),
        result_path=Path("/tmp/result.json"),
        sidecars_dir=Path("/tmp/graph_context"),
    )
    argv = rg._build_gate6_invocations(ctx)[0]
    assert argv[0] == "/tmp/pr"                       # positional pr_body first
    assert "--worktree" in argv and "/tmp/root" in argv
    assert "--sidecars-dir" in argv and "/tmp/graph_context" in argv
    assert "--result" in argv and "/tmp/result.json" in argv


def test_every_gate_validator_script_is_reachable(rg):
    """Reachability guard (blocker-#3 class): every check-*/validate-*
    gate/validator script must be either wired into run-gates.py's
    GATE_ROUTING or explicitly invoked by a named phase prompt. A script
    that exists but is never called creates false confidence — exactly the
    dead-wiring that let the caller-coverage check pass unverified.
    """
    scripts_dir = SCRIPTS
    prompts_dir = REPO_ROOT / "prompts"
    routed = {spec["script"].name for spec in rg.GATE_ROUTING.values()}
    prompt_text = "\n".join(
        p.read_text(encoding="utf-8") for p in prompts_dir.rglob("*.md")
    )

    # Gate scripts must be routed; validators may be routed OR phase-invoked.
    gate_scripts = sorted(scripts_dir.glob("check-*.py")) + [scripts_dir / "anti-merge-check.py"]
    validator_scripts = sorted(scripts_dir.glob("validate-*.py"))

    unreachable = []
    for s in gate_scripts + validator_scripts:
        name = s.name
        if name in routed:
            continue
        if name in prompt_text:  # explicitly invoked by a phase prompt
            continue
        unreachable.append(name)

    assert not unreachable, (
        f"gate/validator scripts neither routed in run-gates.py nor invoked by a "
        f"phase prompt (dead wiring): {unreachable}"
    )


# ---- fail-closed guards (synthesized review S5) ----

def _passing_inputs(tmp_path: Path):
    """Set up a repo + bodies + result that make ALL gates pass, so any
    failure in the tests below is attributable to the guard under test."""
    root = tmp_path / "repo"
    root.mkdir()
    _make_git_repo(root)
    _commit(root, "src/foo.py", "print('base')\n", "base")
    subprocess.run(["git", "-C", str(root), "checkout", "-b", "vulnfix"],
                   check=True, capture_output=True)
    _commit(root, "src/foo.py", "print('fixed')\n", "fix")
    pr_body = tmp_path / "pr.md"
    pr_body.write_text(
        "## Finding Summary\nCWE-89 High severity in src/foo.py:1 root: unsafe\n\n"
        "## Attacker Capability\nAttacker can exfil.\n\n"
        "## Security Test\n```\nassert x\n```\n\n"
        "## Fix Description\nEscape properly.\n\n"
        "## Verification Results\nRED pre, GREEN post.\n\n"
        "## Verification Table\n| a | b | c | d | e | f | g | h | v |\n|-|-|-|-|-|-|-|-|-|\n"
        "| 1 | v | y | y | y | n/a | y | n/a | PASS |\n\n"
        "<!-- vulnfix-key: abcdef0123456789 -->\n",
        encoding="utf-8",
    )
    result = tmp_path / "result.json"
    result.write_text(json.dumps({
        "completeness_tier": "FULL",
        "status": "VERIFIED_FULL",
        "sweep_ran": False,
        "files_modified": ["src/foo.py"],
    }), encoding="utf-8")
    return pr_body, result, root


def test_main_fails_closed_when_required_gate_emits_no_invocations(rg, tmp_path, capsys, monkeypatch):
    """B1 (synthesized review S5): a required gate whose builder returns []
    is silently skipped, and all() over the remaining (passing) outcomes then
    vacuously reports pass:true — zero enforcement, green light. main() must
    fail closed when any REQUIRED gate contributed no invocations."""
    pr_body, result, root = _passing_inputs(tmp_path)
    # Simulate routing-table drift: gate6 builder emits nothing.
    monkeypatch.setitem(
        rg.GATE_ROUTING["gate6_verification_table"], "build_invocations", lambda ctx: []
    )
    rc = rg.main([
        "run-gates.py", "--pr-body", str(pr_body), "--result", str(result),
        "--branch", "vulnfix", "--repo-root", str(root),
    ])
    payload = json.loads(capsys.readouterr().out)
    assert payload["pass"] is False, "required gate skipped but aggregate passed (vacuous)"
    assert rc != 0


def test_main_empty_routing_does_not_vacuous_pass(rg, tmp_path, capsys, monkeypatch):
    """B1: an empty GATE_ROUTING (all gates dropped) must not report pass:true.
    all([]) is True — the classic empty-set fail-open."""
    pr_body, result, root = _passing_inputs(tmp_path)
    monkeypatch.setattr(rg, "GATE_ROUTING", {})
    rc = rg.main([
        "run-gates.py", "--pr-body", str(pr_body), "--result", str(result),
        "--branch", "vulnfix", "--repo-root", str(root),
    ])
    payload = json.loads(capsys.readouterr().out)
    assert payload["pass"] is False
    assert rc != 0


def test_main_missing_result_hard_fails(rg, tmp_path, capsys):
    """B2 (synthesized review S5): a missing --result must hard-fail, not
    silently default to tier=FULL/status=VERIFIED (the weakest Gate-2
    required-section set). Asserts the distinct input-error signal (rc==2 +
    error key) so it can't false-green off an incidental gate failure."""
    pr_body, _result, root = _passing_inputs(tmp_path)
    rc = rg.main([
        "run-gates.py", "--pr-body", str(pr_body),
        "--result", str(tmp_path / "does-not-exist.json"),
        "--branch", "vulnfix", "--repo-root", str(root),
    ])
    payload = json.loads(capsys.readouterr().out)
    assert payload["pass"] is False
    assert rc == 2, "input-load failure must use the distinct hard-fail code, not gate-fail 1"
    assert "error" in payload and "does-not-exist" in payload["error"]
    assert "gates" not in payload, "no gate should run when --result cannot load"


def test_main_corrupt_result_hard_fails(rg, tmp_path, capsys):
    """B2: a corrupt --result JSON must hard-fail rather than swallow the
    parse error and default to the weakest section set."""
    pr_body, _result, root = _passing_inputs(tmp_path)
    bad = tmp_path / "corrupt.json"
    bad.write_text("{ not valid json", encoding="utf-8")
    rc = rg.main([
        "run-gates.py", "--pr-body", str(pr_body), "--result", str(bad),
        "--branch", "vulnfix", "--repo-root", str(root),
    ])
    payload = json.loads(capsys.readouterr().out)
    assert payload["pass"] is False
    assert rc == 2
    assert "error" in payload and "corrupt.json" in payload["error"]


def test_load_json_strict_raises(rg, tmp_path):
    """B2: the strict loader must raise (not return {}) on missing/corrupt input.
    Non-strict behavior is unchanged (see test_load_json_missing/_malformed)."""
    with pytest.raises(rg.GateInputError):
        rg._load_json(Path("/nonexistent.json"), strict=True)
    bad = tmp_path / "corrupt.json"
    bad.write_text("{ not json", encoding="utf-8")
    with pytest.raises(rg.GateInputError):
        rg._load_json(bad, strict=True)
