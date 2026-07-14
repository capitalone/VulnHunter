"""Coverage + integration tests for scripts/build_graph.py."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"


@pytest.fixture(scope="module")
def bg():
    spec = importlib.util.spec_from_file_location("bg", SCRIPTS / "build_graph.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules["bg"] = m
    spec.loader.exec_module(m)
    return m


def _seed_repo(root: Path) -> None:
    (root / "app.py").write_text(
        "def authenticate(user, pw):\n"
        "    return check_password(user, pw)\n"
        "def check_password(user, pw):\n"
        "    return user == 'admin'\n",
        encoding="utf-8",
    )


def test_builds_graph_to_cache(bg, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _seed_repo(repo)
    work = tmp_path / "work"
    assert bg.main(["build_graph.py", "--repo-root", str(repo), "--work-dir", str(work)]) == 0
    assert (work / "cache" / "graph.json").is_file()
    doc = json.loads((work / "cache" / "graph.json").read_text(encoding="utf-8"))
    assert doc["backend"] in ("ast", "grep", "none")


def test_repo_root_not_a_dir(bg, tmp_path, capsys):
    assert bg.main([
        "build_graph.py",
        "--repo-root", str(tmp_path / "nope"),
        "--work-dir", str(tmp_path / "work"),
    ]) == 2
    assert "not a directory" in capsys.readouterr().err


def test_sidecar_emission(bg, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _seed_repo(repo)
    work = tmp_path / "work"

    findings = tmp_path / "findings.json"
    findings.write_text(json.dumps({
        "findings": [
            {
                "id": "VULN-1",
                "title": "Weak auth",
                "cwe": "CWE-287",
                "severity": "High",
                "location": "app.py:authenticate",
                "status": "Confirmed",
            },
            {
                "id": "VULN-2",
                "title": "Injection",
                "cwe": "CWE-89",
                "severity": "High",
                "location": "app.py:check_password",
                "status": "Confirmed",
            },
        ]
    }), encoding="utf-8")

    rc = bg.main([
        "build_graph.py",
        "--repo-root", str(repo),
        "--work-dir", str(work),
        "--findings", str(findings),
    ])
    # 0 (ast) or 3 (grep fallback) both acceptable — the sidecars still land.
    assert rc in (0, 3)

    for vuln in ("VULN-1", "VULN-2"):
        sc_path = work / "graph_context" / f"{vuln}.json"
        assert sc_path.is_file(), f"missing sidecar for {vuln}"
        sc = json.loads(sc_path.read_text(encoding="utf-8"))
        assert sc["vuln_id"] == vuln
        assert sc["confidence"] in ("high", "low")
        assert sc["graph_backend"] in ("ast", "grep", "none")
        assert "callers_of_sink" in sc


def test_sidecar_list_shape(bg, tmp_path):
    """findings payload as a bare list should also work."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _seed_repo(repo)
    work = tmp_path / "work"
    findings = tmp_path / "f.json"
    findings.write_text(json.dumps([
        {"id": "VULN-9", "cwe": "CWE-89", "location": "app.py:authenticate"},
    ]), encoding="utf-8")
    rc = bg.main([
        "build_graph.py",
        "--repo-root", str(repo),
        "--work-dir", str(work),
        "--findings", str(findings),
    ])
    assert rc in (0, 3)
    assert (work / "graph_context" / "VULN-9.json").is_file()


def test_sidecar_single_finding(bg, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _seed_repo(repo)
    work = tmp_path / "work"
    findings = tmp_path / "f.json"
    findings.write_text(json.dumps(
        {"id": "VULN-42", "cwe": "CWE-89", "location": "app.py:authenticate"}
    ), encoding="utf-8")
    rc = bg.main([
        "build_graph.py",
        "--repo-root", str(repo),
        "--work-dir", str(work),
        "--findings", str(findings),
    ])
    assert rc in (0, 3)
    assert (work / "graph_context" / "VULN-42.json").is_file()


def test_findings_missing_file(bg, tmp_path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    _seed_repo(repo)
    rc = bg.main([
        "build_graph.py",
        "--repo-root", str(repo),
        "--work-dir", str(tmp_path / "work"),
        "--findings", str(tmp_path / "nope.json"),
    ])
    assert rc == 2


def test_findings_bad_json(bg, tmp_path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    _seed_repo(repo)
    findings = tmp_path / "f.json"
    findings.write_text("not-json{", encoding="utf-8")
    rc = bg.main([
        "build_graph.py",
        "--repo-root", str(repo),
        "--work-dir", str(tmp_path / "work"),
        "--findings", str(findings),
    ])
    assert rc == 2


def test_findings_wrong_shape(bg, tmp_path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    _seed_repo(repo)
    findings = tmp_path / "f.json"
    findings.write_text(json.dumps({"not": "findings"}), encoding="utf-8")
    rc = bg.main([
        "build_graph.py",
        "--repo-root", str(repo),
        "--work-dir", str(tmp_path / "work"),
        "--findings", str(findings),
    ])
    assert rc == 2


def test_finding_without_id_skipped(bg, tmp_path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    _seed_repo(repo)
    work = tmp_path / "work"
    findings = tmp_path / "f.json"
    findings.write_text(json.dumps({
        "findings": [
            {"cwe": "CWE-89", "location": "app.py:authenticate"},  # no id
            {"id": "VULN-1", "cwe": "CWE-89", "location": "app.py:check_password"},
        ]
    }), encoding="utf-8")
    rc = bg.main([
        "build_graph.py",
        "--repo-root", str(repo),
        "--work-dir", str(work),
        "--findings", str(findings),
    ])
    assert rc in (0, 3)
    # VULN-1 was valid — it should exist
    assert (work / "graph_context" / "VULN-1.json").is_file()
