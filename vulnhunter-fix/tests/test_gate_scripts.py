"""Coverage tests for the four Gate CLI scripts (REQ-GAT-002..006).

Covers: scripts/check-severity-mask.py, check-scope.py, check-idempotency.py,
anti-merge-check.py — the mechanical delivery gates.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"


def _load(name: str, mod: str):
    spec = importlib.util.spec_from_file_location(mod, SCRIPTS / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def sev():
    return _load("check-severity-mask.py", "sev")


@pytest.fixture(scope="module")
def scope():
    return _load("check-scope.py", "scope")


@pytest.fixture(scope="module")
def idem():
    return _load("check-idempotency.py", "idem")


@pytest.fixture(scope="module")
def anti():
    return _load("anti-merge-check.py", "anti")


# ---- check-severity-mask.py ----

def test_sev_clean(sev, tmp_path):
    body = tmp_path / "body.md"
    body.write_text("This PR fixes a High severity issue.\n", encoding="utf-8")
    assert sev.main(["check-severity-mask.py", str(body)]) == 0


def test_sev_violates(sev, tmp_path, capsys):
    body = tmp_path / "body.md"
    body.write_text("This is critical work.\n", encoding="utf-8")
    assert sev.main(["check-severity-mask.py", str(body)]) == 1
    assert "severity mask violation" in capsys.readouterr().err


def test_sev_safe_phrase_criticality(sev, tmp_path):
    body = tmp_path / "body.md"
    body.write_text("Business criticality is documented.\n", encoding="utf-8")
    assert sev.main(["check-severity-mask.py", str(body)]) == 0


def test_sev_safe_phrase_non_critical(sev, tmp_path):
    body = tmp_path / "body.md"
    body.write_text("This is non-critical.\n", encoding="utf-8")
    assert sev.main(["check-severity-mask.py", str(body)]) == 0


def test_sev_flags_critically_important(sev, tmp_path, capsys):
    """F1 (segment-review S3): the inflection 'critically important' MUST
    be flagged — severity-mask-rule.md:29 says so explicitly — but the old
    \\bcritical\\b regex missed it (trailing \\b can't sit before 'ly'). This
    is the RED guard for the \\bcritical\\w* fix."""
    body = tmp_path / "body.md"
    body.write_text("This bug is critically important to fix.\n", encoding="utf-8")
    assert sev.main(["check-severity-mask.py", str(body)]) == 1
    assert "severity mask violation" in capsys.readouterr().err


def test_sev_inflections_still_suppress_safe_phrases(sev, tmp_path):
    """The \\bcritical\\w* fix must NOT start flagging the safe inflections."""
    body = tmp_path / "body.md"
    body.write_text(
        "Business criticality is documented; this is non-critical; "
        "see the Critical Section; constructive criticism; a fair critique.\n",
        encoding="utf-8",
    )
    assert sev.main(["check-severity-mask.py", str(body)]) == 0


def test_sev_safe_phrase_critical_section(sev, tmp_path):
    body = tmp_path / "body.md"
    body.write_text("See the Critical Section documentation.\n", encoding="utf-8")
    assert sev.main(["check-severity-mask.py", str(body)]) == 0


def test_sev_zero_width_obfuscation_flagged(sev, tmp_path, capsys):
    """S5 (12-seg review): a zero-width space inside 'critical' slipped past the
    mask. Normalization must strip ZWSP and still flag it."""
    body = tmp_path / "body.md"
    body.write_text("This is a cri​tical vulnerability.\n", encoding="utf-8")
    assert sev.main(["check-severity-mask.py", str(body)]) == 1
    assert "severity mask violation" in capsys.readouterr().err


def test_sev_homoglyph_obfuscation_flagged(sev, tmp_path, capsys):
    """S5: a Cyrillic homoglyph ('с' U+0441) spoofing the leading 'c' slipped
    past the mask. Common confusables for the letters in 'critical' must fold
    to Latin before matching."""
    body = tmp_path / "body.md"
    body.write_text("This is a сritical vulnerability.\n", encoding="utf-8")
    assert sev.main(["check-severity-mask.py", str(body)]) == 1
    assert "severity mask violation" in capsys.readouterr().err


def test_sev_safe_phrase_criticism(sev, tmp_path):
    body = tmp_path / "body.md"
    body.write_text("Received constructive criticism.\n", encoding="utf-8")
    assert sev.main(["check-severity-mask.py", str(body)]) == 0


def test_sev_safe_phrase_critique(sev, tmp_path):
    body = tmp_path / "body.md"
    body.write_text("The critique was helpful.\n", encoding="utf-8")
    assert sev.main(["check-severity-mask.py", str(body)]) == 0


def test_sev_nearby_safe_does_not_shield_violation(sev, tmp_path):
    """A safe phrase nearby should NOT hide a real 'critical' match."""
    body = tmp_path / "body.md"
    body.write_text("criticism aside, this is critical.\n", encoding="utf-8")
    assert sev.main(["check-severity-mask.py", str(body)]) == 1


def test_sev_multiple_files(sev, tmp_path):
    f1 = tmp_path / "a.md"
    f2 = tmp_path / "b.md"
    f1.write_text("clean.\n", encoding="utf-8")
    f2.write_text("critical bad.\n", encoding="utf-8")
    assert sev.main(["check-severity-mask.py", str(f1), str(f2)]) == 1


def test_sev_missing_file(sev, tmp_path, capsys):
    missing = tmp_path / "nope.md"
    assert sev.main(["check-severity-mask.py", str(missing)]) == 1
    assert "not a regular file" in capsys.readouterr().err


def test_sev_usage_error(sev, capsys):
    assert sev.main(["check-severity-mask.py"]) == 64
    assert "usage:" in capsys.readouterr().err


# ---- check-idempotency.py ----

def test_idem_pr_valid(idem, tmp_path):
    body = tmp_path / "pr.md"
    body.write_text("hello\n<!-- vulnfix-key: abcdef0123456789 -->\n", encoding="utf-8")
    assert idem.main(["check-idempotency.py", "--body", str(body)]) == 0


def test_idem_pr_missing_key(idem, tmp_path, capsys):
    body = tmp_path / "pr.md"
    body.write_text("no marker\n", encoding="utf-8")
    assert idem.main(["check-idempotency.py", "--body", str(body)]) == 1
    assert "vulnfix-key" in capsys.readouterr().err


def test_idem_issue_valid(idem, tmp_path):
    body = tmp_path / "issue.md"
    body.write_text("<!-- vulnfix-key: 0123456789abcdef -->\n", encoding="utf-8")
    assert idem.main(["check-idempotency.py", "--body", str(body), "--kind", "issue"]) == 0


def test_idem_tracking_valid(idem, tmp_path):
    body = tmp_path / "track.md"
    body.write_text(
        "<!-- vulnfix-key: abcdef1234567890 -->\n"
        "<!-- vulnfix-report-id: 2026-06-30-VULN -->\n",
        encoding="utf-8",
    )
    assert idem.main(["check-idempotency.py", "--body", str(body), "--kind", "tracking"]) == 0


def test_idem_tracking_missing_report_id(idem, tmp_path, capsys):
    body = tmp_path / "track.md"
    body.write_text("<!-- vulnfix-key: abcdef1234567890 -->\n", encoding="utf-8")
    assert idem.main(["check-idempotency.py", "--body", str(body), "--kind", "tracking"]) == 1
    assert "vulnfix-report-id" in capsys.readouterr().err


def test_idem_missing_file(idem, tmp_path, capsys):
    missing = tmp_path / "no.md"
    assert idem.main(["check-idempotency.py", "--body", str(missing)]) == 2
    assert "<io>" in capsys.readouterr().err


# ---- anti-merge-check.py ----

def test_anti_allowed_low_ratio(anti, capsys):
    assert anti.main([
        "anti-merge-check.py",
        "--files-grouped", "2", "--files-split", "5",
    ]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["allowed"] is True
    assert payload["source_ratio"] == 0.4


def test_anti_boundary_exactly_threshold(anti, capsys):
    assert anti.main([
        "anti-merge-check.py",
        "--files-grouped", "3", "--files-split", "5",  # 0.6
    ]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["allowed"] is True


def test_anti_disallowed_high_ratio(anti, capsys):
    assert anti.main([
        "anti-merge-check.py",
        "--files-grouped", "4", "--files-split", "5",  # 0.8
    ]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["allowed"] is False
    assert "split into individual PRs" in payload["reason"]


def test_anti_test_ratio_rescue(anti, capsys):
    """Src ratio fails but test ratio saves the grouping."""
    assert anti.main([
        "anti-merge-check.py",
        "--files-grouped", "4", "--files-split", "5",
        "--test-files-grouped", "2", "--test-files-split", "10",
    ]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["allowed"] is True
    assert "test ratio" in payload["reason"]


def test_anti_both_ratios_fail(anti, capsys):
    assert anti.main([
        "anti-merge-check.py",
        "--files-grouped", "4", "--files-split", "5",
        "--test-files-grouped", "8", "--test-files-split", "10",
    ]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["allowed"] is False


def test_anti_zero_split(anti, capsys):
    """Divide-by-zero guard: when split=0, ratio defaults to 1.0 (disallowed)."""
    assert anti.main([
        "anti-merge-check.py",
        "--files-grouped", "1", "--files-split", "0",
    ]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["source_ratio"] == 1.0
    assert payload["allowed"] is False


def test_anti_negative_counts_rejected(anti, capsys):
    """S5 (12-seg review): no non-negative validation — `--files-grouped -5
    --files-split 1` gives a negative ratio <= 0.6 → allowed:true, gaming the
    gate. Negative counts must be a usage error, not a pass."""
    rc = anti.main(["anti-merge-check.py", "--files-grouped", "-5", "--files-split", "1"])
    assert rc == 2, "negative grouped count was not rejected"
    rc = anti.main(["anti-merge-check.py", "--files-grouped", "1", "--files-split", "-1"])
    assert rc == 2, "negative split count was not rejected"


def test_anti_strict_blocks_disallowed(anti, capsys):
    """S6 (12-seg review): the --strict block path (the mode run-gates.py
    actually uses) was never tested — dropping it would keep tests green while
    enforcement stopped. --strict + disallowed grouping must exit 1."""
    rc = anti.main([
        "anti-merge-check.py", "--files-grouped", "4", "--files-split", "5", "--strict",
    ])
    assert rc == 1
    assert json.loads(capsys.readouterr().out)["allowed"] is False


def test_anti_strict_allows_efficient_grouping(anti, capsys):
    """Allow-path: --strict with an efficient grouping exits 0."""
    rc = anti.main([
        "anti-merge-check.py", "--files-grouped", "2", "--files-split", "5", "--strict",
    ])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["allowed"] is True



# ---- check-scope.py ----

def _make_git_repo(root: Path) -> None:
    subprocess.run(["git", "init", "-b", "main", str(root)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "commit.gpgsign", "false"], check=True)


def _seed(root: Path, name: str, content: str = "seed\n") -> None:
    p = root / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _commit_all(root: Path, msg: str) -> None:
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(root), "commit", "-m", msg],
        check=True, capture_output=True,
    )


def test_scope_clean(scope, tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    _make_git_repo(root)
    _seed(root, "src/foo.py", "print('base')\n")
    _commit_all(root, "base")
    subprocess.run(["git", "-C", str(root), "checkout", "-b", "vulnfix"], check=True, capture_output=True)
    _seed(root, "src/foo.py", "print('fix')\n")
    _commit_all(root, "fix")

    ns = type("N", (), {})()
    ns.repo_root = str(root)
    ns.branch = "vulnfix"
    ns.files_modified = ["src/foo.py"]
    ns.test_file = None
    assert scope.check(ns) == 0


def test_scope_violation(scope, tmp_path, capsys):
    root = tmp_path / "repo"
    root.mkdir()
    _make_git_repo(root)
    _seed(root, "src/foo.py", "a\n")
    _seed(root, "src/bar.py", "b\n")
    _commit_all(root, "base")
    subprocess.run(["git", "-C", str(root), "checkout", "-b", "vulnfix"], check=True, capture_output=True)
    _seed(root, "src/foo.py", "aa\n")
    _seed(root, "src/bar.py", "bb\n")  # bar not allowed
    _commit_all(root, "fix")

    ns = type("N", (), {})()
    ns.repo_root = str(root)
    ns.branch = "vulnfix"
    ns.files_modified = ["src/foo.py"]
    ns.test_file = None
    assert scope.check(ns) == 1
    assert "scope violation" in capsys.readouterr().err


def test_scope_test_file_allowed(scope, tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    _make_git_repo(root)
    _seed(root, "src/foo.py", "a\n")
    _commit_all(root, "base")
    subprocess.run(["git", "-C", str(root), "checkout", "-b", "vulnfix"], check=True, capture_output=True)
    _seed(root, "src/foo.py", "aa\n")
    _seed(root, "tests/test_foo.py", "def test(): pass\n")
    _commit_all(root, "fix")

    ns = type("N", (), {})()
    ns.repo_root = str(root)
    ns.branch = "vulnfix"
    ns.files_modified = ["src/foo.py"]
    ns.test_file = "tests/test_foo.py"
    assert scope.check(ns) == 0


def test_scope_invalid_branch_name(scope, capsys):
    ns = type("N", (), {})()
    ns.repo_root = "/tmp/whatever"
    ns.branch = "--evil-flag"
    ns.files_modified = ["src/foo.py"]
    ns.test_file = None
    assert scope.check(ns) == 2
    assert "looks like a flag" in capsys.readouterr().err


def test_scope_rejects_empty_files_modified(scope, capsys):
    """REQ-GAT-004: an empty files_modified is either a plan/verify phase bug or
    a fabricated result artifact — check-scope must fail loud with an
    informative error instead of surfacing argparse's confusing "expected at
    least one argument" via nargs='+'. Recovered from E2E on
    cosp-admitone-data-management-api where run-gates.py forwarded empty
    files_modified and the operator saw a usage error, not an actionable one.
    """
    ns = type("N", (), {})()
    ns.repo_root = "/tmp/whatever"
    ns.branch = "vulnfix/foo"
    ns.files_modified = []
    ns.test_file = None
    assert scope.check(ns) == 1
    err = capsys.readouterr().err
    assert "--files-modified must be non-empty" in err
    assert "REQ-GAT-004" in err


def test_scope_git_missing(scope, tmp_path, capsys):
    """When git can't run, return 2 (system error)."""
    ns = type("N", (), {})()
    ns.repo_root = str(tmp_path / "not-a-repo")
    ns.branch = "vulnfix"
    ns.files_modified = ["src/foo.py"]
    ns.test_file = None
    (tmp_path / "not-a-repo").mkdir()
    # No git init done, so git diff will fail with a CalledProcessError
    assert scope.check(ns) == 2
    assert "git diff failed" in capsys.readouterr().err
