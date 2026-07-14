"""Coverage tests for lint + language-detect scripts.

Covers: scripts/safe-phrase-sync-lint.py (REQ-GAT-008),
scripts/prompt-lint.py (REQ-CWE-010), scripts/language-detect.py (REQ-CWE-005).
"""
from __future__ import annotations

import importlib.util
import json
import sys
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
def sync_lint():
    return _load("safe-phrase-sync-lint.py", "sync_lint")


@pytest.fixture(scope="module")
def prompt_lint():
    return _load("prompt-lint.py", "prompt_lint")


@pytest.fixture(scope="module")
def lang_detect():
    return _load("language-detect.py", "lang_detect")


# ---- safe-phrase-sync-lint.py ----

def test_sync_lint_current_state_passes(sync_lint):
    """The two files should currently be in sync."""
    assert sync_lint.main() == 0


def test_sync_lint_extract_from_delivery(sync_lint):
    got = sync_lint._extract_constant(
        REPO_ROOT / "vulnhunter_fix" / "delivery.py",
        "SAFE_PHRASE_PATTERNS",
    )
    assert got is not None
    assert "non-critical" in got


def test_sync_lint_extract_missing_returns_none(sync_lint, tmp_path):
    fake = tmp_path / "empty.py"
    fake.write_text("x = 1\n", encoding="utf-8")
    assert sync_lint._extract_constant(fake, "SAFE_PHRASE_PATTERNS") is None


def test_sync_lint_missing_in_delivery(sync_lint, monkeypatch, tmp_path, capsys):
    """When SAFE_PHRASE_PATTERNS is missing from the delivery module."""
    fake = tmp_path / "delivery.py"
    fake.write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(sync_lint, "DELIVERY", fake)
    rc = sync_lint.main()
    assert rc == 2
    assert "SAFE_PHRASE_PATTERNS not found" in capsys.readouterr().err


def test_sync_lint_missing_in_gate1(sync_lint, monkeypatch, tmp_path, capsys):
    fake = tmp_path / "gate1.py"
    fake.write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(sync_lint, "GATE1", fake)
    rc = sync_lint.main()
    assert rc == 2
    assert "SAFE_PHRASE_PATTERNS not found" in capsys.readouterr().err


def test_sync_lint_drift_detected(sync_lint, monkeypatch, tmp_path, capsys):
    fake = tmp_path / "gate1.py"
    fake.write_text(
        'SAFE_PHRASE_PATTERNS = ("different", "list", "of", "phrases", "here")\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(sync_lint, "GATE1", fake)
    rc = sync_lint.main()
    assert rc == 1
    assert "drift detected" in capsys.readouterr().err


# ---- prompt-lint.py ----

def _make_prompt_stubs(dir_: Path) -> None:
    """Create a set of valid CWE-class prompt files that reference the common preamble."""
    dir_.mkdir(parents=True, exist_ok=True)
    (dir_ / "worker_agent_common.md").write_text("# common\n", encoding="utf-8")
    for cwe in ("authz", "injection", "crypto", "resource", "config"):
        (dir_ / f"worker_agent_{cwe}.md").write_text(
            f"# {cwe}\nSee worker_agent_common.md for the preamble.\n",
            encoding="utf-8",
        )


def test_prompt_lint_default_prompts_dir_passes(prompt_lint):
    """The repo's actual prompts/ directory should currently lint clean."""
    assert prompt_lint.main(["prompt-lint.py"]) == 0


def test_prompt_lint_synthetic_clean(prompt_lint, tmp_path):
    _make_prompt_stubs(tmp_path / "prompts")
    assert prompt_lint.main(["prompt-lint.py", "--prompts-dir", str(tmp_path / "prompts")]) == 0


def test_prompt_lint_missing_common(prompt_lint, tmp_path, capsys):
    p = tmp_path / "prompts"
    p.mkdir()
    for cwe in ("authz", "injection", "crypto", "resource", "config"):
        (p / f"worker_agent_{cwe}.md").write_text(
            "no reference here\n", encoding="utf-8",
        )
    rc = prompt_lint.main(["prompt-lint.py", "--prompts-dir", str(p)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "missing shared preamble" in err


def test_prompt_lint_missing_cwe_file(prompt_lint, tmp_path, capsys):
    p = tmp_path / "prompts"
    p.mkdir()
    (p / "worker_agent_common.md").write_text("# common\n", encoding="utf-8")
    # only 4 of 5 CWE classes present
    for cwe in ("authz", "injection", "crypto", "resource"):
        (p / f"worker_agent_{cwe}.md").write_text(
            "See worker_agent_common.md.\n", encoding="utf-8",
        )
    rc = prompt_lint.main(["prompt-lint.py", "--prompts-dir", str(p)])
    assert rc == 1
    assert "missing CWE-class prompt file" in capsys.readouterr().err


def test_prompt_lint_missing_preamble_reference(prompt_lint, tmp_path, capsys):
    p = tmp_path / "prompts"
    _make_prompt_stubs(p)
    # break one file
    (p / "worker_agent_crypto.md").write_text("no common ref\n", encoding="utf-8")
    rc = prompt_lint.main(["prompt-lint.py", "--prompts-dir", str(p)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "does not reference" in err


def test_prompt_lint_stale_worker_agent_md_flagged(prompt_lint, tmp_path, capsys):
    p = tmp_path / "prompts"
    _make_prompt_stubs(p)
    (p / "worker_agent.md").write_text("stale legacy file\n", encoding="utf-8")
    rc = prompt_lint.main(["prompt-lint.py", "--prompts-dir", str(p)])
    assert rc == 1
    assert "legacy worker_agent.md must be deleted" in capsys.readouterr().err


# ---- language-detect.py ----

def test_lang_detect_go_manifest(lang_detect, tmp_path):
    (tmp_path / "go.mod").write_text("module x\n", encoding="utf-8")
    result = lang_detect.detect(tmp_path)
    assert result["language"] == "go"
    assert result["confidence"] == "high"


def test_lang_detect_python_manifest(lang_detect, tmp_path):
    (tmp_path / "Pipfile").write_text("[packages]\n", encoding="utf-8")
    result = lang_detect.detect(tmp_path)
    assert result["language"] == "python"


def test_lang_detect_typescript_preferred_over_js(lang_detect, tmp_path):
    (tmp_path / "package.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "tsconfig.json").write_text("{}\n", encoding="utf-8")
    result = lang_detect.detect(tmp_path)
    assert result["language"] == "typescript"


def test_lang_detect_medium_confidence_manifest(lang_detect, tmp_path):
    (tmp_path / "requirements.txt").write_text("pytest\n", encoding="utf-8")
    result = lang_detect.detect(tmp_path)
    assert result["language"] == "python"
    assert result["confidence"] == "medium"


def test_lang_detect_suffix_fallback(lang_detect, tmp_path):
    # No manifest — trigger suffix vote
    for i in range(4):
        (tmp_path / f"a{i}.py").write_text("x=1\n", encoding="utf-8")
    (tmp_path / "b.go").write_text("package main\n", encoding="utf-8")
    result = lang_detect.detect(tmp_path)
    assert result["language"] == "python"


def test_lang_detect_suffix_high_confidence(lang_detect, tmp_path):
    for i in range(9):
        (tmp_path / f"a{i}.py").write_text("x=1\n", encoding="utf-8")
    (tmp_path / "b.go").write_text("package main\n", encoding="utf-8")
    result = lang_detect.detect(tmp_path)
    assert result["confidence"] == "high"


def test_lang_detect_skip_dirs(lang_detect, tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "junk.js").write_text("x\n", encoding="utf-8")
    (tmp_path / "src.py").write_text("y=1\n", encoding="utf-8")
    result = lang_detect.detect(tmp_path)
    assert result["language"] == "python"


def test_lang_detect_empty_repo(lang_detect, tmp_path):
    result = lang_detect.detect(tmp_path)
    assert result["language"] is None
    assert result["confidence"] == "low"


def test_lang_detect_main_usage_error(lang_detect, capsys):
    assert lang_detect.main(["language-detect.py"]) == 64
    assert "usage:" in capsys.readouterr().err


def test_lang_detect_main_not_a_dir(lang_detect, tmp_path, capsys):
    fake = tmp_path / "not-there"
    assert lang_detect.main(["language-detect.py", str(fake)]) == 2
    assert "not a directory" in capsys.readouterr().err


def test_lang_detect_main_success(lang_detect, tmp_path, capsys):
    (tmp_path / "go.mod").write_text("module x\n", encoding="utf-8")
    assert lang_detect.main(["language-detect.py", str(tmp_path)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["language"] == "go"


def test_lang_detect_survives_permission_denied_dir(lang_detect, tmp_path):
    """Repeats the bug from cosp-admitone-data-management-api E2E: an
    unreadable directory under the repo (macOS sandbox blocks .envrc-
    adjacent entries) crashed language-detect's rglob walker. The shared
    walker in config.py fixes it — this test pins that behavior.
    """
    import os
    # No manifest — force the suffix-vote path
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "hidden.py").write_text("y = 2\n", encoding="utf-8")
    try:
        os.chmod(locked, 0o000)
        result = lang_detect.detect(tmp_path)  # must not raise
    finally:
        os.chmod(locked, 0o755)
    assert result["language"] == "python"


def test_lang_detect_survives_unreadable_manifest(lang_detect, tmp_path):
    """Even the manifest probe should tolerate a permission-denied check —
    an unreadable go.mod / Pipfile shouldn't crash detection.
    """
    import os
    manifest = tmp_path / "go.mod"
    manifest.write_text("module x\n", encoding="utf-8")
    try:
        os.chmod(manifest, 0o000)
        # Manifest is unreadable but detection should still succeed
        # (either via other manifests or suffix vote) without raising.
        result = lang_detect.detect(tmp_path)  # must not raise
    finally:
        os.chmod(manifest, 0o644)
    assert result is not None
    assert "language" in result


# ---- heading-sync-lint.py (REQ-GAT-003) ----


@pytest.fixture(scope="module")
def heading_lint():
    return _load("heading-sync-lint.py", "heading_lint")


def test_heading_lint_current_state_passes(heading_lint):
    """Body templates carry the required H2s and no em-dash Breaking-Change
    heading survives in the corpus."""
    assert heading_lint.main() == 0


def test_heading_lint_extracts_gate2_constants(heading_lint):
    req = heading_lint._extract_tuple_constant(heading_lint.GATE2, "REQUIRED_ALWAYS")
    assert req is not None
    assert "## Finding Summary" in req
    assert "## Attacker Capability" in req
    cond = heading_lint._extract_str_constant(heading_lint.GATE2, "CONDITIONAL_BREAKING")
    assert cond == "## Breaking Change"


def test_heading_lint_present_accepts_bare_and_colon(heading_lint):
    assert heading_lint._heading_present("## Finding Summary\n\nbody", "## Finding Summary")
    assert heading_lint._heading_present("## Finding Summary:\n", "## Finding Summary")


def test_heading_lint_present_rejects_h3_downgrade(heading_lint):
    # An H3 downgrade of a required heading must not satisfy the H2 check.
    assert not heading_lint._heading_present("### Attacker Capability\n", "## Attacker Capability")


def test_heading_lint_em_dash_regex_catches_suffix(heading_lint):
    """The Breaking-Change heading regex must flag the em-dash form that
    Gate 2 rejects, and pass the bare form."""
    bad = "## Breaking Change — Caller Action Required\n"
    m = heading_lint._BREAKING_HEADING.search(bad)
    assert m is not None
    suffix = m.group("suffix").strip()
    assert suffix and not suffix.startswith(":")   # would be flagged

    good = "## Breaking Change\n"
    m2 = heading_lint._BREAKING_HEADING.search(good)
    assert m2 is not None
    assert m2.group("suffix").strip() == ""         # bare — not flagged

    colon = "## Breaking Change:\n"
    m3 = heading_lint._BREAKING_HEADING.search(colon)
    assert m3.group("suffix").strip().startswith(":")  # colon form — not flagged


def test_heading_lint_flags_block_placeholder_in_comment(heading_lint, tmp_path, monkeypatch):
    """Regression guard: pr_body_cluster.md's idempotency comment used to embed
    the literal {PER_FINDING_SECTIONS} token, so global substitution injected
    each finding's own vulnfix-key comment inside it — nesting HTML comments and
    dumping finding blocks as visible garbage in every multi-finding cluster PR. The
    lint must flag a *block* placeholder inside a comment while leaving a scalar
    marker like the vulnfix-key comment alone.
    """
    import re
    open_c = "<!" + "--"
    close_c = "--" + ">"
    fake_templates = tmp_path / "templates"
    fake_templates.mkdir()
    required = heading_lint._extract_tuple_constant(heading_lint.GATE2, "REQUIRED_ALWAYS")
    conds = [heading_lint._extract_str_constant(heading_lint.GATE2, c) for c in
             ("CONDITIONAL_TABLE", "CONDITIONAL_RESIDUAL", "CONDITIONAL_BREAKING", "CONDITIONAL_SWEEP")]
    headings = "\n\n".join(f"{h}\n\nbody" for h in [*required, *conds])
    # BAD: block placeholder appears as content AND inside a comment; scalar
    # marker appears only inside its own comment (must NOT be flagged).
    bad = (headings + "\n\n{PER_FINDING_SECTIONS}\n\n"
           + f"{open_c} refers to {{PER_FINDING_SECTIONS}} {close_c}\n"
           + f"{open_c} vulnfix-key: {{IDEMPOTENCY_KEY}} {close_c}\n")
    (fake_templates / "pr_body.md").write_text(bad, encoding="utf-8")
    (fake_templates / "pr_body_cluster.md").write_text(bad, encoding="utf-8")
    (fake_templates / "issue_body.md").write_text(headings + "\n", encoding="utf-8")
    monkeypatch.setattr(heading_lint, "TEMPLATES", fake_templates)
    monkeypatch.setattr(heading_lint, "SCAN_DIRS", ())  # skip corpus em-dash scan
    assert heading_lint.main() == 1  # block placeholder in comment must fail

    # The shipped template must be clean under the real check.
    tmpl = (REPO_ROOT / "templates" / "pr_body_cluster.md").read_text(encoding="utf-8")
    content_wo = re.sub(r"<!--.*?-->", "", tmpl, flags=re.DOTALL)
    blocks = set(re.findall(r"\{[A-Z_]+\}", content_wo))
    for m in re.finditer(r"<!--.*?-->", tmpl, re.DOTALL):
        for tok in re.findall(r"\{[A-Z_]+\}", m.group(0)):
            assert tok not in blocks, f"pr_body_cluster.md comment embeds block placeholder {tok}"
