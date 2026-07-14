"""TS-11 — Gate 2 CLI contract (REQ-GAT-003, REQ-GAT-012).

Covers the six CLI combinations required to prevent regressions on the
Gate 2 contract:

1. No `--enforce-strings` — passes when structural checks pass.
2. Missing required section → fail.
3. Empty required section → fail.
4. Forbidden token (default set) present → fail.
5. `--enforce-strings` succeeds when token present, fails when absent.
6. Conditional sections (tier / status / sweep_ran) toggle correctly.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
GATE2 = REPO_ROOT / "scripts" / "check-body-completeness.py"


BASE_BODY = """\
## Finding Summary
CWE-89 · High+ severity · sink at src/x.py:42.

## Attacker Capability
Attacker executes arbitrary SQL.

## Security Test
```python
def test_x(): pass
```

## Fix Description
Parameterized query.

## Verification Results
Pre-fix FAIL, post-fix PASS.

## Verification Table
| # | VULN-NNN | ... | Verdict |
| 1 | VULN-001 | ... | FULL |

<!-- vulnfix-key: abcd1234abcd1234 -->
"""


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def _run(*args):
    return subprocess.run([sys.executable, str(GATE2), *args], capture_output=True, text=True, check=False)


def test_case1_no_enforce_strings_passes_on_full(tmp_path):
    body = _write(tmp_path, "pr.md", BASE_BODY)
    r = _run("--body", str(body), "--kind", "pr", "--tier", "FULL",
             "--status", "VERIFIED", "--sweep-ran", "false")
    assert r.returncode == 0, r.stderr


def test_case2_missing_section_fails(tmp_path):
    body = _write(tmp_path, "pr.md", BASE_BODY.replace("## Attacker Capability", "## Attack Cap"))
    r = _run("--body", str(body), "--kind", "pr", "--tier", "FULL",
             "--status", "VERIFIED", "--sweep-ran", "false")
    assert r.returncode == 1
    assert "Attacker Capability" in r.stderr


def test_case3_empty_section_fails(tmp_path):
    body = _write(tmp_path, "pr.md", BASE_BODY.replace(
        "## Attacker Capability\nAttacker executes arbitrary SQL.",
        "## Attacker Capability\n"))
    r = _run("--body", str(body), "--kind", "pr", "--tier", "FULL",
             "--status", "VERIFIED", "--sweep-ran", "false")
    assert r.returncode == 1


def test_case4_forbidden_token_fails(tmp_path):
    body = _write(tmp_path, "pr.md", BASE_BODY + "\nTODO: fix later\n")
    r = _run("--body", str(body), "--kind", "pr", "--tier", "FULL",
             "--status", "VERIFIED", "--sweep-ran", "false")
    assert r.returncode == 1
    assert "forbidden token" in r.stderr


def test_case5_enforce_strings_succeeds_and_fails(tmp_path):
    body = _write(tmp_path, "pr.md", BASE_BODY + "\n(grep_fallback) note\n")
    r = _run("--body", str(body), "--kind", "pr", "--tier", "FULL",
             "--status", "VERIFIED", "--sweep-ran", "false",
             "--enforce-strings", "(grep_fallback)")
    assert r.returncode == 0, r.stderr

    body2 = _write(tmp_path, "pr2.md", BASE_BODY)
    r2 = _run("--body", str(body2), "--kind", "pr", "--tier", "FULL",
              "--status", "VERIFIED", "--sweep-ran", "false",
              "--enforce-strings", "(grep_fallback)")
    assert r2.returncode == 1


def test_case6_conditional_sections_toggle(tmp_path):
    body_no_residual = _write(tmp_path, "pr.md", BASE_BODY)
    # Tier != FULL requires ## Residual Risk section
    r = _run("--body", str(body_no_residual), "--kind", "pr", "--tier", "MITIGATION",
             "--status", "VERIFIED", "--sweep-ran", "false")
    assert r.returncode == 1
    assert "Residual Risk" in r.stderr

    body_with_residual = _write(tmp_path, "pr2.md",
                                BASE_BODY + "\n## Residual Risk\n- open vector\n")
    r2 = _run("--body", str(body_with_residual), "--kind", "pr", "--tier", "MITIGATION",
              "--status", "VERIFIED", "--sweep-ran", "false")
    assert r2.returncode == 0, r2.stderr
