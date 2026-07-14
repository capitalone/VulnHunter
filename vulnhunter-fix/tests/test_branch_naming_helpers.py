"""Tests for branch-naming helpers restored to vulnhunter_fix.delivery.

Locks in REQ-SEC-002 (masked branch naming) and REQ-SEC-003 (descriptor
must not reveal specific vulnerability class). These helpers moved back
to delivery.py after headless/scripts/deliver_repo.py was deleted with
the rest of the headless/ tree on main.

prompts/implement.md and prompts/plan.md import from vulnhunter_fix.delivery,
so a rename or accidental deletion of these functions breaks the fix
loop at branch-creation time — this test catches that.
"""

from __future__ import annotations

import pytest

from vulnhunter_fix.delivery import (
    compute_idempotency_key,
    compute_masked_branch_name,
    cwe_to_descriptor,
)


@pytest.mark.parametrize("cwe,expected", [
    ("CWE-89", "input-validation"),   # SQL injection
    ("CWE-78", "input-validation"),   # OS command injection
    ("CWE-79", "input-validation"),   # XSS
    ("CWE-287", "auth-handling"),     # improper authentication
    ("CWE-862", "access-control"),    # missing authorization
    ("CWE-327", "crypto-handling"),   # broken crypto
    ("CWE-400", "memory-handling"),   # resource exhaustion
    ("CWE-362", "concurrency-handling"),  # race
    ("CWE-200", "information-handling"),  # info exposure
    ("CWE-319", "network-handling"),  # cleartext transmission
    ("CWE-798", "credential-handling"),   # hardcoded creds
    ("CWE-16", "configuration-handling"),  # config
    ("CWE-9999", "general-hardening"),    # unmapped → fallback
    ("", "general-hardening"),            # empty → fallback
    ("not-a-cwe", "general-hardening"),   # malformed → fallback
])
def test_cwe_to_descriptor(cwe, expected):
    assert cwe_to_descriptor(cwe) == expected


def test_compute_masked_branch_name_shape():
    """Branch name shape matches REQ-SEC-002: fix/code-quality-<desc>-<hash[:8]>."""
    branch = compute_masked_branch_name("CWE-89", "abcdef0123456789")
    assert branch == "fix/code-quality-input-validation-abcdef01"


def test_compute_masked_branch_name_empty_key():
    """Empty idempotency key still produces a valid-shape branch name."""
    branch = compute_masked_branch_name("CWE-89", "")
    assert branch == "fix/code-quality-input-validation-"


def test_compute_masked_branch_name_masks_class():
    """REQ-SEC-003: a specific vulnerability class (e.g. SQL Injection) must
    not appear in the branch name. Only the generalized descriptor does."""
    branch = compute_masked_branch_name("CWE-89", "0" * 16)
    assert "sql" not in branch.lower()
    assert "injection" not in branch.lower()
    assert "input-validation" in branch


def test_compute_idempotency_key_deterministic():
    """Same inputs → same key (idempotent)."""
    a = compute_idempotency_key("src/auth.py:42", "CWE-89", "unparameterized query")
    b = compute_idempotency_key("src/auth.py:42", "CWE-89", "unparameterized query")
    assert a == b
    assert len(a) == 16
    assert all(c in "0123456789abcdef" for c in a)


def test_compute_idempotency_key_differs_by_input():
    """Different inputs → different keys."""
    a = compute_idempotency_key("src/auth.py:42", "CWE-89", "reason A")
    b = compute_idempotency_key("src/auth.py:43", "CWE-89", "reason A")
    c = compute_idempotency_key("src/auth.py:42", "CWE-78", "reason A")
    d = compute_idempotency_key("src/auth.py:42", "CWE-89", "reason B")
    assert len({a, b, c, d}) == 4


def test_compute_idempotency_key_matches_parse_results_shape():
    """delivery.compute_idempotency_key must return the same value as
    scripts/parse_results.compute_vulnfix_key for the same inputs — the
    idempotency marker correlates across the intake and delivery halves
    of the pipeline."""
    from scripts._skill_bootstrap import _SKILL_ROOT  # noqa: F401 — bootstrap side-effect
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location(
        "parse_results",
        Path(__file__).resolve().parents[1] / "scripts" / "parse_results.py",
    )
    parse_results = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(parse_results)

    delivery_key = compute_idempotency_key("src/x.py:1", "CWE-89", "root")
    intake_key = parse_results.compute_vulnfix_key("src/x.py:1", "CWE-89", "root")
    assert delivery_key == intake_key
