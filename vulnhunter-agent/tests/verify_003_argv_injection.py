"""Security test: VULN-003 — git clone/fetch argv must resist option injection.

CWE-88. A leading-dash "URL" must not reach git as an option. The clone argv
must carry a '--' end-of-options separator before the URL, dash-leading URLs
must be rejected at the boundary, and clone_at_commit must reject a commit
that is not a hex SHA (CQ-1).
"""

import tempfile
from pathlib import Path
from unittest import mock

import pytest

from agent import clone as clone_mod


def _capture_clone(url):
    captured = {}

    class _R:
        returncode = 0

    def _fake_run(argv, *a, **k):
        captured.setdefault("argv", argv)
        return _R()

    base = Path(tempfile.gettempdir()) / "vh_v003_base"
    with mock.patch.object(clone_mod, "_GIT_EXECUTABLE", "/usr/bin/git"), \
            mock.patch.object(clone_mod.subprocess, "run", _fake_run), \
            mock.patch.object(clone_mod.shutil, "rmtree"):
        clone_mod.shallow_clone(url, base, github_token="")
    return captured["argv"]


def test_clone_argv_has_end_of_options_separator():
    argv = _capture_clone("https://github.com/acme/repo.git")
    url_pos = argv.index("https://github.com/acme/repo.git")
    assert "--" in argv[1:url_pos], "missing '--' end-of-options guard before URL"


def test_leading_dash_url_is_rejected():
    with pytest.raises((RuntimeError, ValueError)):
        _capture_clone("--upload-pack=touch /tmp/pwned")


def test_clone_at_commit_rejects_non_hex_commit():
    base = Path(tempfile.gettempdir()) / "vh_v003_commit"
    with mock.patch.object(clone_mod, "_GIT_EXECUTABLE", "/usr/bin/git"):
        for bad in ("--upload-pack=x", "notahex", "HEAD; rm -rf /"):
            with pytest.raises((RuntimeError, ValueError)):
                clone_mod.clone_at_commit(
                    "https://github.com/acme/repo.git", base, bad, github_token=""
                )
