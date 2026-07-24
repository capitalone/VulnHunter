"""Tests for local_harness.batch.run."""

import pytest

import local_harness.batch.run as brun
from local_harness.scan import ScanResult


def test_repo_name_from_url():
    assert brun.repo_name_from_url("https://github.com/a/widget") == "widget"
    assert brun.repo_name_from_url("https://github.com/a/widget.git") == "widget"
    assert brun.repo_name_from_url("https://github.com/a/widget/") == "widget"


class _Args:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def test_cmd_scan_no_urls(monkeypatch):
    monkeypatch.setattr(brun, "parse_repo_list", lambda: [])
    with pytest.raises(SystemExit):
        brun.cmd_scan(_Args(re_clone=False, resume=False, max_workers=1))


def test_cmd_scan_all_clone_fail(monkeypatch):
    monkeypatch.setattr(brun, "parse_repo_list", lambda: ["https://github.com/a/b"])
    monkeypatch.setattr(brun, "shallow_clone", lambda url, td, re_clone=False: (td, "boom"))
    with pytest.raises(SystemExit):
        brun.cmd_scan(_Args(re_clone=False, resume=False, max_workers=1))


def test_cmd_scan_success(monkeypatch, tmp_path):
    monkeypatch.setattr(brun, "parse_repo_list",
                        lambda: ["https://github.com/a/b", "https://github.com/a/c"])
    monkeypatch.setattr(brun, "BATCH_CLONE_BASE_DIR", str(tmp_path))
    monkeypatch.setattr(brun, "shallow_clone",
                        lambda url, td, re_clone=False: (td, None))

    def fake_scan_targets(targets, max_workers=None, log_filename=None, readonly=False):
        return [
            (t["key"], ScanResult(t["clone_dir"], t["key"], 0, 5, 10.0, "rd", {"total_cost_usd": 1.5}))
            for t in targets[:1]
        ] + [
            (t["key"], ScanResult(t["clone_dir"], t["key"], 1, 0, 2.0, None, {}))
            for t in targets[1:]
        ]
    monkeypatch.setattr(brun, "scan_targets", fake_scan_targets)
    brun.cmd_scan(_Args(re_clone=False, resume=False, max_workers=2, execute=False))  # Updated for CANON-03


def test_cmd_scan_resume_all_have_results(monkeypatch, tmp_path):
    monkeypatch.setattr(brun, "parse_repo_list", lambda: ["https://github.com/a/b"])
    monkeypatch.setattr(brun, "BATCH_CLONE_BASE_DIR", str(tmp_path))
    monkeypatch.setattr(brun, "shallow_clone", lambda url, td, re_clone=False: (td, None))
    monkeypatch.setattr(brun, "clean_incomplete_results", lambda f, log_filename=None: [])
    monkeypatch.setattr(brun, "has_valid_results", lambda f: True)
    with pytest.raises(SystemExit):
        brun.cmd_scan(_Args(re_clone=False, resume=True, max_workers=1))


def test_cmd_scan_resume_partial(monkeypatch, tmp_path):
    monkeypatch.setattr(brun, "parse_repo_list",
                        lambda: ["https://github.com/a/b", "https://github.com/a/c"])
    monkeypatch.setattr(brun, "BATCH_CLONE_BASE_DIR", str(tmp_path))
    monkeypatch.setattr(brun, "shallow_clone", lambda url, td, re_clone=False: (td, None))
    monkeypatch.setattr(brun, "clean_incomplete_results", lambda f, log_filename=None: ["x"])
    # first folder has results (skipped), second doesn't
    monkeypatch.setattr(brun, "has_valid_results", lambda f: f.endswith("b"))
    monkeypatch.setattr(brun, "scan_targets",
                        lambda targets, max_workers=None, log_filename=None, readonly=False: [
                            (t["key"], ScanResult(t["clone_dir"], t["key"], 0, 1, 1.0, "rd", {}))
                            for t in targets])
    brun.cmd_scan(_Args(re_clone=False, resume=True, max_workers=1, execute=False))  # Updated for CANON-03


def test_cmd_scan_readonly_propagates(monkeypatch, tmp_path):
    # CANON-03: read-only is the default; --execute opts into code execution.
    monkeypatch.setattr(brun, "parse_repo_list", lambda: ["https://github.com/a/b"])
    monkeypatch.setattr(brun, "BATCH_CLONE_BASE_DIR", str(tmp_path))
    monkeypatch.setattr(brun, "shallow_clone", lambda url, td, re_clone=False: (td, None))

    seen = {}

    def fake_scan_targets(targets, max_workers=None, log_filename=None, readonly=True):
        seen["readonly"] = readonly
        return [(t["key"], ScanResult(t["clone_dir"], t["key"], 0, 1, 1.0, "rd", {})) for t in targets]

    monkeypatch.setattr(brun, "scan_targets", fake_scan_targets)

    # Default (execute=False) -> read-only scan (no Bash on the untrusted repo).
    brun.cmd_scan(_Args(re_clone=False, resume=False, max_workers=1, execute=False))
    assert seen["readonly"] is True

    # Explicit --execute opts into code execution.
    brun.cmd_scan(_Args(re_clone=False, resume=False, max_workers=1, execute=True))
    assert seen["readonly"] is False


def test_cmd_status(monkeypatch):
    called = {}
    monkeypatch.setattr(brun, "scan_status", lambda: called.setdefault("s", True))
    brun.cmd_status(_Args())
    assert called["s"]


def test_cmd_collect(monkeypatch):
    got = {}
    monkeypatch.setattr(brun, "collect_results",
                        lambda upload_dir=None: got.setdefault("dir", upload_dir))
    brun.cmd_collect(_Args(upload_dir="/tmp/up"))
    assert got["dir"] == "/tmp/up"


def test_main_dispatches_scan(monkeypatch):
    called = {}
    monkeypatch.setattr(brun, "cmd_scan", lambda a: called.setdefault("scan", True))
    monkeypatch.setattr(brun.sys, "argv", ["run", "scan", "--max-workers", "2"])
    brun.main()
    assert called["scan"]


def test_main_default_command(monkeypatch):
    called = {}
    monkeypatch.setattr(brun, "cmd_scan", lambda a: called.setdefault("scan", a))
    monkeypatch.setattr(brun.sys, "argv", ["run"])
    brun.main()
    assert called["scan"].command == "scan"


def test_main_status(monkeypatch):
    called = {}
    monkeypatch.setattr(brun, "cmd_status", lambda a: called.setdefault("status", True))
    monkeypatch.setattr(brun.sys, "argv", ["run", "status"])
    brun.main()
    assert called["status"]


def test_main_collect(monkeypatch):
    called = {}
    monkeypatch.setattr(brun, "cmd_collect", lambda a: called.setdefault("collect", True))
    monkeypatch.setattr(brun.sys, "argv", ["run", "collect"])
    brun.main()
    assert called["collect"]
