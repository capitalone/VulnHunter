"""Tests for local_harness.batch.utils."""

import json
import os

import local_harness.batch.utils as utils


def test_parse_repo_list(monkeypatch, tmp_path):
    f = tmp_path / "repos.txt"
    f.write_text("# comment\n\nhttps://github.com/a/b\n  https://github.com/c/d  \n#skip\n")
    urls = utils.parse_repo_list(str(f))
    assert urls == ["https://github.com/a/b", "https://github.com/c/d"]


def test_parse_repo_list_default(monkeypatch, tmp_path):
    f = tmp_path / "default.txt"
    f.write_text("https://github.com/x/y\n")
    monkeypatch.setattr(utils, "BATCH_REPO_LIST_FILE", str(f))
    assert utils.parse_repo_list() == ["https://github.com/x/y"]


def test_collect_results_no_clone_base(tmp_path):
    out = utils.collect_results(clone_base=str(tmp_path / "nope"),
                                upload_dir=str(tmp_path / "up"))
    assert out == {"copied": [], "missing": []}


def test_collect_results(tmp_path):
    base = tmp_path / "repos"
    base.mkdir()
    # repo with results
    repo = base / "repoA"
    repo.mkdir()
    rd = repo / "repoA_VULNHUNT_RESULTS_1"
    rd.mkdir()
    (rd / "README.md").write_text("report")
    # repo missing results
    (base / "repoB").mkdir()
    # a stray non-dir and a top-level results dir (skipped)
    (base / "stray.txt").write_text("x")
    (base / "top_VULNHUNT_RESULTS_x").mkdir()

    upload = tmp_path / "up"
    out = utils.collect_results(clone_base=str(base), upload_dir=str(upload))
    assert "repoA_VULNHUNT_RESULTS_1" in out["copied"]
    assert "repoB" in out["missing"]
    assert (upload / "repoA_VULNHUNT_RESULTS_1" / "README.md").exists()


def test_collect_results_overwrites_existing_dst(tmp_path):
    base = tmp_path / "repos"
    base.mkdir()
    repo = base / "repoA"
    repo.mkdir()
    rd = repo / "repoA_VULNHUNT_RESULTS_1"
    rd.mkdir()
    (rd / "README.md").write_text("new report")
    upload = tmp_path / "up"
    upload.mkdir()
    stale = upload / "repoA_VULNHUNT_RESULTS_1"
    stale.mkdir()
    (stale / "OLD.md").write_text("old")

    utils.collect_results(clone_base=str(base), upload_dir=str(upload))
    assert not (upload / "repoA_VULNHUNT_RESULTS_1" / "OLD.md").exists()
    assert (upload / "repoA_VULNHUNT_RESULTS_1" / "README.md").exists()


def test_collect_results_does_not_follow_symlinks(tmp_path):
    # CANON-18: a scanned (untrusted) repo can plant a symlink inside its
    # *_VULNHUNT_RESULTS_* dir pointing at a sensitive host file. collect_results
    # must not follow it and copy the target's contents into the published upload.
    secret = tmp_path / "SECRET_host_file"
    secret.write_text("TOP-SECRET-HOST-CONTENT-abc123")

    base = tmp_path / "repos"
    base.mkdir()
    repo = base / "evilrepo"
    repo.mkdir()
    rd = repo / "evilrepo_VULNHUNT_RESULTS_1"
    rd.mkdir()
    (rd / "README.md").write_text("legit report")
    os.symlink(str(secret), str(rd / "stolen_passwd"))

    upload = tmp_path / "up"
    utils.collect_results(clone_base=str(base), upload_dir=str(upload))

    dst = upload / "evilrepo_VULNHUNT_RESULTS_1"
    leaked = dst / "stolen_passwd"
    # Secret target contents must never appear in the published tree.
    assert not (leaked.is_file() and not leaked.is_symlink()), \
        "symlink target followed: host secret copied into upload"
    if leaked.exists() or os.path.lexists(str(leaked)):
        assert "TOP-SECRET-HOST-CONTENT" not in leaked.read_text()
    # The legitimate regular file still copies fine.
    assert (dst / "README.md").read_text() == "legit report"


def test_scan_status_no_clone_base(tmp_path):
    out = utils.scan_status(clone_base=str(tmp_path / "nope"))
    assert out == {"complete": [], "errored": [], "running": [], "not_started": []}


def test_scan_status_all_states(monkeypatch, tmp_path):
    base = tmp_path / "repos"
    base.mkdir()
    monkeypatch.setattr(utils, "extract_cost_from_log", lambda p: {"total_cost_usd": 1.0})

    def make(name, last_event=None, empty=False, bad=False):
        d = base / name
        d.mkdir()
        log = d / "batch_scan.log"
        if last_event is None and not empty and not bad:
            return  # no log at all -> not_started
        if empty:
            log.write_text("")
            return
        if bad:
            log.write_text("not json\n")
            return
        log.write_text(json.dumps({"type": "system"}) + "\n" + json.dumps(last_event) + "\n")

    make("complete", {"type": "result", "is_error": False, "duration_ms": 120000})
    make("errored", {"type": "result", "is_error": True, "api_error_status": 429})
    make("running", {"type": "assistant", "subtype": "thinking"})
    make("notstarted")
    make("emptylog", empty=True)
    make("badjson", bad=True)
    # top-level results dir + non-dir are skipped
    (base / "top_VULNHUNT_RESULTS_x").mkdir()
    (base / "file.txt").write_text("x")

    out = utils.scan_status(clone_base=str(base), log_filename="batch_scan.log")
    assert any(name == "complete" for name, *_ in out["complete"])
    assert any(name == "errored" for name, *_ in out["errored"])
    running_names = {name for name, _ in out["running"]}
    assert "running" in running_names and "badjson" in running_names
    assert "notstarted" in out["not_started"] and "emptylog" in out["not_started"]


def test_scan_status_many_not_started(monkeypatch, tmp_path):
    base = tmp_path / "repos"
    base.mkdir()
    for i in range(15):
        (base / f"repo{i:02d}").mkdir()
    out = utils.scan_status(clone_base=str(base))
    assert len(out["not_started"]) == 15
