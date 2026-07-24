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
    # Guard read_text(): on a dangling-link regression lexists() is True but
    # is_file() is False, so read_text() would raise FileNotFoundError and turn
    # a clean failure into a test error. Only read a real regular file; any
    # surviving symlink (dangling or not) is itself an assert failure.
    if leaked.is_file():
        assert "TOP-SECRET-HOST-CONTENT" not in leaked.read_text()
    else:
        assert not os.path.lexists(str(leaked)), \
            "symlink shipped into upload (dangling or otherwise)"
    # The legitimate regular file still copies fine.
    assert (dst / "README.md").read_text() == "legit report"


def test_collect_results_does_not_follow_symlinked_results_root(tmp_path):
    # CANON-18 (source-root vector): the *_VULNHUNT_RESULTS_* dir itself is a
    # symlink pointing at a sensitive host directory. os.path.isdir() follows
    # it, so it must be rejected before copytree — otherwise copytree follows
    # the symlinked source and copies the target dir's files into the upload.
    secret_dir = tmp_path / "victim_home_ssh"
    secret_dir.mkdir()
    (secret_dir / "id_rsa").write_text("PRIVATE-KEY-HOST-CONTENT-xyz789")

    base = tmp_path / "repos"
    base.mkdir()
    repo = base / "evilrepo"
    repo.mkdir()
    # results-dir root is a symlink to the sensitive directory
    os.symlink(str(secret_dir), str(repo / "evilrepo_VULNHUNT_RESULTS_2"))

    upload = tmp_path / "up"
    utils.collect_results(clone_base=str(base), upload_dir=str(upload))

    dst = upload / "evilrepo_VULNHUNT_RESULTS_2"
    leaked = dst / "id_rsa"
    assert not (leaked.exists() or os.path.lexists(str(leaked))), \
        "symlinked results-dir root followed: host secret copied into upload"


def test_collect_results_does_not_follow_deep_nested_symlinked_subdir(tmp_path):
    # CANON-18 (deep-nested vector): the results dir is a real tree several
    # levels deep, and at a deep leaf sits a symlink to a DIRECTORY outside the
    # tree holding a secret. copytree's per-directory ignore= callable must drop
    # the symlinked subdir *before* recursing into it, so neither the linked
    # directory nor its secret contents ship. This locks in that the fix walks
    # the whole tree, not just the top level.
    secret_dir = tmp_path / "outside_secret_dir"
    secret_dir.mkdir()
    (secret_dir / "creds.env").write_text("AWS_SECRET_ACCESS_KEY=DEEP-NESTED-SECRET-qq42")

    base = tmp_path / "repos"
    base.mkdir()
    repo = base / "evilrepo"
    repo.mkdir()
    rd = repo / "evilrepo_VULNHUNT_RESULTS_3"
    rd.mkdir()
    # A real, several-levels-deep subtree of legitimate content.
    deep = rd / "a" / "b" / "c"
    deep.mkdir(parents=True)
    (deep / "finding.md").write_text("legit deep finding")
    # At the deep leaf, plant a symlink to the outside secret DIRECTORY.
    os.symlink(str(secret_dir), str(deep / "linked_dir"))

    upload = tmp_path / "up"
    utils.collect_results(clone_base=str(base), upload_dir=str(upload))

    dst = upload / "evilrepo_VULNHUNT_RESULTS_3"
    # The legitimate deep tree ships intact.
    assert (dst / "a" / "b" / "c" / "finding.md").read_text() == "legit deep finding"
    # The symlinked subdir must not ship at all (not even as a dangling link).
    linked_upload = dst / "a" / "b" / "c" / "linked_dir"
    assert not os.path.lexists(str(linked_upload)), \
        "deep-nested symlinked subdir shipped into upload"
    # The secret's contents must appear nowhere under the upload dir.
    for root, _dirs, files in os.walk(str(upload)):
        for name in files:
            fp = os.path.join(root, name)
            if os.path.islink(fp) or not os.path.isfile(fp):
                continue
            with open(fp, "r", errors="ignore") as f:
                assert "DEEP-NESTED-SECRET" not in f.read(), \
                    f"secret leaked into upload at {fp}"


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
