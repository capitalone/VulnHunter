"""Tests for local_harness.scan."""

import json
import os
import types

import pytest

import local_harness.batch.utils as utils
import local_harness.scan as scan

# Captured before the autouse stub below replaces it, for the tests that
# exercise the real git lookups.
_real_git_metadata = scan.git_metadata


@pytest.fixture(autouse=True)
def _stub_git_metadata(monkeypatch):
    # The scan_folder tests fake subprocess.Popen, which subprocess.run (used
    # for the git lookups) goes through too; keep git out of them.
    monkeypatch.setattr(scan, "git_metadata",
                        lambda folder: ("main [abc1234]", "https://github.com/o/r"))


def _prompt_results_dir(prompt):
    """The VULNHUNT_DIR value from the kickoff prompt's pre-resolved metadata."""
    for line in prompt.splitlines():
        if line.startswith("- VULNHUNT_DIR: "):
            return line[len("- VULNHUNT_DIR: "):]
    raise AssertionError(f"no VULNHUNT_DIR in prompt: {prompt!r}")


# --- results dir helpers ---

def test_find_results_dir_missing(tmp_path):
    assert scan.find_results_dir(str(tmp_path / "nope")) is None


def test_find_results_dir_found(tmp_path):
    d = tmp_path / "repo_VULNHUNT_RESULTS_2024"
    d.mkdir()
    assert scan.find_results_dir(str(tmp_path)) == str(d)


def test_find_results_dir_none_match(tmp_path):
    (tmp_path / "src").mkdir()
    assert scan.find_results_dir(str(tmp_path)) is None


def test_find_results_dir_ignores_file(tmp_path):
    (tmp_path / "x_VULNHUNT_RESULTS_y").write_text("a file, not a dir")
    assert scan.find_results_dir(str(tmp_path)) is None


def test_has_valid_results_true(tmp_path):
    rd = tmp_path / "r_VULNHUNT_RESULTS_1"
    rd.mkdir()
    (rd / "README.md").write_text("x" * 200)
    assert scan.has_valid_results(str(tmp_path)) is True


def test_has_valid_results_readme_too_small(tmp_path):
    rd = tmp_path / "r_VULNHUNT_RESULTS_1"
    rd.mkdir()
    (rd / "README.md").write_text("tiny")
    assert scan.has_valid_results(str(tmp_path)) is False


def test_has_valid_results_no_results_dir(tmp_path):
    assert scan.has_valid_results(str(tmp_path)) is False


# --- clean helpers ---

def test_clean_incomplete_results_removes_invalid(tmp_path):
    clone = tmp_path / "clone"
    clone.mkdir()
    bad = clone / "a_VULNHUNT_RESULTS_1"
    bad.mkdir()
    (bad / "README.md").write_text("short")
    (clone / "benchmark_scan.log").write_text("log")
    removed = scan.clean_incomplete_results(str(clone))
    assert "a_VULNHUNT_RESULTS_1" in removed
    assert not bad.exists()
    assert not (clone / "benchmark_scan.log").exists()


def test_clean_incomplete_results_keeps_valid(tmp_path):
    clone = tmp_path / "clone"
    clone.mkdir()
    good = clone / "a_VULNHUNT_RESULTS_1"
    good.mkdir()
    (good / "README.md").write_text("x" * 200)
    removed = scan.clean_incomplete_results(str(clone))
    assert removed == []
    assert good.exists()


def test_clean_incomplete_results_missing_dir(tmp_path):
    assert scan.clean_incomplete_results(str(tmp_path / "nope")) == []


def test_clean_incomplete_results_skips_non_dir_entry(tmp_path):
    clone = tmp_path / "clone"
    clone.mkdir()
    (clone / "x_VULNHUNT_RESULTS_file").write_text("not a dir")
    assert scan.clean_incomplete_results(str(clone)) == []


def test_clean_prior_results_removes_all(tmp_path):
    clone = tmp_path / "clone"
    clone.mkdir()
    rd = clone / "a_VULNHUNT_RESULTS_1"
    rd.mkdir()
    (clone / "benchmark_scan.log").write_text("log")
    removed = scan.clean_prior_results(str(clone))
    assert "a_VULNHUNT_RESULTS_1" in removed
    assert "benchmark_scan.log" in removed


def test_clean_prior_results_missing_dir(tmp_path):
    assert scan.clean_prior_results(str(tmp_path / "nope")) == []


def test_clean_prior_results_symlink_to_dir_no_crash(tmp_path):
    # CANON-34: an untrusted clone can plant a symlink named
    # *_VULNHUNT_RESULTS_* pointing at a directory. os.path.isdir follows the
    # link so the old code reached shutil.rmtree(symlink) -> OSError, aborting
    # the whole scan (DoS). Cleanup must remove the link (not its target)
    # without raising.
    target = tmp_path / "real_target_dir"
    target.mkdir()
    (target / "keep.txt").write_text("do not delete me")

    clone = tmp_path / "clone"
    clone.mkdir()
    link = clone / "evil_VULNHUNT_RESULTS_1"
    os.symlink(str(target), str(link))

    removed = scan.clean_prior_results(str(clone))  # must not raise
    assert not os.path.lexists(str(link)), "planted symlink was not removed"
    assert target.is_dir() and (target / "keep.txt").exists(), \
        "symlink target must be left intact (only the link is removed)"


def test_clean_incomplete_results_symlink_to_dir_no_crash(tmp_path):
    # CANON-34 companion: same DoS applies to clean_incomplete_results.
    target = tmp_path / "real_target_dir"
    target.mkdir()
    (target / "keep.txt").write_text("do not delete me")

    clone = tmp_path / "clone"
    clone.mkdir()
    link = clone / "evil_VULNHUNT_RESULTS_1"
    os.symlink(str(target), str(link))

    scan.clean_incomplete_results(str(clone))  # must not raise
    assert not os.path.lexists(str(link)), "planted symlink was not removed"
    assert target.is_dir() and (target / "keep.txt").exists(), \
        "symlink target must be left intact (only the link is removed)"


# --- log inspection ---

def test_is_rate_limit_failure_no_file():
    assert scan.is_rate_limit_failure(None) is False
    assert scan.is_rate_limit_failure("/does/not/exist") is False


def test_is_rate_limit_failure_true(tmp_path):
    log = tmp_path / "scan.log"
    log.write_text(json.dumps({"type": "result", "api_error_status": 429}) + "\n")
    assert scan.is_rate_limit_failure(str(log)) is True


def test_is_rate_limit_failure_false(tmp_path):
    log = tmp_path / "scan.log"
    log.write_text(
        "\n"
        + json.dumps({"type": "system"}) + "\n"
        + "not json\n"
        + json.dumps({"type": "result", "api_error_status": None}) + "\n"
    )
    assert scan.is_rate_limit_failure(str(log)) is False


def test_extract_cost_no_file():
    assert scan.extract_cost_from_log(None) == {}
    assert scan.extract_cost_from_log("/nope") == {}


def test_extract_cost_from_log(tmp_path):
    log = tmp_path / "scan.log"
    event = {
        "type": "result",
        "total_cost_usd": 1.25,
        "duration_api_ms": 4200,
        "num_turns": 7,
        "modelUsage": {
            "m1": {"inputTokens": 10, "outputTokens": 20,
                   "cacheReadInputTokens": 5, "cacheCreationInputTokens": 3},
            "m2": {"inputTokens": 1, "outputTokens": 2},
        },
    }
    log.write_text("junk\n" + json.dumps(event) + "\n")
    cost = scan.extract_cost_from_log(str(log))
    assert cost["total_cost_usd"] == 1.25
    assert cost["input_tokens"] == 11
    assert cost["output_tokens"] == 22
    assert cost["cache_read_tokens"] == 5
    assert cost["num_turns"] == 7


def test_extract_cost_no_result_event(tmp_path):
    log = tmp_path / "scan.log"
    log.write_text(json.dumps({"type": "system"}) + "\n")
    assert scan.extract_cost_from_log(str(log)) == {}


def test_ts_format():
    out = scan.ts()
    assert len(out) == 8 and out.count(":") == 2


# --- scan_folder ---

def test_scan_folder_skill_not_installed(monkeypatch, tmp_path):
    monkeypatch.setattr(scan.os.path, "isdir", lambda p: False)
    result = scan.scan_folder(str(tmp_path / "repo"))
    assert result.returncode == 1
    assert result.results_dir is None


class _FakePopen:
    def __init__(self, lines, returncode=0):
        self.stdout = iter(lines)
        self.stderr = iter([])
        self.returncode = returncode
        self.killed = False

    def wait(self):
        return self.returncode

    def kill(self):
        self.killed = True


def test_scan_folder_success(monkeypatch, tmp_path):
    folder = tmp_path / "repo"
    folder.mkdir()
    # SKILLS_DIR must look installed; results dir found after scan.
    monkeypatch.setattr(scan, "SKILLS_DIR", str(tmp_path / "skills"))
    (tmp_path / "skills").mkdir()

    events = [json.dumps({"type": "system", "n": i}) for i in range(3)]
    events.append(json.dumps({"type": "result", "total_cost_usd": 0.5,
                              "modelUsage": {"m": {"inputTokens": 4, "outputTokens": 6}}}))
    lines = [e + "\n" for e in events] + ["\n", "not-json\n"]
    written = {}

    def fake_popen(cmd, *a, **k):
        written["rd"] = _prompt_results_dir(cmd[2])
        with open(os.path.join(written["rd"], "README.md"), "w") as f:
            f.write("report")
        return _FakePopen(lines, returncode=0)
    monkeypatch.setattr(scan.subprocess, "Popen", fake_popen)

    # avoid real timer thread firing
    class _NoTimer:
        def __init__(self, *a, **k):
            pass
        def start(self):
            pass
        def cancel(self):
            pass
    monkeypatch.setattr(scan.threading, "Timer", _NoTimer)

    result = scan.scan_folder(str(folder))
    folder_path, label, returncode, event_count, elapsed, results_dir, cost = result
    assert returncode == 0
    assert event_count == 4
    assert results_dir == written["rd"]
    assert os.path.dirname(results_dir) == str(folder)
    assert cost["total_cost_usd"] == 0.5


def test_scan_folder_readonly_appends_prompt(monkeypatch, tmp_path):
    folder = tmp_path / "repo"
    folder.mkdir()
    monkeypatch.setattr(scan, "SKILLS_DIR", str(tmp_path / "skills"))
    (tmp_path / "skills").mkdir()

    captured = {}

    def fake_popen(cmd, *a, **k):
        captured["prompt"] = cmd[2]
        return _FakePopen([json.dumps({"type": "result"}) + "\n"], returncode=0)
    monkeypatch.setattr(scan.subprocess, "Popen", fake_popen)

    class _NoTimer:
        def __init__(self, *a, **k):
            pass
        def start(self):
            pass
        def cancel(self):
            pass
    monkeypatch.setattr(scan.threading, "Timer", _NoTimer)

    scan.scan_folder(str(folder), readonly=True)
    assert "read-only scan" in captured["prompt"]

    scan.clean_prior_results(str(folder))  # as the retry path does between attempts
    scan.scan_folder(str(folder), readonly=False)
    assert "read-only scan" not in captured["prompt"]


def _capture_scan_argv(monkeypatch, tmp_path, **scan_kwargs):
    """Run scan_folder with Popen stubbed and return the claude argv."""
    folder = tmp_path / "repo"
    folder.mkdir()
    monkeypatch.setattr(scan, "SKILLS_DIR", str(tmp_path / "skills"))
    (tmp_path / "skills").mkdir()

    captured = {}

    def fake_popen(cmd, *a, **k):
        captured["argv"] = cmd
        # The results dir named in the prompt must exist when claude is launched.
        assert os.path.isdir(_prompt_results_dir(cmd[2]))
        return _FakePopen([json.dumps({"type": "result"}) + "\n"], returncode=0)
    monkeypatch.setattr(scan.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(scan.threading, "Timer", _NoTimer)

    scan.scan_folder(str(folder), **scan_kwargs)
    return captured["argv"]


def _flag_values(argv, flag):
    """Values following `flag` up to the next --option."""
    out = []
    for tok in argv[argv.index(flag) + 1:]:
        if tok.startswith("--"):
            break
        out.append(tok)
    return out


@pytest.mark.parametrize("kwargs", [{}, {"readonly": True}])
def test_scan_folder_readonly_tool_boundary(monkeypatch, tmp_path, kwargs):
    """CANON-03: the default (and explicit) read-only scan is a real boundary.

    --tools removes Bash outright (--allowedTools only pre-approves), and with
    --permission-mode default the only pre-approved write is the pre-created
    results dir: no bare Read/Write/Edit grant that would cover every path.
    """
    argv = _capture_scan_argv(monkeypatch, tmp_path, **kwargs)
    assert not any("Bash" in tok for tok in argv[3:]), argv
    assert _flag_values(argv, "--tools") == ["Read,Write,Edit,Grep,Glob,Agent"]
    assert _flag_values(argv, "--permission-mode") == ["default"]

    results_dir = _prompt_results_dir(argv[2])
    rule = f"Edit(//{os.path.realpath(results_dir).lstrip('/')}/**)"
    assert _flag_values(argv, "--allowedTools") == [rule, "Agent"]


@pytest.mark.parametrize("readonly", [True, False])
def test_scan_folder_skips_project_settings_and_mcp(monkeypatch, tmp_path, readonly):
    """CANON-19 (harness): the clone's .claude/settings*.json hooks must not run
    on the host, and MCP servers (an exfiltration channel) are not loaded, in
    either mode."""
    argv = _capture_scan_argv(monkeypatch, tmp_path, readonly=readonly)
    assert _flag_values(argv, "--setting-sources") == ["user"]
    assert "--strict-mcp-config" in argv


def test_scan_folder_execute_optin_grants_bash(monkeypatch, tmp_path):
    """CANON-03: only an explicit opt-out (readonly=False) re-adds Bash."""
    argv = _capture_scan_argv(monkeypatch, tmp_path, readonly=False)
    assert {"Read", "Write", "Edit", "Bash", "Agent"} <= set(_flag_values(argv, "--allowedTools"))
    assert _flag_values(argv, "--permission-mode") == ["acceptEdits"]


def test_scan_folder_readonly_no_parent_add_dir(monkeypatch, tmp_path):
    """CANON-03/Fix B: a read-only (default) scan must NOT --add-dir the parent
    (sibling clones). The scanned folder itself is still added."""
    argv = _capture_scan_argv(monkeypatch, tmp_path)
    folder = str(tmp_path / "repo")
    add_dirs = [argv[i + 1] for i, tok in enumerate(argv[:-1]) if tok == "--add-dir"]
    assert folder in add_dirs, add_dirs
    assert os.path.dirname(folder) not in add_dirs, add_dirs


@pytest.mark.parametrize("readonly,bash_line", [
    (True, "Bash is NOT available"),
    (False, "Bash is AVAILABLE"),
])
def test_scan_folder_prompt_has_preresolved_metadata(monkeypatch, tmp_path, readonly, bash_line):
    """Without Bash, SKILL.md path B would ask the user for a results dir and
    git metadata, which a headless run can't answer; the harness pre-creates
    the dir and hands the values over as SKILL.md path A expects."""
    argv = _capture_scan_argv(monkeypatch, tmp_path, readonly=readonly)
    prompt = argv[2]
    assert "Pre-resolved scan metadata" in prompt
    results_dir = _prompt_results_dir(prompt)
    # _capture_scan_argv checks that the dir exists when claude is launched;
    # a dir the scan left empty is removed once the scan has finished.
    assert os.path.basename(results_dir).startswith("repo_VULNHUNT_RESULTS_")
    assert "- VULNHUNT_BRANCH: main [abc1234]" in prompt
    assert "- Repository URL: https://github.com/o/r" in prompt
    assert bash_line in prompt


def test_scan_folder_results_dir_none_when_scan_wrote_nothing(monkeypatch, tmp_path):
    folder = tmp_path / "repo"
    folder.mkdir()
    result = _run_fake_scan(monkeypatch, tmp_path, folder)
    assert result.results_dir is None


def test_scan_folder_removes_empty_results_dir(monkeypatch, tmp_path):
    folder = tmp_path / "repo"
    folder.mkdir()
    _run_fake_scan(monkeypatch, tmp_path, folder)
    assert [e for e in os.listdir(folder) if "_VULNHUNT_RESULTS_" in e] == []


def test_scan_folder_tolerates_failure_to_remove_empty_results_dir(monkeypatch, tmp_path):
    folder = tmp_path / "repo"
    folder.mkdir()

    def fail_rmdir(path):
        raise PermissionError(path)
    monkeypatch.setattr(scan.os, "rmdir", fail_rmdir)

    result = _run_fake_scan(monkeypatch, tmp_path, folder)

    assert result.results_dir is None


def test_failed_scan_is_reported_missing_by_collect_results(monkeypatch, tmp_path):
    # An empty results dir left by a scan that wrote nothing used to be copied
    # to the upload dir and counted as a result.
    base = tmp_path / "clones"
    folder = base / "owner__repo"
    folder.mkdir(parents=True)
    _run_fake_scan(monkeypatch, tmp_path, folder)

    out = utils.collect_results(clone_base=str(base), upload_dir=str(tmp_path / "up"))

    assert out == {"copied": [], "missing": ["owner__repo"]}


def test_create_results_dir_refuses_existing(monkeypatch, tmp_path):
    class _FixedDatetime:
        @staticmethod
        def now():
            import datetime as _dt
            return _dt.datetime(2026, 1, 2, 3, 4, 5)
    monkeypatch.setattr(scan, "datetime", _FixedDatetime)
    rd = scan.create_results_dir(str(tmp_path))
    assert rd == str(tmp_path / f"{tmp_path.name}_VULNHUNT_RESULTS_2026-01-02-030405")
    with pytest.raises(FileExistsError):
        scan.create_results_dir(str(tmp_path))


@pytest.mark.parametrize("raw,expected", [
    ("git@github.com:org/repo.git", "https://github.com/org/repo"),
    ("https://user:tok@github.com/org/repo.git", "https://github.com/org/repo"),
    ("https://github.com/org/repo", "https://github.com/org/repo"),
])
def test_normalize_repo_url(raw, expected):
    assert scan._normalize_repo_url(raw) == expected


def test_git_metadata_real_repo(tmp_path):
    import subprocess
    repo = tmp_path / "proj"
    repo.mkdir()
    git = ["git", "-c", "user.email=a@b", "-c", "user.name=a"]
    subprocess.run(git + ["init", "-q", "-b", "main"], cwd=repo, check=True)
    (repo / "f").write_text("x")
    subprocess.run(git + ["add", "f"], cwd=repo, check=True)
    subprocess.run(git + ["commit", "-qm", "c"], cwd=repo, check=True)
    subprocess.run(["git", "remote", "add", "origin",
                    "https://u:secret@github.com/org/proj.git"], cwd=repo, check=True)
    branch, url = _real_git_metadata(str(repo))
    assert branch.startswith("main [") and branch.endswith("]")
    assert url == "https://github.com/org/proj"


def test_git_metadata_not_a_repo(tmp_path):
    assert _real_git_metadata(str(tmp_path)) == ("unknown", tmp_path.name)


def test_scan_folder_timeout(monkeypatch, tmp_path):
    folder = tmp_path / "repo"
    folder.mkdir()
    monkeypatch.setattr(scan, "SKILLS_DIR", str(tmp_path / "skills"))
    (tmp_path / "skills").mkdir()

    proc_holder = {}

    def fake_popen(*a, **k):
        p = _FakePopen([json.dumps({"type": "system"}) + "\n"], returncode=-9)
        proc_holder["p"] = p
        return p
    monkeypatch.setattr(scan.subprocess, "Popen", fake_popen)

    # Timer that fires immediately on start to simulate a timeout kill.
    class _FireTimer:
        def __init__(self, interval, fn):
            self.fn = fn
        def start(self):
            self.fn()
        def cancel(self):
            pass
    monkeypatch.setattr(scan.threading, "Timer", _FireTimer)

    result = scan.scan_folder(str(folder))
    assert proc_holder["p"].killed is True
    assert result.cost_data == {}  # cost empty on timeout


def test_scan_folder_timeout_with_valid_results_not_discarded(monkeypatch, tmp_path):
    # A scan that finishes exactly as the timer fires still produced valid
    # results; scan_folder must not discard them as a timeout.
    folder = tmp_path / "repo"
    folder.mkdir()
    monkeypatch.setattr(scan, "SKILLS_DIR", str(tmp_path / "skills"))
    (tmp_path / "skills").mkdir()

    events = [json.dumps({"type": "result", "total_cost_usd": 0.9,
                          "modelUsage": {"m": {"inputTokens": 1, "outputTokens": 1}}}) + "\n"]
    written = {}

    def fake_popen(cmd, *a, **k):
        written["rd"] = _prompt_results_dir(cmd[2])
        with open(os.path.join(written["rd"], "README.md"), "w") as f:
            f.write("x" * 200)
        return _FakePopen(events, returncode=0)
    monkeypatch.setattr(scan.subprocess, "Popen", fake_popen)

    class _FireTimer:
        def __init__(self, interval, fn):
            self.fn = fn
        def start(self):
            self.fn()  # fire immediately -> sets timed_out True
        def cancel(self):
            pass
    monkeypatch.setattr(scan.threading, "Timer", _FireTimer)

    result = scan.scan_folder(str(folder))
    assert result.results_dir == written["rd"]
    assert result.cost_data["total_cost_usd"] == 0.9  # not discarded


# --- retry wrapper ---

def test_scan_folder_with_retry_success_first_try(monkeypatch, tmp_path):
    folder = str(tmp_path / "repo")
    monkeypatch.setattr(scan, "scan_folder",
                        lambda fp, log_file=None, readonly=False: scan.ScanResult(fp, "repo", 0, 3, 1.0, "rd", {"total_cost_usd": 1}))
    monkeypatch.setattr(scan, "is_rate_limit_failure", lambda p: False)
    result = scan.scan_folder_with_retry(folder)
    assert result.returncode == 0


def test_scan_folder_with_retry_429_then_success(monkeypatch, tmp_path):
    folder = str(tmp_path / "repo")
    calls = {"n": 0}

    def fake_scan(fp, log_file=None, readonly=False):
        calls["n"] += 1
        if calls["n"] == 1:
            return scan.ScanResult(fp, "repo", 1, 0, 0.5, None, {})
        return scan.ScanResult(fp, "repo", 0, 5, 1.0, "rd", {})

    monkeypatch.setattr(scan, "scan_folder", fake_scan)
    monkeypatch.setattr(scan, "is_rate_limit_failure", lambda p: calls["n"] == 1)
    monkeypatch.setattr(scan, "clean_prior_results", lambda *a, **k: [])
    monkeypatch.setattr(scan.time, "sleep", lambda s: None)
    result = scan.scan_folder_with_retry(folder, log_filename="x.log")
    assert result.returncode == 0
    assert result.elapsed == 1.5  # elapsed summed across attempts
    assert calls["n"] == 2


def test_scan_folder_with_retry_429_exhausted(monkeypatch, tmp_path):
    folder = str(tmp_path / "repo")
    monkeypatch.setattr(scan, "scan_folder",
                        lambda fp, log_file=None, readonly=False: scan.ScanResult(fp, "repo", 1, 0, 0.5, None, {}))
    monkeypatch.setattr(scan, "is_rate_limit_failure", lambda p: True)
    monkeypatch.setattr(scan, "clean_prior_results", lambda *a, **k: ["r"])
    monkeypatch.setattr(scan.time, "sleep", lambda s: None)
    monkeypatch.setattr(scan, "SCAN_MAX_RETRIES", 2)
    result = scan.scan_folder_with_retry(folder)
    assert result.returncode == 1


# --- scan_targets ---

def test_scan_targets_collects_results(monkeypatch):
    targets = [{"clone_dir": "/c/a", "key": "a"}, {"clone_dir": "/c/b", "key": "b"}]
    monkeypatch.setattr(scan, "scan_folder_with_retry",
                        lambda cd, log_filename=None: (cd, "lbl", 0, 1, 1.0, "rd", {}))
    results = scan.scan_targets(targets, max_workers=2, status_interval=10_000)
    keys = {k for k, _ in results}
    assert keys == {"a", "b"}


def test_scan_targets_exception_path(monkeypatch):
    targets = [{"clone_dir": "/c/a", "key": "a"}]

    def boom(cd, log_filename=None):
        raise RuntimeError("kaboom")
    monkeypatch.setattr(scan, "scan_folder_with_retry", boom)
    # status_interval=0 forces the periodic status print branch.
    results = scan.scan_targets(targets, max_workers=1, status_interval=0)
    assert results[0][0] == "a"
    assert results[0][1].returncode == -1  # returncode sentinel


def test_scan_targets_default_workers(monkeypatch):
    monkeypatch.setattr(scan, "scan_folder_with_retry",
                        lambda cd, log_filename=None: (cd, "lbl", 0, 1, 1.0, "rd", {}))
    results = scan.scan_targets([{"clone_dir": "/c/a", "key": "a"}], status_interval=10_000)
    assert len(results) == 1


# --- scan log must not follow links planted in the (untrusted) clone ---

class _NoTimer:
    def __init__(self, *a, **k):
        pass

    def start(self):
        pass

    def cancel(self):
        pass


def _run_fake_scan(monkeypatch, tmp_path, folder, **kw):
    monkeypatch.setattr(scan, "SKILLS_DIR", str(tmp_path / "skills"))
    (tmp_path / "skills").mkdir(exist_ok=True)
    lines = [json.dumps({"type": "result", "total_cost_usd": 0.1}) + "\n"]
    monkeypatch.setattr(scan.subprocess, "Popen",
                        lambda *a, **k: _FakePopen(lines, returncode=0))
    monkeypatch.setattr(scan.threading, "Timer", _NoTimer)
    return scan.scan_folder(str(folder), **kw)


def test_scan_folder_does_not_write_through_symlinked_log(monkeypatch, tmp_path):
    # A repo can commit `benchmark_scan.log -> ~/.zshrc`; opening the log with
    # plain open(path, "w") follows the link and truncates the host file.
    victim = tmp_path / "victim_rc"
    victim.write_text("export SECRET=1\n")
    folder = tmp_path / "repo"
    folder.mkdir()
    log = folder / "benchmark_scan.log"
    os.symlink(str(victim), str(log))

    _run_fake_scan(monkeypatch, tmp_path, folder)

    assert victim.read_text() == "export SECRET=1\n", "host file was overwritten via symlink"
    assert not os.path.islink(str(log))
    assert '"result"' in log.read_text()


def test_scan_folder_does_not_create_dangling_symlink_target(monkeypatch, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    planted_target = outside / "created_by_attacker"
    folder = tmp_path / "repo"
    folder.mkdir()
    log = folder / "batch_scan.log"
    os.symlink(str(planted_target), str(log))

    _run_fake_scan(monkeypatch, tmp_path, folder, log_file=str(log))

    assert not planted_target.exists(), "dangling symlink target was created on the host"
    assert log.is_file() and not os.path.islink(str(log))


def test_scan_folder_does_not_truncate_hardlinked_log(monkeypatch, tmp_path):
    # An agent with Bash in the clone could leave a hard link to a host file at
    # the log path before a retry; O_TRUNC through it would clobber the file.
    victim = tmp_path / "victim_rc"
    victim.write_text("keep me\n")
    folder = tmp_path / "repo"
    folder.mkdir()
    log = folder / "benchmark_scan.log"
    os.link(str(victim), str(log))

    _run_fake_scan(monkeypatch, tmp_path, folder)

    assert victim.read_text() == "keep me\n"


def _result_log(path, status=429):
    path.write_text(json.dumps({"type": "result", "api_error_status": status,
                                "total_cost_usd": 9.99}) + "\n")


def test_log_readers_ignore_symlinked_log(tmp_path):
    real = tmp_path / "elsewhere.log"
    _result_log(real)
    link = tmp_path / "benchmark_scan.log"
    os.symlink(str(real), str(link))
    assert scan.is_rate_limit_failure(str(link)) is False
    assert scan.extract_cost_from_log(str(link)) == {}


def test_log_readers_ignore_fifo_log(tmp_path):
    fifo = tmp_path / "benchmark_scan.log"
    os.mkfifo(str(fifo))
    # Must return promptly rather than block opening the FIFO for read.
    assert scan.is_rate_limit_failure(str(fifo)) is False
    assert scan.extract_cost_from_log(str(fifo)) == {}


def test_clean_prior_results_removes_dangling_log_link(tmp_path):
    clone = tmp_path / "clone"
    clone.mkdir()
    log = clone / "benchmark_scan.log"
    os.symlink(str(tmp_path / "missing"), str(log))
    removed = scan.clean_prior_results(str(clone))
    assert not os.path.lexists(str(log))
    assert "benchmark_scan.log" in removed


def test_clean_prior_results_unlinks_log_link_not_target(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("keep")
    clone = tmp_path / "clone"
    clone.mkdir()
    log = clone / "benchmark_scan.log"
    os.symlink(str(victim), str(log))
    scan.clean_prior_results(str(clone))
    assert not os.path.lexists(str(log))
    assert victim.read_text() == "keep"


def test_clean_incomplete_results_removes_dangling_log_link(tmp_path):
    clone = tmp_path / "clone"
    clone.mkdir()
    (clone / "clone_VULNHUNT_RESULTS_1").mkdir()  # incomplete: no README
    log = clone / "batch_scan.log"
    os.symlink(str(tmp_path / "missing"), str(log))
    scan.clean_incomplete_results(str(clone), log_filename="batch_scan.log")
    assert not os.path.lexists(str(log))


# --- results-dir discovery must not trust links or repo-committed results ---

import shutil as _shutil
import subprocess as _subprocess

_BIG_README = "# Report\n" + ("x" * 200) + "\n"


def _real_results(parent, name="clone_VULNHUNT_RESULTS_1"):
    rd = parent / name
    rd.mkdir()
    (rd / "README.md").write_text(_BIG_README)
    return rd


def test_find_results_dir_skips_symlinked_results_root(tmp_path):
    outside = _real_results(tmp_path, "outside")
    clone = tmp_path / "clone"
    clone.mkdir()
    os.symlink(str(outside), str(clone / "clone_VULNHUNT_RESULTS_1"))
    assert scan.find_results_dir(str(clone)) is None
    assert scan.has_valid_results(str(clone)) is False


def test_find_results_dir_prefers_real_dir_over_planted_link(tmp_path):
    outside = _real_results(tmp_path, "outside")
    clone = tmp_path / "clone"
    clone.mkdir()
    os.symlink(str(outside), str(clone / "aaa_VULNHUNT_RESULTS_0"))
    real = _real_results(clone, "clone_VULNHUNT_RESULTS_1")
    assert scan.find_results_dir(str(clone)) == str(real)


def test_has_valid_results_rejects_symlinked_readme(tmp_path):
    host = tmp_path / "host_secret.txt"
    host.write_text("s" * 500)
    clone = tmp_path / "clone"
    clone.mkdir()
    rd = clone / "clone_VULNHUNT_RESULTS_1"
    rd.mkdir()
    os.symlink(str(host), str(rd / "README.md"))
    assert scan.has_valid_results(str(clone)) is False


def _git(*args, cwd):
    _subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false",
         *args],
        cwd=cwd, check=True, capture_output=True,
    )


needs_git = pytest.mark.skipif(_shutil.which("git") is None, reason="git not installed")


def _clone_with_committed_results(tmp_path):
    clone = tmp_path / "clone"
    clone.mkdir()
    _git("init", "-q", cwd=clone)
    (clone / "app.py").write_text("print(1)\n")
    _real_results(clone, "clone_VULNHUNT_RESULTS_2020-01-01-000000")
    _git("add", "-A", cwd=clone)
    _git("commit", "-q", "-m", "init", cwd=clone)
    return clone


@needs_git
def test_committed_results_dir_is_not_trusted(tmp_path):
    # A repo that ships its own *_VULNHUNT_RESULTS_* dir would make --resume
    # skip the scan and collect publish the attacker's report.
    clone = _clone_with_committed_results(tmp_path)
    assert scan.find_results_dir(str(clone)) is None
    assert scan.has_valid_results(str(clone)) is False


@needs_git
def test_committed_results_dir_ignored_but_scan_output_found(tmp_path):
    clone = _clone_with_committed_results(tmp_path)
    produced = _real_results(clone, "clone_VULNHUNT_RESULTS_2026-10-05-120000")
    assert scan.find_results_dir(str(clone)) == str(produced)
    assert scan.has_valid_results(str(clone)) is True


@needs_git
def test_clean_incomplete_results_removes_committed_results_dir(tmp_path):
    clone = _clone_with_committed_results(tmp_path)
    removed = scan.clean_incomplete_results(str(clone), log_filename="batch_scan.log")
    assert removed == ["clone_VULNHUNT_RESULTS_2020-01-01-000000"]
    assert not (clone / "clone_VULNHUNT_RESULTS_2020-01-01-000000").exists()


@needs_git
def test_committed_results_fallback_when_git_unavailable(monkeypatch, tmp_path):
    # Without a usable git the check degrades to the previous behaviour.
    clone = _clone_with_committed_results(tmp_path)

    def boom(*a, **k):
        raise FileNotFoundError("git")
    monkeypatch.setattr(scan.subprocess, "run", boom)
    assert scan.has_valid_results(str(clone)) is True


def test_results_dir_not_a_git_repo_still_trusted(tmp_path):
    clone = tmp_path / "clone"
    clone.mkdir()
    rd = _real_results(clone)
    assert scan.find_results_dir(str(clone)) == str(rd)
    assert scan.has_valid_results(str(clone)) is True
