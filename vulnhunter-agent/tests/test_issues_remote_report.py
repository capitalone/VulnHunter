"""Tests for issues_remote_report._newest_subdir and download semantics.

We don't exercise the real `git clone` here — that's covered in
test_publish.py for the symmetrical case. We test the post-clone
directory-walking logic that picks the newest report.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from agent import issues_remote_report as remote_mod
from agent.issues_remote_report import (
    DownloadedReport,
    RemoteReportError,
    download_latest_report,
)


class TestDownloadLatestReport:
    @pytest.fixture
    def populated_dest(self, tmp_path: Path) -> Path:
        """Build a fake dest checkout: <owner>/<name>/<commit>/<results>/README.md."""
        dest = tmp_path / "dest_checkout"
        results = (
            dest
            / "src_owner"
            / "src_name"
            / "abc1234"
            / "src_name_VULNHUNT_RESULTS_opus47_2026-06-23-141824"
        )
        results.mkdir(parents=True)
        (results / "README.md").write_text("# report")
        return dest

    @pytest.fixture
    def older_and_newer(self, tmp_path: Path) -> Path:
        """Two reports under the same owner/name; pick the newest by name."""
        dest = tmp_path / "dest_checkout"
        for ts in ["2026-06-22-090000", "2026-06-24-110000"]:
            results = (
                dest
                / "src_owner"
                / "src_name"
                / "abc1234"
                / f"src_name_VULNHUNT_RESULTS_opus47_{ts}"
            )
            results.mkdir(parents=True)
            (results / "README.md").write_text("# report")
        return dest

    @pytest.fixture
    def with_timestamp_segment(self, tmp_path: Path) -> Path:
        """Newer publish format that adds a timestamp path segment."""
        dest = tmp_path / "dest_checkout"
        results = (
            dest
            / "src_owner"
            / "src_name"
            / "2026-06-23-141824"
            / "abc1234"
            / "src_name_VULNHUNT_RESULTS_opus47_2026-06-23-141824"
        )
        results.mkdir(parents=True)
        (results / "README.md").write_text("# report")
        return dest

    def _stub_clone(
        self,
        monkeypatch: pytest.MonkeyPatch,
        dest_checkout: Path,
    ) -> None:
        """Patch _run so we don't actually shell out to git.

        The real flow does: clone, sparse-checkout init, sparse-checkout
        set, checkout. We make the first call rename our pre-built
        checkout into the workdir argument, and stub the rest.
        """
        import shutil

        def fake_run(cmd: list[str], *, cwd: Any = None, timeout: int = 300) -> Any:
            if cmd[:2] == ["git", "clone"]:
                target = Path(cmd[-1])
                shutil.rmtree(target, ignore_errors=True)
                shutil.copytree(dest_checkout, target)

            class _Result:
                returncode = 0
                stdout = ""
                stderr = ""

            return _Result()

        monkeypatch.setattr(remote_mod, "_run", fake_run)

    def _cfg_authed(self, populated_agent_config: Any) -> Any:
        from dataclasses import replace

        return replace(
            populated_agent_config,
            github=replace(populated_agent_config.github, reports_token="ghp_x"),
            publish=replace(
                populated_agent_config.publish,
                destination_repo="https://github.com/o/dest",
            ),
        )

    def test_picks_newest_by_results_dir_name(
        self,
        older_and_newer: Path,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        cfg = self._cfg_authed(populated_agent_config)
        self._stub_clone(monkeypatch, older_and_newer)
        result = download_latest_report(
            "https://github.com/src_owner/src_name",
            config=cfg,
        )
        try:
            assert isinstance(result, DownloadedReport)
            assert "2026-06-24-110000" in result.path.name
            assert "2026-06-24-110000" in result.rel_path_in_dest
            assert (result.path / "README.md").is_file()
        finally:
            result.cleanup()

    def test_works_without_timestamp_segment(
        self,
        populated_dest: Path,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        """Older publish format: <owner>/<name>/<commit>/<results>/."""
        cfg = self._cfg_authed(populated_agent_config)
        self._stub_clone(monkeypatch, populated_dest)
        result = download_latest_report(
            "https://github.com/src_owner/src_name",
            config=cfg,
        )
        try:
            assert (result.path / "README.md").is_file()
            assert result.rel_path_in_dest == (
                "src_owner/src_name/abc1234/"
                "src_name_VULNHUNT_RESULTS_opus47_2026-06-23-141824"
            )
        finally:
            result.cleanup()

    def test_works_with_timestamp_segment(
        self,
        with_timestamp_segment: Path,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        """Newer publish format: <owner>/<name>/<timestamp>/<commit>/<results>/."""
        cfg = self._cfg_authed(populated_agent_config)
        self._stub_clone(monkeypatch, with_timestamp_segment)
        result = download_latest_report(
            "https://github.com/src_owner/src_name",
            config=cfg,
        )
        try:
            assert (result.path / "README.md").is_file()
            assert result.rel_path_in_dest == (
                "src_owner/src_name/2026-06-23-141824/abc1234/"
                "src_name_VULNHUNT_RESULTS_opus47_2026-06-23-141824"
            )
        finally:
            result.cleanup()

    def test_skips_dirs_without_readme(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        """A *VULNHUNT_RESULTS* dir without a README.md must not be selected."""
        dest = tmp_path / "dest_checkout"
        # Older / partial run with no README.
        bad = dest / "src_owner" / "src_name" / "abc" / "src_name_VULNHUNT_RESULTS_old"
        bad.mkdir(parents=True)
        # Good run with README.
        good = dest / "src_owner" / "src_name" / "def" / "src_name_VULNHUNT_RESULTS_new"
        good.mkdir(parents=True)
        (good / "README.md").write_text("# r")
        cfg = self._cfg_authed(populated_agent_config)
        self._stub_clone(monkeypatch, dest)
        result = download_latest_report(
            "https://github.com/src_owner/src_name",
            config=cfg,
        )
        try:
            assert result.path.name == "src_name_VULNHUNT_RESULTS_new"
        finally:
            result.cleanup()

    def test_cleanup_removes_workdir(
        self,
        populated_dest: Path,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        """DownloadedReport.cleanup() must delete the workdir on success."""
        cfg = self._cfg_authed(populated_agent_config)
        self._stub_clone(monkeypatch, populated_dest)
        result = download_latest_report(
            "https://github.com/src_owner/src_name",
            config=cfg,
        )
        workdir = result.workdir
        assert workdir.is_dir()
        result.cleanup()
        assert not workdir.exists(), f"workdir {workdir} survived cleanup"

    def test_missing_destination_raises(
        self, populated_agent_config: Any
    ) -> None:
        from dataclasses import replace

        cfg = replace(
            populated_agent_config,
            publish=replace(
                populated_agent_config.publish, destination_repo=""
            ),
        )
        with pytest.raises(RemoteReportError, match="destination_repo"):
            download_latest_report(
                "https://github.com/src_owner/src_name",
                config=cfg,
            )

    def test_missing_token_raises(self, populated_agent_config: Any) -> None:
        from dataclasses import replace

        cfg = replace(
            populated_agent_config,
            publish=replace(
                populated_agent_config.publish,
                destination_repo="https://github.com/o/dest",
            ),
            github=replace(populated_agent_config.github, reports_token=""),
        )
        with pytest.raises(RemoteReportError, match="reports_token"):
            download_latest_report(
                "https://github.com/src_owner/src_name",
                config=cfg,
            )

    def test_empty_owner_dir_raises(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        """Owner subtree exists but has no *VULNHUNT_RESULTS* dirs at all."""
        dest = tmp_path / "dest_checkout"
        # owner/name exists but no report dirs underneath.
        (dest / "src_owner" / "src_name" / "stuff" / "subdir").mkdir(parents=True)
        cfg = self._cfg_authed(populated_agent_config)
        self._stub_clone(monkeypatch, dest)
        with pytest.raises(
            RemoteReportError, match="No \\*VULNHUNT_RESULTS\\*"
        ):
            download_latest_report(
                "https://github.com/src_owner/src_name",
                config=cfg,
            )

    def test_no_owner_subtree_raises(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        """Dest repo doesn't have <owner>/<name>/ at all."""
        empty = tmp_path / "dest_checkout"
        empty.mkdir()
        cfg = self._cfg_authed(populated_agent_config)
        self._stub_clone(monkeypatch, empty)
        with pytest.raises(RemoteReportError, match="No published reports"):
            download_latest_report(
                "https://github.com/src_owner/src_name",
                config=cfg,
            )

    def test_workdir_cleanup_on_failure(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        populated_agent_config: Any,
    ) -> None:
        """If git clone fails, workdir is cleaned up before the error propagates."""
        cfg = self._cfg_authed(populated_agent_config)

        recorded_workdirs: list[Path] = []

        def failing_run(
            cmd: list[str], *, cwd: Any = None, timeout: int = 300
        ) -> Any:
            if cmd[:2] == ["git", "clone"]:
                recorded_workdirs.append(Path(cmd[-1]))
                raise RemoteReportError("synthetic clone failure")

            class _Result:
                returncode = 0
                stdout = ""
                stderr = ""

            return _Result()

        monkeypatch.setattr(remote_mod, "_run", failing_run)
        with pytest.raises(RemoteReportError, match="synthetic clone failure"):
            download_latest_report(
                "https://github.com/src_owner/src_name",
                config=cfg,
                cache_base_dir=tmp_path,
            )
        assert recorded_workdirs, "git clone was never invoked"
        for wd in recorded_workdirs:
            assert not wd.exists(), f"workdir {wd} survived failure cleanup"


class TestRunSubprocess:
    def test_failed_command_raises_with_redacted_url(
        self, tmp_path: Path
    ) -> None:
        """Exercise the real _run wrapper to cover its error path."""
        from agent.issues_remote_report import _run

        with pytest.raises(RemoteReportError, match="git command failed"):
            _run(
                ["git", "-C", str(tmp_path), "status"],
            )

    def test_url_redacted_in_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The token in cmd args + stderr must not leak in the raised error.

        Mocks ``subprocess.run`` rather than invoking a real ``git clone``
        — the latter is network-dependent (CI's path to github.com may
        not fail within a short timeout) and isn't what's being tested
        here. ``_run``'s job is to redact when the underlying command
        fails; the failure cause is irrelevant.
        """
        from agent.issues_remote_report import _run

        class _Result:
            returncode = 128
            stdout = ""
            # git typically echoes the URL in its error output, so make
            # the fake stderr match that shape so we know redaction
            # actually scrubs both the cmd args AND stderr text.
            stderr = (
                "fatal: unable to access "
                "'https://x-access-token:secret@github.com/o/r/': "
                "boom"
            )

        monkeypatch.setattr(
            "agent.issues_remote_report.subprocess.run",
            lambda *a, **kw: _Result(),
        )

        with pytest.raises(RemoteReportError) as exc_info:
            _run(
                [
                    "git",
                    "clone",
                    "https://x-access-token:secret@github.com/o/r",
                    str(tmp_path / "nope"),
                ],
            )
        msg = str(exc_info.value)
        assert "secret" not in msg, msg
        # Sanity: the redacted form must show up so we know we exercised
        # the redaction path rather than producing an empty error.
        assert "***" in msg, msg
