"""Download the newest VulnHunter report for a source repo from the publish destination.

When the agent runs with ``--no-scan --issues``, there's no fresh
results directory locally — we have to fetch the most recent published
report. The publish stage files reports under
``<source_owner>/<source_name>/...`` but the depth varies between
publish-format generations (some have a ``<timestamp>`` segment, some
don't). Rather than assume a layout, we sparse-checkout
``<source_owner>/<source_name>/`` and find every directory whose name
matches ``*VULNHUNT_RESULTS*`` and contains a ``README.md``. The
newest one (by name — the directory name encodes
``YYYY-MM-DD-HHMMSS``) wins.

The returned ``DownloadedReport`` carries the temp workdir so the
caller can clean it up after the issues stage finishes — without that,
``/tmp`` would accumulate one tree per ``--no-scan`` run.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ._github import parse_owner_repo
from ._url import inject_token, redact
from .config import AgentConfig
from .token_client import get_github_token

logger = logging.getLogger(__name__)


class RemoteReportError(RuntimeError):
    """Raised when the latest published report can't be located or fetched."""


@dataclass(frozen=True)
class DownloadedReport:
    """A successfully-downloaded report and the workdir it lives in.

    Callers must invoke ``cleanup()`` (or ``shutil.rmtree(self.workdir)``)
    when done reading from ``path``. The workdir is a fresh
    ``tempfile.mkdtemp`` dir; without cleanup, ``/tmp`` accumulates one
    tree per run.
    """

    path: Path  # local results dir under the workdir
    rel_path_in_dest: str  # path inside the publish dest repo (for URL building)
    workdir: Path  # tempdir to clean up after use

    def cleanup(self) -> None:
        shutil.rmtree(self.workdir, ignore_errors=True)


def _run(
    cmd: list[str], *, cwd: Path | None = None, timeout: int = 300
) -> subprocess.CompletedProcess:
    # GIT_TERMINAL_PROMPT=0 mirrors what shallow_clone does in
    # agent/clone.py: makes git fail instead of hanging on a tty
    # credential prompt when the injected token is wrong / the repo
    # is private. Without this, a 401 from the destination repo
    # silently blocks the verify run forever.
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    result = subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env
    )
    if result.returncode != 0:
        rendered = " ".join(redact(arg) for arg in cmd)
        raise RemoteReportError(
            f"git command failed (exit {result.returncode}): {rendered}\n"
            f"{redact(result.stderr.strip())}"
        )
    return result


def download_latest_report(
    source_repo_url: str,
    *,
    config: AgentConfig,
    cache_base_dir: Path | None = None,
) -> DownloadedReport:
    """Sparse-checkout the publish dest and return the newest report.

    Raises ``RemoteReportError`` if no report exists yet. On any failure
    the temp workdir is removed; on success it's the caller's
    responsibility (call ``DownloadedReport.cleanup()``).
    """
    publish = config.publish
    issues = config.issues
    if not publish.destination_repo:
        raise RemoteReportError(
            "publish.destination_repo must be set when --no-scan + --issues "
            "are both used (we need somewhere to download the latest report from)."
        )
    token = get_github_token("reports", config)
    if not token:
        raise RemoteReportError(
            "reports_token is required to download from the publish destination."
        )

    source_owner, source_name = parse_owner_repo(source_repo_url)
    sparse_path = f"{source_owner}/{source_name}"
    authed_url = inject_token(publish.destination_repo, token, config.github.host)

    workdir = Path(tempfile.mkdtemp(prefix="vulnhunt-fetch-", dir=cache_base_dir))
    try:
        _run(
            [
                "git",
                "clone",
                "--filter=blob:none",
                "--no-checkout",
                "--depth=1",
                "--branch",
                publish.branch,
                authed_url,
                str(workdir),
            ],
            timeout=issues.request_timeout_seconds * 5,
        )
        _run(["git", "sparse-checkout", "init"], cwd=workdir)
        _run(
            ["git", "sparse-checkout", "set", "--no-cone", f"/{sparse_path}/*"],
            cwd=workdir,
        )
        _run(["git", "checkout", publish.branch], cwd=workdir)

        owner_dir = workdir / sparse_path
        if not owner_dir.is_dir():
            raise RemoteReportError(
                f"No published reports found for {source_owner}/{source_name} "
                f"at {redact(publish.destination_repo)}@{publish.branch}."
            )

        candidates = [
            p
            for p in owner_dir.rglob("*VULNHUNT_RESULTS*")
            if p.is_dir() and (p / "README.md").is_file()
        ]
        if not candidates:
            raise RemoteReportError(
                f"No *VULNHUNT_RESULTS* directory with a README.md was found "
                f"under {sparse_path} in {redact(publish.destination_repo)}@"
                f"{publish.branch}."
            )

        newest = max(candidates, key=lambda p: p.name)
        rel_path_in_dest = str(newest.relative_to(workdir))

        logger.info(
            "Downloaded latest report for %s/%s: %s",
            source_owner,
            source_name,
            rel_path_in_dest,
        )
        return DownloadedReport(
            path=newest, rel_path_in_dest=rel_path_in_dest, workdir=workdir
        )
    except Exception:
        shutil.rmtree(workdir, ignore_errors=True)
        raise


def download_named_report(
    source_repo_url: str,
    results_dir_name: str,
    *,
    config: AgentConfig,
    timeout_seconds: int = 300,
    cache_base_dir: Path | None = None,
) -> DownloadedReport:
    """Sparse-checkout the publish dest and return the report whose
    directory basename equals ``results_dir_name``.

    Used by ``--mode=verify``: the GitHub issue body's
    ``vulnhunt-results-dir`` marker names the exact scan we need to
    verify against; an unrelated newer report (which is what
    ``download_latest_report`` would return) would be wrong.

    Raises ``RemoteReportError`` when the named directory cannot be
    found. **Never** falls back to the newest report — silently
    swapping in a different scan would corrupt the verifier's
    judgment.
    """
    publish = config.publish
    if not publish.destination_repo:
        raise RemoteReportError(
            "publish.destination_repo must be set; verify mode downloads "
            "the original scan's report from there."
        )
    # Downloads from publish.destination_repo require the reports-role
    # token (post PR #38's dual-token migration).
    reports_token = get_github_token("reports", config)
    if not reports_token:
        raise RemoteReportError(
            "reports_token is required to download from the publish destination."
        )
    if not results_dir_name:
        raise RemoteReportError(
            "results_dir_name must be a non-empty basename (from the "
            "issue's `vulnhunt-results-dir` marker)."
        )

    source_owner, source_name = parse_owner_repo(source_repo_url)
    sparse_path = f"{source_owner}/{source_name}"
    authed_url = inject_token(
        publish.destination_repo, reports_token, config.github.host
    )

    workdir = Path(tempfile.mkdtemp(prefix="vulnhunt-verify-fetch-", dir=cache_base_dir))
    try:
        _run(
            [
                "git",
                "clone",
                "--filter=blob:none",
                "--no-checkout",
                "--depth=1",
                "--branch",
                publish.branch,
                authed_url,
                str(workdir),
            ],
            timeout=timeout_seconds,
        )
        _run(["git", "sparse-checkout", "init"], cwd=workdir)
        _run(
            ["git", "sparse-checkout", "set", "--no-cone", f"/{sparse_path}/*"],
            cwd=workdir,
        )
        _run(["git", "checkout", publish.branch], cwd=workdir)

        owner_dir = workdir / sparse_path
        if not owner_dir.is_dir():
            raise RemoteReportError(
                f"No published reports found for {source_owner}/{source_name} "
                f"at {redact(publish.destination_repo)}@{publish.branch}."
            )

        matches = [
            p
            for p in owner_dir.rglob(results_dir_name)
            if p.is_dir() and p.name == results_dir_name
        ]
        if not matches:
            raise RemoteReportError(
                f"No directory named '{results_dir_name}' was found under "
                f"{sparse_path} in {redact(publish.destination_repo)}@"
                f"{publish.branch}."
            )
        if len(matches) > 1:
            # Pathological: the same scan ID published twice. Surface
            # the ambiguity rather than guessing.
            raise RemoteReportError(
                f"Multiple directories named '{results_dir_name}' found under "
                f"{sparse_path} ({len(matches)} matches); cannot resolve "
                "which one is the original."
            )

        match = matches[0]
        if not (match / "README.md").is_file():
            raise RemoteReportError(
                f"Report directory '{results_dir_name}' exists but lacks a "
                "README.md — not a valid VulnHunter results directory."
            )

        rel_path_in_dest = str(match.relative_to(workdir))
        logger.info(
            "Downloaded named report for %s/%s: %s",
            source_owner,
            source_name,
            rel_path_in_dest,
        )
        return DownloadedReport(
            path=match, rel_path_in_dest=rel_path_in_dest, workdir=workdir
        )
    except Exception:
        shutil.rmtree(workdir, ignore_errors=True)
        raise
