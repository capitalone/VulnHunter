"""Publish stage: push the VULNHUNT_RESULTS directory to a remote git repo.

After /vulnhunt finishes we have a directory like
``vulnhunter_VULNHUNT_RESULTS_opus47_2026-06-22-180000`` inside the
clone. This module clones the configured destination repo into a temp
dir, copies that results directory in (preserving its timestamped name
so multiple scans coexist), commits, and pushes.

If ``destination_repo`` does not exist yet, we create it via the GitHub
REST API as a private repo (auto-initialised so the configured branch
already exists when we go to clone). No external CLI (``gh``, etc.) is
required — ``httpx`` is already a dependency.

Authentication uses the ``reports`` identity via ``get_github_token``
(broker file when ``broker_token_dir`` is set, ``[github].reports_token``
in standalone). The host-matched token-injection helper is the same one
used at clone time.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

import httpx

from ._github import GitHubURLError, api_base, extract_timestamp, parse_owner_repo
from ._url import inject_token, redact
from .auth import resolve_verify
from .config import AgentConfig, PublishConfig
from .token_client import BrokerTokenAuth, get_github_token

logger = logging.getLogger(__name__)


# Resolve git's absolute path once at module load — kills Bandit B607
# at every subprocess call site in this module. ``None`` when git is
# not on PATH; ``_run`` raises a clear PublishError rather than letting
# an OSError surface mid-publish.
_GIT_EXECUTABLE: str | None = shutil.which("git")


class PublishError(RuntimeError):
    """Raised when the publish stage cannot push results."""


def _parse_owner_repo(repo_url: str) -> tuple[str, str]:
    """publish-error wrapper around the shared parser."""
    try:
        return parse_owner_repo(repo_url)
    except GitHubURLError as exc:
        raise PublishError(str(exc)) from exc


def ensure_destination_repo(
    publish: PublishConfig,
    config: AgentConfig,
    *,
    timeout_seconds: int = 30,
) -> bool:
    """Make sure the destination repo exists, creating it private if not.

    Returns True if a new repo was created, False if it already existed.
    Raises PublishError on any other outcome (missing token, owner not
    found, permission denied, unexpected status).
    """
    if not get_github_token("reports", config):
        raise PublishError(
            "ensure_destination_repo requires reports_token to be set."
        )
    owner, name = _parse_owner_repo(publish.destination_repo)
    api = api_base(config.github.host)
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    verify = resolve_verify(config.tls)

    with httpx.Client(
        verify=verify,
        timeout=timeout_seconds,
        headers=headers,
        auth=BrokerTokenAuth("reports", config),
    ) as client:
        # 1. Already there?
        resp = client.get(f"{api}/repos/{owner}/{name}")
        if resp.status_code == 200:
            logger.info("Destination repo %s/%s already exists", owner, name)
            return False
        if resp.status_code != 404:
            raise PublishError(
                f"unexpected {resp.status_code} checking {owner}/{name}: "
                f"{resp.text[:200]}"
            )

        # 2. Look up the owner so we know whether to use /orgs or /user.
        owner_resp = client.get(f"{api}/users/{owner}")
        if owner_resp.status_code != 200:
            raise PublishError(
                f"GitHub owner '{owner}' not found "
                f"({owner_resp.status_code}): {owner_resp.text[:200]}"
            )
        owner_type = owner_resp.json().get("type")

        body = {
            "name": name,
            "private": True,
            # auto_init creates a README on the default branch so subsequent
            # `git clone --depth 1 --branch <branch>` doesn't fail.
            "auto_init": True,
            "description": "VulnHunter scan results.",
        }
        if owner_type == "Organization":
            create_url = f"{api}/orgs/{owner}/repos"
        elif owner_type == "User":
            # We can only create in the authenticated user's own namespace.
            me = client.get(f"{api}/user")
            if me.status_code != 200 or me.json().get("login") != owner:
                raise PublishError(
                    f"refusing to create repo in user namespace '{owner}': "
                    "the configured token does not authenticate as that user."
                )
            create_url = f"{api}/user/repos"
        else:
            raise PublishError(
                f"unknown owner type {owner_type!r} for {owner}; "
                "expected User or Organization."
            )

        create = client.post(create_url, json=body)
        if create.status_code != 201:
            raise PublishError(
                f"creating {owner}/{name} failed "
                f"({create.status_code}): {create.text[:300]}"
            )
        logger.info(
            "Created %s/%s as a private repo (auto-initialised on default branch)",
            owner,
            name,
        )
        return True


def _run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 300,
) -> subprocess.CompletedProcess:
    """Run a git command and capture both streams; redact stderr on failure.

    Boundary site for Bandit B607 hardening: if ``cmd[0] == "git"`` we
    swap in the absolute path resolved at module load. Callers continue
    to pass the human-readable ``["git", ...]`` form for readability.
    """
    if cmd and cmd[0] == "git":
        if _GIT_EXECUTABLE is None:
            raise PublishError("git not on PATH; cannot publish")
        cmd = [_GIT_EXECUTABLE, *cmd[1:]]
    # nosec B603 — argv is statically constructed by callers in this
    # module (clone init, remote add, fetch, reset, add, commit, push,
    # status, rev-parse); cwd / env come from the agent's own config.
    # No untrusted input enters the argv list.
    result = subprocess.run(  # nosec B603
        cmd,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        stderr = redact(result.stderr.strip())
        # Redact the command too in case the URL leaked into argv.
        rendered = " ".join(redact(arg) for arg in cmd)
        raise PublishError(
            f"git command failed (exit {result.returncode}): {rendered}\n{stderr}"
        )
    return result


def _validate_token_compatibility(
    publish: PublishConfig, config: AgentConfig
) -> None:
    """Refuse to push if the configured token can't authenticate the destination."""
    parsed = urlparse(publish.destination_repo)
    if parsed.scheme not in ("http", "https"):
        raise PublishError(
            f"publish.destination_repo must be an http(s) URL: {publish.destination_repo}"
        )
    # urlparse lowercases hostname; lowercase the configured host too so a
    # config like host = "GitHub.com" doesn't trigger a false mismatch.
    config_host = config.github.host.lower() if config.github.host else ""
    if (parsed.hostname or "") != config_host:
        raise PublishError(
            f"publish.destination_repo host '{parsed.hostname}' does not match "
            f"github.host '{config.github.host}'. The configured token would not be "
            "injected, so the push would fail. Either change github.host or "
            "use a destination on the same host."
        )
    if not get_github_token("reports", config):
        raise PublishError(
            "publish requires reports_token to be set so the destination "
            "repo can be cloned and pushed to."
        )


def publish_results(
    results_dir: Path,
    publish: PublishConfig,
    config: AgentConfig,
    *,
    source_repo_url: str,
    source_commit_hash: str = "unknown",
    timeout_seconds: int = 300,
) -> str:
    """Push results_dir into publish.destination_repo on publish.branch.

    Results are filed under
    ``<source_owner>/<source_repo>/<timestamp>/<source_commit_hash>/<results_name>/``
    inside the destination so multiple sources, multiple runs at
    different times, and multiple commits coexist without colliding
    (e.g. ``your-org/repo1/2026-06-23-141824/abc1234/...``). The
    timestamp comes from the YYYY-MM-DD-HHMMSS suffix the skill bakes
    into the results dir name; if missing, the segment is "unknown".

    If the destination repo doesn't exist, it's created as a private
    repo on the configured host (auto-initialised so the configured
    branch is immediately clonable). Returns the commit SHA that was
    pushed.
    """
    if not results_dir.is_dir():
        raise PublishError(f"results dir is not a directory: {results_dir}")

    _validate_token_compatibility(publish, config)
    source_owner, source_name = _parse_owner_repo(source_repo_url)
    commit_segment = source_commit_hash or "unknown"
    timestamp_segment = extract_timestamp(results_dir.name)

    created = ensure_destination_repo(publish, config)
    if created:
        logger.info(
            "Destination %s was created on this run; pushing first commit.",
            redact(publish.destination_repo),
        )

    authed_url = inject_token(
        publish.destination_repo,
        get_github_token("reports", config),
        config.github.host,
    )

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_AUTHOR_NAME"] = publish.commit_author_name
    env["GIT_AUTHOR_EMAIL"] = publish.commit_author_email
    env["GIT_COMMITTER_NAME"] = publish.commit_author_name
    env["GIT_COMMITTER_EMAIL"] = publish.commit_author_email

    workdir = Path(tempfile.mkdtemp(prefix="vulnhunt-publish-"))
    dest_clone = workdir / "dest"

    try:
        logger.info(
            "Publishing %s to %s (branch=%s)",
            results_dir.name,
            redact(publish.destination_repo),
            publish.branch,
        )

        # Use init + remote + fetch instead of `git clone --branch X` so we
        # handle the case where the branch doesn't exist yet on the remote
        # (common when the destination repo is empty or was created without
        # auto_init). If fetch succeeds we reset onto upstream; if it fails
        # we'll create the branch with the first push.
        dest_clone.mkdir(parents=True)
        _run(
            ["git", "init", "--initial-branch", publish.branch],
            cwd=dest_clone,
            env=env,
        )
        _run(
            ["git", "remote", "add", "origin", authed_url],
            cwd=dest_clone,
            env=env,
        )
        # Inline fetch (rather than _run) because we tolerate non-zero
        # exit to detect a fresh branch. Resolved git path + nosec match
        # _run's hardening (Bandit B607 / B603).
        if _GIT_EXECUTABLE is None:
            raise PublishError("git not on PATH; cannot publish")
        fetch = subprocess.run(  # nosec B603
            [_GIT_EXECUTABLE, "fetch", "--depth=1", "origin", publish.branch],
            cwd=dest_clone,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        creating_branch = fetch.returncode != 0
        if creating_branch:
            logger.info(
                "Branch %s doesn't exist at %s yet; will create it with the "
                "first push.",
                publish.branch,
                redact(publish.destination_repo),
            )
        else:
            _run(
                ["git", "reset", "--hard", "FETCH_HEAD"],
                cwd=dest_clone,
                env=env,
            )

        # Copy the results dir under
        # <source_owner>/<source_name>/<timestamp>/<sha>/ so multiple
        # sources, runs, and commits coexist without colliding.
        # shutil.copytree refuses to overwrite, so wipe a same-named
        # existing dir first (re-runs of the same scan).
        # Path-relative-to-dest is what we hand to `git add`.
        rel_path = (
            f"{source_owner}/{source_name}/{timestamp_segment}/"
            f"{commit_segment}/{results_dir.name}"
        )
        target = (
            dest_clone
            / source_owner
            / source_name
            / timestamp_segment
            / commit_segment
            / results_dir.name
        )
        if target.exists():
            logger.info("Replacing existing %s in destination", rel_path)
            shutil.rmtree(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(results_dir, target)

        # Stage + commit. If the working tree has no changes, fail loud:
        # the caller asked us to publish results that aren't actually new.
        _run(["git", "add", "--", rel_path], cwd=dest_clone, env=env)
        status = _run(
            ["git", "status", "--porcelain"], cwd=dest_clone, env=env
        ).stdout.strip()
        if not status:
            raise PublishError(
                f"No changes to commit after copying {rel_path}; "
                "the destination already contains identical content."
            )

        commit_msg = f"Add VulnHunt results: {rel_path}"
        _run(
            ["git", "commit", "-m", commit_msg],
            cwd=dest_clone,
            env=env,
        )

        sha = _run(
            ["git", "rev-parse", "HEAD"], cwd=dest_clone, env=env
        ).stdout.strip()

        # Push. When the branch is new on the remote we set the upstream
        # so subsequent runs can fetch it.
        push_cmd = ["git", "push"]
        if creating_branch:
            push_cmd += ["--set-upstream"]
        push_cmd += ["origin", f"HEAD:{publish.branch}"]
        _run(
            push_cmd,
            cwd=dest_clone,
            env=env,
            timeout=timeout_seconds,
        )

        logger.info(
            "Pushed %s to %s@%s (commit %s)%s",
            rel_path,
            redact(publish.destination_repo),
            publish.branch,
            sha[:8],
            " (created branch)" if creating_branch else "",
        )
        return sha
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
