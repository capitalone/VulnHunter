"""Shallow-clone an arbitrary git URL into the configured clone base dir."""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlparse

from ._url import inject_token, redact

logger = logging.getLogger(__name__)


# Resolve git's absolute path once at module load — kills Bandit B607
# at the subprocess call sites below. ``None`` when git is not on PATH;
# ``shallow_clone`` then raises a clear error rather than letting an
# OSError surface mid-operation.
_GIT_EXECUTABLE: str | None = shutil.which("git")

# A commit must be a hex SHA (7-40 chars). Anything else — including a
# leading-dash option payload — is refused before it reaches a git argv
# (CWE-88 argv option injection, CQ-1).
_COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")


def _reject_option_like(value: str, what: str) -> None:
    """Refuse a value that git would parse as an option (leading '-').

    Guards against CWE-88 argv option injection: a URL or ref beginning
    with '-' (e.g. ``--upload-pack=<cmd>``) would be interpreted by git
    as an option rather than a positional argument.
    """
    if value.startswith("-"):
        raise RuntimeError(
            f"refusing {what} that looks like a git option: {value!r}"
        )


def _derive_repo_name(repo_url: str) -> str:
    """Extract a filesystem-safe repo name from a git URL."""
    parsed = urlparse(repo_url)
    # Handle both "https://host/org/repo(.git)" and "git@host:org/repo(.git)".
    path = parsed.path or repo_url
    last = path.rstrip("/").split("/")[-1]
    if last.endswith(".git"):
        last = last[:-4]
    last = re.sub(r"[^A-Za-z0-9._-]", "_", last)
    return last or "repo"


def shallow_clone(
    repo_url: str,
    clone_base_dir: str | os.PathLike[str],
    *,
    timeout_seconds: int = 300,
    re_clone: bool = False,
    github_token: str = "",
    github_host: str = "github.com",
    allowed_token_path_prefixes: Iterable[str] | None = None,
) -> Path:
    """Shallow-clone repo_url into <clone_base_dir>/<repo_name>.

    Returns the absolute path to the clone. If a clone already exists at the
    target path it is reused unless re_clone=True. Pass github_token to
    authenticate against a private GitHub repo whose host matches
    github_host; non-matching URLs are not rewritten.

    ``allowed_token_path_prefixes`` is forwarded to ``inject_token`` to scope
    token attachment by repo path (confused-deputy guard, CWE-441). ``None``
    (default) applies no path restriction — appropriate for the operator-
    supplied target repo; an iterable restricts token attachment to those
    authorized owner / owner-repo paths.
    """
    base = Path(clone_base_dir).expanduser().resolve()
    base.mkdir(parents=True, exist_ok=True)
    target = base / _derive_repo_name(repo_url)

    if target.exists():
        if not re_clone:
            logger.info("Reusing existing clone: %s", target)
            return target
        logger.info("Removing existing clone (re-clone requested): %s", target)
        shutil.rmtree(target)

    logger.info("Cloning %s -> %s", redact(repo_url), target)
    # GIT_TERMINAL_PROMPT=0 makes git fail instead of hanging on a tty
    # credential prompt that would otherwise be hidden. We deliberately
    # leave GIT_ASKPASS and the user's credential.helper alone so the
    # macOS keychain / gh helper can still authenticate non-interactively.
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"

    effective_url = inject_token(
        repo_url,
        github_token,
        github_host,
        allowed_path_prefixes=allowed_token_path_prefixes,
    )
    if effective_url != repo_url:
        logger.info("  using configured GitHub token for %s", github_host)

    # CWE-88 guard: refuse a URL git would treat as an option, and pass a
    # '--' end-of-options separator so the URL is always a positional.
    _reject_option_like(effective_url, "clone URL")

    if _GIT_EXECUTABLE is None:
        raise RuntimeError("git not on PATH; cannot clone")
    try:
        # nosec B603 — argv is statically constructed ("clone --progress
        # --depth 1 --"); effective_url comes from the agent's own URL
        # validation + token injection; target is a Path the agent
        # owns. Absolute git path resolved at module load (kills B607).
        result = subprocess.run(  # nosec B603
            [_GIT_EXECUTABLE, "clone", "--progress", "--depth", "1", "--", effective_url, str(target)],
            text=True,
            timeout=timeout_seconds,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        raise RuntimeError(
            f"git clone timed out after {timeout_seconds}s: {redact(repo_url)}"
        ) from exc

    if result.returncode != 0:
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        raise RuntimeError(
            f"git clone failed (exit {result.returncode}) for {redact(repo_url)}; "
            "see git output above"
        )

    # Strip the token from the remote URL stored in .git/config. Without
    # this, any subsequent `git remote get-url`, `git config -l`, or
    # `cat .git/config` inside the clone leaks the token into command
    # output — which the orchestrator may dutifully read and log. We
    # don't need the credential anymore: the depth=1 clone is the only
    # network operation we'll ever do against this repo.
    if effective_url != repo_url:
        # nosec B603 — argv is static ("remote set-url origin"); repo_url
        # already passed the agent's URL validation upstream.
        scrub = subprocess.run(  # nosec B603
            [_GIT_EXECUTABLE, "remote", "set-url", "origin", repo_url],
            cwd=str(target),
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if scrub.returncode != 0:
            # Don't fail the clone over this — but log so the operator
            # knows to handle the clone as token-bearing.
            logger.warning(
                "Could not scrub token from origin remote (exit %d): %s. "
                "Treat the clone's .git/config as containing credentials.",
                scrub.returncode,
                redact(scrub.stderr.strip()),
            )

    logger.info("Clone complete: %s", target)
    return target


def clone_at_commit(
    repo_url: str,
    clone_base_dir: str | os.PathLike[str],
    commit: str,
    *,
    timeout_seconds: int = 300,
    re_clone: bool = False,
    github_token: str = "",
    github_host: str = "github.com",
    allowed_token_path_prefixes: Iterable[str] | None = None,
) -> Path:
    """Shallow-clone repo_url and check out a specific commit SHA.

    Used by the verify-mode agent when ``--commit <sha>`` is supplied on
    the CLI. The fetch is depth-1 against the specific commit, so the
    working tree ends up containing exactly that commit's snapshot
    without pulling the full history.

    The current scanner always clones the default-branch HEAD via
    ``shallow_clone`` and never pins to a SHA — that's why this is a
    separate entry point rather than a parameter on the existing
    function.

    Raises ``RuntimeError`` if the fetch or checkout fails. Per design
    §8.1, we do **not** silently fall back to HEAD when the SHA is
    unreachable — the caller asked for a specific commit and a
    different one is the wrong answer.
    """
    if _GIT_EXECUTABLE is None:
        raise RuntimeError("git not on PATH; cannot clone")
    if not commit:
        raise ValueError("commit must be a non-empty SHA")
    # CQ-1 / CWE-88: a commit must be a hex SHA. This refuses a dash-leading
    # or metacharacter-bearing value before it reaches the fetch / checkout
    # argv.
    if not _COMMIT_SHA_RE.match(commit):
        raise ValueError(
            f"commit must be a 7-40 char hex SHA, got {commit!r}"
        )

    # Step 1: ordinary shallow clone of the default branch.
    target = shallow_clone(
        repo_url,
        clone_base_dir,
        timeout_seconds=timeout_seconds,
        re_clone=re_clone,
        github_token=github_token,
        github_host=github_host,
        allowed_token_path_prefixes=allowed_token_path_prefixes,
    )

    # If the default-branch HEAD already happens to be the requested
    # commit, skip the extra fetch — common case when the issue closed
    # very recently and the fix is already on main.
    head_check = subprocess.run(  # nosec B603 — static argv, target is agent-owned Path
        [_GIT_EXECUTABLE, "rev-parse", "HEAD"],
        cwd=str(target),
        capture_output=True,
        text=True,
        timeout=10,
    )
    if head_check.returncode == 0 and head_check.stdout.strip() == commit:
        logger.info("Default HEAD already matches commit %s", commit[:12])
        return target

    # Step 2: fetch the specific commit shallowly. We need an
    # auth-bearing URL for the fetch in case the repo is private.
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    effective_url = inject_token(
        repo_url,
        github_token,
        github_host,
        allowed_path_prefixes=allowed_token_path_prefixes,
    )

    logger.info("Fetching commit %s from %s", commit[:12], redact(repo_url))
    # CWE-88 guard: '--' end-of-options separator before the URL; commit is
    # already validated as a hex SHA above so it cannot be option-like.
    _reject_option_like(effective_url, "fetch URL")
    fetch = subprocess.run(  # nosec B603 — static argv, target is agent-owned Path
        [
            _GIT_EXECUTABLE,
            "fetch",
            "--depth",
            "1",
            "--",
            effective_url,
            commit,
        ],
        cwd=str(target),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
    )
    if fetch.returncode != 0:
        raise RuntimeError(
            f"git fetch for commit {commit} failed (exit {fetch.returncode}) "
            f"on {redact(repo_url)}: {redact(fetch.stderr.strip())}"
        )

    # Step 3: check out FETCH_HEAD (which now points at the requested
    # commit) into the working tree. We deliberately don't move a
    # branch ref — detached HEAD is fine for verify reads.
    checkout = subprocess.run(  # nosec B603 — static argv, target is agent-owned Path
        [_GIT_EXECUTABLE, "checkout", "--detach", commit],
        cwd=str(target),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if checkout.returncode != 0:
        raise RuntimeError(
            f"git checkout {commit} failed (exit {checkout.returncode}) "
            f"on {redact(repo_url)}: {redact(checkout.stderr.strip())}"
        )

    logger.info("Checked out commit %s in %s", commit[:12], target)
    return target
