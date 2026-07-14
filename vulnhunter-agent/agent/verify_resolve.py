"""Resolve verify-mode inputs that require git / GitHub operations.

Two responsibilities:

1. **repo_hint → git URL.** The pre-flight cross-repo extractor
   (``agent/verify_refs.py``) emits free-form ``repo_hint`` strings
   (e.g. ``../platform-validators``,
   ``github.cloud.example/shared/foo``). The agent **never infers**
   URLs by org guessing or path matching: resolution succeeds only
   when the hint is already a URL or maps exactly to an alias in
   ``verify.repo_aliases``. Anything else resolves to ``None`` and
   the caller records the hint as unresolvable (per design §8.3).

2. **Named-report download + target clone.** Thin wrappers around
   ``download_named_report`` (specific scan results dir) and
   ``clone_at_commit`` (commit-pinned target repo), used by the
   orchestrator to stage the kickoff inputs.

Failures raise ``ResolveError`` so the orchestrator can map them to
exit code 1 without parsing exception messages.
"""

from __future__ import annotations

import logging
import re
import shutil
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlparse

from .clone import clone_at_commit, shallow_clone
from .config import AgentConfig, GitHubConfig, PublishConfig, VerifyConfig
from .issues_remote_report import DownloadedReport, download_named_report

logger = logging.getLogger(__name__)


class ResolveError(RuntimeError):
    """Verify-side resolve operation (clone/download) failed."""


# Pattern matching a likely git URL (HTTPS or SSH). We only care about
# whether the hint *looks like* a URL — actual cloneability is decided
# by git when we attempt to clone.
_URL_LIKE_RE = re.compile(r"^(https?://|git@[^:]+:|ssh://)")


def _hint_host(url: str) -> str | None:
    """Extract the lowercased hostname from a URL-shaped hint, else None.

    Handles the three shapes ``_URL_LIKE_RE`` accepts: ``https?://`` and
    ``ssh://`` (parsed by ``urlparse``) and the scp-like ``git@host:path``
    form (parsed by hand — ``urlparse`` does not understand it).
    """
    if url.startswith("git@"):
        host = url[len("git@"):].split(":", 1)[0]
        return host.lower() or None
    parsed = urlparse(url)
    return parsed.hostname.lower() if parsed.hostname else None


def resolve_repo_hint(
    hint: str,
    aliases: dict[str, str],
    *,
    allowed_hosts: Iterable[str] = (),
) -> str | None:
    """Map a verify-skill ``repo_hint`` to a clonable git URL.

    Strategies (first match wins, no inference fallback):

    1. ``hint`` already looks like a URL (matches ``_URL_LIKE_RE``) AND
       its host is in ``allowed_hosts`` (case-insensitive) → return it
       as-is. A URL-shaped hint whose host is not allow-listed resolves
       to ``None`` — this is the SSRF guard (CWE-918): attacker-authored
       comments cannot steer the clone at an arbitrary or internal host.
    2. ``hint`` matches an exact key in operator-authored ``aliases`` →
       return the mapped URL. Aliases are config, so they are trusted
       regardless of host.

    Returns ``None`` when neither strategy applies — the caller treats
    the hint as unresolvable and annotates the comments file with an
    R6 entry (see ``verify_extract.render_comments_file``).
    """
    cleaned = (hint or "").strip()
    if not cleaned:
        return None
    if _URL_LIKE_RE.match(cleaned):
        allowed = {h.lower() for h in allowed_hosts if h}
        host = _hint_host(cleaned)
        if host is not None and host in allowed:
            return cleaned
        logger.warning(
            "Repo hint is a URL on a non-allow-listed host (%r); refusing "
            "to resolve it as a clone target.",
            host,
        )
        return None
    return aliases.get(cleaned)


def authorized_token_path_prefixes(
    aliases: dict[str, str], extra: Iterable[str] = ()
) -> tuple[str, ...]:
    """Compute the owner/repo path prefixes eligible for operator-token
    attachment on additional-repo clones (confused-deputy guard, CWE-441).

    Primary source: the owner segment of each operator-authored
    ``repo_aliases`` URL (aliases are trusted config). Extended by any
    explicit ``extra`` prefixes (``config.verify.token_path_prefixes``).
    """
    prefixes: set[str] = {p.strip() for p in extra if p and p.strip()}
    for url in aliases.values():
        if url.startswith("git@"):
            path = url[len("git@"):].split(":", 1)[1] if ":" in url else ""
        else:
            path = urlparse(url).path
        owner = path.strip("/").split("/")[0] if path.strip("/") else ""
        if owner:
            prefixes.add(owner)
    return tuple(sorted(prefixes))


def clone_additional_repo(
    url: str,
    base_dir: Path,
    *,
    github_token: str,
    github_host: str,
    timeout_seconds: int,
    allowed_token_path_prefixes: Iterable[str] = (),
) -> Path:
    """Shallow-clone a resolved additional-repo URL into ``base_dir``.

    Raises ``ResolveError`` on clone failure; the caller will record
    the hint as unresolvable in that case (the URL existed but
    wasn't reachable / authorized).

    ``allowed_token_path_prefixes`` scopes operator-token attachment to
    authorized owner / owner-repo paths (confused-deputy guard, CWE-441).
    Additional repos come from attacker-influenceable comment hints, so
    the token is attached only for operator-authorized paths; an empty
    tuple (the default) attaches no token at all.
    """
    base_dir.mkdir(parents=True, exist_ok=True)
    try:
        return shallow_clone(
            url,
            base_dir,
            timeout_seconds=timeout_seconds,
            github_token=github_token,
            github_host=github_host,
            allowed_token_path_prefixes=allowed_token_path_prefixes,
        )
    except RuntimeError as exc:
        raise ResolveError(
            f"Could not clone additional repo {url!r}: {exc}"
        ) from exc


def clone_target_repo(
    repo_url: str,
    target_dir: Path,
    *,
    commit: str | None,
    github_token: str,
    github_host: str,
    timeout_seconds: int,
) -> Path:
    """Clone the target repo (HEAD or commit-pinned) into ``target_dir``.

    When ``commit`` is supplied, uses ``clone_at_commit`` for strict
    SHA pinning. Otherwise falls back to a vanilla shallow clone of
    the default branch.
    """
    target_dir.mkdir(parents=True, exist_ok=True)
    try:
        if commit:
            return clone_at_commit(
                repo_url,
                target_dir,
                commit,
                timeout_seconds=timeout_seconds,
                github_token=github_token,
                github_host=github_host,
            )
        return shallow_clone(
            repo_url,
            target_dir,
            timeout_seconds=timeout_seconds,
            github_token=github_token,
            github_host=github_host,
        )
    except RuntimeError as exc:
        raise ResolveError(
            f"Could not clone target repo {repo_url!r}: {exc}"
        ) from exc


def stage_report(
    source_repo_url: str,
    results_dir_name: str,
    destination_dir: Path,
    *,
    config: AgentConfig,
) -> Path:
    """Download the named scan results and materialize them at ``destination_dir``.

    ``download_named_report`` fetches into a ``tempfile.mkdtemp`` it
    owns; we copy the matched directory into ``destination_dir`` so
    the agent's scratch tree contains every input under a single
    parent (``<run-id>/repo``, ``<run-id>/report``, ...). The tempdir
    is cleaned up before returning.

    Returns the local path to the staged report.

    Security / trust boundary (VULN-005, VULN-006 — accepted risk):
        ``results_dir_name`` and the companion ``vulnfix-key`` /
        ``vulnhunt-finding-id`` markers originate from the issue body, which
        can be attacker-authored. They are consumed here **without an
        authenticity binding** to the finding under review, so an actor who
        controls the issue markers can point verify at an unrelated published
        report and skew the LLM verdict (CWE-345). This is deliberately NOT
        enforced in-process: ``--mode=verify`` is a convenience function, and
        restricting *who may author the issues fed to it* is the
        responsibility of the party wrapping this container (e.g. an
        orchestrator that only verifies bot-posted, collaborator-locked
        issues). Absent that wrapper the verdict is advisory. Do not treat a
        verify result as authoritative unless the wrapping layer constrains
        issue authorship. Path traversal via ``results_dir_name`` IS blocked
        at extraction (VULN-004, ``verify_extract._RE_RESULTS_DIR``).
    """
    destination_dir.mkdir(parents=True, exist_ok=True)
    try:
        downloaded: DownloadedReport = download_named_report(
            source_repo_url,
            results_dir_name,
            config=config,
            timeout_seconds=config.verify.clone_timeout_seconds,
        )
    except Exception as exc:
        raise ResolveError(
            f"Could not download named report {results_dir_name!r} for "
            f"{source_repo_url!r}: {exc}"
        ) from exc
    try:
        # Copy contents into destination_dir/<results_dir_name>/.
        target = destination_dir / results_dir_name
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(downloaded.path, target)
        return target
    finally:
        downloaded.cleanup()
