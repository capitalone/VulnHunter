"""``--mode=verify`` orchestrator.

Drives the /vulnhunt-fix-verify skill end-to-end against a list of
GitHub issues. The CLI in ``agent/__main__.py`` dispatches to
``run_verify`` here when the user passes ``--mode=verify``.

Phases (matching design doc §6):

1. Fetch each issue via REST and the matching userContentEdits via
   GraphQL. Reconstruct the original body when the issue body has
   been edited. Extract the three machine markers from the original.
2. Validate that every issue in the run shares the same
   ``(repo_owner, repo_name, results_dir_name)`` tuple. Abort
   otherwise — the skill takes one repo + one report per run.
3. Build comments.md (BEGIN/END UNTRUSTED wrapping, see §9.1).
4. Clone the target repo (HEAD by default, --commit override).
5. Download the specific results directory by name (no fall-back
   to "latest", see §8.2).
6. Run a Haiku pre-flight over every developer comment to detect
   and pre-clone cross-repo references (URLs, alias keys). Resolved
   sources land in ``state.additional_repos``; unresolvable hints
   land in ``state.ignored_hints`` and surface in the R6 annotation
   block of ``comments.md``.
7. Invoke the verify skill once with the resolved checkouts. The
   skill no longer emits clone-requests — pre-flight handled all
   cross-repo fetching.
8. Post the verifier's per-finding ``issue_comment`` to each issue,
   plus the body-tampering archival comment when applicable.
   Reopen on NOT_FIXED / PARTIAL / INCONCLUSIVE.

Exit codes mirror the design's error table — see ``_VerifyExitCode``.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from typing import Any

from . import _github_verify as ghv
from ._body_reconstruct import DiffApplyError, reconstruct_original
from ._github_verify import (
    FetchedIssue,
    GitHubVerifyError,
    IssueRef,
    UserContentEdit,
    make_client,
)
from .auth import make_token_manager, resolve_verify
from .config import AgentConfig
from . import audit as _audit
from .repo_properties import RepoProperties
from .token_client import get_github_token
from .verify_extract import (
    ExtractedMarkers,
    IssueNarrative,
    MarkerExtractionError,
    build_narrative,
    extract_markers,
    write_comments_file,
)
from .verify_post import (
    PostResult,
    post_disposition,
)
from .verify_refs import extract_cross_repo_references
from .verify_resolve import (
    ResolveError,
    authorized_token_path_prefixes,
    clone_additional_repo,
    clone_target_repo,
    resolve_repo_hint,
    stage_report,
)
from .verify_runner import (
    OutputKind,
    VerifySessionResult,
    build_kickoff_prompt,
    run_verify_session,
)

logger = logging.getLogger(__name__)


# Exit codes per design §4 + §14.
_EXIT_OK = 0
_EXIT_INFRA_FAILURE = 1
_EXIT_BAD_ARGS = 2
_EXIT_AUTH_FAILURE = 3


# ---- result types ----------------------------------------------------------


@dataclass(frozen=True)
class _FetchedRecord:
    """Per-issue fetch outcome, used to build the homogeneity check and
    the finding_id → issue_number map."""

    ref: IssueRef
    issue: FetchedIssue
    markers: ExtractedMarkers
    body_tampered: bool
    original_body: str
    comments: list[ghv.IssueComment]
    events: list[ghv.IssueEvent]


@dataclass
class _RunState:
    """Mutable state carried into the verify session.

    Populated entirely by the pre-flight cross-repo extractor before
    the skill runs (see ``_preflight_clone_requests``). The skill
    consumes ``additional_repos`` via the kickoff prompt and sees
    ``ignored_hints`` as R6 entries in the rendered comments file.
    """

    additional_repos: list[Path] = field(default_factory=list)
    ignored_hints: set[str] = field(default_factory=set)


# ---- top-level entry point -------------------------------------------------


async def run_verify(
    *,
    config: AgentConfig,
    issue_urls: list[str],
    commit: str | None,
    scratch_base_dir: Path | None,
    no_post: bool,
    no_reopen: bool,
    model_override: str | None,
    audit_writer: "_audit.AuditWriter | None" = None,
    audit_repo_properties: "RepoProperties | None" = None,
) -> int:
    """Run one verify session against the supplied issue URLs.

    Returns the process exit code (see design §4 + §14). Never raises
    on expected failures — exceptions out of this coroutine indicate
    a programming bug.

    ``audit_writer`` and ``audit_repo_properties`` are the audit/
    audit emission surface. When ``audit_writer`` is None
    (audit disabled) verify runs unchanged. When present, three audit
    events fire: ``verify_started`` before the skill session,
    ``verify_decision`` + a findings-stream transition per
    disposition after posting, and ``verify_completed`` at the end.
    """
    if not issue_urls:
        # Empty list can't happen via the CLI (positional argument is
        # ``nargs="+"``, argparse rejects empty). Reaching this branch
        # means a programmatic caller passed an empty list, which is a
        # bug in that caller — exit 2 (bad args).
        logger.error("--mode=verify requires at least one issue URL")
        return _EXIT_BAD_ARGS

    try:
        refs = [ghv.parse_issue_url(url) for url in issue_urls]
    except GitHubVerifyError as exc:
        # Per design §14, malformed URL is treated as an infra failure
        # so the upstream scheduler reacts the same way it reacts to
        # downstream GitHub errors: retry / alert.
        logger.error("Bad issue URL: %s", exc)
        return _EXIT_INFRA_FAILURE

    scan_token = get_github_token("scan", config)
    if not scan_token:
        logger.error(
            "[github] scan_token is required for --mode=verify (used for "
            "REST + GraphQL calls plus target-repo clone)"
        )
        return _EXIT_AUTH_FAILURE

    # Use the first issue's host for all REST/GraphQL calls. All issues
    # must share the same host (different hosts → different
    # repositories, which fails the homogeneity check anyway). Per
    # design §14, this is a caller-shape failure that maps to the same
    # exit code as malformed URLs / heterogeneous scans (infra failure,
    # scheduler-retryable).
    hosts = {ghv.issue_host(u) for u in issue_urls}
    if len(hosts) != 1:
        logger.error(
            "All issue URLs must be on the same host; saw: %s", sorted(hosts)
        )
        return _EXIT_INFRA_FAILURE
    host = next(iter(hosts))

    verify_ssl = resolve_verify(config.tls)
    async with make_client(scan_token, verify_ssl=verify_ssl) as client:
        try:
            records = await _fetch_all_issues(client, host, refs, config=config)
        except GitHubVerifyError as exc:
            logger.error("GitHub fetch failed: %s", exc)
            return _EXIT_INFRA_FAILURE
        except (MarkerExtractionError, DiffApplyError) as exc:
            logger.error("%s", exc)
            return _EXIT_INFRA_FAILURE

        # Homogeneity check (design §6.1). The user supplied issue
        # URLs that span more than one (repo, scan_id) — this is a
        # caller-shape problem, but design §14 maps it to infra
        # failure (exit 1) rather than bad-args (exit 2) so the
        # scheduler treats it the same as a clone or report-fetch
        # failure: "this run can't proceed; retry or alert."
        try:
            _enforce_homogeneity(records)
        except ValueError as exc:
            logger.error("%s", exc)
            return _EXIT_INFRA_FAILURE

        # Audit: emit verify_started once we know scan_id + repo_slug.
        # These are derivable from the records now that homogeneity has
        # been enforced (all records share one target repo + scan_id).
        audit_scan_id = records[0].markers.results_dir
        audit_repo_slug = _target_repo_url_to_slug(records, host)
        audit_target_sha = commit or ""
        audit_model_version = model_override or config.anthropic.model
        verify_wall_start = time.time()
        audit_props = audit_repo_properties or RepoProperties()

        # verify_completed must fire on EVERY exit path (success or
        # failure) once verify_started is emitted — the design's
        # symmetric-pairs contract, matching runner.py's
        # ``_emit_scan_completed_safely``. This mutable state box
        # tracks findings_count and notes; the closure below emits
        # exactly once, driven by ``return _emit_completed_and_exit``
        # in place of each early return.
        _audit_emitted_completed = {"done": False}
        _audit_dispositions_count: list[int | None] = [None]

        def _emit_completed_and_exit(exit_code: int, notes: str = "") -> int:
            """Emit verify_completed (once) and return the exit code.

            Idempotent — calling more than once is a no-op after the
            first emit. Strict-mode AuditWriteError propagates; other
            exceptions are logged and swallowed so we don't mask an
            in-flight failure.
            """
            if audit_writer is None or _audit_emitted_completed["done"]:
                return exit_code
            _audit_emitted_completed["done"] = True
            try:
                audit_writer.emit_audit(
                    _audit.build_verify_completed(
                        app_id=config.audit.app_id,
                        actor=config.audit.actor,
                        repo_slug=audit_repo_slug,
                        report_id=audit_scan_id,
                        model_version=audit_model_version,
                        target_sha=audit_target_sha,
                        findings_count=_audit_dispositions_count[0],
                        scan_duration_seconds=int(
                            time.time() - verify_wall_start
                        ),
                        scan_cost_usd=None,
                        notes=notes,
                    )
                )
            except _audit.AuditWriteError:
                # Strict-mode audit failure. Surface when the verify
                # itself succeeded (audit is the primary signal there);
                # when verify already failed, the verify error is the
                # root cause and the audit write failure becomes
                # secondary noise.
                if exit_code == _EXIT_OK:
                    raise
                logger.error(
                    "Audit strict-mode write failed for verify_completed; "
                    "preserving underlying verify error"
                )
            except Exception:  # noqa: BLE001
                logger.exception(
                    "Failed to emit verify_completed audit event"
                )
            return exit_code

        if audit_writer is not None:
            audit_writer.emit_audit(
                _audit.build_verify_started(
                    app_id=config.audit.app_id,
                    actor=config.audit.actor,
                    repo_slug=audit_repo_slug,
                    report_id=audit_scan_id,
                    model_version=audit_model_version,
                    target_sha=audit_target_sha,
                )
            )

        # Stage the scratch tree and run the loop.
        scratch_root = (scratch_base_dir or Path(config.verify.scratch_base_dir)).expanduser().resolve()
        run_id = _make_run_id(records)
        run_dir = _contained_run_dir(scratch_root, run_id)
        run_dir.mkdir(parents=True, exist_ok=True)
        log_path = run_dir / "agent.log"
        logger.info("Verify run scratch: %s", run_dir)

        try:
            target_repo_url = _target_repo_url(records, host)
            target_repo = clone_target_repo(
                target_repo_url,
                run_dir / "repo",
                commit=commit,
                github_token=scan_token,
                github_host=host,
                timeout_seconds=config.verify.clone_timeout_seconds,
            )
        except ResolveError as exc:
            logger.error("Could not clone target repo: %s", exc)
            return _emit_completed_and_exit(
                _EXIT_INFRA_FAILURE,
                notes=f"failed: clone_target_repo: {exc}",
            )

        try:
            report = stage_report(
                target_repo_url,
                records[0].markers.results_dir,
                run_dir / "report",
                config=config,
            )
        except ResolveError as exc:
            logger.error("Could not stage report: %s", exc)
            return _emit_completed_and_exit(
                _EXIT_INFRA_FAILURE,
                notes=f"failed: stage_report: {exc}",
            )

        narratives = [
            build_narrative(r.issue, r.comments, r.events, r.markers.finding_id)
            for r in records
        ]
        fixed_ids = [r.markers.finding_id for r in records]
        comments_path = run_dir / "comments.md"

        token_manager = make_token_manager(config, name="verify")
        state = _RunState()
        # Pre-flight: ask Haiku to scan every developer comment for
        # cross-repo references and pre-clone what it finds. Operates
        # over the full comments list (not just post-close ones the
        # skill consumes) — cross-repo URLs can appear in any comment.
        # Pre-flight failure is non-fatal: the skill runs against
        # whatever checkouts the pre-flight managed to stage, and
        # unresolvable hints surface in the R6 annotation block.
        await _preflight_clone_requests(
            records=records,
            state=state,
            config=config,
            host=host,
            run_dir=run_dir,
        )

        session_result = await _run_skill(
            config=config,
            token_manager=token_manager,
            run_dir=run_dir,
            log_path=log_path,
            target_repo=target_repo,
            report=report,
            comments_path=comments_path,
            narratives=narratives,
            fixed_ids=fixed_ids,
            state=state,
            model_override=model_override,
        )

        if session_result.kind in (OutputKind.EMPTY, OutputKind.SCHEMA_INVALID):
            logger.error(
                "Skill produced no usable output: %s — %s",
                session_result.kind.value,
                session_result.error_detail,
            )
            return _emit_completed_and_exit(
                _EXIT_INFRA_FAILURE,
                notes=f"failed: skill output {session_result.kind.value}",
            )

        # Disposition path.
        try:
            _verify_entry_count(session_result, fixed_ids)
        except ValueError as exc:
            logger.error("%s", exc)
            return _emit_completed_and_exit(
                _EXIT_INFRA_FAILURE,
                notes=f"failed: verify_entry_count: {exc}",
            )

        # Post per-finding outcomes. A partial failure (some issues
        # got their comment posted, others didn't) downgrades the
        # exit code to 1 even though the skill produced a valid
        # disposition: the upstream scheduler should react to the
        # partial state the same way it reacts to any infra failure.
        # A "partial success" — verdict comment landed but archival
        # comment or reopen failed afterwards — also exits 1 because
        # the issue's state on GitHub is inconsistent with the
        # verdict the agent recorded.
        post_results, failed_finding_ids = await _post_dispositions(
            client=client,
            host=host,
            records=records,
            disposition_doc=session_result.parsed or {},
            no_post=no_post,
            no_reopen=no_reopen,
        )
        # Audit: emit verify_decision per disposition + a findings-stream
        # transition event per finding whose state actually moved.
        # ``_emit_verify_dispositions`` is a no-op when audit_writer is
        # None; on strict-mode failure it re-raises so operators see
        # the write error. Wrapped in a broad except so a bug in the
        # emitter doesn't destroy the post-results the caller is about
        # to log.
        try:
            _emit_verify_dispositions(
                audit_writer=audit_writer,
                config=config,
                dispositions=(session_result.parsed or {}).get("dispositions") or [],
                report_id=audit_scan_id,
                repo_slug=audit_repo_slug,
                model=audit_model_version,
                target_sha=audit_target_sha,
                repo_properties=audit_props,
            )
        except _audit.AuditWriteError:
            # Strict-mode contract: audit failure surfaces to the
            # caller. Post already ran, so log the disposition summary
            # first so the operator sees it before the exception.
            _print_summary(
                post_results, run_dir, no_post=no_post, failed=failed_finding_ids
            )
            raise
        except Exception:  # noqa: BLE001
            logger.exception("Failed to emit verify audit records")
        _print_summary(
            post_results, run_dir, no_post=no_post, failed=failed_finding_ids
        )
        partial_failures = [
            r for r in post_results if r.reopen_failed or r.archival_failed
        ]
        if failed_finding_ids:
            logger.error(
                "Verify completed but %d/%d issues couldn't be updated "
                "on GitHub: %s",
                len(failed_finding_ids),
                len(post_results) + len(failed_finding_ids),
                ", ".join(failed_finding_ids),
            )
            return _emit_completed_and_exit(
                _EXIT_INFRA_FAILURE,
                notes=(
                    f"failed: {len(failed_finding_ids)} issue post(s) failed"
                ),
            )
        if partial_failures:
            logger.error(
                "Verify completed but %d/%d issues are in a partial-success "
                "state (verdict comment landed but archival comment or "
                "reopen failed): %s",
                len(partial_failures),
                len(post_results),
                ", ".join(r.finding_id for r in partial_failures),
            )
            return _emit_completed_and_exit(
                _EXIT_INFRA_FAILURE,
                notes=f"failed: {len(partial_failures)} partial post failure(s)",
            )
        # Success path — verify_completed reflects the disposition count.
        _audit_dispositions_count[0] = len(
            (session_result.parsed or {}).get("dispositions") or []
        )
        return _emit_completed_and_exit(_EXIT_OK)


# ---- input fetch -----------------------------------------------------------


async def _fetch_all_issues(
    client,
    host: str,
    refs: list[IssueRef],
    *,
    config: AgentConfig,
) -> list[_FetchedRecord]:
    """Fetch each issue (REST + GraphQL edit history) and extract markers
    from the reconstructed original body.

    Open issues are silently skipped with a warning — verify reacts to
    closures only, but a mixed batch (some closed, some still open) is
    a common operational shape (the user dumps every recently-touched
    issue URL on the command line). Only when *every* issue is open do
    we raise: with no closed issues to verify, the run has nothing to
    do.

    Sequential rather than concurrent — keeps the GitHub rate-limit
    accounting simple for v1 and matches the design's "single
    invocation" framing.
    """
    records: list[_FetchedRecord] = []
    skipped_open: list[IssueRef] = []
    for ref in refs:
        issue = await ghv.get_issue(client, host, ref)
        if issue.state != "closed":
            logger.warning(
                "Skipping issue #%d on %s/%s: state=%r (verify reacts to "
                "closures only).",
                ref.number,
                ref.owner,
                ref.repo,
                issue.state,
            )
            skipped_open.append(ref)
            continue
        edits = await ghv.list_user_content_edits(
            client,
            host,
            ref,
            max_diff_bytes=config.verify.max_edit_diff_bytes,
            max_total_bytes=config.verify.max_edit_total_bytes,
        )
        body_tampered = bool(edits)
        if body_tampered:
            # Diagnostic dump so a "missing markers after reconstruction"
            # failure on a closed issue can be diagnosed without re-running
            # the agent: log the edit count, every editedAt timestamp, the
            # current body length, and a snippet of each diff. The diffs
            # are user-controlled prose, but they're going to a log file
            # (not to a model) so they're safe to log verbatim.
            logger.info(
                "Issue #%d: body has %d edit(s); reconstructing from "
                "GraphQL userContentEdits.",
                ref.number,
                len(edits),
            )
            logger.info(
                "  current body len=%d chars, first 120: %r",
                len(issue.body),
                issue.body[:120],
            )
            for i, e in enumerate(edits):
                logger.info(
                    "  edit[%d]: editedAt=%s editor=%s diff_len=%d "
                    "diff_first200=%r",
                    i,
                    e.edited_at,
                    e.editor or "(none)",
                    len(e.diff),
                    e.diff[:200],
                )
            try:
                original_body = reconstruct_original(
                    issue.body,
                    [
                        {"editedAt": e.edited_at, "diff": e.diff}
                        for e in edits
                    ],
                )
            except DiffApplyError as exc:
                raise DiffApplyError(
                    f"Issue #{ref.number}: could not reconstruct original "
                    f"body from {len(edits)} edit(s): {exc}"
                ) from exc
            logger.info(
                "  reconstructed body len=%d chars, first 200: %r",
                len(original_body),
                original_body[:200],
            )
        else:
            original_body = issue.body

        markers = extract_markers(
            original_body,
            source_label=f"issue #{ref.number} {'(reconstructed)' if body_tampered else ''}",
        )

        comments = await ghv.list_comments(
            client,
            host,
            ref,
            max_pages=config.verify.max_comment_pages,
            max_total_bytes=config.verify.max_timeline_bytes,
        )
        events = await ghv.list_events(
            client, host, ref, max_pages=config.verify.max_event_pages
        )
        records.append(
            _FetchedRecord(
                ref=ref,
                issue=issue,
                markers=markers,
                body_tampered=body_tampered,
                original_body=original_body,
                comments=comments,
                events=events,
            )
        )
    if not records:
        # Every supplied issue was open (or the list was empty). Surface
        # this the same way as before — the run can't proceed.
        rendered = ", ".join(
            f"#{r.number} on {r.owner}/{r.repo}" for r in skipped_open
        ) or "(no issues provided)"
        raise GitHubVerifyError(
            f"No closed issues to verify; every supplied issue is open: "
            f"{rendered}."
        )
    if skipped_open:
        logger.info(
            "Proceeding with %d closed issue(s); skipped %d open: %s",
            len(records),
            len(skipped_open),
            ", ".join(f"#{r.number}" for r in skipped_open),
        )
    return records


def _enforce_homogeneity(records: list[_FetchedRecord]) -> None:
    """Confirm every record shares (owner, repo, results_dir).

    Raises ``ValueError`` listing the distinct tuples otherwise.
    """
    keys = {
        (r.ref.owner.lower(), r.ref.repo.lower(), r.markers.results_dir)
        for r in records
    }
    if len(keys) == 1:
        return
    rendered = "\n".join(
        f"  - {owner}/{repo} @ {results_dir}"
        for owner, repo, results_dir in sorted(keys)
    )
    raise ValueError(
        "Verify run requires all issues to share the same "
        "(repo, scan_id). Got:\n" + rendered
    )


def _target_repo_url(records: list[_FetchedRecord], host: str) -> str:
    """Compose the HTTPS clone URL for the target repo from any record."""
    owner = records[0].ref.owner
    repo = records[0].ref.repo
    return f"https://{host}/{owner}/{repo}.git"


def _target_repo_url_to_slug(records: list[_FetchedRecord], host: str) -> str:
    """Extract ``org/repo`` from the record set for audit records.

    Homogeneity is enforced before this is called, so any record's
    (owner, repo) works. Kept separate from ``_target_repo_url`` so
    the audit surface never depends on a specific URL shape.
    """
    del host  # unused; owner/repo are canonical on the record.
    return f"{records[0].ref.owner}/{records[0].ref.repo}"


def _emit_verify_dispositions(
    *,
    audit_writer: "_audit.AuditWriter | None",
    config: AgentConfig,
    dispositions: list[dict[str, Any]],
    report_id: str,
    repo_slug: str,
    model: str,
    target_sha: str,
    repo_properties: RepoProperties,
) -> None:
    """Fan out one verify_decision + one finding-state transition per row.

    Verdict-to-status mapping mirrors the scan-side taxonomy:
    ``FIXED`` → PASS / RESOLVED; ``NOT_FIXED`` / ``PARTIAL`` /
    ``INCONCLUSIVE`` → FAIL / REOPENED; ``INVALID_INPUT`` and unknown
    verdicts → FAIL / (no state transition — status omitted). The
    findings-event is only emitted when there IS a state transition;
    otherwise the verify_decision audit alone carries the outcome.
    """
    if audit_writer is None:
        return
    for row in dispositions or []:
        if not isinstance(row, dict):
            continue
        vuln_id = str(row.get("finding_id") or "").strip()
        verdict_raw = str(row.get("verdict") or "").strip().upper()
        audit_verdict, to_status = _map_verify_verdict(verdict_raw)
        finding_id = _audit.finding_id_for(report_id, vuln_id)
        rationale = str(row.get("rationale") or "").strip()
        audit_writer.emit_audit(
            _audit.build_verify_decision(
                app_id=config.audit.app_id,
                actor=config.audit.actor,
                repo_slug=repo_slug,
                report_id=report_id,
                finding_id=finding_id,
                verdict=audit_verdict,
                to_status=to_status,
                from_status="OPEN",
                evidence_text=rationale,
                model_version=model,
                target_sha=target_sha,
                notes=f"verdict={verdict_raw}" if verdict_raw else "",
            )
        )
        if to_status:
            audit_writer.emit_finding(
                _audit.build_finding_event(
                    app_id=config.audit.app_id,
                    repo_slug=repo_slug,
                    report_id=report_id,
                    finding_id=finding_id,
                    vuln_id=vuln_id,
                    # Transitions carry state change + rationale only;
                    # the scan-side initial emission already recorded
                    # static fields (title, cwe, severity, location).
                    title="",
                    cwe="CWE-UNKNOWN",
                    severity="informational",
                    status=to_status,
                    location="",
                    root_cause=rationale,
                    opened=False,
                    repo_properties=repo_properties.values,
                )
            )


def _map_verify_verdict(verdict: str) -> tuple[str, str]:
    """Disposition verdict → (audit_verdict, to_status).

    Same shape as ``verify_runner._map_verdict`` in the pre-rebase
    audit branch. Kept close to the emitter so the mapping is
    self-contained.
    """
    if verdict == "FIXED":
        return "PASS", "RESOLVED"
    if verdict in ("NOT_FIXED", "PARTIAL", "INCONCLUSIVE"):
        return "FAIL", "REOPENED"
    if verdict == "INVALID_INPUT":
        return "FAIL", ""
    logger.warning(
        "Unknown disposition verdict %r; emitting FAIL without a "
        "state transition.",
        verdict,
    )
    return "FAIL", ""


def _contained_run_dir(scratch_root: Path, run_id: str) -> Path:
    """Join ``run_id`` under ``scratch_root`` and assert containment.

    CWE-22 sink-side guard: even though the results-dir marker is validated
    at extraction, this defends the ``mkdir(parents=True)`` sink against any
    run_id that would resolve outside ``scratch_root``.
    """
    root = scratch_root.resolve()
    run_dir = (root / run_id).resolve()
    if run_dir != root and not run_dir.is_relative_to(root):
        raise ValueError(
            f"run_dir {run_dir} escapes scratch_root {root}; refusing to create it"
        )
    return run_dir


def _make_run_id(records: list[_FetchedRecord]) -> str:
    """Build a human-readable, collision-free scratch-dir name.

    Format: ``<repo>-<scan-id-short>-<utc-ts>``. The scan-id-short
    portion comes from the right-hand timestamp suffix of the results
    dir, falling back to ``noscanid`` if the dir doesn't carry one.
    """
    r = records[0]
    repo = r.ref.repo.lower()
    results_dir = r.markers.results_dir
    scan_short = results_dir.split("_")[-1] if "_" in results_dir else "noscanid"
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{repo}-{scan_short}-{ts}"


# ---- skill invocation ------------------------------------------------------


async def _run_skill(
    *,
    config: AgentConfig,
    token_manager: OAuthTokenManager,
    run_dir: Path,
    log_path: Path,
    target_repo: Path,
    report: Path,
    comments_path: Path,
    narratives: list[IssueNarrative],
    fixed_ids: list[str],
    state: _RunState,
    model_override: str | None,
) -> VerifySessionResult:
    """Render ``comments.md`` and run the verify skill once.

    All additional-repo resolution happens in the pre-flight (see
    ``_preflight_clone_requests``) — the skill is never asked to emit
    a clone-request anymore, so this is a single call rather than a
    retry loop. Unresolvable hints surface in the comments file as
    R6 entries; the skill prose-warns about them in its verdict
    comment.
    """
    write_comments_file(
        comments_path,
        narratives,
        ignored_hints=sorted(state.ignored_hints),
    )

    out_dir = run_dir / "out" / "iter-1"
    out_dir.mkdir(parents=True, exist_ok=True)

    prompt = build_kickoff_prompt(
        repo=target_repo,
        report=report,
        fixed_ids=fixed_ids,
        out=out_dir,
        comments=comments_path,
        additional_repos=list(state.additional_repos) or None,
    )
    auth_token = token_manager.get_valid_token()
    logger.info(
        "Verify skill invocation — additional_repos=%d ignored_hints=%d",
        len(state.additional_repos),
        len(state.ignored_hints),
    )
    return await run_verify_session(
        config=config,
        auth_token=auth_token,
        cwd=run_dir,
        out_dir=out_dir,
        prompt=prompt,
        log_path=log_path,
        model_override=model_override,
    )


async def _preflight_clone_requests(
    *,
    records: list[_FetchedRecord],
    state: _RunState,
    config: AgentConfig,
    host: str,
    run_dir: Path,
) -> None:
    """Run a Haiku pre-flight over every developer comment and pre-clone
    any unambiguous cross-repo references it finds.

    Mutates ``state.additional_repos`` and ``state.ignored_hints`` in
    place so the main skill loop sees the resolved/ignored hints on
    the kickoff prompt and in the rendered ``comments.md``. Failure of
    the pre-flight is non-fatal: an empty extraction (or LLM failure)
    just means cross-repo URLs in comments don't get pre-cloned, and
    the skill's R2 classifies them as ``rejected_unverifiable``.

    Unlike the skill-facing ``comments.md``, the pre-flight scans
    **every** comment regardless of close-event timestamp. The skill's
    post-close filter exists to suppress scanner-vs-reviewer dialogue
    in R0-R7 evaluation; the pre-flight's job is to find every URL
    the developer mentioned anywhere in the thread, so we ignore the
    filter here.
    """
    preflight_text = _build_preflight_text(records)
    total_comments = sum(len(r.comments) for r in records)
    if not preflight_text:
        logger.info(
            "Pre-flight: skipped — %d issue(s) had no comments to scan.",
            len(records),
        )
        return
    logger.info(
        "Pre-flight: scanning %d comment(s) across %d issue(s) "
        "(%d chars) for cross-repo references.",
        total_comments,
        len(records),
        len(preflight_text),
    )
    refs_token_mgr = make_token_manager(config, name="verify-refs")
    references = await extract_cross_repo_references(
        preflight_text,
        config=config,
        token_manager=refs_token_mgr,
    )
    if not references:
        logger.info("Pre-flight: extractor found no cross-repo references.")
        return
    logger.info(
        "Pre-flight: extracted %d cross-repo reference(s); resolving.",
        len(references),
    )
    for r in references:
        logger.info(
            "  reference: hint=%r excerpt=%r",
            r.get("repo_hint", ""),
            r.get("claim_excerpt", "")[:120],
        )
    _process_clone_request(
        {"requested_sources": references},
        state=state,
        github_token=get_github_token("scan", config),
        github_host=host,
        timeout_seconds=config.verify.clone_timeout_seconds,
        additional_repos_dir=run_dir / "additional_repos",
        aliases=config.verify.repo_aliases,
        allowed_hosts=(host, *config.verify.allowed_clone_hosts),
        allowed_token_path_prefixes=authorized_token_path_prefixes(
            config.verify.repo_aliases, config.verify.token_path_prefixes
        ),
    )
    logger.info(
        "Pre-flight resolved %d additional repo(s); %d ignored.",
        len(state.additional_repos),
        len(state.ignored_hints),
    )


def _build_preflight_text(records: list[_FetchedRecord]) -> str:
    """Concatenate every developer comment across all issues into one
    text blob for the Haiku extractor.

    Format is intentionally simple — one section per comment with a
    header identifying the issue number and author so the extractor's
    ``claim_excerpt`` can stay anchored. No close-event filtering: the
    extractor sees the full thread. Returns ``""`` when no issue has
    any comments.

    The body of each comment is run through ``_neutralize_preflight_body``
    before insertion: a hostile commenter who echoes the literal
    ``----- BEGIN COMMENTS -----`` / ``----- END COMMENTS -----``
    boundary tokens the Haiku user prompt uses (see
    ``verify_refs.extract_cross_repo_references``) could otherwise
    forge a fake end-of-region and try to slip extraction-directive
    text into what the model treats as instructions. Substituting the
    boundary substrings inside user content keeps the markers
    unambiguous without altering the visible meaning of the comment.
    """
    sections: list[str] = []
    for r in records:
        for c in r.comments:
            body = (c.body or "").strip()
            if not body:
                continue
            sections.append(
                f"### Comment on issue #{r.ref.number} from @{c.author or '(unknown)'}\n"
                f"\n"
                f"{_neutralize_preflight_body(body)}\n"
            )
    return "\n".join(sections)


# Substrings the Haiku user prompt uses to bound the user-supplied region.
# Mirroring the skill-side ``_neutralize_markers`` strategy in
# ``verify_extract.py`` — substitute occurrences inside user content with
# a token that's visibly close to the original but breaks the literal
# match the boundary parser keys on.
_PREFLIGHT_BOUNDARY_SUBSTITUTIONS = (
    ("----- BEGIN COMMENTS -----", "----- BEGIN COMMENTS [user-quoted] -----"),
    ("----- END COMMENTS -----", "----- END COMMENTS [user-quoted] -----"),
)


def _neutralize_preflight_body(body: str) -> str:
    """Replace the Haiku-prompt boundary markers inside user content so
    a hostile comment can't terminate the region early."""
    for needle, replacement in _PREFLIGHT_BOUNDARY_SUBSTITUTIONS:
        body = body.replace(needle, replacement)
    return body


def _process_clone_request(
    payload: dict,
    *,
    state: _RunState,
    github_token: str,
    github_host: str,
    timeout_seconds: int,
    additional_repos_dir: Path,
    aliases: dict[str, str],
    allowed_hosts: tuple[str, ...] = (),
    allowed_token_path_prefixes: tuple[str, ...] = (),
) -> None:
    """Resolve the requested sources, cloning each that resolves and
    recording the rest as ignored.

    Mutates ``state`` in place: every successfully cloned source is
    appended to ``state.additional_repos``; every unresolvable hint
    is added to ``state.ignored_hints`` for later R6 annotation.
    Returns nothing — there's only one caller now (the pre-flight)
    and it doesn't need fixed-point detection.
    """
    additional_repos_dir.mkdir(parents=True, exist_ok=True)
    sources = payload.get("requested_sources", []) or []
    for entry in sources:
        hint = (entry or {}).get("repo_hint", "")
        if not hint or hint in state.ignored_hints:
            continue
        url = resolve_repo_hint(hint, aliases, allowed_hosts=allowed_hosts)
        if url is None:
            state.ignored_hints.add(hint)
            logger.warning(
                "Repo hint %r is unresolvable (no URL, no alias); "
                "annotating comments file under R6.",
                hint,
            )
            continue
        try:
            clone_root = additional_repos_dir / _sanitize_clone_subdir(hint)
            local = clone_additional_repo(
                url,
                clone_root,
                github_token=github_token,
                github_host=github_host,
                timeout_seconds=timeout_seconds,
                allowed_token_path_prefixes=allowed_token_path_prefixes,
            )
        except ResolveError as exc:
            state.ignored_hints.add(hint)
            logger.warning(
                "Repo hint %r resolved to %s but clone failed (%s); "
                "annotating under R6.",
                hint,
                url,
                exc,
            )
            continue
        if local in state.additional_repos:
            continue
        state.additional_repos.append(local)
        logger.info("Resolved additional repo %r -> %s", hint, local)


def _sanitize_clone_subdir(hint: str) -> str:
    """Build a filesystem-safe subdirectory name from a repo_hint.

    The hint may be a URL, an alias key, or a path-like string. We
    only need a stable, collision-free local name;
    ``clone_additional_repo`` re-derives the actual clone directory
    from the URL.

    Defends against path traversal: hints like ``..``, ``.``, or
    ``../../etc`` (which could land in the working set if the skill
    naively echoes a user-supplied citation) MUST NOT produce a
    name that resolves outside ``additional_repos_dir``. We replace
    every non-`[A-Za-z0-9-_]` character with `_` (notably stripping
    `.`, which previously slipped through and allowed `..`), and
    reject empty / dot-only results by falling back to a stable
    SHA-256 prefix of the original hint.
    """
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in hint)
    # Truncate before the empty/dot check so an 80-char run of `.`s
    # doesn't first produce "..." and then survive a `lstrip(".")`
    # that we don't do anyway.
    safe = safe[:80]
    if not safe or set(safe) <= {"_", "-"}:
        # Hash the *original* hint (not the sanitized one) so two
        # different unsafe hints don't collide on the same fallback.
        digest = hashlib.sha256(hint.encode("utf-8")).hexdigest()[:12]
        return f"additional-repo-{digest}"
    return safe


# ---- output dispatch -------------------------------------------------------


def _verify_entry_count(
    session_result: VerifySessionResult,
    fixed_ids: list[str],
) -> None:
    """Ensure the disposition has exactly one entry per fixed ID."""
    payload = session_result.parsed or {}
    dispositions = payload.get("dispositions", []) or []
    got_ids = {d.get("finding_id") for d in dispositions}
    want_ids = set(fixed_ids)
    if got_ids != want_ids:
        missing = sorted(want_ids - got_ids)
        extra = sorted(got_ids - want_ids)
        raise ValueError(
            "Disposition entry-count mismatch: "
            f"missing={missing} extra={extra}"
        )


async def _post_dispositions(
    *,
    client,
    host: str,
    records: list[_FetchedRecord],
    disposition_doc: dict,
    no_post: bool,
    no_reopen: bool,
) -> tuple[list[PostResult], list[str]]:
    """Fan disposition entries back out to their issues.

    Returns ``(succeeded, failed)`` — the list of successful
    ``PostResult`` entries plus a parallel list of finding IDs whose
    GitHub mutations failed. The caller uses the latter to downgrade
    the run's exit code: a partial-post failure isn't a clean run,
    even when the verifier produced a valid disposition.
    """
    by_finding = {r.markers.finding_id: r for r in records}
    succeeded: list[PostResult] = []
    failed: list[str] = []
    for entry in disposition_doc.get("dispositions", []) or []:
        finding_id = entry.get("finding_id", "")
        record = by_finding.get(finding_id)
        if record is None:
            logger.warning(
                "Disposition entry %s has no matching issue in this run; "
                "skipping post.",
                finding_id,
            )
            # An entry without a matching issue means the skill returned
            # a finding we didn't request. _verify_entry_count already
            # catches this before we get here; reaching this branch is
            # defensive only — don't count it as a post failure since
            # there's nothing to post to.
            continue
        verdict = entry.get("verdict", "")
        issue_comment = entry.get("issue_comment", "")
        if no_post:
            logger.info(
                "Dry-run (--no-post): would post %s verdict for %s on "
                "issue #%d",
                verdict,
                finding_id,
                record.ref.number,
            )
            succeeded.append(
                PostResult(
                    finding_id=finding_id,
                    issue_number=record.ref.number,
                    verdict=verdict,
                    verdict_comment_url="(dry-run)",
                    archival_comment_url="",
                    reopened=False,
                )
            )
            continue
        try:
            result = await post_disposition(
                client,
                host,
                record.ref,
                finding_id=finding_id,
                verdict=verdict,
                issue_comment_md=issue_comment,
                body_tampered=record.body_tampered,
                original_body=record.original_body,
                allow_reopen=not no_reopen,
            )
        except GitHubVerifyError as exc:
            logger.error(
                "Failed to post %s for %s on issue #%d: %s",
                verdict,
                finding_id,
                record.ref.number,
                exc,
            )
            failed.append(finding_id)
            continue
        succeeded.append(result)
    return succeeded, failed


def _print_summary(
    results: list[PostResult],
    run_dir: Path,
    *,
    no_post: bool,
    failed: list[str] | None = None,
) -> None:
    """Final stdout summary line + per-finding breakdown.

    Per-finding action labels distinguish four states:
    - ``[reopened]`` — non-FIXED verdict, issue successfully reopened.
    - ``[left closed]`` — FIXED or INVALID_INPUT, issue stays closed.
    - ``[REOPEN_FAILED]`` — verdict comment landed but the reopen
      PATCH failed; the issue is closed but the verdict said reopen.
    - ``[ARCHIVAL_FAILED]`` — body was tampered, verdict comment
      landed but the archival-context comment didn't.
    Findings whose verdict comment never landed appear separately
    under ``POST_FAILED``.
    """
    counts: dict[str, int] = {}
    for r in results:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    mode = " (dry-run)" if no_post else ""
    print()
    print(f"Verify complete{mode}. Run: {run_dir.name}")
    print(f"Scratch: {run_dir}")
    if not results and not failed:
        print("  (no results)")
        return
    for r in results:
        labels: list[str] = []
        if r.reopened:
            labels.append("reopened")
        elif r.verdict in {"FIXED", "INVALID_INPUT"}:
            labels.append("left closed")
        if r.reopen_failed:
            labels.append("REOPEN_FAILED")
        if r.archival_failed:
            labels.append("ARCHIVAL_FAILED")
        action = " [" + ", ".join(labels) + "]" if labels else ""
        print(f"  {r.finding_id} (#{r.issue_number}): {r.verdict}{action}")
    if failed:
        for finding_id in failed:
            print(f"  {finding_id}: POST_FAILED")
    counts_summary = ", ".join(f"{n} {v}" for v, n in sorted(counts.items()))
    if failed:
        counts_summary = (
            f"{counts_summary}, {len(failed)} POST_FAILED"
            if counts_summary
            else f"{len(failed)} POST_FAILED"
        )
    print(f"Totals: {counts_summary}")
