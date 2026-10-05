"""Issues stage entrypoint: extract → ensure labels → fetch → dedup → post.

Orchestrates the per-finding GitHub issue creation. Continues past
per-issue failures and surfaces them in the summary so a flaky 5xx on
one issue doesn't block the rest.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from . import audit as _audit
from . import audit_extract as _audit_extract
from . import issues_dedup, issues_extract, issues_fetch, issues_render, skill_version
from ._github import api_base, extract_timestamp, parse_owner_repo
from ._llm import CostStats
from .auth import TokenProvider, resolve_verify
from .config import AgentConfig
from .issues_extract import ExtractedReport, Finding
from .issues_render import CleanScanContext
from .repo_properties import RepoProperties
from .token_client import BrokerTokenAuth, get_github_token

logger = logging.getLogger(__name__)


class IssuesStageError(RuntimeError):
    """Raised when the issues stage cannot start at all (config/auth)."""


class IssuePostError(RuntimeError):
    """Raised when a single issue cannot be created.

    Distinct from ``IssuesStageError`` so the orchestrator can record
    it as a per-finding failure rather than aborting the stage.
    """


# Backoff between transient-error retries. One retry on 429/5xx; if that
# also fails, surface the failure to the caller rather than retrying
# indefinitely.
_RETRY_BACKOFF_SECONDS = 30


def _is_retryable(status_code: int) -> bool:
    """True for status codes worth retrying once (rate-limit + server error)."""
    return status_code == 429 or status_code >= 500


def _github_default_headers() -> dict[str, str]:
    """Static headers for GitHub API calls. Authorization is injected
    per-request by ``BrokerTokenAuth`` so the no-cache contract holds at
    the request boundary."""
    return {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _emit_finding_opened(
    *,
    audit_writer: "_audit.AuditWriter | None",
    config: AgentConfig,
    finding: Finding,
    url: str,
    results_dir: Path,
    report_id: str,
    repo_slug: str,
    repo_properties: RepoProperties | None = None,
) -> None:
    """Emit both audit + findings-event records after a successful POST.

    No-op when ``audit_writer`` is ``None`` OR when the caller didn't
    thread a ``report_id`` / ``repo_slug`` through. Wrapped in a broad
    try/except so a failing audit emit never breaks the issues stage's
    per-finding contract — a lost audit record is preferable to a lost
    issue.
    """
    if audit_writer is None or not report_id:
        return
    finding_id = _audit.finding_id_for(report_id, finding.id)
    props = repo_properties or RepoProperties()
    try:
        audit_writer.emit_audit(
            _audit.build_finding_opened(
                app_id=config.audit.app_id,
                actor=config.audit.actor,
                repo_slug=repo_slug,
                report_id=report_id,
                finding_id=finding_id,
                github_issue_url=url,
                to_status="OPEN",
            )
        )
        audit_writer.emit_finding(
            _audit.build_finding_event(
                app_id=config.audit.app_id,
                repo_slug=repo_slug,
                report_id=report_id,
                finding_id=finding_id,
                vuln_id=finding.id,
                title=finding.title,
                cwe=finding.cwe or "CWE-UNKNOWN",
                severity=finding.severity,
                status="OPEN",
                location=finding.location,
                root_cause=finding.root_cause,
                entry_point=finding.entry_point,
                data_flow=finding.data_flow,
                proposed_fix_strategy=finding.fix_strategy,
                proposed_fix_why=finding.severity_rationale,
                poc_file=_audit_extract.relativize(finding.poc_path, results_dir),
                exploit_test_file=_audit_extract.relativize(
                    finding.exploit_test_path, results_dir
                ),
                github_issue_url=url,
                # Transition, not initial open — the initial open was
                # already emitted from __main__ right after the scan.
                opened=False,
                repo_properties=props.values,
            )
        )
    except Exception:  # noqa: BLE001
        logger.exception("Failed to emit finding_opened audit for %s", finding.id)


@dataclass(frozen=True)
class PostedIssue:
    finding_id: str
    title: str
    url: str


@dataclass(frozen=True)
class SkippedIssue:
    finding_id: str
    matched_issue_numbers: list[int]
    via: str  # "key" | "semantic"


@dataclass(frozen=True)
class FailedIssue:
    finding_id: str
    title: str
    error: str


@dataclass(frozen=True)
class CleanScanOutcome:
    """Result of a clean-scan notification attempt.

    ``mode`` values:

    - ``"created"``: a fresh issue was POSTed AND closed successfully.
    - ``"appended"``: an existing open clean-scan issue got a comment.
    - ``"close_back_failed"``: the issue was POSTed but the PATCH to
      close it failed; the issue remains open. Next scan will find it
      via the open-label lookup and comment on it (self-heal).
    - ``"skipped"``: nothing was posted (label-ensure failed,
      open-issue lookup failed, or comment POST failed). ``url`` is
      empty in this case, except on the append-path comment failure
      where it retains the existing issue's URL for context.

    ``state`` reflects the GitHub state we believe the referenced issue
    is in (``"CLOSED"`` / ``"OPEN"`` / ``""``). Empty when nothing was
    posted or on the ``appended`` path — we didn't modify the target
    issue's state, so we don't claim knowledge of it here. Note the
    intentional asymmetry with the audit event: ``clean_scan_notified``
    records ``to_status="CLOSED"`` on the append path because the
    receipt-as-a-whole is still "issue was closed after a scan
    reported zero findings", even though this specific scan didn't
    perform the close. Don't unify the two fields.
    """

    url: str
    mode: str
    state: str
    note: str = ""


@dataclass
class PostSummary:
    posted: list[PostedIssue] = field(default_factory=list)
    skipped: list[SkippedIssue] = field(default_factory=list)
    failed: list[FailedIssue] = field(default_factory=list)
    note: str = ""
    cost: CostStats = field(default_factory=CostStats)
    clean_scan: CleanScanOutcome | None = None

    @property
    def any_failed(self) -> bool:
        return bool(self.failed)


_LABEL_COLORS = {
    "security": "d73a4a",  # red
    "vulnhunter": "5319e7",  # purple
}
_DEFAULT_LABEL_COLOR = "ededed"
# Green — visually distinguishes clean-scan receipts from findings at a
# glance in the repo's Issues list. Applied only when we create the
# label; existing repos with a differently-colored copy are left alone.
_CLEAN_SCAN_LABEL_COLOR = "0e8a16"
_CLEAN_SCAN_LABEL_DESCRIPTION = "VulnHunter clean-scan receipt (informational)"
# Cap on how many stray open-clean-scan issue numbers we render in the
# state-drift WARN line. A repo with dozens of strays is already
# broken; readability of the log matters more than completeness there.
_MAX_STRAYS_IN_LOG = 5


async def _ensure_label(
    client: httpx.AsyncClient,
    *,
    api: str,
    owner: str,
    name: str,
    label: str,
    description: str = "VulnHunter scan finding",
    color: str | None = None,
) -> None:
    """Create a label on the target repo if it doesn't already exist.

    Labels can contain spaces or other URL-special characters, so the
    label name is URL-encoded into the GET path. Default labels
    (security, vulnhunter) wouldn't need encoding, but user-customized
    labels via [issues].labels might.

    ``description`` and ``color`` are only applied when this call creates
    the label. Existing labels are left untouched so a manual
    color/description tweak in the repo isn't clobbered on every scan.
    """
    encoded = quote(label, safe="")
    get = await client.get(f"{api}/repos/{owner}/{name}/labels/{encoded}")
    if get.status_code == 200:
        return
    if get.status_code != 404:
        raise IssuesStageError(
            f"checking label {label!r} on {owner}/{name}: "
            f"{get.status_code} {get.text[:200]}"
        )
    resolved_color = color or _LABEL_COLORS.get(label, _DEFAULT_LABEL_COLOR)
    body = {
        "name": label,
        "color": resolved_color,
        "description": description,
    }
    post = await client.post(
        f"{api}/repos/{owner}/{name}/labels", json=body
    )
    if post.status_code in (200, 201):
        logger.info("Created label %r on %s/%s", label, owner, name)
        return
    # 422 here is usually a concurrent create losing the race against
    # another agent run targeting the same repo (GET→404 / POST→201 by
    # the other run / our POST→422). Re-GET to disambiguate from a real
    # validation failure (e.g. invalid label name or color) before we
    # blow up the whole stage.
    if post.status_code == 422:
        recheck = await client.get(
            f"{api}/repos/{owner}/{name}/labels/{encoded}"
        )
        if recheck.status_code == 200:
            logger.debug(
                "Label %r already exists on %s/%s (created concurrently)",
                label,
                owner,
                name,
            )
            return
    raise IssuesStageError(
        f"creating label {label!r} on {owner}/{name}: "
        f"{post.status_code} {post.text[:200]}"
    )


async def _ensure_all_labels(
    *,
    target_repo_url: str,
    config: AgentConfig,
    verify: str | bool,
) -> None:
    if not get_github_token("scan", config):
        raise IssuesStageError(
            "scan_token is required to ensure labels and post issues."
        )
    owner, name = parse_owner_repo(target_repo_url)
    api = api_base(config.github.host)
    timeout = config.issues.request_timeout_seconds
    async with httpx.AsyncClient(
        verify=verify,
        timeout=timeout,
        headers=_github_default_headers(),
        auth=BrokerTokenAuth("scan", config),
    ) as client:
        for label in config.issues.labels:
            await _ensure_label(
                client, api=api, owner=owner, name=name, label=label
            )


async def _create_issue(
    client: httpx.AsyncClient,
    *,
    api: str,
    owner: str,
    name: str,
    title: str,
    body: str,
    labels: list[str],
    log_retries: bool = False,
) -> str:
    """POST /issues with one transient-error retry. Returns html_url.

    Raises ``IssuePostError`` if the call fails after retry, or if the
    201 response is missing ``html_url`` (defensive — GitHub's API
    always includes it, but we'd rather fail loud than silently store
    an empty URL in the summary).
    """
    payload: dict[str, Any] = {
        "title": title,
        "body": body,
        "labels": list(labels),
    }
    last_status = 0
    last_text = ""
    for attempt in range(2):
        resp = await client.post(
            f"{api}/repos/{owner}/{name}/issues", json=payload
        )
        if resp.status_code == 201:
            html_url = resp.json().get("html_url")
            if not html_url:
                raise IssuePostError(
                    f"GitHub returned 201 but no html_url for {title!r}"
                )
            return str(html_url)
        last_status = resp.status_code
        last_text = resp.text[:300]
        if not _is_retryable(resp.status_code):
            break
        if attempt == 0:
            if log_retries:
                logger.info(
                    "POST issue %r got %d; retrying once after %ds backoff",
                    title,
                    resp.status_code,
                    _RETRY_BACKOFF_SECONDS,
                )
            await asyncio.sleep(_RETRY_BACKOFF_SECONDS)
    raise IssuePostError(f"POST issues failed: {last_status} {last_text}")


async def _close_issue(
    client: httpx.AsyncClient,
    *,
    api: str,
    owner: str,
    name: str,
    number: int,
    log_retries: bool = False,
) -> None:
    """PATCH an issue to state=closed with one transient-error retry.

    Raises ``IssuePostError`` on final failure so the caller can leave
    the issue open and record the anomaly. Uses ``state_reason=completed``
    so the closed state renders as a purple checkmark rather than a red
    "not planned" tombstone — this is a receipt, not a rejection.
    """
    payload = {"state": "closed", "state_reason": "completed"}
    last_status = 0
    last_text = ""
    for attempt in range(2):
        resp = await client.patch(
            f"{api}/repos/{owner}/{name}/issues/{number}", json=payload
        )
        if resp.status_code in (200, 201):
            return
        last_status = resp.status_code
        last_text = resp.text[:300]
        if not _is_retryable(resp.status_code):
            break
        if attempt == 0:
            if log_retries:
                logger.info(
                    "PATCH close issue #%d got %d; retrying once after %ds backoff",
                    number,
                    resp.status_code,
                    _RETRY_BACKOFF_SECONDS,
                )
            await asyncio.sleep(_RETRY_BACKOFF_SECONDS)
    raise IssuePostError(
        f"PATCH close issue #{number} failed: {last_status} {last_text}"
    )


async def _post_issue_comment(
    client: httpx.AsyncClient,
    *,
    api: str,
    owner: str,
    name: str,
    number: int,
    body: str,
    log_retries: bool = False,
) -> str:
    """POST a comment on an issue with one transient-error retry.

    Returns the comment's ``html_url``. Raises ``IssuePostError`` on
    final failure.
    """
    payload = {"body": body}
    last_status = 0
    last_text = ""
    for attempt in range(2):
        resp = await client.post(
            f"{api}/repos/{owner}/{name}/issues/{number}/comments", json=payload
        )
        if resp.status_code in (200, 201):
            html_url = resp.json().get("html_url")
            if not html_url:
                raise IssuePostError(
                    f"GitHub returned {resp.status_code} but no html_url on "
                    f"comment for issue #{number}"
                )
            return str(html_url)
        last_status = resp.status_code
        last_text = resp.text[:300]
        if not _is_retryable(resp.status_code):
            break
        if attempt == 0:
            if log_retries:
                logger.info(
                    "POST comment on #%d got %d; retrying once after %ds backoff",
                    number,
                    resp.status_code,
                    _RETRY_BACKOFF_SECONDS,
                )
            await asyncio.sleep(_RETRY_BACKOFF_SECONDS)
    raise IssuePostError(
        f"POST comment on #{number} failed: {last_status} {last_text}"
    )


def _iso_from_results_timestamp(results_dir_name: str) -> str:
    """Convert the ``YYYY-MM-DD-HHMMSS`` suffix to ISO-8601 UTC.

    Returns ``""`` when the timestamp is missing or unparseable — the
    renderer swaps a blank back to ``"—"`` so the table still renders.
    """
    ts = extract_timestamp(results_dir_name)
    if not ts or ts == "unknown":
        return ""
    try:
        parsed = _dt.datetime.strptime(ts, "%Y-%m-%d-%H%M%S").replace(
            tzinfo=_dt.timezone.utc
        )
    except ValueError:
        return ""
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_clean_scan_ctx(
    *,
    results_dir: Path,
    report_url: str,
    repo_slug: str,
    commit_sha: str,
    config: AgentConfig,
    scan_completed_at: str,
) -> CleanScanContext:
    """Assemble a CleanScanContext from what the caller has on hand.

    ``scan_started_at`` and ``duration_seconds`` are derived from the
    results-dir timestamp. When the timestamp is missing (unusual but
    possible on hand-crafted results dirs), both fields render as
    dashes — the receipt is still posted.
    """
    started_iso = _iso_from_results_timestamp(results_dir.name)
    duration: int | None = None
    if started_iso and scan_completed_at:
        try:
            # fromisoformat handles the trailing ``Z`` and optional
            # fractional seconds since Python 3.11, so we don't have to
            # pre-massage either input regardless of which side carries
            # milliseconds.
            start_dt = _dt.datetime.fromisoformat(started_iso)
            end_dt = _dt.datetime.fromisoformat(scan_completed_at)
            duration = max(0, int((end_dt - start_dt).total_seconds()))
        except ValueError:
            duration = None
    short_sha = commit_sha[:7] if commit_sha else ""
    return CleanScanContext(
        scan_id=results_dir.name,
        repo_slug=repo_slug,
        commit_sha_short=short_sha,
        app_id=config.audit.app_id,
        scan_started_at=started_iso,
        scan_completed_at=scan_completed_at,
        duration_seconds=duration,
        model_version=config.anthropic.model,
        skill_version=skill_version.resolve(),
        report_url=report_url or "",
    )


def _emit_clean_scan_notified(
    *,
    audit_writer: "_audit.AuditWriter | None",
    config: AgentConfig,
    report_id: str,
    repo_slug: str,
    issue_url: str,
    commit_sha: str,
    to_status: str,
    notes: str,
) -> None:
    """Emit the ``clean_scan_notified`` audit event.

    No-op when audit is off. Wrapped in try/except so a failing audit
    write never breaks the notification path — a lost audit record is
    preferable to a lost receipt.
    """
    if audit_writer is None:
        return
    try:
        audit_writer.emit_audit(
            _audit.build_clean_scan_notified(
                app_id=config.audit.app_id,
                actor=config.audit.actor,
                repo_slug=repo_slug,
                report_id=report_id,
                github_issue_url=issue_url,
                model_version=config.anthropic.model,
                target_sha=commit_sha,
                to_status=to_status,
                notes=notes,
            )
        )
    except Exception:  # noqa: BLE001
        logger.exception("Failed to emit clean_scan_notified audit event")


async def _post_clean_scan_notice(
    *,
    results_dir: Path,
    report_url: str,
    target_repo_url: str,
    config: AgentConfig,
    commit_sha: str,
    audit_writer: "_audit.AuditWriter | None",
    audit_report_id: str,
    audit_repo_slug: str,
) -> CleanScanOutcome:
    """Post (or append a comment to) a clean-scan receipt issue.

    See docs/clean-scan-notifications-design.md for the full contract.
    Non-fatal failures (label ensure, open-issue lookup, comment POST)
    downgrade to a ``skipped`` outcome — the scan itself already
    succeeded, so a receipt-posting failure is not worth failing the
    stage or the run.

    Belt-and-suspenders exception handling: each protocol step catches
    its own domain error class **and** ``httpx.RequestError`` so
    transport failures (DNS, TLS reset, timeout) are classified with a
    meaningful ``note`` field. The outer ``except Exception`` is the
    absolute last-line defense — any exception we didn't foresee
    (e.g. a malformed target_repo_url producing ``GitHubURLError``, or
    a programmer error inside the render path) still yields a
    ``skipped`` outcome instead of tipping the issues-stage exit code.
    """
    try:
        return await _post_clean_scan_notice_inner(
            results_dir=results_dir,
            report_url=report_url,
            target_repo_url=target_repo_url,
            config=config,
            commit_sha=commit_sha,
            audit_writer=audit_writer,
            audit_report_id=audit_report_id,
            audit_repo_slug=audit_repo_slug,
        )
    except Exception as exc:  # noqa: BLE001
        # Design §2: no receipt-path failure — including ones we didn't
        # anticipate — is allowed to fail the run. logger.exception
        # preserves the traceback for post-mortem while we return a
        # tidy "skipped" outcome.
        logger.exception(
            "Unexpected clean-scan notice failure; downgrading to skipped"
        )
        return CleanScanOutcome(
            url="",
            mode="skipped",
            state="",
            note=f"unexpected error: {type(exc).__name__}: {exc}",
        )


async def _post_clean_scan_notice_inner(
    *,
    results_dir: Path,
    report_url: str,
    target_repo_url: str,
    config: AgentConfig,
    commit_sha: str,
    audit_writer: "_audit.AuditWriter | None",
    audit_report_id: str,
    audit_repo_slug: str,
) -> CleanScanOutcome:
    """Body of ``_post_clean_scan_notice``. See wrapper's docstring."""
    if not get_github_token("scan", config):
        return CleanScanOutcome(
            url="",
            mode="skipped",
            state="",
            note="scan_token missing; cannot post clean-scan receipt",
        )
    owner, name = parse_owner_repo(target_repo_url)
    api = api_base(config.github.host)
    timeout = config.issues.request_timeout_seconds
    label = config.issues.clean_scan_label
    verify = resolve_verify(config.tls)
    # Seconds-precision UTC ISO-8601 for symmetry with scan_started_at
    # (which is parsed from the results-dir name at second granularity).
    # The audit stream uses ms precision via event_time_now(); this
    # timestamp is only for the receipt body's Scan-completed cell.
    scan_completed_at = _dt.datetime.now(_dt.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    ctx = _build_clean_scan_ctx(
        results_dir=results_dir,
        report_url=report_url,
        repo_slug=audit_repo_slug,
        commit_sha=commit_sha,
        config=config,
        scan_completed_at=scan_completed_at,
    )
    body = issues_render.render_clean_scan_body(ctx)
    comment_body = issues_render.render_clean_scan_comment(ctx)
    title = issues_render.render_clean_scan_title()

    # Both the domain error and transport failures (DNS/TLS/timeout)
    # must downgrade to a skipped outcome — design §2 forbids receipt
    # failures from tipping the issues-stage exit code.
    try:
        async with httpx.AsyncClient(
            verify=verify,
            timeout=timeout,
            headers=_github_default_headers(),
            auth=BrokerTokenAuth("scan", config),
        ) as client:
            await _ensure_label(
                client,
                api=api,
                owner=owner,
                name=name,
                label=label,
                description=_CLEAN_SCAN_LABEL_DESCRIPTION,
                color=_CLEAN_SCAN_LABEL_COLOR,
            )
    except (IssuesStageError, httpx.RequestError) as exc:
        logger.warning("Clean-scan label ensure failed: %s", exc)
        return CleanScanOutcome(
            url="",
            mode="skipped",
            state="",
            note=f"label-ensure failed: {exc}",
        )

    # Same containment contract as label ensure — see comment above.
    try:
        opens = issues_fetch.fetch_open_issues_with_label(
            target_repo_url,
            label,
            config=config,
            log_retries=config.logging.retries,
        )
    except (issues_fetch.IssuesFetchError, httpx.RequestError) as exc:
        logger.warning("Clean-scan open-issue lookup failed: %s", exc)
        return CleanScanOutcome(
            url="",
            mode="skipped",
            state="",
            note=f"open-issue lookup failed: {exc}",
        )

    async with httpx.AsyncClient(
        verify=verify,
        timeout=timeout,
        headers=_github_default_headers(),
        auth=BrokerTokenAuth("scan", config),
    ) as client:
        if opens:
            # Design §5: an existing open receipt means a prior
            # close-back failed. Comment on the lowest-numbered one
            # (deterministic tiebreak) rather than creating a duplicate.
            target = min(opens, key=lambda o: o.number)
            if len(opens) > 1:
                strays = sorted(
                    o.number for o in opens if o.number != target.number
                )
                # Cap the log line so a pathological repo with dozens
                # of strays doesn't produce an unreadable WARN.
                shown = strays[:_MAX_STRAYS_IN_LOG]
                overflow = len(strays) - len(shown)
                stray_repr = (
                    f"{shown} (+{overflow} more)" if overflow else str(shown)
                )
                logger.warning(
                    "%d open clean-scan issues on %s/%s (expected 0 or 1); "
                    "commenting on the oldest (#%d). Other open issues: %s",
                    len(opens),
                    owner,
                    name,
                    target.number,
                    stray_repr,
                )
            try:
                comment_url = await _post_issue_comment(
                    client,
                    api=api,
                    owner=owner,
                    name=name,
                    number=target.number,
                    body=comment_body,
                    log_retries=config.logging.retries,
                )
            except (IssuePostError, httpx.RequestError) as exc:
                logger.warning(
                    "Clean-scan comment POST on #%d failed: %s",
                    target.number,
                    exc,
                )
                return CleanScanOutcome(
                    url=target.html_url,
                    mode="skipped",
                    state="",
                    note=f"comment POST failed: {exc}",
                )
            logger.info(
                "Appended clean-scan comment to #%d (%s)",
                target.number,
                comment_url,
            )
            _emit_clean_scan_notified(
                audit_writer=audit_writer,
                config=config,
                report_id=audit_report_id,
                repo_slug=audit_repo_slug,
                issue_url=target.html_url,
                commit_sha=commit_sha,
                to_status="CLOSED",
                notes=f"append: {target.html_url}",
            )
            return CleanScanOutcome(
                url=target.html_url,
                mode="appended",
                state="",
                note=f"comment: {comment_url}",
            )

        try:
            issue_url = await _create_issue(
                client,
                api=api,
                owner=owner,
                name=name,
                title=title,
                body=body,
                labels=[label],
                log_retries=config.logging.retries,
            )
        except (IssuePostError, httpx.RequestError) as exc:
            logger.warning("Clean-scan issue POST failed: %s", exc)
            return CleanScanOutcome(
                url="",
                mode="skipped",
                state="",
                note=f"issue POST failed: {exc}",
            )
        # URL-parse failure and PATCH failure share the same audit
        # branch — either way the issue was created but we couldn't
        # close it, so the receipt stays "open" and self-heals on
        # the next scan.
        try:
            issue_number = _issue_number_from_url(issue_url)
            await _close_issue(
                client,
                api=api,
                owner=owner,
                name=name,
                number=issue_number,
                log_retries=config.logging.retries,
            )
        except (IssuePostError, httpx.RequestError) as exc:
            logger.error(
                "Clean-scan close-back on %s failed; issue left open: %s",
                issue_url,
                exc,
            )
            _emit_clean_scan_notified(
                audit_writer=audit_writer,
                config=config,
                report_id=audit_report_id,
                repo_slug=audit_repo_slug,
                issue_url=issue_url,
                commit_sha=commit_sha,
                to_status="OPEN",
                notes=f"close-back failed: {exc}",
            )
            return CleanScanOutcome(
                url=issue_url,
                mode="close_back_failed",
                state="OPEN",
                note=str(exc),
            )
        logger.info("Posted clean-scan receipt: %s", issue_url)
        _emit_clean_scan_notified(
            audit_writer=audit_writer,
            config=config,
            report_id=audit_report_id,
            repo_slug=audit_repo_slug,
            issue_url=issue_url,
            commit_sha=commit_sha,
            to_status="CLOSED",
            notes="",
        )
        return CleanScanOutcome(url=issue_url, mode="created", state="CLOSED")


def _issue_number_from_url(html_url: str) -> int:
    """Extract the issue number from GitHub's issue ``html_url``.

    GitHub's response ``html_url`` is `https://.../issues/<n>` (no
    trailing path segments, no query, no fragment). Anything else is a
    contract violation from GitHub or a bug in URL passing on our side
    — treat it as a hard fail rather than folding it into a fake 404
    on ``/issues/0`` where the audit trail would blame close-back.
    """
    tail = html_url.rstrip("/").rsplit("/", 1)[-1]
    try:
        return int(tail)
    except ValueError as exc:
        raise IssuePostError(
            f"cannot parse issue number from html_url {html_url!r}"
        ) from exc


async def post_issues(
    *,
    results_dir: Path,
    report_url: str,
    target_repo_url: str,
    config: AgentConfig,
    token_manager: TokenProvider,
    audit_writer: "_audit.AuditWriter | None" = None,
    audit_report_id: str = "",
    audit_repo_slug: str = "",
    audit_repo_properties: RepoProperties | None = None,
    extracted: ExtractedReport | None = None,
    commit_sha: str = "",
) -> PostSummary:
    """Run the full issues stage. Errors below are caught per-finding.

    ``extracted`` may be supplied by the caller when it has already
    parsed the report (e.g. for the audit path) — the LLM extractor
    isn't re-invoked in that case. When ``audit_writer`` is non-None,
    each successful POST also emits a ``finding_opened`` audit event
    plus a findings-event transition record.

    On a zero-findings scan the flow diverges into the clean-scan
    receipt path (see docs/clean-scan-notifications-design.md) —
    ``commit_sha`` is threaded through so the receipt can display it.
    """
    summary = PostSummary()
    verify = resolve_verify(config.tls)

    if extracted is None:
        extracted = await issues_extract.extract_findings(
            results_dir, config, token_manager, cost_tracker=summary.cost,
            audit_writer=audit_writer,
        )
    if not extracted.findings:
        summary.note = "no confirmed findings in report"
        if config.issues.notify_clean_scan:
            summary.clean_scan = await _post_clean_scan_notice(
                results_dir=results_dir,
                report_url=report_url,
                target_repo_url=target_repo_url,
                config=config,
                commit_sha=commit_sha,
                audit_writer=audit_writer,
                audit_report_id=audit_report_id,
                audit_repo_slug=audit_repo_slug,
            )
        else:
            logger.info(
                "Clean-scan notification disabled (issues.notify_clean_scan=false); "
                "skipping receipt POST."
            )
        return summary

    await _ensure_all_labels(
        target_repo_url=target_repo_url, config=config, verify=verify
    )

    open_issues = issues_fetch.fetch_open_issues_with_label(
        target_repo_url,
        config.issues.dedup_label,
        config=config,
        log_retries=config.logging.retries,
    )
    decisions = await issues_dedup.dedup(
        extracted.findings,
        open_issues,
        config,
        token_manager,
        cost_tracker=summary.cost,
        audit_writer=audit_writer,
    )
    duplicate_map = {
        d.finding_id: d for d in decisions if d.matched_issues
    }

    owner, name = parse_owner_repo(target_repo_url)
    api = api_base(config.github.host)
    timeout = config.issues.request_timeout_seconds

    async with httpx.AsyncClient(
        verify=verify,
        timeout=timeout,
        headers=_github_default_headers(),
        auth=BrokerTokenAuth("scan", config),
    ) as client:
        for f in extracted.findings:
            if f.id in duplicate_map:
                d = duplicate_map[f.id]
                summary.skipped.append(
                    SkippedIssue(
                        finding_id=f.id,
                        matched_issue_numbers=d.matched_issues,
                        via=d.via,
                    )
                )
                logger.info(
                    "Skip %s — duplicate of #%s (via %s)",
                    f.id,
                    ", #".join(str(n) for n in d.matched_issues),
                    d.via,
                )
                continue

            title = issues_render.render_title(f)
            body = issues_render.render_body(
                f,
                report=extracted,
                report_url=report_url,
            )
            try:
                url = await _create_issue(
                    client,
                    api=api,
                    owner=owner,
                    name=name,
                    title=title,
                    body=body,
                    labels=config.issues.labels,
                    log_retries=config.logging.retries,
                )
                summary.posted.append(
                    PostedIssue(finding_id=f.id, title=title, url=url)
                )
                logger.info("Posted %s → %s", f.id, url)
                _emit_finding_opened(
                    audit_writer=audit_writer,
                    config=config,
                    finding=f,
                    url=url,
                    results_dir=results_dir,
                    report_id=audit_report_id,
                    repo_slug=audit_repo_slug,
                    repo_properties=audit_repo_properties,
                )
            except IssuePostError as exc:
                summary.failed.append(
                    FailedIssue(finding_id=f.id, title=title, error=str(exc))
                )
                logger.warning("Failed to post %s: %s", f.id, exc)

    return summary


# When more than this many issues were posted, switch the summary's
# Posted line from a one-line comma-joined list to one URL per line —
# the comma list gets unreadable quickly.
_POSTED_INLINE_LIMIT = 3


def print_summary(summary: PostSummary) -> None:
    """Render the end-of-run summary to stdout (called from __main__)."""
    print()
    print("Issues:")
    if summary.note:
        print(f"  Note:    {summary.note}")
    if summary.posted:
        if len(summary.posted) <= _POSTED_INLINE_LIMIT:
            urls = ", ".join(p.url for p in summary.posted)
            print(f"  Posted:  {len(summary.posted):<3} ({urls})")
        else:
            print(f"  Posted:  {len(summary.posted)}")
            for p in summary.posted:
                print(f"    - {p.url}")
    else:
        print("  Posted:  0")
    if summary.clean_scan is not None:
        cs = summary.clean_scan
        if cs.mode == "created":
            print(f"  Clean:   posted+closed ({cs.url})")
        elif cs.mode == "appended":
            print(f"  Clean:   appended-comment ({cs.url})")
        elif cs.mode == "close_back_failed":
            print(f"  Clean:   posted, close-back FAILED ({cs.url})")
        else:  # skipped
            print(f"  Clean:   skipped ({cs.note or 'unspecified'})")
    if summary.skipped:
        skip_lines = [
            f"{s.finding_id}→#{','.join(str(n) for n in s.matched_issue_numbers)} ({s.via})"
            for s in summary.skipped
        ]
        print(f"  Skipped: {len(summary.skipped):<3} (duplicates: {'; '.join(skip_lines)})")
    else:
        print("  Skipped: 0")
    if summary.failed:
        print(f"  Failed:  {len(summary.failed):<3}")
        for fail in summary.failed:
            print(f"    - {fail.finding_id}: {fail.error}")
    else:
        print("  Failed:  0")
    if summary.cost.calls:
        print(
            f"  Cost:    ${summary.cost.cost_usd:.4f} "
            f"({summary.cost.calls} call(s), {summary.cost.num_turns} turn(s), "
            f"API duration={summary.cost.duration_api_ms}ms)"
        )


def build_report_url_for_local_scan(
    *,
    publish_destination_repo: str,
    publish_branch: str,
    source_repo_url: str,
    source_commit_hash: str,
    results_dir: Path,
) -> str:
    """Construct the URL the freshly-published report will live at."""
    return issues_render._build_report_url(
        publish_destination_repo=publish_destination_repo,
        publish_branch=publish_branch,
        source_repo_url=source_repo_url,
        source_commit_hash=source_commit_hash,
        timestamp=extract_timestamp(results_dir.name),
        results_dir_name=results_dir.name,
    )


def build_report_url_for_remote_report(
    *,
    publish_destination_repo: str,
    publish_branch: str,
    rel_path_in_dest: str,
) -> str:
    """Construct the URL for an already-published report we just downloaded.

    ``rel_path_in_dest`` is the path inside the destination repo where
    the results dir lives — supplied directly by ``download_latest_report``
    so we don't have to assume a fixed publish layout.
    """
    dest = publish_destination_repo.rstrip("/")
    if dest.endswith(".git"):
        dest = dest[: -len(".git")]
    return f"{dest}/blob/{publish_branch}/{rel_path_in_dest}/README.md"
