"""CLI entrypoint: ``--mode=scan`` clones a repo and runs /vulnhunt;
``--mode=verify`` reacts to a list of GitHub issues by running
/vulnhunt-fix-verify against the supplied finding.

Usage (scan mode):
    python -m agent --mode=scan <repo-url> [--config PATH] [--model MODEL]
                                            [--clone-dir DIR] [--re-clone]
                                            [--scan | --no-scan]
                                            [--publish | --no-publish]
                                            [--issues | --no-issues]
                                            [--issues-target-repo URL]
                                            [--audit | --no-audit]
                                            [--audit-events-path PATH]
                                            [--audit-findings-path PATH]
                                            [--audit-stdout | --no-audit-stdout]
                                            [--app-id SLUG] [--audit-actor NAME]
                                            [--repo-property NAME=VALUE ...]
                                            [-v | -vv]

Usage (verify mode):
    python -m agent --mode=verify <issue-url> [<issue-url> ...]
                                              [--config PATH] [--model MODEL]
                                              [--commit SHA] [--scratch-dir DIR]
                                              [--no-post] [--no-reopen]
                                              [audit flags as above]
                                              [-v | -vv]

``--mode`` is required — there is no implicit default. Old-style
invocations like ``python -m agent <repo-url>`` fail with a clear
parser error.

Scan-mode toggles default to scan/publish/issues all enabled (publish
takes its default from config). The issues stage requires either
``--scan`` (so we have a fresh report) or a previous published report
we can download. ``--scan + --no-publish + --issues`` is incoherent
(issues link to a report that wouldn't exist remotely) and is
rejected up front.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import logging
import shutil
import subprocess
import sys
from pathlib import Path

import httpx

from . import audit as audit_mod
from . import audit_extract
from . import issues as issues_stage
from . import issues_extract
from . import repo_properties as repo_props
from ._github import api_base
from .auth import make_token_manager, resolve_verify
from .clone import shallow_clone
from .config import AgentConfig, AuditConfig, load_config
from .issues_remote_report import (
    DownloadedReport,
    RemoteReportError,
    download_latest_report,
)
from .publish import PublishError, publish_results
from .runner import (
    _git_context,
    _normalize_repo_url,
    _repo_slug_from_url,
    run_vulnhunt,
    set_verbosity,
)
from ._stream_events import SessionTotals
from .issues import PostSummary
from .issues_extract import Finding
from .manifest import write_manifest
from .token_client import GitHubRole, get_github_token


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m agent",
        description=(
            "Clone a GitHub repo and run /vulnhunt (--mode=scan), or "
            "react to a list of closed issues with /vulnhunt-fix-verify "
            "(--mode=verify)."
        ),
    )
    parser.add_argument(
        "--mode",
        # Defer the required-check to main() so the parser error
        # message can be friendlier than argparse's default. Without
        # this, missing --mode produces "the following arguments are
        # required: --mode" which is unhelpful given that --mode is a
        # deliberate breaking change from the pre-verify CLI.
        required=False,
        default=None,
        choices=("scan", "verify"),
        help=(
            "Required. 'scan' runs the existing scanner against a repo URL. "
            "'verify' runs the fix-verify agent against one or more issue URLs."
        ),
    )
    # In scan mode this is the repo URL (exactly one). In verify mode this
    # is one or more issue URLs. We use nargs="+" and validate the count
    # in main() once we know which mode is in effect.
    parser.add_argument(
        "targets",
        nargs="+",
        help=(
            "Positional argument(s). In --mode=scan: exactly one git repo URL. "
            "In --mode=verify: one or more full GitHub issue URLs."
        ),
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Path to TOML config (default: $VULNHUNT_AGENT_CONFIG or agent/config.toml)",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Override anthropic.model from config (e.g. claude-opus-4-8, claude-sonnet-5)",
    )

    # ---- scan-mode flags -------------------------------------------------

    scan_section = parser.add_argument_group("scan-mode options")
    scan_section.add_argument(
        "--clone-dir",
        default=None,
        help="Override scan.clone_base_dir from config",
    )
    scan_section.add_argument(
        "--re-clone",
        action="store_true",
        help="Delete and re-clone if a clone already exists at the target path",
    )
    scan_section.add_argument(
        "--scan-id",
        default="",
        help="Optional identifier embedded in OTEL resource attributes",
    )

    scan_group = scan_section.add_mutually_exclusive_group()
    scan_group.add_argument(
        "--scan",
        dest="scan",
        action="store_true",
        default=None,
        help="Run the /vulnhunt scan stage (default: enabled).",
    )
    scan_group.add_argument(
        "--no-scan",
        dest="scan",
        action="store_false",
        default=None,
        help="Skip scanning. Requires --issues; downloads the most recent "
        "published report from publish.destination_repo for the target.",
    )

    publish_group = scan_section.add_mutually_exclusive_group()
    publish_group.add_argument(
        "--publish",
        dest="publish",
        action="store_true",
        default=None,
        help="Push results to publish.destination_repo (overrides config)",
    )
    publish_group.add_argument(
        "--no-publish",
        dest="publish",
        action="store_false",
        default=None,
        help="Skip the publish stage (overrides config)",
    )

    issues_group = scan_section.add_mutually_exclusive_group()
    issues_group.add_argument(
        "--issues",
        dest="issues",
        action="store_true",
        default=None,
        help="Post a GitHub issue per confirmed finding (overrides config; "
        "default: enabled).",
    )
    issues_group.add_argument(
        "--no-issues",
        dest="issues",
        action="store_false",
        default=None,
        help="Skip the issue-posting stage (overrides config).",
    )
    scan_section.add_argument(
        "--issues-target-repo",
        default=None,
        help="Override the repo issues are filed against (default: repo_url).",
    )

    notify_clean_group = scan_section.add_mutually_exclusive_group()
    notify_clean_group.add_argument(
        "--notify-clean-scan",
        dest="notify_clean_scan",
        action="store_true",
        default=None,
        help="Post an informational closed issue when a scan finds "
        "nothing (overrides config; default: enabled).",
    )
    notify_clean_group.add_argument(
        "--no-notify-clean-scan",
        dest="notify_clean_scan",
        action="store_false",
        default=None,
        help="Suppress the clean-scan receipt issue (overrides config).",
    )

    readonly_group = scan_section.add_mutually_exclusive_group()
    readonly_group.add_argument(
        "--read-only",
        dest="read_only",
        action="store_true",
        default=None,
        help="Append a read-only suffix to the /vulnhunt prompt: skip "
        "dependency installation and code execution. This is the default.",
    )
    readonly_group.add_argument(
        "--no-read-only",
        dest="read_only",
        action="store_false",
        default=None,
        help="Allow the scan to install dependencies and execute code "
        "(needed for exploit-test verification). Must be combined with "
        "--enable-bash; the runner refuses to start otherwise.",
    )
    scan_section.add_argument(
        "--enable-bash",
        dest="enable_bash",
        action="store_true",
        default=False,
        help="Add Bash to the model's tool allow-list for this run. "
        "Required to pair with --no-read-only. Deliberately CLI-only — "
        "the config file has no equivalent knob, so a stray TOML can't "
        "silently re-enable arbitrary code execution. Has no effect on "
        "read-only scans (the model is told not to execute code anyway).",
    )

    # ---- verify-mode flags -----------------------------------------------

    verify_section = parser.add_argument_group("verify-mode options")
    verify_section.add_argument(
        "--commit",
        default=None,
        help="Pin the target repo to a specific commit SHA instead of "
        "default-branch HEAD. Applies to all issues in the run.",
    )
    verify_section.add_argument(
        "--scratch-dir",
        default=None,
        help="Override verify.scratch_base_dir from config.",
    )
    verify_section.add_argument(
        "--no-post",
        action="store_true",
        help="Dry-run mode: run verify but don't post comments or reopen issues.",
    )
    verify_section.add_argument(
        "--no-reopen",
        action="store_true",
        help="Post comments but don't reopen issues on non-FIXED verdicts.",
    )

    # ---- shared logging --------------------------------------------------

    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase output verbosity. Default mirrors interactive Claude "
        "Code: assistant prose, brief tool calls, terse result summaries, "
        "task starts/completions. -v adds full tool inputs, truncated tool "
        "outputs, task progress, message-stream headers, and forces "
        "[logging].per_turn_usage and [logging].retries on. -vv also adds "
        "thinking blocks and full system-message data dumps.",
    )
    parser.add_argument(
        "--log-level",
        default=None,
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        help="Override the root logger level. Independent of -v/-vv (which "
        "controls *which* messages are emitted, not the threshold).",
    )

    # ------------------------------------------------------------------ audit
    audit_group = parser.add_argument_group(
        "audit stream",
        "JSONL emission of audit lifecycle events + per-finding "
        "observations for downstream ingest.",
    )
    audit_toggle = audit_group.add_mutually_exclusive_group()
    audit_toggle.add_argument(
        "--audit",
        dest="audit",
        action="store_true",
        default=None,
        help="Enable audit + findings JSONL emission (default: enabled).",
    )
    audit_toggle.add_argument(
        "--no-audit",
        dest="audit",
        action="store_false",
        default=None,
        help="Disable audit + findings JSONL emission.",
    )
    audit_group.add_argument(
        "--audit-events-path",
        default=None,
        help="Override the [audit] events_path (audit JSONL file path).",
    )
    audit_group.add_argument(
        "--audit-findings-path",
        default=None,
        help="Override the [audit] findings_path (findings JSONL file path).",
    )
    audit_stdout_group = audit_group.add_mutually_exclusive_group()
    audit_stdout_group.add_argument(
        "--audit-stdout",
        dest="audit_stdout",
        action="store_true",
        default=None,
        help="Also mirror every audit + findings record to stdout as JSONL.",
    )
    audit_stdout_group.add_argument(
        "--no-audit-stdout",
        dest="audit_stdout",
        action="store_false",
        default=None,
        help="Suppress the stdout mirror even when [audit] stdout = true.",
    )
    audit_group.add_argument(
        "--app-id",
        default=None,
        help="Application identifier of the target being scanned "
        "(overrides [audit] app_id). Changes per scan.",
    )
    audit_group.add_argument(
        "--audit-actor",
        default=None,
        help="Worker/agent identity recorded in audit events "
        "(overrides [audit] actor).",
    )

    # ------------------------------------------------------------------ repo properties
    props_group = parser.add_argument_group(
        "repo properties (findings-stream fields)",
        "Stamp operator-defined metadata tags onto emitted findings "
        "records. Each --repo-property NAME=VALUE sets the field NAME to "
        "VALUE, overriding any value resolved from GitHub custom "
        "properties via [repo_properties].github_property_map. Repeatable.",
    )
    props_group.add_argument(
        "--repo-property",
        dest="repo_property",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="Set a findings-stream metadata field (repeatable). NAME is "
        "the emitted field name; VALUE its value. Overrides the "
        "corresponding GitHub custom property when both are present.",
    )
    return parser


def _configure_logging(level: str | None, verbosity: int) -> None:
    if level is None:
        level = "INFO"
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    # Surface Claude Agent SDK debug detail when the user asks for -vv or
    # explicitly sets DEBUG.
    if level == "DEBUG" or verbosity >= 2:
        logging.getLogger("claude_agent_sdk").setLevel(logging.DEBUG)


# Resolve git's absolute path once at module load — kills Bandit B607
# (partial executable path) at the ``_short_sha`` call site. ``None``
# when git is not on PATH; ``_short_sha`` then logs and returns
# "unknown" rather than raising.
_GIT_EXECUTABLE: str | None = shutil.which("git")


def _short_sha(clone_dir: object) -> str:
    """Return ``git rev-parse --short HEAD`` for the cloned source.

    Used in the publish path so the per-source results directory is
    namespaced by the exact commit that was scanned. Falls back to
    "unknown" if anything goes wrong (corrupted clone, git not on PATH);
    we'd rather publish under an "unknown" subdir than fail the upload.
    """
    if _GIT_EXECUTABLE is None:
        logging.warning("git not on PATH; commit hash will be 'unknown'")
        return "unknown"
    try:
        # nosec B603 — argv is static ("rev-parse --short HEAD"); cwd
        # is a Path the caller owns. Absolute git path resolved at module
        # load via shutil.which (kills B607).
        out = subprocess.run(  # nosec B603
            [_GIT_EXECUTABLE, "rev-parse", "--short", "HEAD"],
            cwd=str(clone_dir),
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logging.warning("Could not resolve source commit hash: %s", exc)
        return "unknown"
    if out.returncode != 0:
        logging.warning(
            "git rev-parse failed (exit %d): %s",
            out.returncode,
            out.stderr.strip(),
        )
        return "unknown"
    sha = out.stdout.strip()
    return sha or "unknown"


def _resolve_modes(
    args: argparse.Namespace, config: AgentConfig
) -> tuple[bool, bool, bool]:
    """Resolve the (scan, publish, issues) tristate flags + config defaults.

    Each flag defaults to True if not explicitly set; publish additionally
    falls through to the config value (which is True/False explicit).
    Then we validate the combination — see _validate_modes.
    """
    scan = True if args.scan is None else args.scan
    if args.publish is None:
        publish = config.publish.enabled
    else:
        publish = args.publish
    if args.issues is None:
        issues = config.issues.enabled
    else:
        issues = args.issues
    return scan, publish, issues


def _validate_modes(
    *, scan: bool, publish: bool, issues: bool, config: AgentConfig
) -> None:
    """Reject incoherent toggle combinations before we do any work."""
    if not scan and not publish and not issues:
        raise ValueError(
            "Nothing to do: --no-scan + --no-publish + --no-issues. "
            "Enable at least one stage."
        )
    if scan and not publish and issues:
        raise ValueError(
            "--scan + --no-publish + --issues is incoherent: posted issues "
            "embed a link to the published report, but the report wouldn't "
            "be uploaded. Either flip --publish on, or pass --no-issues."
        )
    if not scan and issues:
        if not config.publish.destination_repo:
            raise ValueError(
                "--no-scan + --issues requires publish.destination_repo to be "
                "set (we need somewhere to download the latest report from)."
            )
    # Token presence is required by stage, not blanket.
    # - issues needs scan_token (post + label + dedup-fetch on target repo)
    # - publish needs reports_token (push to destination_repo)
    # - --no-scan + --issues additionally needs reports_token (download prior report)
    # In broker mode the literals are empty by design; defer the check to
    # the preflight step (TOKEN-CLIENT-005) which talks to GitHub directly.
    if config.github.broker_token_dir:
        return
    if issues and not config.github.scan_token:
        raise ValueError(
            "--issues requires [github] scan_token (used to list, label, and "
            "create issues on the target repo)."
        )
    if publish and not config.github.reports_token:
        raise ValueError(
            "--publish requires [github] reports_token (used to push results "
            "to publish.destination_repo)."
        )
    if not scan and issues and not config.github.reports_token:
        raise ValueError(
            "--no-scan + --issues requires [github] reports_token (used to "
            "download the latest report from publish.destination_repo)."
        )


class PreflightError(RuntimeError):
    """Raised when a configured GitHub token fails its startup auth check."""


def _required_roles(*, scan: bool, publish: bool, issues: bool) -> list[GitHubRole]:
    """Per-stage role requirements (standalone preflight only).

    - issues          → scan (label/list/post on target)
    - publish         → reports (push to destination_repo)
    - --no-scan+issues→ reports (download prior report from destination_repo)
    Clone alone (scan=True, publish=issues=False) does not require a
    token unless the repo is private — we don't know that at startup,
    so we don't preflight it (the clone will fail loudly if denied).
    """
    roles: list[GitHubRole] = []
    if issues:
        roles.append("scan")
    if publish or (not scan and issues):
        if "reports" not in roles:
            roles.append("reports")
    return roles


def _preflight_standalone_tokens(
    *,
    config: AgentConfig,
    scan: bool,
    publish: bool,
    issues: bool,
    timeout_seconds: int = 30,
) -> None:
    """Hit ``GET /installation/repositories`` once per needed role.

    Acceptable responses (the auth layer accepted the token):

    - ``200`` — installation access token; endpoint applied.
    - ``404`` — some PATs return this on the App-only endpoint; the
      auth layer was already exercised on the way to the 404.
    - ``403`` with body ``"You must authenticate with an installation
      access token..."`` — this is what GitHub actually returns for
      classic and fine-grained PATs on this endpoint. GitHub *did*
      accept the credentials (otherwise the reply would be a
      bad-credentials 401 or a generic 403 with a different message);
      it only rejects the *endpoint* choice for the token type.

    A network error is treated as preflight failure so a
    misconfigured proxy doesn't silently progress into a half-broken
    scan.

    Any other 401/403 (bad token, SSO not authorized, revoked,
    expired) still raises — with GitHub's actual response body plus
    diagnostic headers so operators can distinguish scope vs. SSO
    vs. token-mismatch at a glance.
    """
    roles = _required_roles(scan=scan, publish=publish, issues=issues)
    if not roles:
        return
    api = api_base(config.github.host)
    verify = resolve_verify(config.tls)
    logger = logging.getLogger(__name__)
    for role in roles:
        token = get_github_token(role, config)
        if not token:
            # _validate_modes already gates the obvious missing-token
            # combinations, but a future caller could call _amain
            # directly with an inconsistent config. Belt-and-suspenders.
            raise PreflightError(
                f"[github] {role}_token is empty but role '{role}' is required "
                f"by the enabled stages."
            )
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        try:
            with httpx.Client(verify=verify, timeout=timeout_seconds) as client:
                resp = client.get(f"{api}/installation/repositories", headers=headers)
        except httpx.HTTPError as exc:
            raise PreflightError(
                f"preflight check for '{role}' token failed to reach "
                f"{api}: {exc!s}"
            ) from exc
        if resp.status_code in (401, 403) and not _is_pat_on_app_endpoint(resp):
            raise PreflightError(_format_preflight_failure(role, api, token, resp))
        logger.info(
            "preflight ok: role=%s host=%s status=%d",
            role,
            config.github.host,
            resp.status_code,
        )


# GitHub's error message when a PAT (classic or fine-grained) hits an
# App-only endpoint like /installation/repositories. Auth *succeeded*
# — GitHub only refuses the endpoint. Distinguishing this from real
# auth failures (bad credentials, expired, SSO-unauthorized) is what
# lets the preflight smoke-test work for both installation tokens
# and PATs against the same endpoint.
_PAT_ON_APP_ENDPOINT_MARKER = "authenticate with an installation access token"


def _is_pat_on_app_endpoint(resp: httpx.Response) -> bool:
    """Return True when GitHub's 403/401 is the App-endpoint-vs-PAT mismatch,
    not a real auth failure. The specific body signals the difference."""
    body = (resp.text or "").lower()
    return _PAT_ON_APP_ENDPOINT_MARKER in body


# Diagnostic headers GitHub returns on auth failures. Included in the
# PreflightError message when present.
_PREFLIGHT_DIAGNOSTIC_HEADERS = (
    "X-GitHub-Request-Id",
    "X-OAuth-Scopes",
    "X-Accepted-OAuth-Scopes",
    "X-GitHub-SSO",
    "WWW-Authenticate",
)


def _format_preflight_failure(
    role: str, api: str, token: str, resp: httpx.Response
) -> str:
    """Assemble a diagnostic error message from GitHub's actual response.

    Includes the response body (truncated), key diagnostic headers,
    and a token fingerprint so the operator can compare the token
    actually used by the container against what's in their host
    config. Never logs the token itself.
    """
    fingerprint = _token_fingerprint(token)
    body_preview = (resp.text or "").strip()[:500]
    header_lines: list[str] = []
    for name in _PREFLIGHT_DIAGNOSTIC_HEADERS:
        value = resp.headers.get(name)
        if value:
            header_lines.append(f"    {name}: {value}")
    header_block = "\n".join(header_lines) if header_lines else "    (none)"
    return (
        f"[github] {role}_token failed preflight against "
        f"{api}/installation/repositories (status {resp.status_code}).\n"
        f"  Token fingerprint: {fingerprint}  (compare against the token "
        f"you tested with curl — a mismatch means the container is picking "
        f"up a different token than you expect)\n"
        f"  GitHub response body: {body_preview!r}\n"
        f"  Diagnostic headers:\n{header_block}\n"
        f"  Common causes: SSO not authorized on the token; missing "
        f"'repo' scope; token expired; container reading a stale env "
        f"var or an out-of-date config.toml."
    )


def _token_fingerprint(token: str) -> str:
    """Short prefix/suffix marker so a token can be visually compared
    against a copy without printing the token itself.

    Format: ``ghp_...abcd (len=40)``. Empty/short tokens degrade to
    length-only.
    """
    if not token:
        return "<empty>"
    if len(token) <= 8:
        return f"<{len(token)} chars>"
    return f"{token[:4]}...{token[-4:]} (len={len(token)})"


def _apply_audit_overrides(config: AgentConfig, args: argparse.Namespace) -> AgentConfig:
    """Layer CLI flags on top of the loaded [audit] config (CLI > env > TOML)."""
    a = config.audit
    updates: dict = {}
    if args.audit is not None:
        updates["enabled"] = args.audit
    if args.audit_events_path is not None:
        updates["events_path"] = args.audit_events_path
    if args.audit_findings_path is not None:
        updates["findings_path"] = args.audit_findings_path
    if args.audit_stdout is not None:
        updates["stdout"] = args.audit_stdout
    if args.app_id is not None:
        updates["app_id"] = args.app_id
    if args.audit_actor is not None:
        updates["actor"] = args.audit_actor
    if not updates:
        return config
    return dataclasses.replace(config, audit=dataclasses.replace(a, **updates))


def _apply_issues_overrides(config: AgentConfig, args: argparse.Namespace) -> AgentConfig:
    """Layer CLI flags on top of the loaded [issues] config (CLI > env > TOML).

    Only handles flags that override IssuesConfig values consumed by the
    issues stage. The ``--issues / --no-issues`` toggle is handled
    separately in ``_resolve_modes`` because it gates stage execution
    rather than mutating IssuesConfig.
    """
    notify = getattr(args, "notify_clean_scan", None)
    if notify is None:
        return config
    return dataclasses.replace(
        config,
        issues=dataclasses.replace(config.issues, notify_clean_scan=notify),
    )


def _cli_repo_properties(args: argparse.Namespace) -> repo_props.RepoProperties:
    """Parse the repeatable ``--repo-property NAME=VALUE`` overrides.

    Raises ``ValueError`` (surfaced as an exit-64 usage error) on a
    malformed pair. A blank VALUE is allowed and simply carries no
    override for that field.
    """
    values: dict[str, str] = {}
    for raw in getattr(args, "repo_property", None) or []:
        if "=" not in raw:
            raise ValueError(
                f"--repo-property must be NAME=VALUE (got {raw!r})."
            )
        name, _, value = raw.partition("=")
        name = name.strip()
        if not name:
            raise ValueError(
                f"--repo-property NAME must be non-empty (got {raw!r})."
            )
        values[name] = value.strip()
    return repo_props.RepoProperties(values=values)


def _resolve_repo_properties(
    args: argparse.Namespace,
    config: AgentConfig,
    *,
    repo_url_for_github: str,
) -> repo_props.RepoProperties:
    """Compute the final RepoProperties for this run.

    CLI overrides always win. When the config declares a GitHub
    property map and some mapped field isn't CLI-provided, the missing
    fields fall back to GitHub custom properties (a best-effort fetch —
    failures downgrade to blank). Blank values are dropped from the
    emitted JSON.
    """
    cli = _cli_repo_properties(args)
    property_map = config.repo_properties.github_property_map
    # No map configured, or nowhere to fetch from → CLI values only.
    if not property_map or not repo_url_for_github:
        return repo_props.resolve(cli_overrides=cli, github=None)
    # Skip the GitHub round-trip when the CLI already supplies every
    # mapped field — lets a fully-overridden run work with no network.
    mapped_fields = set(property_map.values())
    if mapped_fields and all(cli.get(f) for f in mapped_fields):
        return cli
    fetched = repo_props.fetch_from_github(repo_url_for_github, config=config)
    return repo_props.resolve(cli_overrides=cli, github=fetched)



async def _amain(args: argparse.Namespace) -> int:
    """Scan-mode entrypoint. Loads config, applies audit + logging
    overrides, and dispatches to ``_run_scan_flow``.

    Verify mode has its own entrypoint (``_amain_verify``) reached
    directly from ``main()``.
    """
    config = load_config(args.config)
    logging.info("Loaded config from %s", config.source_path)
    config = _apply_audit_overrides(config, args)
    config = _apply_issues_overrides(config, args)

    # -v / -vv force the two optional logging slices on without requiring
    # a config edit. They stack with [logging] toggles — config can still
    # enable them independently when no -v is passed.
    if args.verbose >= 1:
        config = dataclasses.replace(
            config,
            logging=dataclasses.replace(
                config.logging,
                per_turn_usage=True,
                retries=True,
            ),
        )

    audit_writer = audit_mod.writer_from_config(config.audit)
    try:
        return await _run_scan_flow(args, config, audit_writer)
    finally:
        if audit_writer is not None:
            audit_writer.close()


async def _run_scan_flow(
    args: argparse.Namespace,
    config: AgentConfig,
    audit_writer: "audit_mod.AuditWriter | None",
) -> int:
    """Original scan → publish → issues workflow, threaded with audit emission."""
    # main() already validates ``len(args.targets) == 1`` for scan mode;
    # unpack the single positional into a local for the rest of the flow.
    repo_url = args.targets[0]

    scan, publish, issues = _resolve_modes(args, config)
    _validate_modes(scan=scan, publish=publish, issues=issues, config=config)
    logging.info("Stages: scan=%s publish=%s issues=%s", scan, publish, issues)

    # Standalone-mode preflight (TOKEN-CLIENT-005). Verifies each token
    # actually needed by the enabled stages can authenticate against
    # GitHub *before* we clone anything. Skipped in broker mode — the
    # broker's successful initial mint already proves the App
    # credentials, and the agent reads on demand thereafter.
    if not config.github.broker_token_dir:
        _preflight_standalone_tokens(
            config=config, scan=scan, publish=publish, issues=issues
        )

    # Preflight the optional operator-defined findings-stream metadata
    # tags. CLI overrides win, then GitHub custom properties (per the
    # configured map), then blank. Doing this here — before the
    # 20-minute /vulnhunt SDK session starts — surfaces a broken
    # GitHub properties endpoint immediately instead of at the end of
    # a completed scan. Skipped entirely when audit is off (nothing
    # will emit these fields anyway) so a --no-audit run doesn't pay
    # the round-trip.
    if audit_writer is not None:
        repo_properties = _resolve_repo_properties(
            args, config, repo_url_for_github=repo_url
        )
        logging.info(
            "Resolved repo properties: %s",
            repo_properties.values or "<none>",
        )
    else:
        repo_properties = repo_props.RepoProperties()

    # Warn if --read-only was set explicitly but the scan stage is off —
    # the flag only affects the scan prompt.
    if not scan and args.read_only is not None:
        logging.warning(
            "--%sread-only is ignored with --no-scan (no scan to constrain).",
            "" if args.read_only else "no-",
        )

    # --enable-bash and --no-read-only are a paired flag: each requires
    # the other. main() ran the parser-level pairing check too — this
    # is a defense-in-depth assertion for programmatic callers that
    # bypass main() (none exist today, but the invariant is small and
    # the failure mode if it ever happened — silently scanning with
    # Bash enabled — is bad enough to justify the belt-and-suspenders).
    effective_read_only = True if args.read_only is None else args.read_only
    if scan and args.enable_bash and effective_read_only:
        raise RuntimeError(
            "Internal invariant violated: enable_bash=True with "
            "read_only=True. main()'s arg-validation should have rejected "
            "this combination before _amain ran."
        )
    if scan and not effective_read_only and not args.enable_bash:
        raise RuntimeError(
            "Internal invariant violated: read_only=False without "
            "enable_bash. main()'s arg-validation should have rejected "
            "this combination before _amain ran."
        )

    # In scan mode there is exactly one target (the repo URL). main()
    # already enforced this; expose a local alias for readability.
    repo_url = args.targets[0]

    exit_code = 0
    download: DownloadedReport | None = None
    scan_totals = SessionTotals()
    extracted = None
    summary: PostSummary | None = None
    results_dir: Path | None = None

    def _persist_manifest(final_exit_code: int) -> None:
        """Serialize the aggregate scan state to ``scan_manifest.json``.

        Called at every exit path where a results directory exists so a
        downstream scan-worker can transition its SCAN row instead of
        stalling on ``manifest_absent``.
        Per AGENT-MANIFEST-002, exit code 2 is suppressed inside
        ``write_manifest`` itself. Writer failures are logged (with
        ``MANIFEST_VALIDATION_FAILURE:`` prefix on validation) but never
        mask the caller's original exit code — the wrapper's failure-path
        fallback (SCAN_FAILED with manifest_absent) still works.
        """
        if results_dir is None:
            return
        try:
            write_manifest(
                results_dir=results_dir,
                scan_id=results_dir.name,
                agent_exit_code=final_exit_code,
                totals=scan_totals,
                findings=extracted.findings if extracted is not None else [],
                post_summary=summary if summary is not None else PostSummary(),
            )
        except Exception:  # noqa: BLE001
            logging.exception("Failed to write scan_manifest.json")

    try:
        # ---- Scan stage --------------------------------------------------
        clone_dir: Path | None = None
        if scan:
            clone_base = args.clone_dir or config.scan.clone_base_dir
            clone_dir = shallow_clone(
                repo_url,
                clone_base,
                timeout_seconds=config.scan.clone_timeout_seconds,
                re_clone=args.re_clone,
                github_token=get_github_token("scan", config),
                github_host=config.github.host,
            )
            results_dir = await run_vulnhunt(
                clone_dir,
                config,
                model_override=args.model,
                scan_id=args.scan_id,
                read_only=effective_read_only,
                enable_bash=args.enable_bash,
                audit_writer=audit_writer,
                totals_out=scan_totals,
            )
            print()
            print(f"Clone:    {clone_dir}")
            if results_dir is None:
                print("Results:  (no *_VULNHUNT_RESULTS_* directory found in the clone)")
                return 1
            print(f"Results:  {results_dir}")
        else:
            print()
            print("Clone:    skipped (--no-scan)")
            print("Results:  skipped (will download latest published report)")

        # ---- Publish stage -----------------------------------------------
        # Compute commit SHA once. Publish and the clean-scan receipt both
        # need it; the findings-issues report URL takes it too. Only
        # computable when we scanned locally; the --no-scan / download
        # path leaves it as "unknown".
        commit_sha = _short_sha(clone_dir) if scan and clone_dir is not None else "unknown"
        report_url: str | None = None
        if scan and publish:
            try:
                sha = publish_results(
                    results_dir,
                    config.publish,
                    config,
                    source_repo_url=repo_url,
                    source_commit_hash=commit_sha,
                )
            except PublishError as exc:
                logging.error("Publish stage failed: %s", exc)
                print(f"Publish:  FAILED ({exc})")
                # Publish failed = exit 2 per HLD §9 / SCAN-AGENT-006. Manifest is
                # suppressed on 2 (AGENT-MANIFEST-002): findings aren't extracted
                # until the later issues stage, so a manifest here would be a
                # phantom findings:[] success marker for a run that never published.
                _persist_manifest(2)
                return 2
            print(
                f"Publish:  {config.publish.destination_repo}@{config.publish.branch} ({sha[:8]})"
            )
            if issues:
                report_url = issues_stage.build_report_url_for_local_scan(
                    publish_destination_repo=config.publish.destination_repo,
                    publish_branch=config.publish.branch,
                    source_repo_url=repo_url,
                    source_commit_hash=commit_sha,
                    results_dir=results_dir,  # type: ignore[arg-type]
                )
        elif scan:
            # We're here only because publish is False. Either the user
            # passed --no-publish (args.publish is False) or the config
            # default is False (args.publish is None).
            if args.publish is False:
                source = "--no-publish flag"
            else:
                source = "[publish] enabled = false in config"
            dest = config.publish.destination_repo or "<destination_repo not set>"
            logging.info(
                "Publish: skipped (%s). Flip [publish] enabled = true "
                "(or VULNHUNT_PUBLISH_ENABLED=true, or pass --publish) "
                "to upload results to %s.",
                source,
                dest,
            )
            print(f"Publish:  skipped ({source})")

        # ---- Download-latest stage (when --no-scan + --issues) ----------
        if not scan and issues:
            try:
                download = download_latest_report(
                    repo_url,
                    config=config,
                )
            except RemoteReportError as exc:
                logging.error("Could not download latest report: %s", exc)
                print(f"Download: FAILED ({exc})")
                _persist_manifest(4)
                return 4
            results_dir = download.path
            print(f"Download: {results_dir}")
            report_url = issues_stage.build_report_url_for_remote_report(
                publish_destination_repo=config.publish.destination_repo,
                publish_branch=config.publish.branch,
                rel_path_in_dest=download.rel_path_in_dest,
            )

        # ---- Issues stage ------------------------------------------------
        # Extraction is done up-front (and shared with the audit stream)
        # so we don't pay for it twice when both --audit and --issues are
        # enabled. Skipped when we have nothing to feed it to.
        audit_ctx = _audit_context_for_results(
            results_dir, args, scan, audit_writer
        )
        # ``repo_properties`` was resolved in preflight (see top of
        # _run_scan_flow) so a broken GitHub properties endpoint fails
        # before the scan starts, not after. The same values are used
        # for both the initial findings-open emission below and the
        # issues-stage transition emit.
        if results_dir is not None and (
            (audit_writer is not None and audit_ctx is not None) or issues
        ):
            token_manager = make_token_manager(config, name="issues")
            try:
                extracted = await issues_extract.extract_findings(
                    results_dir, config, token_manager, audit_writer=audit_writer
                )
            except Exception as exc:  # noqa: BLE001
                logging.warning(
                    "Finding extraction failed (audit findings-open events "
                    "will be skipped): %s",
                    exc,
                )
                extracted = None
            if (
                audit_writer is not None
                and audit_ctx is not None
                and extracted is not None
            ):
                events = audit_extract.build_finding_events(
                    extracted,
                    repo_slug=audit_ctx["repo_slug"],
                    app_id=config.audit.app_id,
                    report_id=audit_ctx["report_id"],
                    results_dir=results_dir,
                    opened=True,
                    status="OPEN",
                    repo_properties=repo_properties,
                )
                for ev in events:
                    audit_writer.emit_finding(ev)

        if issues:
            token_manager = make_token_manager(config, name="issues")
            target_repo_url = (
                args.issues_target_repo or config.issues.target_repo or repo_url
            )
            try:
                summary = await issues_stage.post_issues(
                    results_dir=results_dir,
                    report_url=report_url,
                    target_repo_url=target_repo_url,
                    config=config,
                    token_manager=token_manager,
                    audit_writer=audit_writer,
                    audit_report_id=audit_ctx["report_id"] if audit_ctx else "",
                    audit_repo_slug=audit_ctx["repo_slug"] if audit_ctx else "",
                    audit_repo_properties=repo_properties,
                    extracted=extracted,
                    commit_sha=commit_sha if commit_sha != "unknown" else "",
                )
            except Exception as exc:  # noqa: BLE001
                logging.error("Issues stage failed: %s", exc)
                print(f"Issues:   FAILED ({exc})")
                _persist_manifest(4)
                return 4
            issues_stage.print_summary(summary)
            if summary.any_failed and exit_code == 0:
                # Partial issue post = exit 3 per HLD §9 / SCAN-AGENT-011: the
                # scan completed and published, but some GitHub issues failed to
                # post. Distinct from an issues-stage crash (exit 4 above).
                exit_code = 3

        _persist_manifest(exit_code)
        return exit_code
    finally:
        if download is not None:
            download.cleanup()



async def _amain_verify(args: argparse.Namespace) -> int:
    """Verify-mode entrypoint. Loads config + applies CLI overrides, then
    hands off to ``agent.verify.run_verify``.
    """
    from . import verify as verify_module

    config = load_config(args.config)
    logging.info("Loaded config from %s", config.source_path)
    config = _apply_audit_overrides(config, args)

    if args.verbose >= 1:
        config = dataclasses.replace(
            config,
            logging=dataclasses.replace(
                config.logging,
                per_turn_usage=True,
                retries=True,
            ),
        )

    # Apply verify-specific overrides to the config in place — verify.run_verify
    # only consumes ``config.verify.*`` and the CLI is the user's intent here.
    scratch_dir = Path(args.scratch_dir).expanduser().resolve() if args.scratch_dir else None

    audit_writer = audit_mod.writer_from_config(config.audit)
    # Repo-properties resolution: same shape as scan mode. Parse the
    # first issue URL to get the target repo so the GitHub properties
    # fetch has somewhere to look; homogeneity is enforced later inside
    # ``run_verify``, so if the URLs don't all share a repo we'll fail
    # loudly there — but preflight-fetching properties from the first
    # URL's repo is a reasonable default.
    repo_url_for_props = _issue_url_to_repo_url(args.targets[0]) if args.targets else ""
    if audit_writer is not None:
        repo_properties = _resolve_repo_properties(
            args, config, repo_url_for_github=repo_url_for_props
        )
        logging.info(
            "Resolved repo properties: %s",
            repo_properties.values or "<none>",
        )
    else:
        repo_properties = repo_props.RepoProperties()

    try:
        return await verify_module.run_verify(
            config=config,
            issue_urls=list(args.targets),
            commit=args.commit,
            scratch_base_dir=scratch_dir,
            no_post=args.no_post,
            no_reopen=args.no_reopen,
            model_override=args.model,
            audit_writer=audit_writer,
            audit_repo_properties=repo_properties,
        )
    finally:
        if audit_writer is not None:
            audit_writer.close()


def _issue_url_to_repo_url(issue_url: str) -> str:
    """Convert ``https://github.com/o/r/issues/N`` → ``https://github.com/o/r``.

    Used only for the audit-path GitHub properties fetch. Robust to
    trailing slashes / ``/pull/N`` aliases / bare repo URLs (returned
    unchanged). Empty on unparseable input; caller then skips the
    GitHub round-trip.
    """
    if not issue_url:
        return ""
    # Strip anything from /issues/ or /pull/ onward. If neither
    # segment is present, treat the whole URL as already a repo URL.
    for marker in ("/issues/", "/pull/", "/pulls/"):
        idx = issue_url.find(marker)
        if idx > 0:
            return issue_url[:idx].rstrip("/")
    return issue_url.rstrip("/")

def _audit_context_for_results(
    results_dir: Path | None,
    args: argparse.Namespace,
    scan: bool,
    audit_writer: "audit_mod.AuditWriter | None",
) -> dict[str, str] | None:
    """Compute report_id + repo_slug for audit emissions post-scan.

    Returns None when there's no results dir yet (e.g. --no-scan +
    download hasn't happened) or when audit is off. The scan runner
    already emitted its own scan_started/scan_completed with these
    fields; this recomputation supplies them to the *findings* stream
    and the issues-stage transition events.
    """
    if audit_writer is None or results_dir is None:
        return None
    report_id = audit_mod.report_id_from(results_dir)
    # For --no-scan (download path) we don't have a local clone to
    # inspect for repo_slug; derive from the source_repo_url the user
    # supplied on the CLI. When we DO have a clone, use git origin.
    repo_slug = _repo_slug_for_audit(results_dir, args, scan)
    return {"report_id": report_id, "repo_slug": repo_slug}


def _repo_slug_for_audit(
    results_dir: Path, args: argparse.Namespace, scan: bool
) -> str:
    """Best-effort org/repo derivation for audit records post-scan.

    - When we have a live clone (--scan), read origin via git.
    - When we don't (--no-scan + download), parse the CLI-supplied URL.
    """
    if scan:
        # results_dir sits under clone_dir/<results-basename>.
        clone_dir = results_dir.parent
        git_ctx = _git_context(clone_dir)
        return _repo_slug_from_url(git_ctx["repo_url"], clone_dir.name)
    # ``args.targets[0]`` is the source repo URL under --mode=scan.
    source_url = args.targets[0] if getattr(args, "targets", None) else ""
    if source_url:
        # Normalize before slug extraction: user-supplied URLs on the
        # --no-scan path can be SSH-form (``git@host:org/repo``), which
        # ``_repo_slug_from_url`` would otherwise pass through as a
        # single garbage segment. ``_normalize_repo_url`` returns "" for
        # empty input, so we fall back to the results-dir basename in
        # that unlikely case.
        normalized = _normalize_repo_url(source_url) or source_url
        return _repo_slug_from_url(normalized, results_dir.name)
    return f"unknown/{results_dir.name}"



def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # ---- --mode is required (friendlier than argparse's default) ---------
    if args.mode is None:
        parser.error("--mode is required; choose scan or verify")

    # ---- Mode-specific positional + flag validation -----------------------
    if args.mode == "scan":
        if len(args.targets) != 1:
            parser.error(
                f"--mode=scan takes exactly one positional argument "
                f"(the repo URL); got {len(args.targets)}."
            )
        # Reject verify-only flags when used with scan mode. argparse can't
        # express this in argument groups without subparsers, so we
        # check explicitly here.
        if args.commit is not None:
            parser.error("--commit is verify-mode only.")
        if args.scratch_dir is not None:
            parser.error("--scratch-dir is verify-mode only.")
        if args.no_post:
            parser.error("--no-post is verify-mode only.")
        if args.no_reopen:
            parser.error("--no-reopen is verify-mode only.")

        # Validate the --enable-bash / --no-read-only pairing before any
        # subsequent setup (logging, config load, clone) — the policy lives
        # at the CLI surface so a config-file regression can't quietly land
        # us in Bash-enabled mode. Only enforce when scan would actually
        # run; --no-scan paths are passive and don't touch the SDK.
        if args.scan is not False:  # default None or explicit True
            if args.enable_bash and args.read_only is not False:
                parser.error(
                    "--enable-bash requires --no-read-only. Bash is only "
                    "meaningful when the scan is allowed to install "
                    "dependencies and execute code; a read-only scan has "
                    "nothing to run."
                )
            if args.read_only is False and not args.enable_bash:
                parser.error(
                    "--no-read-only requires --enable-bash. Code execution "
                    "is the whole point of a non-read-only scan, and Bash "
                    "is the tool that runs the exploit tests. Pass both "
                    "flags together to opt in."
                )
    else:  # verify
        # Reject scan-only flags when used with verify mode.
        scan_only_flags = []
        if args.clone_dir is not None:
            scan_only_flags.append("--clone-dir")
        if args.re_clone:
            scan_only_flags.append("--re-clone")
        if args.scan_id:
            scan_only_flags.append("--scan-id")
        if args.scan is not None:
            scan_only_flags.append("--scan/--no-scan")
        if args.publish is not None:
            scan_only_flags.append("--publish/--no-publish")
        if args.issues is not None:
            scan_only_flags.append("--issues/--no-issues")
        if args.issues_target_repo is not None:
            scan_only_flags.append("--issues-target-repo")
        if args.read_only is not None:
            scan_only_flags.append("--read-only/--no-read-only")
        if args.enable_bash:
            scan_only_flags.append("--enable-bash")
        if scan_only_flags:
            parser.error(
                "These flags are scan-mode only and cannot be used with "
                "--mode=verify: " + ", ".join(scan_only_flags)
            )

    _configure_logging(args.log_level, args.verbose)
    set_verbosity(args.verbose)
    try:
        if args.mode == "verify":
            return asyncio.run(_amain_verify(args))
        return asyncio.run(_amain(args))
    except KeyboardInterrupt:
        logging.warning("Interrupted by user")
        return 130
    except FileNotFoundError as exc:
        # Usage/config error (missing config file) — pre-scan invocation error,
        # exit 64 (EX_USAGE) per HLD §9. Kept out of the 0-5 scan-outcome space
        # so it isn't mislabeled publish_failed (2) by SCAN-AGENT-006.
        logging.error("%s", exc)
        return 64
    except ValueError as exc:
        # _validate_modes uses ValueError for incoherent flag combinations.
        # Usage error — exit 64 (EX_USAGE) per HLD §9.
        logging.error("%s", exc)
        return 64
    except Exception as exc:  # noqa: BLE001
        logging.exception("Run failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
