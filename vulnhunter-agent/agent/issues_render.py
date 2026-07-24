"""Render a Finding into a GitHub issue title and body.

Title format (no VULN-ID — those are scan-local and unstable across runs):

    Security Finding: CWE-NNN: <Short Title>

Body uses ``templates/issue_body.md`` and stamps three machine-readable
markers in the footer:

    <!-- vulnfix-key: <16-hex> -->
    <!-- vulnhunt-finding-id: VULN-NNN -->
    <!-- vulnhunt-results-dir: <results_dir_name> -->

The first is the cross-scan idempotency key (matches the vulnhunter-fix
convention so future tooling can correlate). The other two let
downstream consumers locate the exact source PoC/test inside the
published report.
"""

from __future__ import annotations

import html
import logging
import re
from dataclasses import dataclass
from pathlib import Path

from ._github import parse_owner_repo
from .issues_extract import ExtractedReport, Finding

logger = logging.getLogger(__name__)


_TEMPLATE_PATH = Path(__file__).parent / "templates" / "issue_body.md"
_CLEAN_SCAN_BODY_TEMPLATE = Path(__file__).parent / "templates" / "clean_scan_body.md"
_CLEAN_SCAN_COMMENT_TEMPLATE = Path(__file__).parent / "templates" / "clean_scan_comment.md"

_CLEAN_SCAN_TITLE = "[VulnHunter] Clean scan — no findings detected"

# Footer note pointing readers at the private publish destination. Access is
# governed by the operator's own permissions process, so the message is
# intentionally generic — it names no specific group or entitlement.
_REPORT_ACCESS_FALLBACK = (
    "The full report lives in a private repository. If the link 404s "
    "for you, request access from your security team."
)


def _report_access_message() -> str:
    return _REPORT_ACCESS_FALLBACK

# GitHub's heading-anchor algorithm (jch/html-pipeline TableOfContentsFilter):
#   1. Lowercase
#   2. Strip every char that is not [\w\s-]
#   3. Replace spaces with hyphens
# Matches what GitHub auto-renders for a markdown heading.
_PUNCTUATION_RE = re.compile(r"[^\w\s-]", re.UNICODE)


def _github_anchor(heading_text: str) -> str:
    """Return the fragment GitHub generates for an H2 heading."""
    s = heading_text.lower()
    s = _PUNCTUATION_RE.sub("", s)
    s = s.replace(" ", "-")
    return s


def _build_report_url(
    *,
    publish_destination_repo: str,
    publish_branch: str,
    source_repo_url: str,
    source_commit_hash: str,
    timestamp: str,
    results_dir_name: str,
) -> str:
    """Construct a blob URL pointing at README.md inside the publish destination.

    Goes straight to the rendered README (per design); reader navigates
    to siblings (poc/, exploit_tests/) by clicking up one level.
    """
    dest = publish_destination_repo.rstrip("/")
    if dest.endswith(".git"):
        dest = dest[: -len(".git")]
    src_owner, src_name = parse_owner_repo(source_repo_url)
    return (
        f"{dest}/blob/{publish_branch}/{src_owner}/{src_name}/"
        f"{timestamp}/{source_commit_hash}/{results_dir_name}/README.md"
    )


def render_title(f: Finding) -> str:
    cwe = f.cwe or "Unknown CWE"
    title = f.title or "(untitled)"
    return f"Security Finding: {cwe}: {title}"


# Markdown metacharacters that let attacker text form links/images or inline
# code. Backslash-escaping them makes the payload render as literal text. HTML
# escaping (below) handles raw tags (<img>, <a>, <!-- -->).
_MD_ESCAPE_CHARS = ("\\", "`", "[", "]")


# Machine-readable footer markers (``<!-- vulnhunt-finding-id: ... -->`` etc.)
# are intentionally NOT html.escaped so the marker regexes stay exact. But the
# values (``f.id``, ``report.results_dir_name``) are attacker-influenced
# LLM/scan-README data, so a value containing ``-->`` would close the comment
# and inject arbitrary markdown/HTML (CWE-79 / CWE-116). Restrict marker values
# to a strict identifier charset — the same class the downstream parsers accept
# (``VULN-\d{3}`` / ``[A-Za-z0-9._-]+_VULNHUNT_RESULTS_...``) — dropping any
# other char. Removing '<' and '>' makes a comment breakout impossible while
# keeping legitimate ids/dir-names intact.
_MARKER_UNSAFE_RE = re.compile(r"[^A-Za-z0-9._-]")


def _sanitize_marker_value(value: str) -> str:
    """Restrict an HTML-comment marker value to a safe identifier charset so it
    cannot break out of the surrounding ``<!-- ... -->`` (CWE-116)."""
    return _MARKER_UNSAFE_RE.sub("", value or "")


def _sanitize_for_issue_body(value: str) -> str:
    """Neutralize attacker-influenced Finding text before it lands in a
    GitHub issue body (CWE-79).

    The Finding fields originate from an attacker-influenceable scan README
    and are posted under the operator's identity. HTML-escape neutralizes raw
    tags (``<img>``, ``<a>``, ``<!-- -->``); backslash-escaping the markdown
    link/code metacharacters neutralizes ``[text](url)`` / ``![img](url)`` /
    inline code. This is used instead of fenced code blocks because several
    fields render inside a markdown table where fences are invalid.
    """
    s = html.escape(value or "", quote=False)
    for ch in _MD_ESCAPE_CHARS:
        s = s.replace(ch, "\\" + ch)
    return s


def render_body(
    f: Finding,
    *,
    report: ExtractedReport,
    report_url: str,
) -> str:
    template = _TEMPLATE_PATH.read_text(encoding="utf-8")
    # Deep-link to the finding's section anchor in the rendered README.
    # The skill writes each finding under an H2 like
    # ``## VULN-NNN: <Title>``; GitHub's auto-anchor turns that into a
    # lowercase, punctuation-stripped, space→hyphen fragment.
    anchor = _github_anchor(f"{f.id}: {f.title}") if f.id else ""
    deep_link = f"{report_url}#{anchor}" if anchor else report_url
    fields = {
        # Attacker-influenced Finding fields — sanitized (CWE-79).
        "TITLE": _sanitize_for_issue_body(f.title or "(untitled)"),
        "CWE": _sanitize_for_issue_body(f.cwe or "Unknown CWE"),
        "CWE_NAME": _sanitize_for_issue_body(f.cwe_name or "(unspecified)"),
        "SEVERITY": _sanitize_for_issue_body(f.severity or "Unspecified"),
        "LOCATION": _sanitize_for_issue_body(f.location or "(not specified)"),
        "ROOT_CAUSE": _sanitize_for_issue_body(f.root_cause or "(not specified)"),
        "DATA_FLOW": _sanitize_for_issue_body(f.data_flow or "(not specified)"),
        "EXPLOIT_DESCRIPTION": _sanitize_for_issue_body(
            f.exploit_description or "(not specified in report)"
        ),
        "EXPLOIT_IMPACT": _sanitize_for_issue_body(
            f.exploit_impact or "(not specified in report)"
        ),
        "FIX_STRATEGY": _sanitize_for_issue_body(f.fix_strategy or "(see full report)"),
        "SEVERITY_RATIONALE": _sanitize_for_issue_body(
            f.severity_rationale or "(see full report)"
        ),
        # Agent-derived / machine-parseable fields — NOT sanitized so the
        # footer markers stay exact.
        "SCAN_DATE": report.scan_date,
        "REPORT_URL": deep_link,
        "REPORT_ACCESS_MESSAGE": _report_access_message(),
        # Marker values are NOT html.escaped (keeps the marker regexes exact)
        # but ARE restricted to a safe identifier charset so an attacker-
        # influenced value cannot break out of the HTML comment (CWE-116).
        "IDEMPOTENCY_KEY": _sanitize_marker_value(f.vulnfix_key),
        "VULN_ID": _sanitize_marker_value(f.id),
        "RESULTS_DIR_NAME": _sanitize_marker_value(report.results_dir_name),
    }
    body = template
    for key, value in fields.items():
        body = body.replace("{" + key + "}", value)
    leftovers = _find_placeholders(body)
    if leftovers:
        logger.warning(
            "Template placeholders unfilled in rendered body: %s", sorted(leftovers)
        )
    return body


def _find_placeholders(body: str) -> set[str]:
    return set(re.findall(r"\{([A-Z_]+)\}", body))


@dataclass(frozen=True)
class CleanScanContext:
    """Values needed to render a clean-scan issue or comment.

    Every string field is rendered verbatim; empty strings become
    ``"—"`` in the rendered output so a missing value doesn't break
    the markdown table layout. ``report_url`` is the only field that
    conditionally suppresses its whole row when blank.
    """

    scan_id: str
    repo_slug: str
    commit_sha_short: str
    app_id: str
    scan_started_at: str
    scan_completed_at: str
    duration_seconds: int | None
    model_version: str
    skill_version: str
    report_url: str


def render_clean_scan_title() -> str:
    """Return the canonical clean-scan issue title.

    Static — no interpolation. Kept as a function (rather than a bare
    constant) so tests can import a single symbol and the caller code
    reads consistently with ``render_title``.
    """
    return _CLEAN_SCAN_TITLE


def render_clean_scan_body(ctx: CleanScanContext) -> str:
    """Render the full clean-scan issue body.

    Used when creating a new clean-scan issue. See §9.1 of the design.
    """
    return _render_clean_scan(ctx, _CLEAN_SCAN_BODY_TEMPLATE)


def render_clean_scan_comment(ctx: CleanScanContext) -> str:
    """Render an append-comment body posted to an existing open clean-scan issue.

    Compact — the parent issue already establishes context, so the
    comment is a per-scan receipt row. See §9.2 of the design.
    """
    return _render_clean_scan(ctx, _CLEAN_SCAN_COMMENT_TEMPLATE)


def _render_clean_scan(ctx: CleanScanContext, template_path: Path) -> str:
    template = template_path.read_text(encoding="utf-8")
    duration = (
        f"{ctx.duration_seconds} seconds"
        if isinstance(ctx.duration_seconds, int) and ctx.duration_seconds >= 0
        else "—"
    )
    if ctx.report_url:
        # Percent-encode the two characters that break a markdown link
        # in the URL slot. Well-formed GitHub URLs never contain
        # unescaped ) or (, but a misconfigured publish template could
        # in principle produce one and quietly break the link.
        safe_url = ctx.report_url.replace(")", "%29").replace("(", "%28")
        report_line = f"Full scan report: [{ctx.repo_slug or 'report'}]({safe_url})"
    else:
        report_line = ""
    fields = {
        "SCAN_ID": ctx.scan_id or "—",
        "REPO_SLUG": ctx.repo_slug or "—",
        "COMMIT_SHA": ctx.commit_sha_short or "—",
        "APP_ID": ctx.app_id or "—",
        "SCAN_STARTED_AT": ctx.scan_started_at or "—",
        "SCAN_COMPLETED_AT": ctx.scan_completed_at or "—",
        "DURATION": duration,
        "MODEL_VERSION": ctx.model_version or "—",
        "SKILL_VERSION": ctx.skill_version or "unknown",
        "REPORT_URL_LINE": report_line,
    }
    body = template
    for key, value in fields.items():
        body = body.replace("{" + key + "}", value)
    leftovers = _find_placeholders(body)
    if leftovers:
        logger.warning(
            "Clean-scan template placeholders unfilled: %s", sorted(leftovers)
        )
    return body
