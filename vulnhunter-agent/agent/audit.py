"""JSONL audit + findings-event emission.

Two streams — audit lifecycle events and per-finding observations —
appended to local JSONL files for downstream ingest. The invoking
harness ships the files onward; this module only writes locally.

The two streams follow caller-supplied schemas — an audit stream and a
findings stream. Point your own ingest pipeline at the emitted JSONL;
the field names below are the ones this module writes.

Public surface:

- ``AuditWriter``          — file-appender + optional stdout mirror
- ``ULIDGenerator``        — 26-char Crockford base32 monotonic ULID
- ``event_time_now``       — UTC ISO-8601 timestamp
- ``report_id_from``       — results-dir basename → report_id
- ``build_scan_started`` / ``build_scan_completed``
- ``build_verify_started`` / ``build_verify_decision`` / ``build_verify_completed``
- ``build_finding_opened``
- ``build_model_fallback`` / ``build_model_unavailable``

Free-text values are redacted via ``_url.py::redact`` before write so
embedded basic-auth tokens can't leak into the audit stream.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, IO

from ._url import redact as _redact

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ULID
# ---------------------------------------------------------------------------

# Crockford base32 alphabet (excludes I, L, O, U).
_CROCK32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


class ULIDGenerator:
    """Monotonic 26-char Crockford base32 ULID.

    26 chars = 48-bit timestamp (millis since epoch) + 80-bit randomness.
    Monotonic within the same millisecond by incrementing the random
    tail — so events emitted rapid-fire from the same process still
    sort deterministically.

    Not thread-safe (the agent runs on a single asyncio loop and audit
    emissions come from the top-level coroutine). Wrap in a lock if a
    future path multi-plexes.
    """

    def __init__(self) -> None:
        self._last_ms: int = 0
        self._last_rand: int = 0

    def new(self) -> str:
        now_ms = int(time.time() * 1000)
        if now_ms <= self._last_ms:
            # Same-ms or backwards clock → bump the random tail so the
            # ULID sorts after the previous one. 80 bits gives us plenty
            # of headroom for burst emission.
            now_ms = self._last_ms
            rand = (self._last_rand + 1) & ((1 << 80) - 1)
        else:
            rand = int.from_bytes(secrets.token_bytes(10), "big")
        self._last_ms = now_ms
        self._last_rand = rand
        return _encode_ms(now_ms) + _encode_rand(rand)


def _encode_ms(ms: int) -> str:
    """Encode a 48-bit timestamp as 10 Crockford base32 chars."""
    out = ["0"] * 10
    for i in range(9, -1, -1):
        out[i] = _CROCK32[ms & 0x1F]
        ms >>= 5
    return "".join(out)


def _encode_rand(rand: int) -> str:
    """Encode an 80-bit random value as 16 Crockford base32 chars."""
    out = ["0"] * 16
    for i in range(15, -1, -1):
        out[i] = _CROCK32[rand & 0x1F]
        rand >>= 5
    return "".join(out)


# Module-level generator so all builders share one monotonic sequence.
_ULID = ULIDGenerator()


def new_ulid() -> str:
    return _ULID.new()


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def event_time_now() -> str:
    """Return an ISO-8601 UTC timestamp with millisecond precision + Z.

    Millisecond precision matters because the post-scan findings-event
    fan-out emits many records in one second; seconds precision would
    collapse them all to the same ``event_time`` and force downstream
    consumers to rely solely on the ULID for order.
    """
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def report_id_from(results_dir: Path) -> str:
    """report_id = basename of the *_VULNHUNT_RESULTS_* directory.

    Matches ``verify_disposition.schema.json``'s ``scan_id`` field and
    keeps the audit stream cross-referenced to the on-disk artifact.
    """
    return results_dir.name


def finding_id_for(report_id: str, vuln_id: str) -> str:
    """``<report_id>:<VULN-NNN>`` — matches raw-findings schema ``id``.

    Coerces a missing/malformed ``vuln_id`` to ``"unknown"`` so a hostile
    or LLM-malformed source can't emit a trailing-colon id like
    ``report:`` that would fail downstream schema validation. Valid
    unpadded forms (``VULN-1``) are normalized to zero-padded 3-digit
    form (``VULN-001``) — the verify_disposition schema uses
    ``VULN-\\d{3}`` strictly, so downstream materialized views keyed on
    ``id`` need the padded form for reliable joins.
    """
    if not _VULN_ID_RE.match(vuln_id or ""):
        return f"{report_id}:unknown"
    # _VULN_ID_RE guarantees "VULN-\d+" here; extract the digits and
    # re-render zero-padded to at least 3 digits (allowing 4+ digits
    # through unchanged if a scan ever produces that many findings).
    n = int(vuln_id.split("-", 1)[1])
    return f"{report_id}:VULN-{n:03d}"


def event_id(descriptor: str) -> str:
    """New ULID with a human-readable descriptor suffix."""
    return f"{new_ulid()}:{descriptor}"


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditPaths:
    """Resolved absolute paths for both output streams."""

    events: Path
    findings: Path

    @classmethod
    def from_config(cls, events_path: str, findings_path: str) -> "AuditPaths":
        return cls(
            events=Path(events_path).expanduser().resolve(),
            findings=Path(findings_path).expanduser().resolve(),
        )


class AuditWriter:
    """Append JSONL records to the audit + findings streams.

    Behavior:

    - Each record is one line: compact JSON, sorted keys, newline-
      terminated. ``json.dumps`` uses ``default=str`` so ``Path`` /
      ``datetime`` values serialize cleanly if a builder ever leaks one.
    - Every string value walks through ``_redact`` before serialization
      to strip embedded ``https://user:token@`` basic-auth.
    - ``stdout=True`` mirrors the same line to ``sys.stdout``.
    - On IOError: ``strict=True`` raises; otherwise logs at ERROR once
      per stream (subsequent failures on the same stream are silent so
      a jammed disk doesn't spam the log).
    - ``close()`` flushes and closes both handles.
    """

    def __init__(
        self,
        *,
        paths: AuditPaths,
        stdout: bool = False,
        strict: bool = False,
    ) -> None:
        self._paths = paths
        self._stdout = stdout
        self._strict = strict
        self._events_fh: IO[str] | None = None
        self._findings_fh: IO[str] | None = None
        self._events_failed = False
        self._findings_failed = False
        # Once closed, refuse to reopen — an emit after close() is a
        # caller bug, not something to silently paper over by opening a
        # fresh handle that no finally block will close.
        self._closed = False

    def emit_audit(self, record: dict[str, Any]) -> None:
        self._emit("events", record)

    def emit_finding(self, record: dict[str, Any]) -> None:
        self._emit("findings", record)

    def close(self) -> None:
        if self._closed:
            return
        for name, fh in (("events", self._events_fh), ("findings", self._findings_fh)):
            if fh is None:
                continue
            try:
                fh.flush()
                fh.close()
            except OSError as exc:
                logger.warning("audit close(%s) failed: %s", name, exc)
        self._events_fh = None
        self._findings_fh = None
        self._closed = True

    # ------------------------------------------------------------------ private

    def _emit(self, stream: str, record: dict[str, Any]) -> None:
        if self._closed:
            # Never re-open post-close; silently ignoring would hide the
            # caller bug, and raising in strict mode is right anyway.
            msg = "emit called after close()"
            if self._strict:
                raise AuditWriteError(f"audit {stream}: {msg}")
            logger.warning("audit %s: %s (silenced)", stream, msg)
            return
        try:
            line = _serialize(record)
        except (TypeError, ValueError) as exc:
            self._handle_error(stream, f"serialize failed: {exc}")
            return

        if self._stdout:
            try:
                sys.stdout.write(line)
                sys.stdout.flush()
            except OSError as exc:
                # stdout mirror is best-effort; never escalate.
                logger.warning("audit stdout mirror failed: %s", exc)

        try:
            fh = self._get_handle(stream)
        except OSError as exc:
            self._handle_error(stream, f"open failed: {exc}")
            return

        try:
            fh.write(line)
            fh.flush()
        except OSError as exc:
            self._handle_error(stream, f"write failed: {exc}")
            return
        # Durability best-effort. The write above already succeeded and
        # the line is in the kernel's page cache; fsync just forces
        # it to stable storage. A fsync failure means "the line MAY
        # not survive a power loss" — not "the line isn't there". So:
        # log at WARN once per stream (independent of the write-error
        # silenced flag) and do NOT mark the stream as failed. In
        # strict mode we still raise so operators who opted into
        # strict durability get their signal.
        try:
            os.fsync(fh.fileno())
        except OSError as exc:
            if self._strict:
                raise AuditWriteError(
                    f"audit {stream}: fsync failed: {exc}"
                ) from exc
            fsync_flag = f"_{stream}_fsync_warned"
            if not getattr(self, fsync_flag, False):
                logger.warning(
                    "audit %s: fsync failed: %s (subsequent fsync errors "
                    "on this stream silenced; writes continue)",
                    stream,
                    exc,
                )
                setattr(self, fsync_flag, True)

    def _get_handle(self, stream: str) -> IO[str]:
        if stream == "events":
            if self._events_fh is None:
                self._events_fh = _open_append(self._paths.events)
            return self._events_fh
        if stream == "findings":
            if self._findings_fh is None:
                self._findings_fh = _open_append(self._paths.findings)
            return self._findings_fh
        raise ValueError(f"unknown audit stream: {stream}")

    def _handle_error(self, stream: str, msg: str) -> None:
        if self._strict:
            raise AuditWriteError(f"audit {stream}: {msg}")
        failed_attr = f"_{stream}_failed"
        already = getattr(self, failed_attr, False)
        setattr(self, failed_attr, True)
        if not already:
            logger.error("audit %s: %s (further errors on this stream silenced)", stream, msg)


class AuditWriteError(RuntimeError):
    """Raised by AuditWriter when strict=True and a write fails."""


def _open_append(path: Path) -> IO[str]:
    # CWE-732: create the audit artifact owner-only (0o600) regardless of the
    # process umask, rather than the builtin open()'s umask-dependent 0o666
    # (0o644 under umask 022). os.open with an explicit mode + O_CREAT sets the
    # creation mode; chmod also tightens an already-existing file. The parent
    # dir is tightened to 0o700 for the same reason.
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        # Best-effort: a pre-existing dir we don't own shouldn't abort auditing.
        logger.debug("Could not tighten audit dir perms on %s", path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.chmod(path, 0o600)
    except OSError:
        logger.debug("Could not tighten audit file perms on %s", path)
    # Line-buffered so a crash between records still preserves the
    # previously flushed record. ``newline=""`` disables newline
    # translation on Windows; we always write ``\n`` explicitly.
    return os.fdopen(fd, "a", buffering=1, encoding="utf-8", newline="")


def _serialize(record: dict[str, Any]) -> str:
    """Redact strings, drop None/empty values, emit compact JSON line."""
    cleaned = _clean(record)
    return json.dumps(cleaned, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False) + "\n"


def _clean(value: Any) -> Any:
    """Recursively drop keys with None values and redact strings."""
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if v is None:
                continue
            out[k] = _clean(v)
        return out
    if isinstance(value, (list, tuple)):
        return [_clean(v) for v in value]
    if isinstance(value, str):
        return _redact(value)
    return value


# ---------------------------------------------------------------------------
# Common fields
# ---------------------------------------------------------------------------


def _common_scan_fields(
    *,
    app_id: str,
    actor: str,
    repo_slug: str = "",
    report_id: str = "",
) -> dict[str, Any]:
    """Fields present on every audit event (some optional depending on type)."""
    return {
        "event_time": event_time_now(),
        "repo_slug": repo_slug or None,
        "app_id": app_id,
        "report_id": report_id or None,
        "actor": actor or None,
    }


# ---------------------------------------------------------------------------
# Audit event builders
# ---------------------------------------------------------------------------


def build_scan_started(
    *,
    app_id: str,
    actor: str,
    repo_slug: str,
    report_id: str,
    model_version: str,
    target_sha: str,
    notes: str = "",
) -> dict[str, Any]:
    """Emit at the start of a /vulnhunt scan.

    ``target_sha`` may be ``""`` when the clone has no ``.git`` history
    (e.g. a tarball extract); include the key with empty string in that
    case for schema symmetry with scan_completed.
    """
    common = _common_scan_fields(
        app_id=app_id, actor=actor, repo_slug=repo_slug, report_id=report_id
    )
    return {
        **common,
        "event_id": event_id("scan_started"),
        "event_type": "scan_started",
        "model_version": model_version or None,
        "target_sha": target_sha or None,
        "notes": _truncate_freetext(notes) or None,
    }


def build_model_fallback(
    *,
    app_id: str,
    actor: str,
    from_model: str,
    to_model: str,
    stage: str,
    reason: str,
    report_id: str = "",
) -> dict[str, Any]:
    """Emit when a non-scanner LLM call escalates from a lower to a higher
    model tier because the lower tier failed (transient retries exhausted or
    a permanent model-not-provisioned error). The scanner itself does not
    fall back — this is confined to the issues-stage calls."""
    common = _common_scan_fields(app_id=app_id, actor=actor, report_id=report_id)
    return {
        **common,
        "event_id": event_id("model_fallback"),
        "event_type": "model_fallback",
        "from_model": from_model,
        "to_model": to_model,
        "stage": stage or None,
        "notes": _truncate_freetext(reason) or None,
    }


def build_model_unavailable(
    *,
    app_id: str,
    actor: str,
    from_model: str,
    stage: str,
    reason: str,
    report_id: str = "",
) -> dict[str, Any]:
    """Emit when the final model tier also fails — no model in the chain is
    available. The caller then raises; the run surfaces as exit 4."""
    common = _common_scan_fields(app_id=app_id, actor=actor, report_id=report_id)
    return {
        **common,
        "event_id": event_id("model_unavailable"),
        "event_type": "model_unavailable",
        "from_model": from_model,
        "stage": stage or None,
        "notes": _truncate_freetext(reason) or None,
    }


def build_scan_completed(
    *,
    app_id: str,
    actor: str,
    repo_slug: str,
    report_id: str,
    model_version: str,
    target_sha: str,
    findings_count: int | None,
    scan_cost_usd: float | None,
    scan_duration_seconds: int | None,
    notes: str = "",
) -> dict[str, Any]:
    """Emit at the end of a /vulnhunt scan (success or failure).

    On failure, ``findings_count`` / ``scan_cost_usd`` /
    ``scan_duration_seconds`` may be ``None`` and ``notes`` should
    carry ``"failed: <reason>"``.
    """
    common = _common_scan_fields(
        app_id=app_id, actor=actor, repo_slug=repo_slug, report_id=report_id
    )
    return {
        **common,
        "event_id": event_id("scan_completed"),
        "event_type": "scan_completed",
        "model_version": model_version or None,
        "target_sha": target_sha or None,
        "findings_count": findings_count,
        "scan_cost_usd": scan_cost_usd,
        "scan_duration_seconds": scan_duration_seconds,
        "notes": _truncate_freetext(notes) or None,
    }


def build_verify_started(
    *,
    app_id: str,
    actor: str,
    repo_slug: str,
    report_id: str,
    model_version: str,
    target_sha: str,
    notes: str = "",
) -> dict[str, Any]:
    """Emit at the start of a /vulnhunt-fix-verify run."""
    common = _common_scan_fields(
        app_id=app_id, actor=actor, repo_slug=repo_slug, report_id=report_id
    )
    return {
        **common,
        "event_id": event_id("verify_started"),
        "event_type": "verify_started",
        "model_version": model_version or None,
        "target_sha": target_sha or None,
        "notes": _truncate_freetext(notes) or None,
    }


def build_verify_decision(
    *,
    app_id: str,
    actor: str,
    repo_slug: str,
    report_id: str,
    finding_id: str,
    verdict: str,
    to_status: str,
    from_status: str = "",
    evidence_text: str = "",
    model_version: str = "",
    target_sha: str = "",
    notes: str = "",
) -> dict[str, Any]:
    """Emit per-finding after phase-4 verify disposition is available.

    ``verdict`` is ``PASS`` or ``FAIL`` per the audit schema.
    ``to_status`` is the finding-state-machine value (e.g. ``RESOLVED``
    for PASS, ``REOPENED`` for FAIL).
    """
    common = _common_scan_fields(
        app_id=app_id, actor=actor, repo_slug=repo_slug, report_id=report_id
    )
    return {
        **common,
        "event_id": event_id(f"verify_decision:{_short_vuln(finding_id)}"),
        "event_type": "verify_decision",
        "finding_id": finding_id or None,
        "verdict": verdict or None,
        "from_status": from_status or None,
        "to_status": to_status or None,
        "evidence_text": _truncate_freetext(evidence_text) or None,
        "model_version": model_version or None,
        "target_sha": target_sha or None,
        "notes": _truncate_freetext(notes) or None,
    }


def build_verify_completed(
    *,
    app_id: str,
    actor: str,
    repo_slug: str,
    report_id: str,
    model_version: str,
    target_sha: str,
    findings_count: int | None,
    scan_duration_seconds: int | None,
    scan_cost_usd: float | None = None,
    notes: str = "",
) -> dict[str, Any]:
    """Emit at the end of a /vulnhunt-fix-verify run (success or failure).

    ``findings_count`` is the number of dispositions produced.
    """
    common = _common_scan_fields(
        app_id=app_id, actor=actor, repo_slug=repo_slug, report_id=report_id
    )
    return {
        **common,
        "event_id": event_id("verify_completed"),
        "event_type": "verify_completed",
        "model_version": model_version or None,
        "target_sha": target_sha or None,
        "findings_count": findings_count,
        "scan_cost_usd": scan_cost_usd,
        "scan_duration_seconds": scan_duration_seconds,
        "notes": _truncate_freetext(notes) or None,
    }


def build_finding_opened(
    *,
    app_id: str,
    actor: str,
    repo_slug: str,
    report_id: str,
    finding_id: str,
    github_issue_url: str,
    from_status: str = "",
    to_status: str = "OPEN",
    notes: str = "",
) -> dict[str, Any]:
    """Emit after a GitHub issue is successfully POSTed for a finding."""
    common = _common_scan_fields(
        app_id=app_id, actor=actor, repo_slug=repo_slug, report_id=report_id
    )
    return {
        **common,
        "event_id": event_id(f"finding_opened:{_short_vuln(finding_id)}"),
        "event_type": "finding_opened",
        "finding_id": finding_id or None,
        "from_status": from_status or None,
        "to_status": to_status or None,
        "github_issue_url": github_issue_url or None,
        "notes": _truncate_freetext(notes) or None,
    }


def build_clean_scan_notified(
    *,
    app_id: str,
    actor: str,
    repo_slug: str,
    report_id: str,
    github_issue_url: str,
    model_version: str,
    target_sha: str,
    to_status: str = "CLOSED",
    notes: str = "",
) -> dict[str, Any]:
    """Emit after posting (or appending to) a clean-scan receipt issue.

    ``to_status`` is ``"CLOSED"`` on the happy path (issue POSTed and
    closed successfully), ``"OPEN"`` when the close-back PATCH failed
    and the issue was left visible, and unchanged (``"CLOSED"``) on the
    append-to-existing path — the existing issue's state is not modified
    when we comment on it, so from the audit stream's point of view the
    receipt is still associated with a closed anomaly.

    ``notes`` carries the disambiguator:

    - ``""`` on the happy create+close path
    - ``"append: <url>"`` when a comment was posted on an existing open issue
    - ``"close-back failed: <status>"`` when the PATCH to close failed

    ``findings_count`` is not a schema field on the audit stream — this
    event's semantic is "scan produced zero findings and we told the
    repo about it", so no per-event count is emitted; consumers who
    want the zero can look up the matching ``scan_completed`` row.
    """
    common = _common_scan_fields(
        app_id=app_id, actor=actor, repo_slug=repo_slug, report_id=report_id
    )
    return {
        **common,
        "event_id": event_id("clean_scan_notified"),
        "event_type": "clean_scan_notified",
        "to_status": to_status or None,
        "github_issue_url": github_issue_url or None,
        "model_version": model_version or None,
        "target_sha": target_sha or None,
        "notes": _truncate_freetext(notes) or None,
    }


def _short_vuln(finding_id: str) -> str:
    """Trim ``<report_id>:VULN-NNN`` to the ``VULN-NNN`` tail for event_ids.

    Coerces anything not matching ``VULN-\\d+`` to ``"unknown"`` so a
    hostile disposition JSON can't inject arbitrary content into the
    event_id descriptor (which is otherwise passed through unchanged).
    """
    if not finding_id:
        return "unknown"
    tail = finding_id.rsplit(":", 1)[-1]
    return tail if _VULN_ID_RE.match(tail) else "unknown"


# VULN identifiers as emitted by the scanner: ``VULN-`` (uppercase)
# followed by one or more digits. Matches both zero-padded (``VULN-001``)
# and unpadded (``VULN-1``) forms — the extractor normalizes, but
# disposition files can carry either.
_VULN_ID_RE = re.compile(r"^VULN-\d+$")


# Free-text fields (``notes``, ``evidence_text``) are capped to prevent
# an oversized stringified exception (e.g. an ``httpx.HTTPStatusError``
# echoing a 20 KB response body, or a verbose LLM rationale) from
# blowing past downstream ingest field limits. The design doc calls out
# this concern explicitly. Long values are truncated with a visible
# marker so operators can tell the field was clipped.
_FREETEXT_MAX = 1000


def _truncate_freetext(value: str) -> str:
    if not value or len(value) <= _FREETEXT_MAX:
        return value
    marker = "...<truncated>"
    return value[: _FREETEXT_MAX - len(marker)] + marker


# ---------------------------------------------------------------------------
# Findings-event builder
# ---------------------------------------------------------------------------


def build_finding_event(
    *,
    app_id: str,
    repo_slug: str,
    report_id: str,
    finding_id: str,
    vuln_id: str,
    title: str,
    cwe: str,
    severity: str,
    status: str,
    location: str,
    root_cause: str,
    entry_point: str = "",
    data_flow: str = "",
    exploit_test_cmd: str = "",
    proposed_fix_strategy: str = "",
    proposed_fix_files: str = "",
    proposed_fix_why: str = "",
    poc_file: str = "",
    exploit_test_file: str = "",
    github_issue_url: str = "",
    opened: bool = False,
    repo_properties: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build one findings-event record.

    ``opened=True`` populates ``opened_at``; on later transitions leave
    ``opened=False`` so the upstream materialized view keeps the
    original open timestamp. ``transitioned_at`` is always the event
    time.

    ``repo_properties`` is an optional, operator-defined mapping of
    metadata tags describing the target's operational context (resolved
    per-invocation via ``agent.repo_properties`` — CLI > GitHub custom
    properties > blank). Non-blank entries are merged into the emitted
    record under their configured field names; blank values are dropped.
    """
    now = event_time_now()
    safe_vuln = vuln_id if _VULN_ID_RE.match(vuln_id or "") else _short_vuln(finding_id)
    record: dict[str, Any] = {
        "event_id": event_id(f"finding_state:{safe_vuln}"),
        "event_time": now,
        "repo_slug": repo_slug or None,
        "app_id": app_id,
        "report_id": report_id,
        "opened_at": now if opened else None,
        "transitioned_at": now,
        "github_issue_url": github_issue_url or None,
        "id": finding_id,
        "title": title or "",
        "cwe": cwe or "CWE-UNKNOWN",
        "severity": (severity or "informational").lower(),
        "status": status or None,
        "location": location or "",
        "root_cause": root_cause or "",
        "entry_point": entry_point or None,
        "data_flow": data_flow or None,
        "exploit_test": exploit_test_cmd or None,
        "proposed_fix": {
            "strategy": proposed_fix_strategy or "",
            "files_to_change": proposed_fix_files or "",
            "why": proposed_fix_why or "",
        },
        "files": {
            "poc": poc_file or None,
            "exploit_test": exploit_test_file or None,
        },
    }
    for key, value in (repo_properties or {}).items():
        if value:
            record[key] = value
    return record


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def writer_from_config(audit_config: Any) -> AuditWriter | None:
    """Instantiate an AuditWriter from an ``AuditConfig``.

    Returns ``None`` when audit is disabled. Callers should treat a
    ``None`` writer as "audit is off" and skip emission accordingly —
    passing ``None`` to the wire-in points is the canonical way to opt
    out for tests.
    """
    if not getattr(audit_config, "enabled", False):
        return None
    paths = AuditPaths.from_config(
        audit_config.events_path, audit_config.findings_path
    )
    return AuditWriter(
        paths=paths,
        stdout=bool(getattr(audit_config, "stdout", False)),
        strict=bool(getattr(audit_config, "strict", False)),
    )
