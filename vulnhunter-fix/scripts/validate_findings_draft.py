"""Validate the shape of findings.draft.json produced by Step 5a.

`prompts/parse_issues.md` Step 5a delegates README → draft findings
to a Sonnet subagent. The subagent writes a JSON file the downstream
Step 5b post-process expects in a specific shape. If the subagent
gets it wrong (omitted fields, hallucinated severity, malformed
structure), the failure should surface here with a directed error
rather than letting Step 5b's `json.load` traceback at the developer.

Validation rules per the Step 5a contract:

- Top level: an object with a `findings` array.
- Each finding has these REQUIRED keys (string values; empty string
  allowed if the model couldn't pull the field from the report):
    id, title, cwe, primary_cwe, severity, status, location,
    root_cause, entry_point, data_flow
- Plus a REQUIRED `proposed_fix` object with these keys:
    strategy, files_to_change, why
- `id` must match `^VULN-\\d{3}$` (canonical zero-padded form).
- `primary_cwe` must match `^CWE-\\d+$` if non-empty.
- `severity` must be one of {Critical, High, Medium, Low} — High+
  normalizes upstream and should not reach here. Unknown is also
  accepted (no severity row in body); any other label is rejected.
- `status` must equal "Confirmed".

Usage:
    validate_findings_draft.py <findings.draft.json>

Exits 0 with a one-line "ok: N findings" on success.
Exits 1 with a directed error message on the FIRST violation.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


REQUIRED_TOP_KEYS = {"findings"}
REQUIRED_FINDING_KEYS = {
    "id", "title", "cwe", "primary_cwe", "severity", "status",
    "location", "root_cause", "entry_point", "data_flow", "proposed_fix",
}
REQUIRED_FIX_KEYS = {"strategy", "files_to_change", "why"}

_VULN_ID_RE = re.compile(r"^VULN-\d{3}$")
_PRIMARY_CWE_RE = re.compile(r"^CWE-\d+$")
ACCEPTED_SEVERITIES = {"Critical", "High", "Medium", "Low", "Unknown"}


class ValidationError(ValueError):
    """Validation failed with a directed message identifying what's wrong."""


def validate_payload(payload: Any) -> int:
    """Validate the loaded JSON payload. Returns the finding count.

    Raises ``ValidationError`` on the first rule violation.
    """
    if not isinstance(payload, dict):
        raise ValidationError(
            f"top-level JSON must be an object, got {type(payload).__name__}"
        )
    missing_top = REQUIRED_TOP_KEYS - set(payload.keys())
    if missing_top:
        raise ValidationError(
            f"top-level object missing required keys: {sorted(missing_top)}"
        )
    findings = payload["findings"]
    if not isinstance(findings, list):
        raise ValidationError(
            f"`findings` must be a list, got {type(findings).__name__}"
        )
    for idx, finding in enumerate(findings):
        try:
            _validate_finding(finding)
        except ValidationError as exc:
            # Re-raise with the index so the user knows which finding broke.
            raise ValidationError(f"findings[{idx}]: {exc}") from None
    return len(findings)


def _validate_finding(f: Any) -> None:
    if not isinstance(f, dict):
        raise ValidationError(f"must be an object, got {type(f).__name__}")
    missing = REQUIRED_FINDING_KEYS - set(f.keys())
    if missing:
        raise ValidationError(f"missing required keys: {sorted(missing)}")
    for key in REQUIRED_FINDING_KEYS - {"proposed_fix"}:
        if not isinstance(f[key], str):
            raise ValidationError(
                f"{key!r} must be a string, got {type(f[key]).__name__}"
            )
    if not _VULN_ID_RE.match(f["id"]):
        raise ValidationError(
            f"id={f['id']!r} must match VULN-NNN (zero-padded 3-digit form)"
        )
    if f["primary_cwe"] and not _PRIMARY_CWE_RE.match(f["primary_cwe"]):
        raise ValidationError(
            f"primary_cwe={f['primary_cwe']!r} must match CWE-NNN if non-empty"
        )
    if f["severity"] not in ACCEPTED_SEVERITIES:
        raise ValidationError(
            f"severity={f['severity']!r} must be one of {sorted(ACCEPTED_SEVERITIES)}"
            " (High+ normalizes to Critical in Step 5a — should not appear here)"
        )
    if f["status"] != "Confirmed":
        raise ValidationError(
            f"status={f['status']!r} must be 'Confirmed' — Step 5a only emits "
            f"confirmed findings"
        )
    fix = f["proposed_fix"]
    if not isinstance(fix, dict):
        raise ValidationError(
            f"proposed_fix must be an object, got {type(fix).__name__}"
        )
    missing_fix = REQUIRED_FIX_KEYS - set(fix.keys())
    if missing_fix:
        raise ValidationError(
            f"proposed_fix missing required keys: {sorted(missing_fix)}"
        )
    for key in REQUIRED_FIX_KEYS:
        if not isinstance(fix[key], str):
            raise ValidationError(
                f"proposed_fix.{key!r} must be a string, got "
                f"{type(fix[key]).__name__}"
            )


def main_with_argv(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    args = parser.parse_args(argv)
    try:
        payload = json.loads(args.path.read_text())
    except FileNotFoundError:
        print(f"error: {args.path} not found", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"error: {args.path} is not valid JSON: {exc}", file=sys.stderr)
        return 1
    try:
        count = validate_payload(payload)
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print(
            "Re-run Step 5a's subagent — its output did not match the "
            "documented shape.",
            file=sys.stderr,
        )
        return 1
    print(f"ok: {count} findings")
    return 0


def main() -> int:
    return main_with_argv(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
