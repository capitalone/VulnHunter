#!/usr/bin/env python3
"""Mechanical crypto trust-chain checkers (REQ-CWE-009).

Populates the four booleans in the per-finding triage sidecar's
`crypto_trust_chain` object. Pure functions of the fix diff + repo
state; NEVER invokes an LLM.

    algorithm_approved       — approved algorithm identifier appears in diff
    key_source_approved      — approved key-source pattern present, no denied pattern
    key_rotation_present     — rotation call site or annotation detected
    transport_encrypted      — TLS/mTLS at the transport boundary of the fix

Usage:
    crypto-trust-chain-checkers.py --diff <path> --repo-root <path> [--emit-sidecar <vuln>]

Emits JSON on stdout with the four booleans and evidence pointers.
Exit codes:
    0 — checkers ran (booleans may be false)
    2 — usage / IO error
    3 — reference-YAML load failure
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
ALGO_YAML = REPO_ROOT / "references" / "approved-crypto-algorithms.yaml"
KEY_YAML = REPO_ROOT / "references" / "approved-key-sources.yaml"

CHECKER_VERSION = "1"


@dataclass
class TrustChainResult:
    algorithm_approved: bool = False
    key_source_approved: bool = False
    key_rotation_present: bool = False
    transport_encrypted: bool = False
    checker_version: str = CHECKER_VERSION
    algorithm_evidence: str | None = None
    key_source_evidence: str | None = None
    key_rotation_evidence: str | None = None
    transport_evidence: str | None = None


def _unquote(val: str) -> str:
    """Strip a single matching pair of outer quotes; preserve internal quotes.

    YAML values like `'key = "'` (single-quoted, contains a literal double
    quote) must retain the trailing `"`. Naive `.strip('"').strip("'")`
    strips both ends unconditionally and mangles the value.
    """
    if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
        return val[1:-1]
    return val


def _strip_inline_comment(val: str) -> str:
    """Strip a trailing YAML `  # ...` comment.

    Uses two-space + hash as the delimiter to avoid mis-parsing `#` chars
    that appear inside regex character classes or literal patterns.
    """
    if not val:
        return val
    m = re.search(r"\s{2,}#\s", val)
    if m:
        return val[: m.start()].rstrip()
    return val


def _load_yaml_flat(path: Path) -> dict:
    """Tiny hand-rolled YAML loader for our flat structure (no external dep needed).

    Handles two shapes under a top-level key: a list of `- items`, or a
    nested scalar map (`key: value` lines) as used by the `constants:` block.
    The nested map loads as a dict with int coercion so the crypto parameter
    floors (rsa_min_bits, pbkdf2_min_iterations, …) are actually reachable —
    previously `constants:` parsed to an empty list and was read by nothing,
    letting sub-3072-bit RSA pass as approved (synthesized review S8).
    """
    result: dict = {}
    current_key: str | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if line and not line.startswith((" ", "\t")) and ":" in line:
            key = line.split(":", 1)[0].strip()
            result[key] = []
            current_key = key
            continue
        stripped = line.lstrip()
        if current_key and stripped.startswith("-"):
            raw_val = stripped[1:].strip()
            val = _unquote(_strip_inline_comment(raw_val))
            if val:
                result[current_key].append(val)
        elif current_key and ":" in stripped:
            # Nested scalar under a mapping key (e.g. `constants:`). Flip the
            # accumulator from list → dict on first nested scalar.
            k, _, v = stripped.partition(":")
            v = _unquote(_strip_inline_comment(v.strip()))
            if not isinstance(result[current_key], dict):
                result[current_key] = {}
            result[current_key][k.strip()] = int(v) if v.lstrip("-").isdigit() else v
    return result


def _read_diff(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8", errors="replace")


def _added_lines(diff: str) -> list[str]:
    lines = []
    for l in diff.splitlines():
        if l.startswith("+++"):
            continue
        if l.startswith("+"):
            lines.append(l[1:])
    return lines


def _token_present(term: str, text_lower: str) -> bool:
    """Boundary-aware token match against already-lowercased text.

    Substring matching wrongly flagged `DSA` (denied) inside `ECDSA-P256`
    (approved) — every legitimate ECDSA fix was downgraded to MITIGATION
    (peer review major). `\\b` treats the contiguous `C-D` in `ECDSA` as a
    non-boundary, so `\\bDSA\\b` matches a standalone `DSA` token but not
    the `DSA` inside `ECDSA`.

    BUT wrapping every term in `\\b…\\b` unconditionally broke denied
    patterns that begin/end with punctuation — `.MD5(`,
    `MessageDigest.getInstance("MD5"` — because `\\b` requires a word char
    at the boundary, so those never (or only context-dependently) matched
    and Java MD5/SHA1 idioms passed silently (segment-review S6). Apply
    `\\b` only where the term's own edge is a word char; where the edge is
    punctuation, no boundary is needed (and would be wrong). This keeps the
    DSA-in-ECDSA fix (DSA is word-char-edged → `\\bdsa\\b`) while reviving
    the punctuation patterns.
    """
    t = term.lower()
    left = r"\b" if (t[:1].isalnum() or t[:1] == "_") else ""
    right = r"\b" if (t[-1:].isalnum() or t[-1:] == "_") else ""
    return re.search(left + re.escape(t) + right, text_lower) is not None


def _strip_line_comment(line: str) -> str:
    """Drop a trailing line comment so an approved identifier sitting in a
    comment can't green-light weak code (12-seg review S7a). Matches a `#` or
    `//` preceded by start-of-line or whitespace — so `https://` inside a
    string is left intact. String-literal contents are deliberately kept: a
    string like `"AES/GCM/NoPadding"` is legitimate code evidence.
    """
    m = re.search(r"(?:^|\s)(?:#|//)", line)
    return line[: m.start()] if m else line


# Elliptic-curve identifiers → strength in bits, for enforcing ecc_min_bits
# (12-seg review S7c: the floor was declared but never enforced).
_ECC_CURVE_BITS = {
    "secp192r1": 192, "prime192v1": 192, "p-192": 192, "p192": 192,
    "secp224r1": 224, "p-224": 224, "p224": 224,
    "secp256r1": 256, "prime256v1": 256, "p-256": 256, "p256": 256,
    "secp384r1": 384, "p-384": 384, "p384": 384,
    "secp521r1": 521, "p-521": 521, "p521": 521,
}


def _weak_key_parameter(added_lines: list[str], ref: dict) -> str | None:
    """Return a denial reason if the diff sets a crypto parameter below the
    yaml `constants` floor, else None (REQ-CWE-009).

    Bit sizes / iteration counts / curve strengths are not part of the
    algorithm identifier (a 2048-bit key still reads as `RSA-OAEP-SHA256`), so
    identifier matching alone can't catch them. Comments are already stripped
    by the caller. RSA sizes use diff-level context (RSA mentioned anywhere +
    a known-weak modulus {512,768,1024,2048} on any line — so a size split
    onto a different line than the RSA token is still caught, 12-seg S7d),
    while excluding non-RSA sizes like AES `key_size=256`.
    """
    consts = ref.get("constants")
    if not isinstance(consts, dict):
        return None
    text = "\n".join(added_lines)
    rsa_min = consts.get("rsa_min_bits")
    if isinstance(rsa_min, int) and re.search(r"(?i)\brsa\b", text):
        for m in re.finditer(r"\b(512|768|1024|2048|3072|4096|8192)\b", text):
            bits = int(m.group(1))
            if bits < rsa_min:
                return f"weak RSA key size {bits} < required {rsa_min} bits (REQ-CWE-009)"
    ecc_min = consts.get("ecc_min_bits")
    if isinstance(ecc_min, int):
        low = text.lower()
        for curve, bits in _ECC_CURVE_BITS.items():
            if bits < ecc_min and re.search(rf"(?<![a-z0-9]){re.escape(curve)}(?![a-z0-9])", low):
                return f"weak ECC curve {curve} ({bits}-bit) < required {ecc_min} bits (REQ-CWE-009)"
    pbkdf2_min = consts.get("pbkdf2_min_iterations")
    if isinstance(pbkdf2_min, int):
        for line in added_lines:
            if not re.search(r"(?i)pbkdf2", line):
                continue
            for m in re.finditer(r"(?i)iterations?\s*[=:]\s*(\d+)", line):
                iters = int(m.group(1))
                if iters < pbkdf2_min:
                    return f"weak PBKDF2 iterations {iters} < required {pbkdf2_min} (REQ-CWE-009)"
    return None


def check_algorithm_approved(diff: str, ref: dict) -> tuple[bool, str | None]:
    # Strip line comments first: an approved identifier in a comment must not
    # green-light weak code, and a denied token in a comment must not fail a
    # good fix (12-seg review S7a). Matching is grounded in code + strings.
    added_lines = [_strip_line_comment(l) for l in _added_lines(diff)]
    added = "\n".join(added_lines).lower()
    denied = ref.get("symmetric_denied", []) + ref.get("asymmetric_denied", []) + \
             ref.get("hash_denied", []) + ref.get("kdf_denied", []) + ref.get("mac_denied", [])
    for term in denied:
        if term and _token_present(term, added):
            return False, f"denied algorithm present: {term}"
    # Parameter floors (bits/iterations/curve) — an approved identifier with a
    # sub-minimum key size, iteration count, or curve strength is still a fail.
    weak = _weak_key_parameter(added_lines, ref)
    if weak:
        return False, weak
    approved = ref.get("symmetric", []) + ref.get("asymmetric", []) + \
               ref.get("hash", []) + ref.get("kdf", []) + ref.get("mac", [])
    for term in approved:
        if term and _token_present(term, added):
            return True, f"approved algorithm: {term}"
    return False, "no approved algorithm identifier found in fix diff"


def _annotation_within_window(added_lines: list[str], annotation_term: str) -> bool:
    """True iff an approval-annotation line is within 2 lines above a
    key-source context line (REQ-CWE-009, approved-key-sources.yaml).

    approved-key-sources.yaml documents that a `KEY_SOURCE_APPROVED:` comment
    only counts "within the 2 lines preceding the identified key literal or
    read." The old check accepted the annotation ANYWHERE in the diff, so a
    bare annotation floating far from any key green-lit the whole diff
    (segment-review S6 fail-open). Require a key-ish context line within
    the 2 lines FOLLOWING the annotation (i.e. the annotation sits ≤2 lines
    above the key).
    """
    key_ctx = re.compile(r"(secret|key|token|credential|password|passphrase)", re.IGNORECASE)
    term_l = annotation_term.lower()
    for i, line in enumerate(added_lines):
        if term_l in line.lower():
            for follow in added_lines[i + 1:i + 3]:  # next 2 lines
                if key_ctx.search(follow):
                    return True
    return False


def check_key_source_approved(diff: str, ref: dict) -> tuple[bool, str | None]:
    added_lines = _added_lines(diff)
    added = "\n".join(added_lines).lower()
    denied = ref.get("denied", [])
    for term in denied:
        if term and term.lower() in added:   # case-insensitive: a lowercased bare env var must not bypass the deny
            return False, f"denied key source: {term}"
    # Non-annotation approved categories: plain case-insensitive containment.
    approved_categories = ("chamber", "aws_kms", "vault", "gcp_secret_manager", "azure_kv", "kubernetes")
    for cat in approved_categories:
        for term in ref.get(cat, []):
            if term and term.lower() in added:
                return True, f"approved key source ({cat}): {term}"
    # Annotation category: only counts within the documented 2-line window.
    for term in ref.get("annotation", []):
        if term and _annotation_within_window(added_lines, term):
            return True, f"approved key source (annotation): {term}"
    return False, "no approved key-source pattern found"


ROTATION_PATTERNS = [
    r"\brotate_key\s*\(",
    r"\bKMS\.ScheduleKeyDeletion\b",
    r"\bschedule_key_rotation\b",
    r"\bcron:.*rotate",
    r"KEY_ROTATION_ANNOTATION:",
    r"@rotation_schedule",
]


def check_key_rotation_present(diff: str) -> tuple[bool, str | None]:
    added = "\n".join(_added_lines(diff))
    for pat in ROTATION_PATTERNS:
        m = re.search(pat, added)
        if m:
            return True, f"rotation pattern: {m.group(0)}"
    return False, "no rotation call site detected"


TRANSPORT_APPROVED = [
    r"\bhttps://",
    r"\bgrpcs://",
    r"tls\.Config\{",
    r"SSLContext\(",
    r"ssl_context\s*=",
    r"verify=True",
    r"use_ssl=True",
]

TRANSPORT_DENIED = [
    r"\bhttp://(?!localhost|127\.0\.0\.1)",
    r"\bftp://",
    r"verify=False",
    r"insecure_skip_verify\s*:\s*true",
]


def check_transport_encrypted(diff: str) -> tuple[bool, str | None]:
    added = "\n".join(_added_lines(diff))
    for pat in TRANSPORT_DENIED:
        m = re.search(pat, added)
        if m:
            return False, f"denied transport: {m.group(0)}"
    for pat in TRANSPORT_APPROVED:
        m = re.search(pat, added)
        if m:
            return True, f"approved transport: {m.group(0)}"
    return False, "no transport indicator in fix diff"


def run_checkers(diff: str) -> TrustChainResult:
    try:
        algo_ref = _load_yaml_flat(ALGO_YAML)
        key_ref = _load_yaml_flat(KEY_YAML)
    except OSError as exc:
        raise SystemExit(f"reference YAML load failed: {exc}")

    result = TrustChainResult()
    result.algorithm_approved, result.algorithm_evidence = check_algorithm_approved(diff, algo_ref)
    result.key_source_approved, result.key_source_evidence = check_key_source_approved(diff, key_ref)
    result.key_rotation_present, result.key_rotation_evidence = check_key_rotation_present(diff)
    result.transport_encrypted, result.transport_evidence = check_transport_encrypted(diff)
    return result


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Crypto trust-chain checkers (REQ-CWE-009).")
    ap.add_argument("--diff", required=True, help="Path to unified diff, or '-' for stdin.")
    ap.add_argument("--repo-root", default=".", help="Repo root (currently unused; reserved).")
    ap.add_argument("--emit-sidecar", default=None, help="If set, treated as VULN-NNN id and prints sidecar-compatible fragment.")
    args = ap.parse_args(argv[1:])

    try:
        diff = _read_diff(args.diff)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    result = run_checkers(diff)
    payload = asdict(result)
    if args.emit_sidecar:
        payload = {"vuln_id": args.emit_sidecar, "crypto_trust_chain": payload}
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
