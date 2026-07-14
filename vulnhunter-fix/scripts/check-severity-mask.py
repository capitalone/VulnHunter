#!/usr/bin/env python3
"""Gate 1 — severity mask (REQ-GAT-002).

Regex-scans an artifact body for uses of `critical` outside the
five-phrase safe-list. Exits 0 on clean, non-zero on any match with a
diagnostic naming the offending line.

Usage:
    check-severity-mask.py <path> [<path> ...]
"""

from __future__ import annotations

import re
import sys
import unicodedata
from pathlib import Path


# Obfuscations that would slip a masked severity past the regex (12-seg
# review S5): zero-width joiners/spaces, and common Cyrillic/Greek homoglyphs
# of the Latin letters in "critical".
_ZERO_WIDTH = dict.fromkeys([0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF], None)
_CONFUSABLES = {
    0x0441: "c", 0x0421: "C",   # Cyrillic es
    0x0456: "i", 0x0406: "I",   # Cyrillic byelorussian-ukrainian i
    0x0430: "a", 0x0410: "A",   # Cyrillic a
    0x0435: "e", 0x0415: "E",   # Cyrillic ie
    0x043E: "o", 0x041E: "O",   # Cyrillic o
    0x0440: "p", 0x0420: "P",   # Cyrillic er
    0x0455: "s", 0x0405: "S",   # Cyrillic dze
    0x03B1: "a", 0x03BF: "o", 0x0399: "I", 0x03F2: "c",  # Greek
}


def _normalize(text: str) -> str:
    """Fold obfuscations before matching so a masked severity can't hide behind
    a zero-width char or a homoglyph. Newlines are preserved so line numbers
    stay meaningful. Best-effort: covers ZWSP + common Cyrillic/Greek
    confusables, then NFKC-folds compatibility forms (e.g. fullwidth)."""
    text = text.translate(_ZERO_WIDTH)
    text = text.translate(_CONFUSABLES)
    return unicodedata.normalize("NFKC", text)


SAFE_PHRASE_PATTERNS = (
    "non-critical",
    "criticality",
    "Critical Section",
    "criticism",
    "critique",
)

# Match the `critical` stem plus any word-char suffix so inflections
# ("critically") are caught, not just the bare word. severity-mask-rule.md
# explicitly requires "critically important" to be blocked; the old
# `\bcritical\b` missed it (trailing \b can't sit before "ly"). Safe
# inflections ("criticality", "non-critical", "Critical Section") are still
# suppressed by _matches_safe_phrase containment. "criticism"/"critique"
# never match this stem (they diverge before "critical" completes).
CRITICAL_RE = re.compile(r"\bcritical\w*", re.IGNORECASE)


def _matches_safe_phrase(text: str, start: int, end: int) -> bool:
    """True iff the [start, end) match falls entirely inside a safe-phrase occurrence.

    Previous version used a byte-window check that accepted the match as safe
    whenever a safe phrase appeared anywhere within `len(phrase)` bytes on
    either side. That let "critical" pass whenever an unrelated "criticism"
    sat nearby. This version requires actual containment: the safe phrase's
    own span must cover the match's span.
    """
    text_l = text.lower()
    for phrase in SAFE_PHRASE_PATTERNS:
        phrase_l = phrase.lower()
        idx = 0
        while True:
            p_start = text_l.find(phrase_l, idx)
            if p_start == -1:
                break
            p_end = p_start + len(phrase_l)
            if p_start <= start and end <= p_end:
                return True
            idx = p_start + 1
    return False


def scan(path: Path) -> list[str]:
    if not path.is_file():
        return [f"{path}: not a regular file"]
    text = _normalize(path.read_text(encoding="utf-8", errors="replace"))
    violations: list[str] = []
    for m in CRITICAL_RE.finditer(text):
        if _matches_safe_phrase(text, m.start(), m.end()):
            continue
        line_no = text[:m.start()].count("\n") + 1
        line_start = text.rfind("\n", 0, m.start()) + 1
        line_end = text.find("\n", m.end())
        line_end = line_end if line_end != -1 else len(text)
        line_content = text[line_start:line_end].strip()
        violations.append(f"{path}:{line_no}: severity mask violation: {line_content!r}")
    return violations


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: check-severity-mask.py <path> [<path> ...]", file=sys.stderr)
        return 64
    violations: list[str] = []
    for arg in argv[1:]:
        violations.extend(scan(Path(arg)))
    if violations:
        for v in violations:
            print(v, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
