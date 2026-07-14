"""Security test: VULN-013 — audit file must be created 0o600.

CWE-732. _open_append used builtin open() with no explicit mode, so the audit
JSONL inherited the process umask (0o644 under umask 022). It must be created
owner-only regardless of umask, and its parent dir owner-only.
"""

import os
import stat

from agent.audit import _open_append


def test_audit_file_is_owner_only(tmp_path):
    os.umask(0o022)  # the umask that would otherwise leak 0o644
    path = tmp_path / "sub" / "audit_events.jsonl"
    fh = _open_append(path)
    try:
        fh.write("{}\n")
    finally:
        fh.close()
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode & 0o077 == 0, f"audit file is group/world-accessible: {oct(mode)}"


def test_audit_parent_dir_is_owner_only(tmp_path):
    os.umask(0o022)
    path = tmp_path / "nested" / "audit_events.jsonl"
    fh = _open_append(path)
    fh.close()
    parent_mode = stat.S_IMODE(os.stat(path.parent).st_mode)
    assert parent_mode & 0o077 == 0, f"audit dir is group/world-accessible: {oct(parent_mode)}"


def test_append_semantics_preserved(tmp_path):
    path = tmp_path / "audit.jsonl"
    for line in ("a\n", "b\n"):
        fh = _open_append(path)
        fh.write(line)
        fh.close()
    assert path.read_text() == "a\nb\n"
