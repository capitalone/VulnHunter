#!/usr/bin/env python3
"""Render the harness-neutral skill sources into per-harness skill bundles.

The skill directories at the repo root (``vulnhunt``, ``vulnhunter-fix``,
``vulnhunt-fix-verify``) are the canonical methodology text and remain the
Claude Code layout. Each adapter lives in ``adapters/<name>/adapter.json``
and declares declarative transforms; this script applies them and writes
``dist/<adapter>/<skill>/``.

The ``claude-code`` adapter is the identity transform: its output must stay
byte-identical to the sources (enforced by tests/test_render_skills.py).
Any non-identity change to a source file is therefore a deliberate prompt
change that all adapters inherit.

Transform types (applied in declared order):
  substitute          Literal find/replace. Fails loudly when ``find`` is
                      absent (unless ``optional``), so upstream edits that
                      break an adapter are caught at render time.
  prepend             Insert text after the YAML frontmatter (or at the very
                      top with ``after_frontmatter: false``).
  frontmatter_append  Insert lines just before the closing ``---``.
  override            Replace (or create) a file wholesale from the adapter
                      directory — used when a harness needs a file format the
                      core does not carry (e.g. an AGENTS.md).
  drop                Delete files from the rendered bundle.

File patterns are matched against the path relative to dist/<adapter>/ and
support ``**`` (any depth), ``*`` (within one segment) and ``?``.

Usage:
  python3 scripts/render_skills.py [--adapter NAME|all] [--out DIR]
  python3 scripts/render_skills.py --adapter NAME --check --baseline DIR

``--check`` compares a fresh render against ``--baseline`` (a previously
rendered tree). ``dist/`` is gitignored and rendered fresh in CI, so
``--check`` has no committed tree to diff against and requires an explicit
baseline; CI verifies byte-identity through ``tests/test_render_skills.py``.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ALL_SKILLS = ("vulnhunt", "vulnhunt-fix-verify", "vulnhunter-fix")
COPY_IGNORE = shutil.ignore_patterns(".installed-from", ".venv", "__pycache__", "*.pyc")


def is_ignored(path: Path) -> bool:
    """True when ``path`` matches a COPY_IGNORE pattern.

    ``shutil.ignore_patterns`` returns a callable expecting
    ``(dir, names_iterable)`` and returning the set of ignored names — it
    must be given an iterable, never a bare str (which it would iterate
    character-by-character, matching nothing). Centralizing the call here
    keeps the correct shape in one place for both the renderer and tests.
    """
    return path.name in COPY_IGNORE(str(path.parent), [path.name])


class TransformError(Exception):
    """A declared transform could not be applied to the current sources."""


def _glob_to_regex(pattern: str) -> re.Pattern:
    parts = pattern.split("/")
    out = []
    for i, part in enumerate(parts):
        if part == "**":
            out.append("(?:[^/]+/)*" if i < len(parts) - 1 else ".*")
        else:
            out.append(fnmatch.translate(part).replace(r"\Z", ""))
    # fnmatch.translate anchors with (?s:...)\Z; rebuild without it.
    return re.compile("(?s:" + "/".join(out) + r")\Z")


@dataclass
class RenderedFile:
    path: str  # relative to dist/<adapter>/
    text: str | None = None  # None → binary, kept as raw bytes
    bytes: bytes = field(default=b"", repr=False)


def load_adapter(adapter_dir: Path) -> dict:
    manifest = adapter_dir / "adapter.json"
    if not manifest.is_file():
        raise TransformError(f"no adapter.json in {adapter_dir}")
    with manifest.open(encoding="utf-8") as fh:
        cfg = json.load(fh)
    for key in ("name", "skills", "transforms"):
        if key not in cfg:
            raise TransformError(f"{manifest}: missing required key '{key}'")
    if cfg["name"] != adapter_dir.name:
        raise TransformError(
            f"{manifest}: adapter name {cfg['name']!r} does not match directory {adapter_dir.name!r}"
        )
    unknown = [s for s in cfg["skills"] if s not in ALL_SKILLS]
    if unknown:
        raise TransformError(f"{manifest}: unknown skills {unknown}")
    return cfg


def _resolve_text(spec: dict, adapter_dir: Path) -> str:
    if "text" in spec:
        return spec["text"]
    if "text_file" in spec:
        return (adapter_dir / spec["text_file"]).read_text(encoding="utf-8")
    raise TransformError(f"transform needs 'text' or 'text_file': {spec}")


def _iter_targets(spec: dict, files: dict[str, RenderedFile]) -> list[str]:
    pattern = spec.get("files")
    if not pattern:
        raise TransformError(f"transform missing 'files': {spec}")
    rx = _glob_to_regex(pattern)
    if any(c in pattern for c in "*?"):
        matches = sorted(p for p in files if rx.match(p))
    else:
        matches = [pattern] if pattern in files else []
    if not matches:
        raise TransformError(f"no rendered files match pattern {pattern!r}")
    return matches


def _frontmatter_split(text: str) -> tuple[str, str] | None:
    """Split '---\n<yaml>\n---\n<rest>' into (frontmatter block incl. both
    fences, remainder). Returns None when the file has no frontmatter."""
    if not text.startswith("---\n"):
        return None
    end = text.find("\n---\n", 3)
    if end == -1:
        return None
    return text[: end + 5], text[end + 5 :]


def _apply_substitute(spec: dict, files: dict[str, RenderedFile], adapter_dir: Path, stats: dict):
    find, replace = spec.get("find"), spec.get("replace", "")
    if not find:
        raise TransformError(f"substitute missing 'find': {spec}")
    expected = spec.get("count")
    optional = spec.get("optional", False)
    hits = 0
    for rel in _iter_targets(spec, files):
        f = files[rel]
        if f.text is None:
            continue
        n = f.text.count(find)
        if n == 0:
            continue
        hits += n
        f.text = f.text.replace(find, replace)
    if hits == 0 and not optional:
        raise TransformError(f"substitute 'find' not present in any target: {find!r}")
    if expected is not None and hits != expected:
        raise TransformError(
            f"substitute expected {expected} occurrence(s), found {hits}: {find!r}"
        )
    stats["substituted"] += hits


def _apply_prepend(spec: dict, files: dict[str, RenderedFile], adapter_dir: Path, stats: dict):
    text = _resolve_text(spec, adapter_dir).rstrip("\n") + "\n\n"
    after_fm = spec.get("after_frontmatter", True)
    for rel in _iter_targets(spec, files):
        f = files[rel]
        if f.text is None:
            continue
        if after_fm:
            fm = _frontmatter_split(f.text)
            if fm:
                f.text = fm[0] + text + fm[1].lstrip("\n")
                stats["prepended"] += 1
                continue
        f.text = text + f.text
        stats["prepended"] += 1


def _apply_frontmatter_append(spec: dict, files: dict[str, RenderedFile], adapter_dir: Path, stats: dict):
    text = _resolve_text(spec, adapter_dir).rstrip("\n")
    for rel in _iter_targets(spec, files):
        f = files[rel]
        if f.text is None:
            continue
        fm = _frontmatter_split(f.text)
        if not fm:
            raise TransformError(f"frontmatter_append: {rel} has no frontmatter")
        block, rest = fm
        if not block.endswith("---\n"):
            raise TransformError(f"frontmatter_append: malformed closing fence in {rel}")
        f.text = block[:-4] + text + "\n---\n" + rest
        stats["frontmatter"] += 1


def _apply_override(spec: dict, files: dict[str, RenderedFile], adapter_dir: Path, stats: dict):
    src = adapter_dir / spec["from"]
    if not src.is_file():
        raise TransformError(f"override source missing: {src}")
    rel = spec["path"]
    try:
        text = src.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        files[rel] = RenderedFile(path=rel, text=None, bytes=src.read_bytes())
    else:
        files[rel] = RenderedFile(path=rel, text=text)
    stats["overridden"] += 1


def _apply_drop(spec: dict, files: dict[str, RenderedFile], stats: dict):
    pattern = spec.get("files")
    rx = _glob_to_regex(pattern)
    doomed = [p for p in files if rx.match(p)]
    for p in doomed:
        del files[p]
    stats["dropped"] += len(doomed)


_APPLICATORS = {
    "substitute": _apply_substitute,
    "prepend": _apply_prepend,
    "frontmatter_append": _apply_frontmatter_append,
    "override": _apply_override,
    "drop": _apply_drop,
}


def render_adapter(adapter_dir: Path, repo_root: Path, out_root: Path) -> dict:
    cfg = load_adapter(adapter_dir)
    files: dict[str, RenderedFile] = {}
    for skill in cfg["skills"]:
        src = repo_root / skill
        if not (src / "SKILL.md").is_file():
            raise TransformError(f"skill source missing SKILL.md: {src}")
        for p in sorted(src.rglob("*")):
            if not p.is_file() or is_ignored(p):
                continue
            rel = f"{skill}/{p.relative_to(src).as_posix()}"
            try:
                files[rel] = RenderedFile(path=rel, text=p.read_text(encoding="utf-8"))
            except UnicodeDecodeError:
                files[rel] = RenderedFile(path=rel, text=None, bytes=p.read_bytes())

    stats = {"substituted": 0, "prepended": 0, "frontmatter": 0, "overridden": 0, "dropped": 0}
    for i, spec in enumerate(cfg["transforms"]):
        kind = spec.get("type")
        applicator = _APPLICATORS.get(kind)
        if applicator is None:
            raise TransformError(f"transform[{i}]: unknown type {kind!r}")
        applicator(spec, files, adapter_dir, stats)

    out_dir = out_root / cfg["name"]
    if out_dir.exists():
        shutil.rmtree(out_dir)
    for rel in sorted(files):
        dest = out_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        f = files[rel]
        if f.text is None:
            dest.write_bytes(f.bytes)
        else:
            dest.write_text(f.text, encoding="utf-8")
    return {"adapter": cfg["name"], "skills": cfg["skills"], "files": len(files), **stats}


def check_render(adapter_dir: Path, repo_root: Path, baseline_root: Path) -> bool:
    """Render into a temp dir and compare with a supplied baseline.

    ``baseline_root`` holds a previously rendered ``<adapter>/`` tree (an
    installed bundle, a pinned reference render, etc.). ``dist/`` is
    gitignored and rendered fresh in CI, so there is no committed tree to
    diff against — the caller must point ``--baseline`` at whatever
    reference it wants to verify (the same fresh render is emitted with
    ``render_skills.py --out <dir>`` first).
    """
    cfg = load_adapter(adapter_dir)
    with tempfile.TemporaryDirectory() as tmp:
        tmp_out = Path(tmp)
        render_adapter(adapter_dir, repo_root, tmp_out)
        baseline = baseline_root / cfg["name"]
        fresh = tmp_out / cfg["name"]
        if not baseline.is_dir():
            print(
                f"{baseline}: baseline not found — render one first "
                f"(render_skills.py --adapter {cfg['name']} --out {baseline_root})",
                file=sys.stderr,
            )
            return False
        baseline_files = {
            p.relative_to(baseline).as_posix()
            for p in baseline.rglob("*")
            if p.is_file()
        }
        fresh_files = {p.relative_to(fresh).as_posix() for p in fresh.rglob("*") if p.is_file()}
        if baseline_files != fresh_files:
            print(
                f"{baseline}: file sets differ "
                f"(missing={sorted(baseline_files - fresh_files)} "
                f"extra={sorted(fresh_files - baseline_files)})",
                file=sys.stderr,
            )
            return False
        for rel in sorted(baseline_files):
            if (baseline / rel).read_bytes() != (fresh / rel).read_bytes():
                print(f"{baseline}/{rel}: content differs from fresh render", file=sys.stderr)
                return False
    return True


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--adapter", default="all", help="adapter name or 'all' (default)")
    ap.add_argument("--source", default=str(REPO_ROOT), help="repo root holding the skill sources")
    ap.add_argument("--out", default=None, help="output root (default <source>/dist)")
    ap.add_argument(
        "--check",
        action="store_true",
        help="verify a fresh render matches --baseline; no files written",
    )
    ap.add_argument(
        "--baseline",
        default=None,
        help="baseline render root to compare against with --check "
        "(holds <adapter>/ subtrees; e.g. a prior --out dir or installed bundle)",
    )
    args = ap.parse_args(argv)

    repo_root = Path(args.source).resolve()
    out_root = Path(args.out).resolve() if args.out else repo_root / "dist"
    adapters_root = repo_root / "adapters"
    if not adapters_root.is_dir():
        print(f"error: {adapters_root} not found", file=sys.stderr)
        return 2
    if args.check and not args.baseline:
        print(
            "error: --check requires --baseline DIR (dist/ is gitignored and "
            "rendered fresh, so there is no committed tree to diff against)",
            file=sys.stderr,
        )
        return 2
    baseline_root = Path(args.baseline).resolve() if args.baseline else None

    names = (
        sorted(p.name for p in adapters_root.iterdir() if (p / "adapter.json").is_file())
        if args.adapter == "all"
        else [args.adapter]
    )
    for name in names:
        adapter_dir = adapters_root / name
        if not adapter_dir.is_dir():
            print(f"error: unknown adapter {name!r}", file=sys.stderr)
            return 2
        if args.check:
            assert baseline_root is not None  # guaranteed by the check above
            ok = check_render(adapter_dir, repo_root, baseline_root)
            print(f"{name}: {'OK' if ok else 'STALE'}")
            if not ok:
                return 1
        else:
            stats = render_adapter(adapter_dir, repo_root, out_root)
            print(
                f"rendered dist/{name}: {stats['files']} files "
                f"(subs={stats['substituted']} prepends={stats['prepended']} "
                f"fm={stats['frontmatter']} overrides={stats['overridden']} drops={stats['dropped']})"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
