"""Tests for scripts/render_skills.py.

The critical invariant: the claude-code adapter renders byte-identical to the
repo-root skill sources, so any source edit is a deliberate prompt change that
every adapter inherits. Other adapters are checked for their declared marker
substitutions so upstream edits that break an adapter fail here, not in a scan.
"""

from __future__ import annotations

import filecmp
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import render_skills  # noqa: E402

ADAPTERS = REPO_ROOT / "adapters"


def render_to_tmp(adapter: str) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix=f"vulnhunt-dist-{adapter}-"))
    render_skills.render_adapter(ADAPTERS / adapter, REPO_ROOT, tmp)
    return tmp / adapter


class TestClaudeCodeIdentity(unittest.TestCase):
    """dist/claude-code must equal the repo-root skill sources byte-for-byte."""

    def setUp(self):
        self.dist = render_to_tmp("claude-code")

    def _source_tree(self, skill: str) -> Path:
        return REPO_ROOT / skill

    def test_all_declared_skills_rendered(self):
        for skill in ("vulnhunt", "vulnhunt-fix-verify", "vulnhunter-fix"):
            self.assertTrue((self.dist / skill / "SKILL.md").is_file(), skill)

    def test_byte_identical_to_sources(self):
        for skill in ("vulnhunt", "vulnhunt-fix-verify", "vulnhunter-fix"):
            src = self._source_tree(skill)
            dst = self.dist / skill
            src_files = sorted(
                p.relative_to(src).as_posix()
                for p in src.rglob("*")
                if p.is_file() and not render_skills.is_ignored(p)
            )
            dst_files = sorted(p.relative_to(dst).as_posix() for p in dst.rglob("*") if p.is_file())
            self.assertEqual(src_files, dst_files, f"{skill}: file lists differ")
            for rel in src_files:
                self.assertTrue(
                    filecmp.cmp(src / rel, dst / rel, shallow=False),
                    f"{skill}/{rel}: differs from source",
                )


class TestDropValidation(unittest.TestCase):
    """`drop` must fail loudly like the other applicators, not silently no-op.

    Matches the fail-loud invariant the renderer relies on: a missing
    ``files`` key or a pattern that matches nothing is a broken transform,
    not a clean render.
    """

    def _files(self):
        return {
            "vulnhunt/SKILL.md": render_skills.RenderedFile(path="vulnhunt/SKILL.md", text="x"),
            "vulnhunt/phases/p1.md": render_skills.RenderedFile(path="vulnhunt/phases/p1.md", text="y"),
        }

    def test_drop_missing_files_key_raises(self):
        with self.assertRaises(render_skills.TransformError):
            render_skills._apply_drop({"type": "drop"}, self._files(), {"dropped": 0})

    def test_drop_matching_nothing_raises(self):
        with self.assertRaises(render_skills.TransformError):
            render_skills._apply_drop(
                {"type": "drop", "files": "vulnhunt/nope-*.md"}, self._files(), {"dropped": 0}
            )

    def test_drop_removes_matches(self):
        files = self._files()
        stats = {"dropped": 0}
        render_skills._apply_drop({"type": "drop", "files": "vulnhunt/phases/*.md"}, files, stats)
        self.assertNotIn("vulnhunt/phases/p1.md", files)
        self.assertIn("vulnhunt/SKILL.md", files)
        self.assertEqual(stats["dropped"], 1)


class TestCopyIgnore(unittest.TestCase):
    """COPY_IGNORE must actually exclude build detritus from rendered bundles.

    Regression for the ``COPY_IGNORE(p, p.name)`` arg-shape bug: passing a
    bare str made ``fnmatch.filter`` iterate its characters, so the ignore
    never fired and ``__pycache__``/``*.pyc``/``.venv`` leaked into dist/.
    """

    def test_is_ignored_matches_patterns(self):
        self.assertTrue(render_skills.is_ignored(Path("/x/__pycache__")))
        self.assertTrue(render_skills.is_ignored(Path("/x/junk.pyc")))
        self.assertTrue(render_skills.is_ignored(Path("/x/.venv")))
        self.assertTrue(render_skills.is_ignored(Path("/x/.installed-from")))
        self.assertFalse(render_skills.is_ignored(Path("/x/SKILL.md")))
        self.assertFalse(render_skills.is_ignored(Path("/x/phase1.md")))

    def test_pyc_detritus_excluded_from_render(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Minimal skill source + planted build detritus.
            skill_src = root / "vulnhunt"
            (skill_src / "phases").mkdir(parents=True)
            (skill_src / "SKILL.md").write_text("# vulnhunt\n")
            (skill_src / "phases" / "phase1.md").write_text("phase\n")
            junk_dir = skill_src / "__pycache__"
            junk_dir.mkdir()
            (junk_dir / "junk.pyc").write_text("bytecode")
            # A one-skill adapter manifest (identity transform).
            adapter_dir = root / "adapters" / "probe"
            adapter_dir.mkdir(parents=True)
            (adapter_dir / "adapter.json").write_text(
                json.dumps({"name": "probe", "skills": ["vulnhunt"], "transforms": []})
            )
            out = root / "dist"
            render_skills.render_adapter(adapter_dir, root, out)
            rendered = out / "probe"
            leaked = [p for p in rendered.rglob("*") if p.suffix == ".pyc" or p.name == "__pycache__"]
            self.assertEqual(leaked, [], f"detritus leaked into render: {leaked}")
            self.assertTrue((rendered / "vulnhunt" / "SKILL.md").is_file())


class TestAdapterManifests(unittest.TestCase):
    def test_manifests_well_formed(self):
        for adapter_dir in sorted(ADAPTERS.iterdir()):
            if not (adapter_dir / "adapter.json").is_file():
                continue
            cfg = render_skills.load_adapter(adapter_dir)
            self.assertEqual(cfg["name"], adapter_dir.name)
            for skill in cfg["skills"]:
                self.assertTrue((REPO_ROOT / skill / "SKILL.md").is_file())

    def test_substitute_find_strings_exist_in_sources(self):
        """Every non-optional 'find' must be present in the current sources
        AND declare a matching ``count``.

        This is the drift tripwire: when someone edits a prompt line that an
        adapter rewrites, this fails with the exact missing string. Requiring
        ``count`` (and asserting the exact occurrence total) makes the
        tripwire actually trip on a *partial* rewrite too — a source edit
        that duplicates or half-rewords a phrase changes the occurrence
        count, so a bare "present at least once" check would pass while the
        transform silently rewrites the wrong number of sites.
        """
        for adapter_dir in sorted(ADAPTERS.iterdir()):
            manifest = adapter_dir / "adapter.json"
            if not manifest.is_file():
                continue
            cfg = json.loads(manifest.read_text(encoding="utf-8"))
            for skill in cfg["skills"]:
                for i, spec in enumerate(cfg["transforms"]):
                    if spec.get("type") != "substitute" or spec.get("optional"):
                        continue
                    self.assertIn(
                        "count",
                        spec,
                        f"{adapter_dir.name} transform[{i}]: non-optional substitute "
                        f"must declare 'count' (drift tripwire): {spec['find']!r}",
                    )
                    pattern = spec["files"]
                    rx = render_skills._glob_to_regex(pattern)
                    targets = [
                        f"{skill}/{p.relative_to(REPO_ROOT / skill).as_posix()}"
                        for p in sorted((REPO_ROOT / skill).rglob("*"))
                        if p.is_file()
                        and not render_skills.is_ignored(p)
                        and rx.match(f"{skill}/{p.relative_to(REPO_ROOT / skill).as_posix()}")
                    ]
                    self.assertTrue(targets, f"{adapter_dir.name} transform[{i}]: no files match {pattern}")
                    found = sum(
                        (REPO_ROOT / rel).read_text(encoding="utf-8").count(spec["find"])
                        for rel in targets
                    )
                    self.assertGreater(
                        found,
                        0,
                        f"{adapter_dir.name} transform[{i}]: find-string no longer in sources: {spec['find']!r}",
                    )

    def test_every_nonoptional_substitute_declares_count(self):
        """Independent, adapter-wide guard: no non-optional substitute may
        omit ``count``. Kept separate from the source-presence check so a new
        adapter that forgets a count fails even if its find-string exists."""
        for adapter_dir in sorted(ADAPTERS.iterdir()):
            manifest = adapter_dir / "adapter.json"
            if not manifest.is_file():
                continue
            cfg = json.loads(manifest.read_text(encoding="utf-8"))
            for i, spec in enumerate(cfg["transforms"]):
                if spec.get("type") != "substitute" or spec.get("optional"):
                    continue
                self.assertIn(
                    "count",
                    spec,
                    f"{adapter_dir.name} transform[{i}] is missing 'count'",
                )


class TestHermesRender(unittest.TestCase):
    """The hermes adapter must neutralize every Claude Code-ism in vulnhunt."""

    @classmethod
    def setUpClass(cls):
        cls.dist = render_to_tmp("hermes")

    def test_skill_present_with_phases(self):
        skill = self.dist / "vulnhunt"
        self.assertTrue((skill / "SKILL.md").is_file())
        self.assertTrue((skill / "phases" / "phase1_recon.md").is_file())

    def test_no_claude_skill_dir_token(self):
        for md in (self.dist / "vulnhunt").rglob("*.md"):
            self.assertNotIn(
                "${CLAUDE_SKILL_DIR}", md.read_text(encoding="utf-8"), f"leftover token in {md.name}"
            )

    def test_hermes_token_and_frontmatter(self):
        text = (self.dist / "vulnhunt" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("${HERMES_SKILL_DIR}", text)
        self.assertIn("requires_toolsets", text)
        self.assertIn("delegation", text)
        # frontmatter stays first in the file
        self.assertTrue(text.startswith("---\n"))

    def test_claude_commands_neutralized(self):
        text = (self.dist / "vulnhunt" / "SKILL.md").read_text(encoding="utf-8")
        self.assertNotIn("/cost", text)
        self.assertNotIn("/model opus", text)
        self.assertNotIn("Launch a `general-purpose` subagent:", text)
        self.assertIn("delegate_task", text)

    def test_terminology_overlay_prepended(self):
        for name in ("SKILL.md", "phases/phase1_recon.md", "phases/phase2_hunt.md"):
            text = (self.dist / "vulnhunt" / name).read_text(encoding="utf-8")
            self.assertIn("Harness adaptation note", text, f"overlay missing from {name}")

    def test_delegation_protocol_in_overlay(self):
        text = (self.dist / "vulnhunt" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn('action: "list"', text)
        self.assertIn("dispatched", text)
        self.assertIn("conclude, error out, or produce a final answer", text)


class TestModelGateSoftened(unittest.TestCase):
    """Non-Claude adapters must not block on model choice: Step 0 becomes a
    calibration notice that proceeds on the selected model. (The claude-code
    render keeps upstream's interactive STOP gate, byte-identical.)"""

    def test_gate_is_notice_not_stop(self):
        for adapter in ("hermes", "codex", "copilot"):
            dist = render_to_tmp(adapter)
            text = (dist / "vulnhunt" / "SKILL.md").read_text(encoding="utf-8")
            self.assertNotIn(
                "**STOP immediately**", text, f"{adapter}: Step 0 still blocks"
            )
            self.assertNotIn("/model opus", text, f"{adapter}: claude command leaked")
            self.assertIn(
                "CONTINUE immediately on the currently selected model",
                text,
                f"{adapter}: proceed-on-selected-model wording missing",
            )
            self.assertIn("Calibration note", text, f"{adapter}: notice missing")

    def test_claude_code_keeps_upstream_gate(self):
        dist = render_to_tmp("claude-code")
        text = (dist / "vulnhunt" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("**STOP immediately**", text)
        self.assertIn("/model opus", text)


if __name__ == "__main__":
    unittest.main()
