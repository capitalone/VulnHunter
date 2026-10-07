# Adapter guide: adding a new agent harness

Adapters live in `adapters/<name>/` and turn the repo-root skill sources
into a harness-specific bundle. You need three artifacts:

## 1. `adapter.json`

```json
{
  "name": "yourharness",
  "description": "One line: what the harness is and how it runs the skill.",
  "skills": ["vulnhunt"],
  "install": {
    "target_dir": "~/.yourharness/skills",
    "script": "./install.sh --target yourharness",
    "headless": "<the exact non-interactive command>",
    "notes": "gotchas"
  },
  "transforms": [ ... ]
}
```

Transform types (applied in order; see `scripts/render_skills.py`):

| type | effect |
|---|---|
| `substitute` | literal find/replace on files matching `files` glob. Fails the render when `find` is absent unless `optional: true`. **`count: N` is required on every non-optional substitute** (enforced by `tests/test_render_skills.py`): it pins the expected occurrence total so a source edit that duplicates or half-rewords a phrase trips the drift test instead of silently rewriting the wrong number of sites. |
| `prepend` | insert text (or `text_file`) after the YAML frontmatter |
| `frontmatter_append` | insert lines before the closing `---` |
| `override` | replace/create a file wholesale from the adapter dir |
| `drop` | delete files from the rendered bundle |

## 2. What you must neutralize

Audit the rendered `SKILL.md` + phases for these Claude-isms (the existing
adapters are the reference — crib from them):

- `${CLAUDE_SKILL_DIR}` → your harness's skill-dir token or absolute path
- "Launch a `general-purpose` subagent:" ×4 → your subagent mechanism **or**
  a documented sequential strategy that preserves the minimum pass count
- Phase-2 fan-out wording — keep the minimum pass count meaningful
- `/cost` → a progress line; `/model opus` gating → a calibration notice
  that proceeds on the selected model (no model enforcement)
- Opus gating sentence → your model-selection guidance
- Tool vocabulary (Grep/Glob/Read/Bash) → a terminology overlay prepended to
  `SKILL.md` and every `phases/*.md` is usually enough
- The ORCHESTRATOR role paragraph — only correct it if your harness cannot
  dispatch subagents

## 3. Wire-up checklist

- [ ] `install.sh` — add a `case` branch: render + set `SKILLS_PARENT`
- [ ] Renderer tests — extend `tests/test_render_skills.py` with a render
      test asserting your key substitutions and overlay presence
- [ ] `vulnhunter-agent/agent/engines/` — add an engine module if the
      harness has a CLI; register it in `engines/__init__.py`
      (`ENGINE_NAMES` + `get_engine`). If it shells out to a CLI, subclass
      `SubprocessEngine` (`engines/_subprocess.py`) and implement only the
      hooks (`_binary_name`, `_install_target`, `_binary_hint`,
      `_skill_paths`, `_build_command`, `_build_kickoff`) — the shared base
      supplies pre-staging, audit, timeout, and the contents-based success
      contract. Add the engine to the parametrized contract tests.
- [ ] `harness/local_harness/config.py` — add an `ENGINES` entry
- [ ] `harness/local_harness/scan.py` / `benchmark/judge.py` — add argv
      builders + tests
- [ ] `docs/ENGINES.md` + `docs/engine-matrix.md` — capability row and
      status (experimental until benchmarked)
- [ ] `adapters/<name>/README.md` — install, headless command, permission
      preset, model policy, status

## Invariants (do not break)

1. `dist/claude-code` stays byte-identical to the repo-root skill sources
   (enforced by tests) — the Claude path must not regress.
2. Success is judged by the results contract — a `*_VULNHUNT_RESULTS_*`
   dir that actually contains the skill's `README.md` report — never by
   engine stdout or by the pre-created directory merely existing.
3. The kickoff prompt always carries the "Pre-resolved scan metadata"
   block (results dir, branch label, repo URL, model tag, shell policy).
4. Read-only runs must not enable arbitrary code execution; exploit-test
   execution is opt-in only (`--enable-bash` parity).
5. Declare the adapter's status honestly: **experimental** until the
   ground-truth benchmark has been run on it.
