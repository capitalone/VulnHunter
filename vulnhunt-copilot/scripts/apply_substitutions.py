#!/usr/bin/env python3
"""Apply the small set of Claude Code -> Copilot text substitutions that
don't warrant a full-file overlay copy.

Why this exists: an earlier revision of this port kept full-file overlay
copies for files where only a handful of words actually differ from the
base Claude Code skill (attribution trailers, a couple of tool-name
mentions in comments). A reviewer (schenksj, on PR #32) pointed out that
~93% of those "delta" files were actually verbatim duplicates of base, and
that duplicating a whole file to change one line creates exactly the drift
risk the overlay design was meant to avoid: a future fix to the base file
wouldn't reach Copilot users unless someone remembered the duplicate
existed too.

This script replaces those full-file copies with a small, explicit,
byte-exact substitution list, applied to the base files (already copied to
the install destination) after the base+overlay merge. Every rule is
generated from a real diff (see the git history of this file for the
generation script) — not retyped by hand — and every rule fails loudly if
its expected text isn't found in the target file, rather than silently
no-op'ing. That matters: if upstream changes the wording this rule expects,
silently skipping the substitution would leave stale "Claude Code" wording
in a Copilot install without anyone noticing. A loud failure here means
"go look at this file, the base wording changed, decide whether the rule
still applies" instead of quietly drifting.

Usage:
    apply_substitutions.py <installed-vulnhunter-fix-dir>
    apply_substitutions.py --check <vulnhunter-fix-dir>

Exits non-zero (with a specific file/rule identified) if any rule's
expected text isn't found, or is found an unexpected number of times.

--check runs the same verification but never writes: it's meant to run in
CI against the repo's own vulnhunter-fix/ directory on every PR, so that a
change to the base wording that breaks a rule is caught in the PR that
introduced it -- not later, silently, whenever someone next runs
install-copilot.sh. Without --check, this script only ever runs at install
time, which means the person who broke a rule and the person who discovers
it broken are almost never the same person.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Each entry: (relative path under the skill dir, old text, new text,
# expected occurrence count). old/new are byte-exact substrings generated
# from a real diff against vulnhunter-fix/ at the time this list was
# written -- see PR #32 review discussion for the reasoning behind each
# category (attribution trailer, tool-name wording, sandbox-comment
# wording, model-tier terminology).
RULES: list[tuple[str, str, str, int]] = [
    (
        "prompts/worker_agent_common.md",
        "Co-Authored-By: Claude Code (VulnFix)\n",
        "Co-Authored-By: GitHub Copilot (VulnFix)\n",
        1,
    ),
    (
        "prompts/verify.md",
        '- Verification agent = fresh Agent tool subagent (model="sonnet" for test-quality review, model="opus" for diagnosis when a test fails). Haiku is documented in `prompts/parse_issues.md` Step 5a as unreliable on shape-variable input — test-quality review (tautological assertions, missing RED phase, mock leakage) is exactly that shape, and a missed flag here lets a fake fix merge.\n'
        "- Fix agent = fresh Agent tool subagent operating on the cluster's worktree under `.vulnhunter-fix/worktrees/<CLUSTER_KEY>/`.\n",
        "- Verification agent = fresh subagent (a standard-tier reasoning model is fine for routine test-quality review; use a stronger reasoning-tier model for diagnosis when a test fails). `prompts/parse_issues.md` Step 5a documents that lightweight/fast models are unreliable on shape-variable input — test-quality review (tautological assertions, missing RED phase, mock leakage) is exactly that shape, and a missed flag here lets a fake fix merge.\n"
        "- Fix agent = fresh subagent operating on the cluster's worktree under `.vulnhunter-fix/worktrees/<CLUSTER_KEY>/`.\n",
        1,
    ),
    (
        "prompts/verify.md",
        "- Verification agent = fresh Agent tool subagent (receives test + source only).\n"
        "- Fix agent = fresh Agent tool subagent (receives fix brief + worktree path).\n",
        "- Verification agent = fresh subagent (receives test + source only).\n"
        "- Fix agent = fresh subagent (receives fix brief + worktree path).\n",
        1,
    ),
    (
        "prompts/verify.md",
        "     Co-Authored-By: Claude Code (VulnFix)\n",
        "     Co-Authored-By: GitHub Copilot (VulnFix)\n",
        1,
    ),
    (
        "prompts/parse.md",
        "- Parser fails → STOP: \"Failed to parse {path}/README.md. The regex parser couldn't extract findings from the summary table. Inspect the report manually and re-run, or if you are in interactive (in-place) mode, use `prompts/parse_issues.md` Step 5a's validated Sonnet extraction instead — do NOT freelance findings from the README, since hallucinated findings would produce PRs for vulnerabilities that don't exist.\"\n",
        "- Parser fails → STOP: \"Failed to parse {path}/README.md. The regex parser couldn't extract findings from the summary table. Inspect the report manually and re-run, or if you are in interactive (in-place) mode, use `prompts/parse_issues.md` Step 5a's validated model extraction instead — do NOT freelance findings from the README, since hallucinated findings would produce PRs for vulnerabilities that don't exist.\"\n",
        1,
    ),
    (
        "prompts/implement.md",
        "If the fix modifies a dependency manifest, also run the **dep-class checks** in fork Step D.3 below. In-place-mode caveat: surface every hit from D.3.a and D.3.b to the developer via the Interactive collaboration loop (`AskUserQuestion` per hit), not a `notes` field — the developer's picks either land in this same commit or become follow-up items. Do NOT auto-bump anything the developer didn't explicitly approve; auto-fixing companion packages violates the CANNOT_AUTO_FIX contract that says the developer, not the skill, decides how far the fix extends.\n",
        "If the fix modifies a dependency manifest, also run the **dep-class checks** in fork Step D.3 below. In-place-mode caveat: surface every hit from D.3.a and D.3.b to the developer via the Interactive collaboration loop (ask the user directly, per hit), not a `notes` field — the developer's picks either land in this same commit or become follow-up items. Do NOT auto-bump anything the developer didn't explicitly approve; auto-fixing companion packages violates the CANNOT_AUTO_FIX contract that says the developer, not the skill, decides how far the fix extends.\n",
        1,
    ),
    (
        "prompts/implement.md",
        "Co-Authored-By: Claude Code (VulnFix)\n",
        "Co-Authored-By: GitHub Copilot (VulnFix)\n",
        2,
    ),
    (
        "prompts/implement.md",
        "**If any stale pin is found — in-place mode:** enter the Interactive collaboration loop and present each hit via `AskUserQuestion`. Concrete options per hit:\n",
        "**If any stale pin is found — in-place mode:** enter the Interactive collaboration loop and present each hit by asking the user directly. Concrete options per hit:\n",
        1,
    ),
    (
        "prompts/implement.md",
        "**Handling matches — in-place mode:** include each older companion in the same `AskUserQuestion` round as D.3.a. Per companion:\n",
        "**Handling matches — in-place mode:** include each older companion in the same question round as D.3.a. Per companion:\n",
        1,
    ),
    (
        "prompts/implement.md",
        "2. **Offer concrete next moves via `AskUserQuestion`.** Each option must be specific enough that the developer doesn't have to guess what it entails. Examples:\n",
        "2. **Offer concrete next moves by asking the user directly.** Each option must be specific enough that the developer doesn't have to guess what it entails. Examples:\n",
        1,
    ),
    (
        "prompts/implement.md",
        "   - Ask the next question with the same `AskUserQuestion` shape, narrowed by what you learned.\n",
        "   - Ask the next question in the same numbered-options shape, narrowed by what you learned.\n",
        1,
    ),
    (
        "templates/pr_body.md",
        "Co-Authored-By: Claude Code (VulnFix)\n",
        "Co-Authored-By: GitHub Copilot (VulnFix)\n",
        1,
    ),
    (
        "templates/pr_body_cluster.md",
        "Co-Authored-By: Claude Code (VulnFix)\n",
        "Co-Authored-By: GitHub Copilot (VulnFix)\n",
        1,
    ),
    (
        "templates/commit_msg.md",
        "Co-Authored-By: Claude Code (VulnFix)\n",
        "Co-Authored-By: GitHub Copilot (VulnFix)\n",
        1,
    ),
    (
        "scripts/cluster_score.py",
        "The top-scoring cluster gets `(Recommended)` in its `AskUserQuestion`\nlabel (per parse_issues.md Step 3(c)).\n",
        "The top-scoring cluster gets `(Recommended)` in its cluster-selection\nquestion label (per parse_issues.md Step 3(c)).\n",
        1,
    ),
    (
        "scripts/cluster_score.py",
        "# through into the AskUserQuestion checkboxes — generic labels give\n",
        "# through into the cluster-selection question — generic labels give\n",
        1,
    ),
    (
        "scripts/validate_findings_draft.py",
        "to a Sonnet subagent. The subagent writes a JSON file the downstream\n",
        "to a frontier-model subagent. The subagent writes a JSON file the downstream\n",
        1,
    ),
    (
        "tests/test_graph_build_bugs.py",
        "    the Claude Code sandbox blocks with PermissionError. Catalyst hit and\n",
        "    macOS agent sandboxes block with PermissionError (first observed under\n    Claude Code's Bash tool). Catalyst hit and\n",
        1,
    ),
    (
        "vulnhunter_fix/graph/build.py",
        '    ``os.sysconf("SC_SEM_NSEMS_MAX")`` which the macOS Claude Code sandbox\n    blocks with ``PermissionError: Operation not permitted``. That aborts\n',
        '    ``os.sysconf("SC_SEM_NSEMS_MAX")`` which macOS agent sandboxes (observed\n    under Claude Code\'s Bash tool; VS Code Copilot\'s terminal tool sandboxes\n    similarly) block with ``PermissionError: Operation not permitted``. That aborts\n',
        1,
    ),
    (
        "vulnhunter_fix/graph/config.py",
        "    Claude Code sandbox blocks reads of ``.envrc``, submodule ``.git``\n",
        "    agent sandboxes — Claude Code's Bash tool and VS Code Copilot's terminal\n    tool both block reads of ``.envrc``, submodule ``.git``\n",
        1,
    ),
    (
        "vulnhunter_fix/graph/config.py",
        "    sandbox / permission-denied entries (macOS Claude Code sandbox blocks\n",
        "    sandbox / permission-denied entries (macOS agent sandboxes — Claude\n    Code's Bash tool and VS Code Copilot's terminal tool both block\n",
        1,
    ),
    # preflight.py's Claude CLI check is a hard failure for every base
    # (Claude Code) user, which is correct there — but it would make Step 0
    # of /vulnhunter-fix unpassable for every Copilot user, since installing
    # the Claude Code CLI isn't part of this port. Downgrade both outcomes
    # to optional=True (a [WARN], not a [FAIL]) so the check still runs and
    # still reports, but never blocks a Copilot-only machine.
    (
        "scripts/preflight.py",
        '        check("Claude CLI", False, "not found in PATH")\n        return',
        '        check(\n            "Claude CLI", False,\n            "not found in PATH (optional here — only needed if this workflow "\n            "is also driven by the Claude Code CLI)",\n            optional=True,\n        )\n        return',
        1,
    ),
    (
        "scripts/preflight.py",
        '        check("Claude CLI", False, "cannot determine version")',
        '        check("Claude CLI", False, "cannot determine version", optional=True)',
        1,
    ),
]


def main() -> int:
    args = sys.argv[1:]
    check_only = "--check" in args
    if check_only:
        args = [a for a in args if a != "--check"]
    if len(args) != 1:
        print(
            "usage: apply_substitutions.py [--check] <vulnhunter-fix-dir>",
            file=sys.stderr,
        )
        return 2
    skill_dir = Path(args[0])

    by_file: dict[str, list[tuple[str, str, int]]] = {}
    for relpath, old, new, expected in RULES:
        by_file.setdefault(relpath, []).append((old, new, expected))

    had_error = False
    for relpath, rules in by_file.items():
        target = skill_dir / relpath
        if not target.is_file():
            print(f"error: {target} not found — cannot verify substitutions", file=sys.stderr)
            had_error = True
            continue
        content = target.read_text(encoding="utf-8")
        file_ok = True
        for old, new, expected in rules:
            found = content.count(old)
            if found != expected:
                print(
                    f"error: {relpath}: expected {expected} occurrence(s) of a known "
                    f"string, found {found}. Upstream wording likely changed since this "
                    f"substitution list was written — review vulnhunt-copilot/scripts/"
                    f"apply_substitutions.py and update the rule for this file.",
                    file=sys.stderr,
                )
                print(f"--- expected text ---\n{old}", file=sys.stderr)
                file_ok = False
                had_error = True
                continue
            content = content.replace(old, new)
        if not file_ok:
            # Don't apply partial substitutions for a file with a failed
            # rule -- report every problem in this file before giving up on
            # it, but never write a half-substituted result. This is scoped
            # to THIS file only -- an error in one file must not cause a
            # later, unrelated file's valid substitutions to be discarded.
            continue
        if check_only:
            print(f"  OK: {len(rules)} rule(s) verified against {relpath}")
        else:
            target.write_text(content, encoding="utf-8")
            print(f"  applied {len(rules)} substitution(s) to {relpath}")

    if had_error:
        return 1
    if check_only:
        print(f"All {len(RULES)} substitution rule(s) still match current wording.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
