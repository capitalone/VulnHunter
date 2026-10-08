#!/bin/bash
set -e

# HOME guard: destinations (and the rm -rf below) derive from HOME. An empty
# HOME turns "rm -rf $dst" into "rm -rf /.copilot/..." — refuse cleanly.
if [ -z "${HOME:-}" ]; then
    echo "error: HOME unset — refusing to run install-copilot.sh" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILLS_PARENT="$HOME/.copilot/skills"

# find_python/build_vulnfix_venv/VULNFIX_DEPS are shared with install.sh
# (both build the same bundled venv for vulnhunter-fix) -- see
# _install_common.sh for why this is a separate sourced file rather than
# duplicated in both scripts.
INSTALL_INVOCATION="./install-copilot.sh"
COMMON_SH="$SCRIPT_DIR/_install_common.sh"
if [ ! -f "$COMMON_SH" ]; then
    echo "Error: $COMMON_SH not found." >&2
    echo "Make sure you are running this script from the repository root." >&2
    exit 1
fi
# shellcheck source=_install_common.sh
source "$COMMON_SH"

# Each Copilot Agent Skill is assembled from two sources at install time
# rather than stored fully duplicated in the repo:
#   base    - the existing Claude Code skill directory (unmodified)
#   overlay - vulnhunt-copilot/skills/<name>/, containing only the files
#             that differ because Copilot's tool set (subagent dispatch,
#             terminal tool) differs from Claude Code's
# Copying base then overlay on top means the two skills share one copy of
# every file that doesn't need to differ — most importantly, vulnhunter-fix's
# Python package and its test suite are never duplicated.
SKILLS=(vulnhunt vulnhunt-fix-verify vulnhunter-fix)

if [ ! -d "$SKILLS_PARENT" ]; then
    echo "Creating directory $SKILLS_PARENT"
    mkdir -p "$SKILLS_PARENT"
fi

installed_any=0
for name in "${SKILLS[@]}"; do
    base="$SCRIPT_DIR/$name"
    overlay="$SCRIPT_DIR/vulnhunt-copilot/skills/$name"
    dst="$SKILLS_PARENT/$name"

    if [ ! -f "$base/SKILL.md" ]; then
        if [ "$name" = "vulnhunt" ]; then
            echo "Error: base skill not found at $base" >&2
            echo "Make sure you are running this script from the repository root." >&2
            exit 1
        else
            echo "Skipping $name — $base/SKILL.md not present on this branch."
            continue
        fi
    fi
    if [ ! -d "$overlay" ]; then
        echo "Error: Copilot overlay not found at $overlay" >&2
        echo "Make sure you are running this script from the repository root." >&2
        exit 1
    fi

    if [ -L "$dst" ]; then
        echo "Removing old symlink for $name..."
        rm "$dst"
    elif [ -d "$dst" ]; then
        echo "Removing old copy of $name..."
        rm -rf "$dst"
    fi

    # Base first, overlay on top. Files (not symlinks — symlinks can break
    # workspace search tooling), and the trailing "/." on each source copies
    # directory *contents* into $dst rather than nesting a subdirectory.
    mkdir -p "$dst"
    cp -R "$base/." "$dst/"
    # The base directory's own README.md documents the Claude Code skill
    # ("The core VulnHunter scanner skill for Claude Code...") — leaving it
    # in the installed Copilot skill folder would be actively misleading.
    # SKILL.md (the actual functional entry point) is unaffected.
    rm -f "$dst/README.md"
    cp -R "$overlay/." "$dst/"

    # vulnhunt-fix-verify references verify_disposition.schema.json, which
    # lives in vulnhunter-agent/ today rather than in either skill's own
    # tree — copy it in from its real location instead of duplicating it a
    # second time inside the overlay directory.
    if [ "$name" = "vulnhunt-fix-verify" ]; then
        cp "$SCRIPT_DIR/vulnhunter-agent/verify_disposition.schema.json" "$dst/verify_disposition.schema.json"
    fi

    # Record the source commit so a skill's staleness check (e.g.
    # vulnhunter-fix SKILL.md Step 0b) can compare the installed copy
    # against upstream main. Best-effort: skipped outside a git checkout.
    git -C "$SCRIPT_DIR" rev-parse HEAD > "$dst/.installed-from" 2>/dev/null || true
    echo "Installed $name (copied to $dst)"

    if [ "$name" = "vulnhunter-fix" ]; then
        # A handful of base files need small, well-defined text substitutions
        # (attribution trailers, a few tool-name mentions in comments) rather
        # than a full duplicate overlay copy — see apply_substitutions.py for
        # why and exactly what changes. Fails loudly if upstream wording has
        # drifted since the substitution list was written, rather than
        # silently leaving stale Claude Code wording in the Copilot install.
        SUBST_PY="$(find_python)" || {
            echo "error: python3.11+ not found (needed to apply Copilot text substitutions)." >&2
            exit 1
        }
        if ! "$SUBST_PY" "$SCRIPT_DIR/vulnhunt-copilot/scripts/apply_substitutions.py" "$dst"; then
            echo "error: failed to apply Copilot text substitutions to $dst" >&2
            exit 1
        fi
        build_vulnfix_venv "$dst"
    fi

    installed_any=1
done

echo ""
if [ "$installed_any" -eq 1 ]; then
    echo "These are Copilot Agent Skills: VS Code, JetBrains, and GitHub Copilot"
    echo "CLI all auto-discover them from ~/.copilot/skills/ — no further"
    echo "configuration needed."
    echo ""
    echo "Next steps:"
    echo "1. Open the repo you want to scan/fix in your editor."
    echo "2. Open Copilot Chat, switch to Agent mode."
    echo "3. Run: /vulnhunt   (scanner)"
    echo "   or:  /vulnhunter-fix   (fixer, run after a scan)"
    echo "   or:  /vulnhunt-fix-verify   (independent fix verifier)"
    echo ""
    echo "To update after pulling changes: re-run ./install-copilot.sh"
    echo "To uninstall: ./uninstall-copilot.sh"
else
    echo "No skills were installed."
fi
