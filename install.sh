#!/bin/bash
set -e

# HOME guard: destinations (and the rm -rf below) derive from HOME. An empty
# HOME turns "rm -rf $dst" into "rm -rf /.claude/..." — refuse cleanly.
if [ -z "${HOME:-}" ]; then
    echo "error: HOME unset — refusing to run install.sh" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILLS_PARENT="$HOME/.claude/skills"

# find_python/build_vulnfix_venv/VULNFIX_DEPS are shared with
# install-copilot.sh (both build the same bundled venv for vulnhunter-fix) --
# see _install_common.sh for why this is a separate sourced file rather than
# duplicated in both scripts.
INSTALL_INVOCATION="./install.sh"
COMMON_SH="$SCRIPT_DIR/_install_common.sh"
if [ ! -f "$COMMON_SH" ]; then
    echo "Error: $COMMON_SH not found." >&2
    echo "Make sure you are running this script from the repository root." >&2
    exit 1
fi
# shellcheck source=_install_common.sh
source "$COMMON_SH"

# Skills shipped from this repo. Format: <installed-name>:<source-dir>.
# Order matters only for output readability — both are independent.
SKILLS=(
    "vulnhunt:$SCRIPT_DIR/vulnhunt"
    "vulnhunt-fix-verify:$SCRIPT_DIR/vulnhunt-fix-verify"
    "vulnhunter-fix:$SCRIPT_DIR/vulnhunter-fix"
)

# Create the parent skills directory if missing.
if [ ! -d "$SKILLS_PARENT" ]; then
    echo "Creating directory $SKILLS_PARENT"
    mkdir -p "$SKILLS_PARENT"
fi

installed_any=0
for entry in "${SKILLS[@]}"; do
    name="${entry%%:*}"
    src="${entry#*:}"
    dst="$SKILLS_PARENT/$name"

    # Skip-with-warning if the source dir isn't on this branch. Keeps
    # install.sh forward-compatible for hotfix branches that don't
    # include the verify skill yet.
    if [ ! -f "$src/SKILL.md" ]; then
        if [ "$name" = "vulnhunt" ]; then
            echo "Error: SKILL.md not found at $src" >&2
            echo "Make sure you are running this script from the repository root." >&2
            exit 1
        else
            echo "Skipping $name — $src/SKILL.md not present on this branch."
            continue
        fi
    fi

    # Handle existing destination (symlink or directory).
    if [ -L "$dst" ]; then
        echo "Removing old symlink for $name..."
        rm "$dst"
    elif [ -d "$dst" ]; then
        echo "Removing old copy of $name..."
        rm -rf "$dst"
    fi

    # Copy files (not symlink — symlinks break find/glob in subagents).
    cp -R "$src" "$dst"
    # Record the source commit so a skill's staleness check (e.g.
    # vulnhunter-fix SKILL.md Step 0b) can compare the installed copy
    # against upstream main. Best-effort: skipped outside a git checkout.
    git -C "$SCRIPT_DIR" rev-parse HEAD > "$dst/.installed-from" 2>/dev/null || true
    echo "Installed $name (copied to $dst)"

    # vulnhunter-fix ships a Python package whose runtime deps (jsonschema,
    # graphifyy) must live in a bundled venv that scripts/_skill_bootstrap.py
    # loads. The other skills are prompt-only and need no venv.
    if [ "$name" = "vulnhunter-fix" ]; then
        build_vulnfix_venv "$dst"
    fi

    installed_any=1
done

echo ""
if [ "$installed_any" -eq 1 ]; then
    echo "To update after pulling changes: re-run ./install.sh"
    echo "To uninstall: $SCRIPT_DIR/uninstall.sh"
else
    echo "No skills were installed."
fi
