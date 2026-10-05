#!/bin/bash
set -e

# HOME guard: dst (and its rm -rf) derive from HOME. An empty HOME turns
# "rm -rf $dst" into "rm -rf /.claude/skills/..." — refuse cleanly. The
# recursive remove already takes the bundled .venv with it.
if [ -z "${HOME:-}" ]; then
    echo "error: HOME unset — refusing to run uninstall.sh" >&2
    exit 1
fi

SKILLS_PARENT="$HOME/.claude/skills"
CODEX_SKILLS_PARENT="$HOME/.agents/skills"

# Skill names to remove (must match the names install.sh writes).
SKILLS=(vulnhunt vulnhunt-fix-verify vulnhunter-fix)

removed_any=0
for name in "${SKILLS[@]}"; do
    dst="$SKILLS_PARENT/$name"
    if [ -L "$dst" ]; then
        rm "$dst"
        echo "Removed symlink $dst"
        removed_any=1
    elif [ -d "$dst" ]; then
        rm -rf "$dst"
        echo "Removed $dst"
        removed_any=1
    else
        echo "$name is not installed (no entry at $dst)"
    fi
done

codex_dst="$CODEX_SKILLS_PARENT/vulnhunt-codex"
if [ -L "$codex_dst" ]; then
    rm "$codex_dst"
    echo "Removed symlink $codex_dst"
    removed_any=1
elif [ -d "$codex_dst" ]; then
    rm -rf "$codex_dst"
    echo "Removed $codex_dst"
    removed_any=1
else
    echo "vulnhunt-codex is not installed (no entry at $codex_dst)"
fi

echo ""
if [ "$removed_any" -eq 1 ]; then
    echo "Uninstalled VulnHunter skills."
else
    echo "Nothing to uninstall."
fi
