#!/bin/bash
set -e

# HOME guard: dst (and its rm -rf) derives from HOME. An empty HOME turns
# "rm -rf $dst" into something much more dangerous — refuse cleanly. The
# recursive remove already takes the bundled .venv with it.
if [ -z "${HOME:-}" ]; then
    echo "error: HOME unset — refusing to run uninstall-copilot.sh" >&2
    exit 1
fi

SKILLS_PARENT="$HOME/.copilot/skills"

# Skill names to remove (must match the names install-copilot.sh writes).
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

echo ""
if [ "$removed_any" -eq 1 ]; then
    echo "Uninstalled VulnHunter Copilot Agent Skills."
else
    echo "Nothing to uninstall."
fi
