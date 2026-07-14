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

# vulnhunter-fix runtime deps. The skill's scripts/_skill_bootstrap.py expects
# a bundled venv at <skill>/.venv containing these; without it preflight's
# graphifyy check hard-fails. jsonschema is required; graphifyy (import name
# `graphify`) enables AST graph mode and falls back to grep when absent, but
# preflight still requires it. Pin must match preflight.py REQ-GRA-001.
VULNFIX_DEPS=("jsonschema>=4.18" "graphifyy>=0.8.14,<0.9.0")

# Locate a Python for the bundled venv. Prefer 3.11 (graphifyy ships per-minor
# wheels and 3.11 is the reference minor); otherwise accept any python3 that
# satisfies pyproject's requires-python (>=3.11).
find_python() {
    if command -v python3.11 >/dev/null 2>&1; then
        command -v python3.11; return 0
    fi
    for candidate in \
        /opt/homebrew/opt/python@3.11/bin/python3.11 \
        /usr/local/opt/python@3.11/bin/python3.11 \
        /usr/bin/python3.11; do
        if [ -x "$candidate" ]; then echo "$candidate"; return 0; fi
    done
    for cand in python3.13 python3.12 python3; do
        if command -v "$cand" >/dev/null 2>&1 && \
           "$cand" -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3,11) else 1)' 2>/dev/null; then
            command -v "$cand"; return 0
        fi
    done
    return 1
}

# Build the bundled venv for the vulnhunter-fix skill and install its runtime
# deps from PyPI. Hard-fails on error: a half-installed skill would just trip
# preflight's graphifyy check with a more confusing message.
build_vulnfix_venv() {
    local skill_dir="$1"
    local py
    if ! py="$(find_python)"; then
        echo "error: python3.11+ not found (needed for vulnhunter-fix's bundled venv)." >&2
        echo "install python 3.11 (e.g. 'brew install python@3.11') and re-run ./install.sh." >&2
        exit 1
    fi
    local venv="$skill_dir/.venv"
    if [ -d "$venv" ]; then rm -rf "$venv"; fi
    echo "  creating bundled venv with $py"
    "$py" -m venv "$venv"
    "$venv/bin/pip" install --quiet --disable-pip-version-check --upgrade pip
    echo "  installing runtime deps into venv: ${VULNFIX_DEPS[*]}"
    if ! "$venv/bin/pip" install --quiet --disable-pip-version-check "${VULNFIX_DEPS[@]}"; then
        echo "error: failed to install bundled deps into $venv" >&2
        exit 1
    fi
    # Smoke test: the bootstrap must resolve both deps.
    if ! "$py" -c "
import sys
sys.path.insert(0, '$skill_dir/scripts')
import _skill_bootstrap  # loads .venv onto sys.path (re-execs under venv python if needed)
import jsonschema, graphify  # noqa: F401
" >/dev/null 2>&1; then
        echo "error: bootstrap smoke test failed — venv built but jsonschema/graphify not importable." >&2
        echo "       check $venv/lib/python3.*/site-packages/" >&2
        exit 1
    fi
    echo "  bundled venv ready: $venv"
}

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
