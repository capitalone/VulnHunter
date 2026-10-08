#!/bin/bash
# Shared between install.sh and install-copilot.sh: locating a Python
# interpreter and building vulnhunter-fix's bundled venv. Sourced (not
# executed) by both. The caller must set INSTALL_INVOCATION before sourcing
# this file -- it's used only in one error message below, so the message
# names whichever script the user actually ran.

if [ -z "${INSTALL_INVOCATION:-}" ]; then
    echo "error: INSTALL_INVOCATION must be set before sourcing _install_common.sh" >&2
    exit 1
fi

# vulnhunter-fix runtime deps. The skill's scripts/_skill_bootstrap.py expects
# a bundled venv at <skill>/.venv containing these; without it preflight's
# graphifyy check hard-fails. jsonschema is required; graphifyy (import name
# `graphify`) enables AST graph mode and falls back to grep when absent, but
# preflight still requires it. Pin must match preflight.py REQ-GRA-001, and
# stay identical to install.cmd's and install-copilot.cmd's own copies of the
# same value (install.sh and install-copilot.sh both source this file, so
# they can't drift from each other; the .cmd side has no shared file to
# source -- each keeps its own copy, and those two are the remaining places
# this could drift -- CI enforces all three staying in sync via
# vulnhunt-copilot/scripts/check_dep_pins_consistent.py).
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
        echo "install python 3.11 (e.g. 'brew install python@3.11') and re-run $INSTALL_INVOCATION." >&2
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
