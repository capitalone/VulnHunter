#!/usr/bin/env bash
#
# Mode dispatch for the vulnhunter-fix skill.
#
# Canonical implementation of the rule SKILL.md documents in its
# "Mode dispatch (mandatory)" section. The script reads the
# environment + CWD, decides whether the run is in-place or fork,
# and prints a single line to stdout that the calling prompt
# consumes. Exporting variables in a child shell wouldn't survive
# back to the parent agent context, so we use stdout as the wire
# format.
#
# Inputs (env vars; all optional):
#   TARGET_REPO      — explicit fork-mode target (GitHub URL)
#   RESULTS_PATH     — explicit fork-mode results path
#
# Inputs (positional; all optional):
#   $1 = $TARGET_REPO override
#   $2 = $RESULTS_PATH override
#
# Output (stdout, one line, key=value pairs):
#   mode=in_place owner_repo=<o/r> root=<path> origin=<url> [results=<path>]
#   mode=fork target=<url> results=<path>
#   mode=ambiguous owner_repo=<o/r> target=<url>
#   mode=none
#
# The optional `results=<path>` field appears on the in_place line when
# RESULTS_PATH is supplied inside a GitHub checkout — prompts/parse_issues.md
# § Step 0 reads it and short-circuits the GitHub-issue harvest.
#
# Exit codes:
#   0 — clean dispatch (in_place / fork / none)
#   2 — ambiguous (both TARGET_REPO and RESULTS_PATH supplied from within
#       a checkout — genuine conflict, caller must disambiguate)
#
# Examples and edge cases live in tests/test_detect_mode.py.

set -eu

# Allow positional overrides without clobbering exported env.
TARGET_REPO="${1:-${TARGET_REPO:-}}"
RESULTS_PATH="${2:-${RESULTS_PATH:-}}"

TOP="$(git rev-parse --show-toplevel 2>/dev/null || true)"
ORIGIN=""
OWNER_REPO=""
IN_GIT_REPO="no"

if [ -n "$TOP" ]; then
    ORIGIN="$(git -C "$TOP" remote get-url origin 2>/dev/null || true)"

    # Extract the host portion so the GitHub-vs-not check looks
    # only at the host, not the path. The previous `*github*` glob
    # over-matched non-GitHub remotes that happened to carry
    # "github" in the path (e.g., gitlab.com/myorg/github-mirror).
    host=""
    case "$ORIGIN" in
        git@*:*)
            host="${ORIGIN#git@}"
            host="${host%%:*}"
            ;;
        http://*|https://*|ssh://*)
            host="${ORIGIN#*://}"
            host="${host%%/*}"
            host="${host#*@}"
            ;;
    esac

    # Accept github.com, *.github.com, and github.* (GitHub Enterprise
    # installations typically use a `github.<corp-domain>` host).
    is_github="no"
    case "$host" in
        github.com|*.github.com|github.*) is_github="yes" ;;
    esac

    if [ "$is_github" = "yes" ]; then
        # Parse owner/repo from common HTTPS/SSH/SSH+URL shapes.
        stripped="$ORIGIN"
        case "$stripped" in
            git@*:*)
                stripped="${stripped#*:}"
                ;;
            http://*|https://*|ssh://*)
                stripped="${stripped#*://}"
                stripped="${stripped#*/}"
                ;;
        esac
        stripped="${stripped%.git}"
        stripped="${stripped%/}"
        owner="${stripped%%/*}"
        rest="${stripped#*/}"
        repo="${rest%%/*}"
        if [ -n "$owner" ] && [ -n "$repo" ] && [ "$owner" != "$stripped" ]; then
            OWNER_REPO="${owner}/${repo}"
            IN_GIT_REPO="yes"
        fi
    fi
fi

HAS_ARGS="no"
if [ -n "$TARGET_REPO" ] || [ -n "$RESULTS_PATH" ]; then
    HAS_ARGS="yes"
fi

# In-place with a local report (findings from disk instead of harvested
# GitHub issues). Per peer review 4 collapse: the mode identifier stays
# `in_place` — the RESULTS_PATH signal rides on an optional `results=`
# field. Every downstream renderer branches on `work.json.no_source_issues`
# (set by parse_issues.md Step 0), not on the mode string. Findings-source
# is a property of the work, not the mode.
if [ "$IN_GIT_REPO" = "yes" ] && [ -z "$TARGET_REPO" ] && [ -n "$RESULTS_PATH" ]; then
    echo "mode=in_place owner_repo=$OWNER_REPO root=$TOP origin=$ORIGIN results=$RESULTS_PATH"
    exit 0
fi

if [ "$HAS_ARGS" = "yes" ] && [ "$IN_GIT_REPO" = "yes" ]; then
    echo "mode=ambiguous owner_repo=$OWNER_REPO target=$TARGET_REPO results=$RESULTS_PATH"
    exit 2
fi

if [ "$HAS_ARGS" = "yes" ]; then
    echo "mode=fork target=$TARGET_REPO results=$RESULTS_PATH"
    exit 0
fi

if [ "$IN_GIT_REPO" = "yes" ]; then
    echo "mode=in_place owner_repo=$OWNER_REPO root=$TOP origin=$ORIGIN"
    exit 0
fi

echo "mode=none"
exit 0
