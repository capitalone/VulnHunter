#!/usr/bin/env bash
set -euo pipefail

# Create or reuse a git worktree for one finding under
# <repo_root>/.vulnhunter-fix/worktrees/<key>/ on branch
# <branch_prefix>/<key>.
#
# Usage:
#   setup_worktree.sh <vulnfix_key> <branch_slug> [base_branch]
#
# Args:
#   vulnfix_key  — 16-char hex key (used as the worktree subdir name)
#   branch_slug  — short slug appended to the branch prefix (e.g.,
#                  "sql-injection-user-lookup"). Sanitized: lowercase
#                  ASCII alphanumerics and dashes only.
#   base_branch  — optional, defaults to the repo's default branch
#                  resolved from `gh repo view`. Falls back to "main"
#                  if gh isn't available.
#
# Idempotent: if the worktree already exists, re-prints its path and
# exits 0 without re-creating. If the branch exists but isn't
# attached to a worktree, attaches.
#
# Always also writes .git/info/exclude to ignore the work dir.

KEY="${1:?Usage: setup_worktree.sh <vulnfix_key> <branch_slug> [base_branch]}"
SLUG="${2:?Usage: setup_worktree.sh <vulnfix_key> <branch_slug> [base_branch]}"
BASE_BRANCH="${3:-}"

# Defense-in-depth: KEY flows into WT_PATH unsanitized; reject anything
# that isn't the canonical 16-hex shape produced by compute_vulnfix_key.
[[ "$KEY" =~ ^[0-9a-f]{16}$ ]] || {
    echo "setup_worktree.sh: invalid vulnfix_key (expected 16 lowercase hex): $KEY" >&2
    exit 1
}

REPO_ROOT="$(git rev-parse --show-toplevel)"
WORK_SUBDIR=".vulnhunter-fix"
WORK_ROOT="${REPO_ROOT}/${WORK_SUBDIR}"
WT_ROOT="${WORK_ROOT}/worktrees"
WT_PATH="${WT_ROOT}/${KEY}"
BRANCH_PREFIX="vulnfix"
BRANCH="${BRANCH_PREFIX}/${SLUG}"

# Sanitize: only [a-z0-9-] allowed in the slug portion of the branch.
sanitized_slug="$(echo "$SLUG" | tr '[:upper:]' '[:lower:]' | sed -e 's/[^a-z0-9-]/-/g' -e 's/-\{2,\}/-/g' -e 's/^-//' -e 's/-$//')"
if [ -z "$sanitized_slug" ]; then
    echo "error: branch slug sanitized to empty string from input: $SLUG" >&2
    exit 1
fi
BRANCH="${BRANCH_PREFIX}/${sanitized_slug}"

# Add .vulnhunter-fix/ to the local-only exclude file once. This stays
# out of tracked .gitignore so we never accidentally commit it for the
# user.
EXCLUDE_FILE="${REPO_ROOT}/.git/info/exclude"
if [ -f "$EXCLUDE_FILE" ]; then
    if ! grep -qxF "${WORK_SUBDIR}/" "$EXCLUDE_FILE"; then
        printf '%s/\n' "$WORK_SUBDIR" >> "$EXCLUDE_FILE"
    fi
fi

# Determine base branch when caller didn't supply one. Prefer
# git-local plumbing over `gh repo view` — `gh` makes a network call
# that hits the same TLS/sandbox problems documented in SKILL.md, and
# the default branch is locally discoverable from refs alone:
#   1. origin/HEAD symref (set automatically on `git clone`)
#   2. main / master if they exist on the remote
#   3. currently-checked-out branch
if [ -z "$BASE_BRANCH" ]; then
    BASE_BRANCH="$(git -C "$REPO_ROOT" symbolic-ref --short refs/remotes/origin/HEAD 2>/dev/null \
        | sed 's|^origin/||' || true)"
    if [ -z "$BASE_BRANCH" ]; then
        for b in main master; do
            if git -C "$REPO_ROOT" rev-parse --verify --quiet "refs/remotes/origin/$b" >/dev/null 2>&1; then
                BASE_BRANCH="$b"
                break
            fi
        done
    fi
    if [ -z "$BASE_BRANCH" ]; then
        BASE_BRANCH="$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo main)"
    fi
fi

mkdir -p "$WT_ROOT"

# Prune stale worktrees first — clears entries whose directories were
# deleted between runs but whose metadata still lingers under .git/.
git -C "$REPO_ROOT" worktree prune

# If the worktree already exists at the target path, reuse it.
if [ -d "${WT_PATH}/.git" ] || [ -f "${WT_PATH}/.git" ]; then
    printf '{"status":"ok","reused":true,"path":"%s","branch":"%s"}\n' \
        "$WT_PATH" "$BRANCH"
    exit 0
fi

# If the branch exists but isn't attached, attach it. Otherwise create
# both branch and worktree from base.
if git -C "$REPO_ROOT" show-ref --verify --quiet "refs/heads/${BRANCH}"; then
    git -C "$REPO_ROOT" worktree add "$WT_PATH" "$BRANCH" >/dev/null
else
    # Ensure we have the base branch locally; if it only exists on the
    # remote, fetch it.
    if ! git -C "$REPO_ROOT" show-ref --verify --quiet "refs/heads/${BASE_BRANCH}"; then
        git -C "$REPO_ROOT" fetch origin "$BASE_BRANCH:$BASE_BRANCH" >/dev/null 2>&1 || true
    fi
    git -C "$REPO_ROOT" worktree add -b "$BRANCH" "$WT_PATH" "$BASE_BRANCH" >/dev/null
fi

printf '{"status":"ok","reused":false,"path":"%s","branch":"%s","base":"%s"}\n' \
    "$WT_PATH" "$BRANCH" "$BASE_BRANCH"
