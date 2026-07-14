#!/usr/bin/env bash
set -euo pipefail

# Clone (or fork then clone) a GitHub repo.
# When forking: creates a private fork and adds collaborators.
# Usage: clone_repo.sh <github_url> <target_dir> [--fork [--fork-org ORG] [--fork-prefix PREFIX]]

REPO_URL="${1:?Usage: clone_repo.sh <github_url> <target_dir> [--fork [--fork-org ORG] [--fork-prefix PREFIX]]}"
TARGET_DIR="${2:?Usage: clone_repo.sh <github_url> <target_dir> [--fork ...]}"
shift 2

DO_FORK=""
FORK_ORG=""
FORK_PREFIX=""
SKILL_DIR="${VULNFIX_SKILL_DIR:-$(dirname "$0")/..}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fork) DO_FORK="true"; shift ;;
    --fork-org) FORK_ORG="$2"; shift 2 ;;
    --fork-prefix) FORK_PREFIX="$2"; shift 2 ;;
    *) shift ;;
  esac
done

GH_HOST="${VULNFIX_GH_HOST:-github.com}"
OWNER_REPO=$(echo "$REPO_URL" | sed -E 's|.*github\.com[:/]||; s|\.git$||; s|/tree/.*||')
REPO_NAME=$(basename "$OWNER_REPO")

if [ "$DO_FORK" = "true" ]; then
  # Determine fork name
  FORK_REPO_NAME="${REPO_NAME}"
  if [ -n "$FORK_PREFIX" ]; then
    FORK_REPO_NAME="${FORK_PREFIX}-${REPO_NAME}"
  fi

  # Determine fork org
  FORK_TARGET=""
  if [ -n "$FORK_ORG" ]; then
    FORK_TARGET="--org $FORK_ORG"
  fi

  echo "Forking ${OWNER_REPO} as ${FORK_REPO_NAME}..."
  GH_HOST="$GH_HOST" gh repo fork "$OWNER_REPO" --fork-name "$FORK_REPO_NAME" $FORK_TARGET --clone=false 2>&1

  # Determine the full fork path
  if [ -n "$FORK_ORG" ]; then
    FORK_FULL="${FORK_ORG}/${FORK_REPO_NAME}"
  else
    FORK_FULL="$(gh api user --jq '.login')/${FORK_REPO_NAME}"
  fi

  # Set fork to private
  echo "Setting fork to private..."
  gh repo edit "$FORK_FULL" --visibility private --accept-visibility-change-consequences 2>&1 || true

  # Enable issues
  gh repo edit "$FORK_FULL" --enable-issues 2>&1 || true

  # Add collaborators from collaborators.json
  COLLAB_FILE="${SKILL_DIR}/collaborators.json"
  if [ -f "$COLLAB_FILE" ]; then
    echo "Adding collaborators from ${COLLAB_FILE}..."
    # Pass values via argv to a single-quoted heredoc so the shell
    # never expands them into Python source. Otherwise a fork name
    # carrying a quote or backslash could escape the Python string
    # context.
    python3 - "$COLLAB_FILE" "$FORK_FULL" <<'PY'
import json
import subprocess
import sys

collab_file, fork_full = sys.argv[1], sys.argv[2]
with open(collab_file) as f:
    data = json.load(f)
for c in data.get("collaborators", []):
    user = c["username"]
    role = c.get("role", "write")
    print(f"  Adding {user} with {role} access...")
    result = subprocess.run(
        [
            "gh", "api",
            f"repos/{fork_full}/collaborators/{user}",
            "-X", "PUT",
            "-f", f"permission={role}",
        ],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"  Warning: Failed to add {user}: {result.stderr.strip()}", file=sys.stderr)
PY
  fi

  # Clone the fork
  echo "Cloning fork ${FORK_FULL}..."
  git -c init.templateDir= clone --template= --depth 1 "https://github.com/${FORK_FULL}.git" "${TARGET_DIR}/${FORK_REPO_NAME}" 2>&1

  if [ -d "${TARGET_DIR}/${FORK_REPO_NAME}" ]; then
    echo "{\"status\": \"ok\", \"path\": \"${TARGET_DIR}/${FORK_REPO_NAME}\", \"repo\": \"${FORK_FULL}\", \"upstream\": \"${OWNER_REPO}\", \"visibility\": \"private\"}"
    exit 0
  else
    echo "{\"status\": \"error\", \"message\": \"Clone failed for ${FORK_FULL}\"}"
    exit 1
  fi

else
  echo "Cloning ${OWNER_REPO}..."
  git -c init.templateDir= clone --template= --depth 1 "https://github.com/${OWNER_REPO}.git" "${TARGET_DIR}/${REPO_NAME}" 2>&1

  if [ -d "${TARGET_DIR}/${REPO_NAME}" ]; then
    echo "{\"status\": \"ok\", \"path\": \"${TARGET_DIR}/${REPO_NAME}\", \"repo\": \"${OWNER_REPO}\"}"
    exit 0
  else
    echo "{\"status\": \"error\", \"message\": \"Clone failed for ${OWNER_REPO}\"}"
    exit 1
  fi
fi
