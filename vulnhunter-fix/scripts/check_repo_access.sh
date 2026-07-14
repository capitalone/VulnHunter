#!/usr/bin/env bash
set -euo pipefail

# Verify push/write access to a GitHub repo.
# Usage: check_repo_access.sh <github_url>
# Exit 0 = write access, Exit 1 = no write access

REPO_URL="${1:?Usage: check_repo_access.sh <github_url>}"

# Extract owner/repo from URL (handles https://github.com/org/repo and github.com/org/repo)
OWNER_REPO=$(echo "$REPO_URL" | sed -E 's|.*github\.com[:/]||; s|\.git$||')

GH_HOST="${VULNFIX_GH_HOST:-github.com}"

PERMISSIONS=$(GH_HOST="$GH_HOST" gh api "repos/${OWNER_REPO}" --jq '.permissions' 2>/dev/null) || {
  echo '{"error": "Cannot access repo API. Check authentication with: gh auth status"}'
  exit 1
}

HAS_PUSH=$(echo "$PERMISSIONS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('push', False))" 2>/dev/null)

if [ "$HAS_PUSH" = "True" ]; then
  echo "{\"repo\": \"${OWNER_REPO}\", \"push\": true}"
  exit 0
else
  echo "{\"repo\": \"${OWNER_REPO}\", \"push\": false}"
  exit 1
fi
