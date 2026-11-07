#!/usr/bin/env bash
# Launch Claude Code for /vulnhunt on Claude or DeepSeek.
#
# Usage:
#   ./vulnhunt.sh            # asks which provider
#   ./vulnhunt.sh claude     # skip the menu
#   ./vulnhunt.sh deepseek   # skip the menu (needs DEEPSEEK_API_KEY)
#
# Any extra arguments are passed through to `claude`.
#
# DeepSeek settings apply to this one `claude` process only, so your normal
# claude.ai login is untouched. Override the defaults below via env vars.
set -euo pipefail

DEEPSEEK_BASE_URL="${DEEPSEEK_BASE_URL:-https://api.deepseek.com/anthropic}"
DEEPSEEK_PRO_MODEL="${DEEPSEEK_PRO_MODEL:-deepseek-v4-pro}"
DEEPSEEK_FLASH_MODEL="${DEEPSEEK_FLASH_MODEL:-deepseek-v4-flash}"

provider="${1:-}"
if [ -n "$provider" ]; then
    shift
else
    echo "Pick provider:"
    echo "  1) Claude"
    echo "  2) DeepSeek"
    read -r -p "> " choice
    case "$choice" in
        1) provider="claude" ;;
        2) provider="deepseek" ;;
        *) echo "error: pick 1 or 2" >&2; exit 1 ;;
    esac
fi

if ! command -v claude >/dev/null 2>&1; then
    echo "error: claude CLI not found on PATH" >&2
    exit 1
fi

case "$provider" in
    claude)
        exec claude --model opus "$@"
        ;;
    deepseek)
        if [ -z "${DEEPSEEK_API_KEY:-}" ]; then
            echo "error: DEEPSEEK_API_KEY is not set (add it to ~/.zshrc)" >&2
            exit 1
        fi
        # Base URL must NOT end in /v1 — the CLI appends /v1/messages.
        # ANTHROPIC_API_KEY is dropped so a Claude key is never sent to DeepSeek.
        exec env -u ANTHROPIC_API_KEY \
            ANTHROPIC_BASE_URL="$DEEPSEEK_BASE_URL" \
            ANTHROPIC_AUTH_TOKEN="$DEEPSEEK_API_KEY" \
            ANTHROPIC_DEFAULT_OPUS_MODEL="$DEEPSEEK_PRO_MODEL" \
            ANTHROPIC_DEFAULT_SONNET_MODEL="$DEEPSEEK_FLASH_MODEL" \
            ANTHROPIC_DEFAULT_HAIKU_MODEL="$DEEPSEEK_FLASH_MODEL" \
            CLAUDE_CODE_SUBAGENT_MODEL="inherit" \
            API_TIMEOUT_MS="600000" \
            claude --model opus "$@"
        ;;
    *)
        echo "error: provider must be 'claude' or 'deepseek', got '$provider'" >&2
        exit 1
        ;;
esac
