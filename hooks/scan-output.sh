#!/usr/bin/env bash
# SecretScan PostToolUse hook — redacts secrets from tool output before they
# enter Claude's context window.
#
# Add to ~/.claude/settings.json:
# {
#   "hooks": {
#     "PostToolUse": [
#       { "matcher": "*", "hooks": [{ "type": "command", "command": "/path/to/secretscan hook" }] }
#     ]
#   }
# }
# Or run: secretscan setup

set -euo pipefail

SECRETSCAN="${SECRETSCAN_BIN:-secretscan}"
if ! command -v "$SECRETSCAN" &>/dev/null; then
  for candidate in \
    "$HOME/.cargo/bin/secretscan" \
    "/usr/local/bin/secretscan" \
    "$(dirname "$0")/../core/target/release/secretscan"; do
    if [[ -x "$candidate" ]]; then
      SECRETSCAN="$candidate"
      break
    fi
  done
fi

SESSION_ID="${CLAUDE_SESSION_ID:-default}"
INPUT=$(cat)

if command -v "$SECRETSCAN" &>/dev/null || [[ -x "$SECRETSCAN" ]]; then
  echo "$INPUT" | "$SECRETSCAN" hook --session "$SESSION_ID" 2>/dev/null || echo "$INPUT"
else
  echo "$INPUT"
fi
