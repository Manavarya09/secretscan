#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="$SCRIPT_DIR/../core/target/release/secretscan"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.cargo/bin}"

if [[ ! -f "$BINARY" ]]; then
  echo "Building first..."
  "$SCRIPT_DIR/build.sh"
fi

echo "=== SecretScan Install ==="
mkdir -p "$INSTALL_DIR"
cp "$BINARY" "$INSTALL_DIR/secretscan"
chmod +x "$INSTALL_DIR/secretscan"
mkdir -p "$HOME/.secretscan"

echo "✅  Installed to $INSTALL_DIR/secretscan"
echo ""
echo "Auto-configure Claude Code hook:"
echo "  secretscan setup"
echo ""
echo "Or manually add to ~/.claude/settings.json:"
echo '  { "hooks": { "PostToolUse": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "secretscan hook" }] }] } }'
