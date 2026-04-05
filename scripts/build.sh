#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/../core"
echo "=== SecretScan Build ==="
cargo build --release
SIZE=$(du -sh target/release/secretscan | cut -f1)
echo "✅  Built: target/release/secretscan ($SIZE)"
echo "Run ./scripts/install.sh to install."
