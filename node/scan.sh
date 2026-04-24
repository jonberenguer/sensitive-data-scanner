#!/usr/bin/env bash
# scan.sh — Linux/macOS wrapper for the sensitive data scanner
# Usage: ./scan.sh <directory> [options]  (see --help for full option list)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODE_BIN="${NODE_BIN:-node}"

if ! command -v "$NODE_BIN" &>/dev/null; then
  echo "Error: Node.js not found. Install it from https://nodejs.org, then re-run." >&2
  exit 1
fi

exec "$NODE_BIN" "$SCRIPT_DIR/scanner.js" "$@"
