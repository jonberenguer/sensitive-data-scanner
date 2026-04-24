#!/usr/bin/env bash
# scan.sh — Linux/macOS wrapper for the sensitive data scanner (Go binary)
# Usage: ./scan.sh <directory> [options]  (see --help for full option list)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SCRIPT_DIR/build/scanner-linux-amd64"
PATTERNS="$SCRIPT_DIR/patterns.json"

if [ ! -f "$BINARY" ]; then
  echo "Error: scanner binary not found at $BINARY" >&2
  echo "Run './build.sh' (or './build.sh linux') to build it first." >&2
  exit 1
fi

exec "$BINARY" --patterns "$PATTERNS" "$@"
