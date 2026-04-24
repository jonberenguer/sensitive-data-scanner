#!/usr/bin/env bash
# build.sh — builds the sensitive-data-scanner Go binary using a Docker container.
# No local Go installation required.
#
# Usage:
#   ./build.sh                  # build all targets
#   ./build.sh linux            # Linux amd64 only
#   ./build.sh linux-arm64      # Linux arm64 only
#   ./build.sh windows          # Windows amd64 only
#
# Output directory: build/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
IMAGE="golang:1.22-alpine"
TARGET="${1:-all}"

mkdir -p "$BUILD_DIR"

_build() {
  local goos="$1" goarch="$2" out="$3"
  echo "  [${goos}/${goarch}] Building..."
  docker run --rm \
    -v "$SCRIPT_DIR/src:/src:ro" \
    -v "$BUILD_DIR:/out" \
    -w /src \
    "$IMAGE" \
    sh -c "CGO_ENABLED=0 GOOS=${goos} GOARCH=${goarch} go build -ldflags='-s -w' -o /out/${out} ."
  echo "  [${goos}/${goarch}] -> build/${out}"
}

echo "=== sensitive-data-scanner build ==="

case "$TARGET" in
  linux)       _build linux   amd64 scanner-linux-amd64 ;;
  linux-arm64) _build linux   arm64 scanner-linux-arm64 ;;
  windows)     _build windows amd64 scanner-windows-amd64.exe ;;
  all)
    _build linux   amd64 scanner-linux-amd64
    _build linux   arm64 scanner-linux-arm64
    _build windows amd64 scanner-windows-amd64.exe
    ;;
  *)
    echo "Unknown target: '$TARGET'. Use: linux | linux-arm64 | windows | all" >&2
    exit 1
    ;;
esac

echo ""
echo "Done. Binaries are in: $BUILD_DIR"
