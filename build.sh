#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_BIN=${OUT_BIN:-"$ROOT_DIR/dist/discovr"}
GO_TAGS=${GO_TAGS:-}

mkdir -p "$(dirname "$OUT_BIN")"

echo "[+] Building Discovr binary"
if [[ -n "$GO_TAGS" ]]; then
  echo "    • tags: $GO_TAGS"
  go build -tags "$GO_TAGS" -o "$OUT_BIN" ./cmd/discovr
else
  go build -o "$OUT_BIN" ./cmd/discovr
fi

echo "[+] Output: $OUT_BIN"
