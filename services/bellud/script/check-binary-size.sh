#!/usr/bin/env bash
# Measures the binary size added by the scanner libraries (Requirement 19.8).
# Builds cmd/sizeprobe twice with release flags: once without the scanner
# imports (tag sizebase) and once with them, then fails when the delta exceeds
# 150 MiB. Set SIZEPROBE_TAGS to change the scanner build tags (default: osvmatch).
set -euo pipefail

budget=157286400
tags="${SIZEPROBE_TAGS-osvmatch}"
cd "$(dirname "$0")/.."
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

build() {
  go build -trimpath -ldflags "-s -w" -tags "$1" -o "$2" ./cmd/sizeprobe
}

build "sizeprobe,sizebase" "$out/base"
build "sizeprobe${tags:+,$tags}" "$out/full"

base=$(stat -c %s "$out/base")
full=$(stat -c %s "$out/full")
delta=$((full - base))
echo "tags:     sizeprobe${tags:+,$tags}"
echo "baseline: $base bytes"
echo "probe:    $full bytes"
echo "delta:    $delta bytes ($((delta / 1048576)) MiB), budget $budget bytes"

if [ "$delta" -gt "$budget" ]; then
  echo "FAIL: scanner libraries add $((delta - budget)) bytes over the 150 MiB budget" >&2
  exit 1
fi
echo "OK"
