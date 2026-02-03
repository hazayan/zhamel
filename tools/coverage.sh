#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
  echo "cargo-llvm-cov is required (install with: cargo install cargo-llvm-cov)" >&2
  exit 1
fi

cargo llvm-cov --target x86_64-unknown-uefi --summary-only
