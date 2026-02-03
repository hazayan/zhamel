#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASSETS_DIR="${ASSETS_DIR:-$ROOT/tmp/integration/assets}"
OVMF_ASSETS_DIR="$ASSETS_DIR/ovmf"
CLEAN_TMP="${CLEAN_TMP:-1}"

if [[ "$CLEAN_TMP" == "1" ]]; then
  rm -rf "$ROOT/tmp/edk2" "$ROOT/tmp/brotli-src"
fi

if [[ -n "${CLEAN_ASSETS:-1}" ]]; then
  rm -rf "$ASSETS_DIR"
fi
if [[ -n "${CLEAN_EDK2:-1}" ]]; then
  rm -rf "$ROOT/tmp/edk2" "$ROOT/tmp/brotli-src"
fi

mkdir -p "$ASSETS_DIR"
mkdir -p "$OVMF_ASSETS_DIR"

URL_FILES=()
while IFS= read -r -d '' file; do
  URL_FILES+=("$file")
done < <(find "$ROOT/tests/integration/scenarios" -name "kernel.txz.url" -print0)

if [[ ${#URL_FILES[@]} -eq 0 ]]; then
  echo "No kernel.txz.url files found." >&2
  exit 0
fi

if command -v curl >/dev/null 2>&1; then
  FETCH=(curl -fsSL)
elif command -v wget >/dev/null 2>&1; then
  FETCH=(wget -q -O -)
else
  echo "Need curl or wget to download assets" >&2
  exit 1
fi

for url_file in "${URL_FILES[@]}"; do
  url="$(head -n 1 "$url_file" | sed -e 's/[[:space:]]*$//')"
  if [[ -z "$url" ]]; then
    continue
  fi
  out="$ASSETS_DIR/$(basename "$url")"
  if [[ -f "$out" ]]; then
    echo "Asset cached: $out"
    continue
  fi
  echo "Downloading: $url"
  if [[ "${FETCH[0]}" == "curl" ]]; then
    if ! curl -fsSL "$url" -o "$out"; then
      echo "WARN: download failed: $url" >&2
      rm -f "$out"
    fi
  else
    if ! wget -O "$out" "$url"; then
      echo "WARN: download failed: $url" >&2
      rm -f "$out"
    fi
  fi
done

OVMF_CODE_NAME="OVMF_CODE.4m.fd"
OVMF_VARS_NAME="OVMF_VARS.4m.fd"
OVMF_CODE_OUT="$OVMF_ASSETS_DIR/$OVMF_CODE_NAME"
OVMF_VARS_OUT="$OVMF_ASSETS_DIR/$OVMF_VARS_NAME"

OVMF_CODE_CANDIDATES=(
  "/usr/share/edk2/x64/$OVMF_CODE_NAME"
  "/usr/share/OVMF/$OVMF_CODE_NAME"
  "/usr/share/qemu/$OVMF_CODE_NAME"
)
OVMF_VARS_CANDIDATES=(
  "/usr/share/edk2/x64/$OVMF_VARS_NAME"
  "/usr/share/OVMF/$OVMF_VARS_NAME"
  "/usr/share/qemu/$OVMF_VARS_NAME"
)

if [[ ! -f "$OVMF_CODE_OUT" ]]; then
  for src in "${OVMF_CODE_CANDIDATES[@]}"; do
    if [[ -f "$src" ]]; then
      echo "Caching OVMF code: $src"
      cp "$src" "$OVMF_CODE_OUT"
      break
    fi
  done
fi
if [[ ! -f "$OVMF_VARS_OUT" ]]; then
  for src in "${OVMF_VARS_CANDIDATES[@]}"; do
    if [[ -f "$src" ]]; then
      echo "Caching OVMF vars: $src"
      cp "$src" "$OVMF_VARS_OUT"
      break
    fi
  done
fi

if [[ -f "$ROOT/tests/integration/scenarios/zfs-tang-unlock/zfs-real.conf" ]]; then
  if rg -q '^kunci_http_driver=' "$ROOT/tests/integration/scenarios/zfs-tang-unlock/zfs-real.conf"; then
    echo "Preparing edk2 HTTP drivers for zfs-tang-unlock"
    "$ROOT/tools/edk2-build-network-drivers.sh"
  fi
fi
