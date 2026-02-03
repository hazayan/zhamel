#!/usr/bin/env bash
set -euo pipefail

EFI_BIN="$1"
shift || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OVMF_CODE="$ROOT/lib/OVMF_CODE.4m.fd"
OVMF_VARS="$ROOT/lib/OVMF_VARS.4m.fd"

if [[ ! -f "$OVMF_CODE" || ! -f "$OVMF_VARS" ]]; then
  echo "OVMF firmware not found under $ROOT/lib" >&2
  exit 1
fi

WORK="$(mktemp -d)"
ESP="$WORK/esp"
mkdir -p "$ESP/EFI/BOOT"
cp "$EFI_BIN" "$ESP/EFI/BOOT/BOOTX64.EFI"
cp "$OVMF_VARS" "$WORK/OVMF_VARS.fd"
LOG_FILE="${UEFI_TEST_LOG:-}"

QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"

set +e
if [[ -n "$LOG_FILE" ]]; then
  "$QEMU_BIN" \
  -machine q35 \
  -m 512 \
  -net none \
  -serial stdio \
  -display none \
  -no-reboot \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
  -drive if=pflash,format=raw,file="$WORK/OVMF_VARS.fd" \
  -drive format=raw,file=fat:rw:"$ESP" \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  ${QEMU_EXTRA_ARGS:-} | tee "$LOG_FILE"
else
  "$QEMU_BIN" \
  -machine q35 \
  -m 512 \
  -net none \
  -serial stdio \
  -display none \
  -no-reboot \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
  -drive if=pflash,format=raw,file="$WORK/OVMF_VARS.fd" \
  -drive format=raw,file=fat:rw:"$ESP" \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  ${QEMU_EXTRA_ARGS:-}
fi
STATUS=$?
set -e
# isa-debug-exit returns (code << 1) | 1
if [[ $STATUS -eq 33 ]]; then
  exit 0
elif [[ $STATUS -eq 35 ]]; then
  if [[ -n "$LOG_FILE" ]]; then
    echo "UEFI test failure log ($LOG_FILE):" >&2
    sed -n '1,200p' "$LOG_FILE" >&2 || true
  fi
  exit 1
fi
if [[ $STATUS -ne 0 && -n "$LOG_FILE" ]]; then
  echo "UEFI test log ($LOG_FILE):" >&2
  sed -n '1,200p' "$LOG_FILE" >&2 || true
fi
exit $STATUS
