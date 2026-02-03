#!/usr/bin/env bash
set -euo pipefail

SCENARIO="${1:-}"
if [[ -z "$SCENARIO" ]]; then
  echo "Usage: $0 <scenario-name>" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCEN_DIR="$ROOT/tests/integration/scenarios/$SCENARIO"
OVMF_CODE_DEFAULT="$ROOT/lib/OVMF_CODE.4m.fd"
OVMF_VARS_DEFAULT="$ROOT/lib/OVMF_VARS.4m.fd"
OVMF_CODE_ASSETS="$ROOT/tmp/integration/assets/ovmf/OVMF_CODE.4m.fd"
OVMF_VARS_ASSETS="$ROOT/tmp/integration/assets/ovmf/OVMF_VARS.4m.fd"
OVMF_CODE="${OVMF_CODE_PATH:-$OVMF_CODE_DEFAULT}"
OVMF_VARS="${OVMF_VARS_PATH:-$OVMF_VARS_DEFAULT}"
EFI_BIN="${EFI_BIN:-$ROOT/target/x86_64-unknown-uefi/debug/zhamel.efi}"
QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
TIMEOUT_SEC="${TIMEOUT_SEC:-10}"
ATTEMPTS="${ATTEMPTS:-1}"
QEMU_RNG="${QEMU_RNG:-1}"
RAW_FAT_MB="${RAW_FAT_MB:-256}"
KEEP_WORK_ON_FAIL="${KEEP_WORK_ON_FAIL:-1}"
SHOW_LOG_ON_FAIL="${SHOW_LOG_ON_FAIL:-1}"

if [[ ! -d "$SCEN_DIR" ]]; then
  echo "Scenario not found: $SCEN_DIR" >&2
  exit 2
fi
if [[ ! -f "$OVMF_CODE" && -f "$OVMF_CODE_ASSETS" ]]; then
  OVMF_CODE="$OVMF_CODE_ASSETS"
fi
if [[ ! -f "$OVMF_VARS" && -f "$OVMF_VARS_ASSETS" ]]; then
  OVMF_VARS="$OVMF_VARS_ASSETS"
fi
if [[ ! -f "$OVMF_CODE" || ! -f "$OVMF_VARS" ]]; then
  echo "OVMF firmware not found (set OVMF_CODE_PATH/OVMF_VARS_PATH to override)" >&2
  exit 1
fi

if [[ -z "${NO_BUILD:-}" ]]; then
  (cd "$ROOT" && cargo build --target x86_64-unknown-uefi)
fi
if [[ ! -f "$EFI_BIN" ]]; then
  echo "EFI binary not found: $EFI_BIN" >&2
  exit 1
fi

EXPECT_FILE="$SCEN_DIR/expect.txt"
KERNEL_URL_FILE="$SCEN_DIR/kernel.txz.url"
KERNEL_FULL_FILE="$SCEN_DIR/kernel.txz.full"
KERNEL_MODULES_FILE="$SCEN_DIR/kernel.txz.modules"
KERNEL_ESP_SKIP_FILE="$SCEN_DIR/kernel.txz.esp.skip"
TIMEOUT_FILE="$SCEN_DIR/timeout.sec"
ISO_ROOT_DIR="$SCEN_DIR/iso.root"
MANIFEST_PATHS_FILE="$SCEN_DIR/manifest.paths"
MANIFEST_OUT_FILE="$SCEN_DIR/manifest.out"
MANIFEST_CORRUPT_FILE="$SCEN_DIR/manifest.corrupt"
ZFS_PROBE_FILE="$SCEN_DIR/zfs-probe.conf"
ZFS_REAL_FILE="$SCEN_DIR/zfs-real.conf"
KERNEL_TXZ_PATH="${KERNEL_TXZ_PATH:-}"
KERNEL_TXZ=""
ASSETS_DIR="${ASSETS_DIR:-$ROOT/tmp/integration/assets}"

if [[ -n "$KERNEL_TXZ_PATH" ]]; then
  KERNEL_TXZ="$KERNEL_TXZ_PATH"
elif [[ -f "$KERNEL_URL_FILE" ]]; then
  KERNEL_TXZ_URL="$(head -n 1 "$KERNEL_URL_FILE" | sed -e 's/[[:space:]]*$//')"
  if [[ -n "$KERNEL_TXZ_URL" ]]; then
    mkdir -p "$ASSETS_DIR"
    KERNEL_TXZ="$ASSETS_DIR/$(basename "$KERNEL_TXZ_URL")"
    if [[ ! -f "$KERNEL_TXZ" ]]; then
      if command -v curl >/dev/null 2>&1; then
        if ! curl -fsSL "$KERNEL_TXZ_URL" -o "$KERNEL_TXZ"; then
          echo "Asset download failed: $KERNEL_TXZ_URL" >&2
          exit 1
        fi
      elif command -v wget >/dev/null 2>&1; then
        if ! wget -O "$KERNEL_TXZ" "$KERNEL_TXZ_URL"; then
          echo "Asset download failed: $KERNEL_TXZ_URL" >&2
          exit 1
        fi
      else
        echo "Need curl or wget to download kernel.txz" >&2
        exit 1
      fi
    fi
    if [[ ! -f "$KERNEL_TXZ" ]]; then
      echo "Kernel asset missing: $KERNEL_TXZ" >&2
      exit 1
    fi
  fi
fi

for attempt in $(seq 1 "$ATTEMPTS"); do
  RUN_TIMEOUT="$TIMEOUT_SEC"
  if [[ -f "$TIMEOUT_FILE" ]]; then
    RUN_TIMEOUT="$(head -n 1 "$TIMEOUT_FILE" | sed -e 's/[[:space:]]*$//')"
  fi
  WORK="$(mktemp -d)"
  ESP="$WORK/esp"
  ESP_IMG="$WORK/esp.img"
  ISO_IMG="$WORK/iso.iso"
  ISO_WORK="$WORK/iso-root"
  ZFS_IMG="$WORK/zfs.img"
  LOG_FILE="$WORK/serial.log"
  QEMU_LOG="$WORK/qemu.log"
NET_ENABLE=""
  mkdir -p "$ESP/EFI/BOOT" "$ESP/EFI/FreeBSD" "$ESP/boot"
  cp "$EFI_BIN" "$ESP/EFI/BOOT/BOOTX64.EFI"
  cp "$OVMF_VARS" "$WORK/OVMF_VARS.fd"
  printf '%s\r\n' '\\EFI\\BOOT\\BOOTX64.EFI' > "$ESP/startup.nsh"

  if [[ -f "$SCEN_DIR/loader.env" ]]; then
    cp "$SCEN_DIR/loader.env" "$ESP/EFI/FreeBSD/loader.env"
  fi
  if [[ -f "$SCEN_DIR/loader.conf" ]]; then
    cp "$SCEN_DIR/loader.conf" "$ESP/boot/loader.conf"
  fi
  if [[ -n "$KERNEL_TXZ" && ! -f "$KERNEL_ESP_SKIP_FILE" ]]; then
    mkdir -p "$ESP/boot/kernel"
    if ! tar -xJf "$KERNEL_TXZ" -C "$ESP" "./boot/kernel/kernel"; then
      tar -xJf "$KERNEL_TXZ" -C "$ESP" "boot/kernel/kernel"
    fi
    if [[ ! -f "$ESP/boot/kernel/kernel" ]]; then
      echo "kernel extraction failed: $ESP/boot/kernel/kernel missing" >&2
      exit 1
    fi
    if [[ -f "$KERNEL_MODULES_FILE" ]]; then
      while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
        if [[ -z "$line" ]]; then
          continue
        fi
        if ! tar -xJf "$KERNEL_TXZ" -C "$ESP" "$line"; then
          echo "module extraction failed: $line" >&2
          exit 1
        fi
      done < "$KERNEL_MODULES_FILE"
    elif [[ -f "$KERNEL_FULL_FILE" ]]; then
      if ! tar -xJf "$KERNEL_TXZ" -C "$ESP" "./boot/kernel"; then
        tar -xJf "$KERNEL_TXZ" -C "$ESP" "boot/kernel"
      fi
    fi
  fi

  if [[ -f "$MANIFEST_PATHS_FILE" ]]; then
    if command -v sha256sum >/dev/null 2>&1; then
      HASH_TOOL="sha256sum"
    elif command -v shasum >/dev/null 2>&1; then
      HASH_TOOL="shasum -a 256"
    elif command -v openssl >/dev/null 2>&1; then
      HASH_TOOL="openssl dgst -sha256"
    else
      echo "sha256sum or shasum or openssl is required for manifest scenarios" >&2
      exit 1
    fi
    MANIFEST_OUT="/boot/manifest"
    if [[ -f "$MANIFEST_OUT_FILE" ]]; then
      MANIFEST_OUT="$(head -n 1 "$MANIFEST_OUT_FILE" | sed -e 's/[[:space:]]*$//')"
    fi
    CORRUPT_LIST=""
    if [[ -f "$MANIFEST_CORRUPT_FILE" ]]; then
      CORRUPT_LIST="$(sed -e 's/[[:space:]]*$//' "$MANIFEST_CORRUPT_FILE")"
    fi
    MANIFEST_HOST="$ESP/${MANIFEST_OUT#/}"
    mkdir -p "$(dirname "$MANIFEST_HOST")"
    : > "$MANIFEST_HOST"
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%%#*}"
      line="$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
      if [[ -z "$line" ]]; then
        continue
      fi
      SRC="$ESP/${line#/}"
      if [[ ! -f "$SRC" ]]; then
        echo "manifest source missing: $line" >&2
        exit 1
      fi
      if [[ "$HASH_TOOL" == "openssl dgst -sha256" ]]; then
        HASH="$($HASH_TOOL "$SRC" | awk '{print $2}')"
      else
        HASH="$($HASH_TOOL "$SRC" | awk '{print $1}')"
      fi
      if [[ -n "$CORRUPT_LIST" ]] && printf '%s\n' "$CORRUPT_LIST" | rg -q "^${line}$"; then
        if [[ "${HASH:0:1}" == "0" ]]; then
          HASH="1${HASH:1}"
        else
          HASH="0${HASH:1}"
        fi
      fi
      printf '%s %s\n' "$HASH" "$line" >> "$MANIFEST_HOST"
    done < "$MANIFEST_PATHS_FILE"
  fi

  ISO_ARGS=()
  if [[ -d "$ISO_ROOT_DIR" ]]; then
    if command -v genisoimage >/dev/null 2>&1; then
      ISO_TOOL="genisoimage"
    elif command -v mkisofs >/dev/null 2>&1; then
      ISO_TOOL="mkisofs"
    else
      echo "genisoimage or mkisofs is required for ISO scenarios" >&2
      exit 1
    fi
    mkdir -p "$ISO_WORK"
    cp -a "$ISO_ROOT_DIR"/. "$ISO_WORK"/
    if [[ -n "$KERNEL_TXZ" ]]; then
      mkdir -p "$ISO_WORK/boot/kernel"
      if ! tar -xJf "$KERNEL_TXZ" -C "$ISO_WORK" "./boot/kernel/kernel"; then
        tar -xJf "$KERNEL_TXZ" -C "$ISO_WORK" "boot/kernel/kernel"
      fi
      if [[ -f "$KERNEL_MODULES_FILE" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
          line="${line%%#*}"
          line="$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
          if [[ -z "$line" ]]; then
            continue
          fi
          if ! tar -xJf "$KERNEL_TXZ" -C "$ISO_WORK" "$line"; then
            echo "module extraction failed: $line" >&2
            exit 1
          fi
        done < "$KERNEL_MODULES_FILE"
      fi
    fi
    "$ISO_TOOL" -J -R -o "$ISO_IMG" "$ISO_WORK" >/dev/null
    ISO_ARGS=(
      -drive if=none,format=raw,readonly=on,file="$ISO_IMG",id=iso
      -device virtio-blk-pci,drive=iso,bootindex=1
    )
  fi

  ZFS_ARGS=()
  if [[ -f "$ZFS_PROBE_FILE" && -f "$ZFS_REAL_FILE" ]]; then
    echo "zfs-probe.conf and zfs-real.conf are mutually exclusive" >&2
    exit 1
  fi
  if [[ -f "$ZFS_PROBE_FILE" ]]; then
    if command -v python3 >/dev/null 2>&1; then
      PYTHON_BIN="python3"
    elif command -v python >/dev/null 2>&1; then
      PYTHON_BIN="python"
    else
      echo "python is required for zfs-probe scenarios" >&2
      exit 1
    fi
    ZFS_POOL_GUID="$(awk -F= '/^pool_guid=/{print $2}' "$ZFS_PROBE_FILE")"
    ZFS_POOL_TXG="$(awk -F= '/^pool_txg=/{print $2}' "$ZFS_PROBE_FILE")"
    ZFS_BOOTONCE="$(awk -F= '/^bootonce=/{print $2}' "$ZFS_PROBE_FILE")"
    ZFS_DISK_SIZE="$(awk -F= '/^disk_size=/{print $2}' "$ZFS_PROBE_FILE")"
    if [[ -z "$ZFS_POOL_GUID" ]]; then
      echo "zfs-probe.conf missing pool_guid" >&2
      exit 1
    fi
    export ZFS_POOL_GUID ZFS_POOL_TXG ZFS_BOOTONCE ZFS_DISK_SIZE ZFS_IMG
    "$PYTHON_BIN" - <<'PY'
import hashlib
import os

pool_guid = int(os.environ["ZFS_POOL_GUID"], 0)
pool_txg = int(os.environ.get("ZFS_POOL_TXG") or "1", 0)
bootonce = os.environ.get("ZFS_BOOTONCE") or ""
disk_size = int(os.environ.get("ZFS_DISK_SIZE") or str(8 * 1024 * 1024), 0)
out_path = os.environ["ZFS_IMG"]

VDEV_PAD_SIZE = 8 * 1024
VDEV_PHYS_SIZE = 112 * 1024
VDEV_LABEL_SIZE = 256 * 1024
ZIO_ECK_SIZE = 40
ZEC_MAGIC = 0x0210da7ab10c7a11

def align4(data):
    while len(data) % 4 != 0:
        data += b"\x00"
    return data

def nvpair_u64(name, value):
    body = (len(name) + 1).to_bytes(4, "big")
    body += name.encode() + b"\x00"
    body = align4(body)
    body += (8).to_bytes(4, "big")
    body += (1).to_bytes(4, "big")
    body += int(value).to_bytes(8, "big")
    size = 8 + len(body)
    return size.to_bytes(4, "big") + size.to_bytes(4, "big") + body

def nvpair_string(name, value):
    body = (len(name) + 1).to_bytes(4, "big")
    body += name.encode() + b"\x00"
    body = align4(body)
    body += (9).to_bytes(4, "big")
    body += (1).to_bytes(4, "big")
    body += (len(value) + 1).to_bytes(4, "big")
    body += value.encode() + b"\x00"
    body = align4(body)
    size = 8 + len(body)
    return size.to_bytes(4, "big") + size.to_bytes(4, "big") + body

def build_nvlist(pairs):
    buf = bytearray()
    buf += bytes([1, 0, 0, 0])
    buf += (0).to_bytes(4, "big")
    buf += (0).to_bytes(4, "big")
    for pair in pairs:
        buf += pair
    buf += (0).to_bytes(4, "big")
    buf += (0).to_bytes(4, "big")
    return buf

def build_label_block(payload, offset):
    buf = bytearray(payload)
    buf += b"\x00" * ZIO_ECK_SIZE
    buf[-ZIO_ECK_SIZE:-ZIO_ECK_SIZE + 8] = ZEC_MAGIC.to_bytes(8, "little")
    checksum_offset = len(payload) + 8
    verifier = [offset, 0, 0, 0]
    verifier_bytes = b"".join(v.to_bytes(8, "little") for v in verifier)
    h = hashlib.sha256()
    h.update(buf[:checksum_offset])
    h.update(verifier_bytes)
    if checksum_offset + 32 < len(buf):
        h.update(buf[checksum_offset + 32:])
    digest = h.digest()
    for idx in range(4):
        word = int.from_bytes(digest[idx * 8:idx * 8 + 8], "big")
        buf[checksum_offset + idx * 8:checksum_offset + idx * 8 + 8] = word.to_bytes(8, "little")
    return buf

bootenv_payload = bytearray(VDEV_PAD_SIZE - ZIO_ECK_SIZE)
bootenv_payload[0:8] = (1).to_bytes(8, "big")
if bootonce:
    nv = build_nvlist([nvpair_string("freebsd:bootonce", bootonce)])
    bootenv_payload[8:8 + len(nv)] = nv
bootenv_block = build_label_block(bootenv_payload, VDEV_PAD_SIZE)

nv = build_nvlist([nvpair_u64("pool_guid", pool_guid), nvpair_u64("txg", pool_txg)])
vdev_payload = bytearray(VDEV_PHYS_SIZE - ZIO_ECK_SIZE)
vdev_payload[:len(nv)] = nv
vdev_phys_block = build_label_block(vdev_payload, VDEV_PAD_SIZE * 2)

label = bytearray(VDEV_LABEL_SIZE)
label[VDEV_PAD_SIZE:VDEV_PAD_SIZE + len(bootenv_block)] = bootenv_block
label[VDEV_PAD_SIZE * 2:VDEV_PAD_SIZE * 2 + len(vdev_phys_block)] = vdev_phys_block

disk = bytearray(disk_size)
disk[:len(label)] = label
with open(out_path, "wb") as f:
    f.write(disk)
PY
    ZFS_ARGS=(
      -drive if=none,format=raw,file="$ZFS_IMG",id=zfsdisk
      -device virtio-blk-pci,drive=zfsdisk,bootindex=2
    )
  fi
  if [[ -f "$ZFS_REAL_FILE" ]]; then
    if ! command -v zpool >/dev/null 2>&1 || ! command -v zfs >/dev/null 2>&1; then
      echo "zfs-real requires zpool and zfs tools" >&2
      exit 1
    fi
    if [[ "$(id -u)" -eq 0 ]]; then
      SUDO_CMD=""
    elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
      SUDO_CMD="sudo -n"
    else
      echo "zfs-real requires root or passwordless sudo" >&2
      exit 1
    fi
    ZFS_REAL_POOL_NAME="$(awk -F= '/^pool_name=/{print $2}' "$ZFS_REAL_FILE")"
    ZFS_REAL_DISK_SIZE="$(awk -F= '/^disk_size=/{print $2}' "$ZFS_REAL_FILE")"
    ZFS_REAL_BOOTENVS="$(awk -F= '/^bootenvs=/{print $2}' "$ZFS_REAL_FILE")"
    ZFS_REAL_ASHIFT="$(awk -F= '/^ashift=/{print $2}' "$ZFS_REAL_FILE")"
    ZFS_REAL_BOOTFS="$(awk -F= '/^bootfs=/{print $2}' "$ZFS_REAL_FILE")"
    ZFS_REAL_POPULATE_KERNEL="$(awk -F= '/^populate_kernel=/{print $2}' "$ZFS_REAL_FILE")"
    ZFS_REAL_BOOTENV_ENCRYPTED="$(awk -F= '/^bootenv_encrypted=/{print $2}' "$ZFS_REAL_FILE")"
    ZFS_REAL_BOOTENV_PASSPHRASE="$(awk -F= '/^bootenv_passphrase=/{print $2}' "$ZFS_REAL_FILE")"
    KUNCI_TANG="$(awk -F= '/^kunci_tang=/{print $2}' "$ZFS_REAL_FILE")"
    KUNCI_PORT="$(awk -F= '/^kunci_port=/{print $2}' "$ZFS_REAL_FILE")"
    KUNCI_HTTP="$(awk -F= '/^kunci_http=/{print $2}' "$ZFS_REAL_FILE")"
    KUNCI_HTTP_DRIVER="$(awk -F= '/^kunci_http_driver=/{print $2}' "$ZFS_REAL_FILE")"
    KUNCI_TRUST="$(awk -F= '/^kunci_trust=/{print $2}' "$ZFS_REAL_FILE")"
    KUNCI_THP="$(awk -F= '/^kunci_thp=/{print $2}' "$ZFS_REAL_FILE")"
    if [[ -z "$ZFS_REAL_POOL_NAME" ]]; then
      ZFS_REAL_POOL_NAME="zhameltest"
    fi
    if [[ -z "$ZFS_REAL_DISK_SIZE" ]]; then
      ZFS_REAL_DISK_SIZE="256M"
    fi
    if [[ -z "$ZFS_REAL_BOOTENVS" ]]; then
      ZFS_REAL_BOOTENVS="default,alt"
    fi
    if [[ -z "$ZFS_REAL_ASHIFT" ]]; then
      ZFS_REAL_ASHIFT="12"
    fi
    if [[ -n "$ZFS_REAL_BOOTENV_ENCRYPTED" && -z "$ZFS_REAL_BOOTENV_PASSPHRASE" ]]; then
      ZFS_REAL_BOOTENV_PASSPHRASE="zhamel-pass"
    fi
    if [[ -n "$KUNCI_TANG" && -z "$KUNCI_PORT" ]]; then
      KUNCI_PORT="8080"
    fi
    if $SUDO_CMD zpool list -H -o name | awk -v name="$ZFS_REAL_POOL_NAME" '$0==name{exit 0} END{exit 1}'; then
      echo "zfs-real pool already exists: $ZFS_REAL_POOL_NAME" >&2
      exit 1
    fi
    if [[ "$ZFS_IMG" != "$WORK/"* ]]; then
      echo "zfs-real unsafe path for ZFS_IMG: $ZFS_IMG" >&2
      exit 1
    fi
    if [[ -b "$ZFS_IMG" ]]; then
      echo "zfs-real refuses block device: $ZFS_IMG" >&2
      exit 1
    fi
    if $SUDO_CMD zpool list -v -H 2>/dev/null | rg -q --fixed-strings "$ZFS_IMG"; then
      echo "zfs-real detected $ZFS_IMG already in use by zpool" >&2
      exit 1
    fi
    truncate -s "$ZFS_REAL_DISK_SIZE" "$ZFS_IMG"
    cleanup_zpool() {
      $SUDO_CMD zpool export "$ZFS_REAL_POOL_NAME" >/dev/null 2>&1 || true
    }
    trap cleanup_zpool EXIT
    $SUDO_CMD zpool create -f -o ashift="$ZFS_REAL_ASHIFT" -o cachefile=none \
      -O mountpoint=none -O canmount=off -O compression=off \
      "$ZFS_REAL_POOL_NAME" "$ZFS_IMG"
    $SUDO_CMD zfs create -o mountpoint=none -o canmount=off "$ZFS_REAL_POOL_NAME/ROOT"
    if [[ -n "$ZFS_REAL_BOOTENV_ENCRYPTED" ]]; then
      ZFS_KEYFILE="$WORK/zfs-keyfile"
      printf '%s' "$ZFS_REAL_BOOTENV_PASSPHRASE" > "$ZFS_KEYFILE"
      chmod 600 "$ZFS_KEYFILE"
    fi
    IFS=',' read -r -a BE_LIST <<< "$ZFS_REAL_BOOTENVS"
    for env in "${BE_LIST[@]}"; do
      env="$(printf '%s' "$env" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
      if [[ -z "$env" ]]; then
        continue
      fi
      if [[ -n "$ZFS_REAL_BOOTENV_ENCRYPTED" && "$env" == "$ZFS_REAL_BOOTENV_ENCRYPTED" ]]; then
        if [[ -n "$KUNCI_TANG" ]]; then
          ZFS_RAW_KEYFILE="$WORK/zfs-raw-key"
          python - "$ZFS_RAW_KEYFILE" <<'PY'
import os
import binascii
import sys
path = sys.argv[1]
key = binascii.hexlify(os.urandom(32))
with open(path, "wb") as handle:
    handle.write(key)
PY
          $SUDO_CMD zfs create -o mountpoint=none -o canmount=noauto \
            -o encryption=on -o keyformat=hex -o keylocation="file://$ZFS_RAW_KEYFILE" \
            "$ZFS_REAL_POOL_NAME/ROOT/$env"
          $SUDO_CMD zfs set keylocation=prompt "$ZFS_REAL_POOL_NAME/ROOT/$env"
        else
          $SUDO_CMD zfs create -o mountpoint=none -o canmount=noauto \
            -o encryption=on -o keyformat=passphrase -o keylocation="file://$ZFS_KEYFILE" \
            "$ZFS_REAL_POOL_NAME/ROOT/$env"
          $SUDO_CMD zfs set keylocation=prompt "$ZFS_REAL_POOL_NAME/ROOT/$env"
        fi
      else
        $SUDO_CMD zfs create -o mountpoint=none -o canmount=noauto \
          "$ZFS_REAL_POOL_NAME/ROOT/$env"
      fi
    done
    if [[ -n "$KUNCI_TANG" && -n "$ZFS_REAL_BOOTENV_ENCRYPTED" ]]; then
      KUNCI_ROOT="${KUNCI_ROOT:-/home/karpal/devel/system/kunci}"
      KUNCI_SERVER_BIN="$KUNCI_ROOT/target/release/kunci-server"
      KUNCI_CLIENT_BIN="$KUNCI_ROOT/target/release/kunci-client"
      if [[ ! -x "$KUNCI_SERVER_BIN" || ! -x "$KUNCI_CLIENT_BIN" ]]; then
        echo "building kunci binaries" >&2
        cargo build --release -p kunci-server -p kunci-client --manifest-path "$KUNCI_ROOT/Cargo.toml"
      fi
      KUNCI_KEYDIR="$WORK/kunci-keys"
      mkdir -p "$KUNCI_KEYDIR"
      KUNCI_HOST_URL="http://127.0.0.1:$KUNCI_PORT"
      KUNCI_GUEST_URL="http://10.0.2.2:$KUNCI_PORT"
      KUNCI_LOG_LEVEL="${KUNCI_LOG_LEVEL:-trace}"
      KUNCI_LOG_MODULES="${KUNCI_LOG_MODULES:-tang,zfs,crypto,jose,pin,remote,http}"
      KUNCI_LOG_JSON="${KUNCI_LOG_JSON:-1}"
      KUNCI_SERVER_LOG="$WORK/kunci-server.log"
      KUNCI_SERVER_ARGS=(--bind 0.0.0.0 --port "$KUNCI_PORT" --directory "$KUNCI_KEYDIR" \
        --log-level "$KUNCI_LOG_LEVEL" --log-modules "$KUNCI_LOG_MODULES")
      if [[ -n "$KUNCI_TRUST" ]]; then
        KUNCI_SERVER_ARGS+=(--allow-tofu)
      fi
      if [[ "$KUNCI_LOG_JSON" == "1" ]]; then
        KUNCI_SERVER_ARGS+=(--log-json)
      fi
      KUNCI_LOG=1 KUNCI_LOG_LEVEL="$KUNCI_LOG_LEVEL" KUNCI_LOG_MODULES="$KUNCI_LOG_MODULES" \
        KUNCI_LOG_JSON="$KUNCI_LOG_JSON" \
        "$KUNCI_SERVER_BIN" "${KUNCI_SERVER_ARGS[@]}" >"$KUNCI_SERVER_LOG" 2>&1 &
      KUNCI_SERVER_PID=$!
      trap 'kill "$KUNCI_SERVER_PID" >/dev/null 2>&1 || true; cleanup_zpool' EXIT
      echo "kunci-server log: $KUNCI_SERVER_LOG" >&2
      sleep 1
      KUNCI_CONFIG="$WORK/kunci-config.json"
      "$KUNCI_CLIENT_BIN" --server "$KUNCI_HOST_URL" --log-level error fetch-adv --as-config > "$KUNCI_CONFIG"
      python - "$KUNCI_CONFIG" <<'PY'
import json
import sys
path = sys.argv[1]
text = open(path, "r", encoding="utf-8").read()
start = text.find("{")
end = text.rfind("}")
if start == -1 or end == -1:
    raise SystemExit("kunci config parse failed")
data = json.loads(text[start:end + 1])
with open(path, "w", encoding="utf-8") as handle:
    json.dump(data, handle)
PY
      sed -i "s|\"url\":\"$KUNCI_HOST_URL\"|\"url\":\"$KUNCI_GUEST_URL\"|" "$KUNCI_CONFIG"
    if [[ -n "$KUNCI_TRUST" || -n "$KUNCI_THP" ]]; then
      python - "$KUNCI_CONFIG" "$KUNCI_TRUST" "$KUNCI_THP" <<'PY'
import json
import sys

path = sys.argv[1]
trust = sys.argv[2].strip()
thp = sys.argv[3].strip()

with open(path, "r", encoding="utf-8") as handle:
    data = json.load(handle)

target = data
if isinstance(data, dict) and "tang" in data and isinstance(data["tang"], dict):
    target = data["tang"]

if trust:
    target["trust"] = True
if thp:
    target["thp"] = thp

with open(path, "w", encoding="utf-8") as handle:
    json.dump(data, handle)
PY
    fi
      TARGET_DATASET="$ZFS_REAL_POOL_NAME/ROOT/$ZFS_REAL_BOOTENV_ENCRYPTED"
      KUNCI_BIND_OUT="$($SUDO_CMD "$KUNCI_CLIENT_BIN" zfs bind --dataset "$TARGET_DATASET" --pin tang --config "$KUNCI_CONFIG")"
      printf '%s\n' "$KUNCI_BIND_OUT"
      LOADER_ENV_PATH="$ESP/EFI/FreeBSD/loader.env"
      if [[ ! -f "$LOADER_ENV_PATH" ]]; then
        mkdir -p "$(dirname "$LOADER_ENV_PATH")"
        : > "$LOADER_ENV_PATH"
      fi
      printf '%s\n' "zfs_kunci_url=$KUNCI_GUEST_URL" >> "$LOADER_ENV_PATH"
      if [[ -n "$KUNCI_HTTP" ]]; then
        printf '%s\n' "zfs_kunci_ip=10.0.2.15" >> "$LOADER_ENV_PATH"
        printf '%s\n' "zfs_kunci_netmask=255.255.255.0" >> "$LOADER_ENV_PATH"
      fi
      if [[ -n "$KUNCI_HTTP_DRIVER" ]]; then
        DRIVER_DIR="$ESP/EFI/FreeBSD/Drivers"
        mkdir -p "$DRIVER_DIR"
        DRIVER_LIST=()
        IFS=',' read -r -a DRIVER_PATHS <<< "$KUNCI_HTTP_DRIVER"
        NEED_BUILD=0
        for src in "${DRIVER_PATHS[@]}"; do
          src="$(printf '%s' "$src" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
          if [[ -n "$src" && ! -f "$src" ]]; then
            NEED_BUILD=1
            break
          fi
        done
        if [[ "$NEED_BUILD" == "1" ]]; then
          "$ROOT/tools/edk2-build-network-drivers.sh"
        fi
        for src in "${DRIVER_PATHS[@]}"; do
          src="$(printf '%s' "$src" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
          if [[ -z "$src" ]]; then
            continue
          fi
          if [[ ! -f "$src" ]]; then
            ALT_FOUND=""
            if [[ "$src" == *"/OvmfPkg/VirtioNetDxe/"* ]]; then
              alt="${src//\/VirtioNetDxe\/VirtioNet\/OUTPUT\//\/VirtioNetDxe\/OUTPUT\/}"
              if [[ -f "$alt" ]]; then
                ALT_FOUND="$alt"
              elif [[ "$alt" == *"VirtioNetDxe.efi" ]]; then
                alt2="${alt%VirtioNetDxe.efi}VirtioNet.efi"
                if [[ -f "$alt2" ]]; then
                  ALT_FOUND="$alt2"
                fi
              fi
              if [[ -z "$ALT_FOUND" && "$src" == *"VirtioNetDxe.efi" ]]; then
                alt3="${src%VirtioNetDxe.efi}VirtioNet.efi"
                if [[ -f "$alt3" ]]; then
                  ALT_FOUND="$alt3"
                fi
              fi
            fi
            if [[ -n "$ALT_FOUND" ]]; then
              src="$ALT_FOUND"
            else
              echo "kunci_http_driver missing: $src" >&2
              exit 1
            fi
          fi
          base="$(basename "$src")"
          dst="$DRIVER_DIR/$base"
          cp "$src" "$dst"
          DRIVER_LIST+=("\\\\EFI\\\\FreeBSD\\\\Drivers\\\\$base")
        done
        if [[ ${#DRIVER_LIST[@]} -gt 0 ]]; then
          printf '%s\n' "zfs_kunci_http_driver=$(IFS=,; printf '%s' "${DRIVER_LIST[*]}")" >> "$LOADER_ENV_PATH"
        fi
      fi
      NET_ENABLE="1"
    fi
    if [[ -n "$ZFS_REAL_BOOTFS" ]]; then
      $SUDO_CMD zpool set bootfs="$ZFS_REAL_POOL_NAME/$ZFS_REAL_BOOTFS" "$ZFS_REAL_POOL_NAME"
    fi
    if [[ "$ZFS_REAL_POPULATE_KERNEL" == "1" ]]; then
      if [[ -z "$KERNEL_TXZ" ]]; then
        echo "zfs-real populate_kernel requires kernel.txz" >&2
        exit 1
      fi
      TARGET_DATASET="$ZFS_REAL_POOL_NAME/${ZFS_REAL_BOOTFS:-ROOT/default}"
      ZFS_MOUNT="$WORK/zfs-mount"
      mkdir -p "$ZFS_MOUNT"
      $SUDO_CMD zfs set mountpoint="$ZFS_MOUNT" "$TARGET_DATASET"
      $SUDO_CMD zfs mount "$TARGET_DATASET"
      $SUDO_CMD mkdir -p "$ZFS_MOUNT/boot/kernel"
      if ! $SUDO_CMD tar -xJf "$KERNEL_TXZ" -C "$ZFS_MOUNT" "./boot/kernel/kernel"; then
        $SUDO_CMD tar -xJf "$KERNEL_TXZ" -C "$ZFS_MOUNT" "boot/kernel/kernel"
      fi
      if [[ -f "$KERNEL_MODULES_FILE" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
          line="${line%%#*}"
          line="$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
          if [[ -z "$line" ]]; then
            continue
          fi
          if ! $SUDO_CMD tar -xJf "$KERNEL_TXZ" -C "$ZFS_MOUNT" "$line"; then
            echo "module extraction failed: $line" >&2
            exit 1
          fi
        done < "$KERNEL_MODULES_FILE"
      fi
      $SUDO_CMD zfs unmount "$TARGET_DATASET"
      $SUDO_CMD zfs set mountpoint=none "$TARGET_DATASET"
    fi
    $SUDO_CMD zpool export "$ZFS_REAL_POOL_NAME"
    ZFS_ARGS=(
      -drive if=none,format=raw,file="$ZFS_IMG",id=zfsdisk
      -device virtio-blk-pci,drive=zfsdisk,bootindex=2
    )
  fi

  if ! command -v mkfs.fat >/dev/null 2>&1 || ! command -v mcopy >/dev/null 2>&1; then
    echo "mkfs.fat and mcopy are required for raw FAT ESP" >&2
    exit 1
  fi
  dd if=/dev/zero of="$ESP_IMG" bs=1M count="$RAW_FAT_MB" status=none
  mkfs.fat -F 32 "$ESP_IMG" >/dev/null
  if ! mcopy -s -o -i "$ESP_IMG" "$ESP"/* ::/; then
    echo "mcopy failed while populating ESP image" >&2
    exit 1
  fi
  DRIVE_ARGS=(-drive if=none,format=raw,file="$ESP_IMG",id=esp)

  set +e
  RNG_ARG=()
  if [[ "$QEMU_RNG" == "1" ]]; then
    RNG_ARG=(-device virtio-rng-pci)
  fi

  NET_ARGS=()
  if [[ "$NET_ENABLE" == "1" ]]; then
    NET_ARGS=(-netdev user,id=net0 -device virtio-net-pci,netdev=net0)
  else
    NET_ARGS=(-net none)
  fi
  timeout "$RUN_TIMEOUT" "$QEMU_BIN" \
    -machine q35 \
    -m 512 \
    "${NET_ARGS[@]}" \
    -serial "file:$LOG_FILE" \
    -display none \
    -no-reboot \
    -boot order=c \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,file="$WORK/OVMF_VARS.fd" \
    "${DRIVE_ARGS[@]}" \
    "${ISO_ARGS[@]}" \
    "${ZFS_ARGS[@]}" \
    -device virtio-blk-pci,drive=esp,bootindex=0 \
    "${RNG_ARG[@]}" \
    ${QEMU_EXTRA_ARGS:-} >"$QEMU_LOG" 2>&1
  STATUS=$?
  set -e
  echo "serial log: $LOG_FILE"
  echo "qemu log: $QEMU_LOG"

  if [[ $STATUS -ne 0 && $STATUS -ne 124 ]]; then
    echo "QEMU failed with status $STATUS" >&2
    exit 1
  fi

  if [[ -s "$LOG_FILE" ]]; then
    :
  else
    echo "serial log is empty (no UEFI output)" >&2
    if [[ "$SHOW_LOG_ON_FAIL" == "1" ]] && [[ -s "$QEMU_LOG" ]]; then
      echo "---- qemu log (first 200 lines) ----" >&2
      sed -n '1,200p' "$QEMU_LOG" >&2
      echo "------------------------------------" >&2
    fi
  fi

  if [[ -f "$EXPECT_FILE" ]]; then
    PASS=1
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%%#*}"
      line="$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
      if [[ -z "$line" ]]; then
        continue
      fi
      if ! rg -q --fixed-strings "$line" "$LOG_FILE"; then
        PASS=0
        break
      fi
    done < "$EXPECT_FILE"

    if [[ $PASS -eq 1 ]]; then
      echo "Scenario '$SCENARIO' passed"
      exit 0
    fi
  else
    echo "Scenario '$SCENARIO' passed"
    exit 0
  fi

  if [[ "$SHOW_LOG_ON_FAIL" == "1" ]]; then
    echo "---- serial log (first 200 lines) ----" >&2
    sed -n '1,200p' "$LOG_FILE" >&2
    echo "-------------------------------------" >&2
  fi
  if [[ "$KEEP_WORK_ON_FAIL" != "1" ]]; then
    rm -rf "$WORK"
  fi
done

echo "Scenario '$SCENARIO' failed after $ATTEMPTS attempts" >&2
exit 1
