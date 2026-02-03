#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_ROOT="$ROOT/tmp"
EDK2_ROOT="${EDK2_ROOT:-$ROOT/tmp/edk2}"
EDK2_REPO="${EDK2_REPO:-https://github.com/tianocore/edk2.git}"
EDK2_ARCH="${EDK2_ARCH:-X64}"
EDK2_TOOLCHAIN="${EDK2_TOOLCHAIN:-GCC5}"
EDK2_BUILD_TYPE="${EDK2_BUILD_TYPE:-RELEASE}"
BROTLI_REPO="${BROTLI_REPO:-https://github.com/google/brotli}"
BROTLI_TMP="$TMP_ROOT/brotli-src"
EDK2_SUBMODULES=(
  BaseTools/Source/C/BrotliCompress/brotli
  MdeModulePkg/Library/BrotliCustomDecompressLib/brotli
  MdePkg/Library/MipiSysTLib/mipisyst
  MdePkg/Library/BaseFdtLib/libfdt
)

if command -v git >/dev/null 2>&1; then
  if [[ ! -d "$TMP_ROOT" ]]; then
    mkdir -p "$TMP_ROOT"
  fi
  echo "cloning edk2 into $EDK2_ROOT" >&2
  git clone --recurse-submodules "$EDK2_REPO" "$EDK2_ROOT"
else
  echo "git is required to fetch edk2" >&2
  exit 1
fi

if [[ ! -f "$EDK2_ROOT/edksetup.sh" ]]; then
  echo "edk2 root missing edksetup.sh: $EDK2_ROOT" >&2
  exit 1
fi

if command -v git >/dev/null 2>&1; then
  echo "syncing edk2 submodules" >&2
  (cd "$EDK2_ROOT" && git submodule sync "${EDK2_SUBMODULES[@]}")
  (cd "$EDK2_ROOT" && git submodule update --init --recursive "${EDK2_SUBMODULES[@]}")
else
  echo "git is required to initialize edk2 submodules" >&2
  exit 1
fi

ensure_brotli_sources() {
  local target="$1"
  if [[ -f "$target/c/common/constants.h" ]]; then
    return 0
  fi
  return 1
}

if ! ensure_brotli_sources "$EDK2_ROOT/BaseTools/Source/C/BrotliCompress/brotli"; then
  echo "edk2 Brotli submodule missing after init; updating brotli submodules" >&2
  (cd "$EDK2_ROOT" && git submodule update --init \
    BaseTools/Source/C/BrotliCompress/brotli \
    MdeModulePkg/Library/BrotliCustomDecompressLib/brotli) || true
fi

if ! ensure_brotli_sources "$EDK2_ROOT/BaseTools/Source/C/BrotliCompress/brotli"; then
  echo "edk2 Brotli submodule still missing; cloning brotli repo once and copying" >&2
  (cd "$EDK2_ROOT" && git submodule status --recursive) >&2 || true
  rm -rf "$BROTLI_TMP"
  git clone --depth 1 "$BROTLI_REPO" "$BROTLI_TMP"
  rm -rf "$EDK2_ROOT/BaseTools/Source/C/BrotliCompress/brotli"
  rm -rf "$EDK2_ROOT/MdeModulePkg/Library/BrotliCustomDecompressLib/brotli"
  cp -a "$BROTLI_TMP" "$EDK2_ROOT/BaseTools/Source/C/BrotliCompress/brotli"
  cp -a "$BROTLI_TMP" "$EDK2_ROOT/MdeModulePkg/Library/BrotliCustomDecompressLib/brotli"
fi

if ! ensure_brotli_sources "$EDK2_ROOT/BaseTools/Source/C/BrotliCompress/brotli"; then
  echo "edk2 Brotli sources still missing after manual copy" >&2
  exit 1
fi


(
  cd "$EDK2_ROOT"
  if [[ -z "${PYTHON_COMMAND:-}" ]]; then
    if command -v python3 >/dev/null 2>&1; then
      PYTHON_COMMAND="python3"
    elif command -v python >/dev/null 2>&1; then
      PYTHON_COMMAND="python"
    else
      echo "python is required for edk2 BaseTools" >&2
      exit 1
    fi
  fi
  export PYTHON_COMMAND
  export WORKSPACE="$EDK2_ROOT"
  # edksetup.sh configures BaseTools and build environment.
  set +u
  source edksetup.sh
  set -u
  make -C BaseTools

  OVMF_DEFINES=(
    -D NETWORK_ENABLE=TRUE
    -D NETWORK_IP4_ENABLE=TRUE
    -D NETWORK_TLS_ENABLE=FALSE
    -D NETWORK_ISCSI_ENABLE=FALSE
  )
  build -a "$EDK2_ARCH" -t "$EDK2_TOOLCHAIN" -b "$EDK2_BUILD_TYPE" \
    -p OvmfPkg/OvmfPkgX64.dsc \
    "${OVMF_DEFINES[@]}"

  NETWORK_MODULES=(
    NetworkPkg/DpcDxe/DpcDxe.inf
    NetworkPkg/SnpDxe/SnpDxe.inf
    NetworkPkg/MnpDxe/MnpDxe.inf
    NetworkPkg/ArpDxe/ArpDxe.inf
    NetworkPkg/Ip4Dxe/Ip4Dxe.inf
    NetworkPkg/Udp4Dxe/Udp4Dxe.inf
    NetworkPkg/TcpDxe/TcpDxe.inf
    NetworkPkg/Dhcp4Dxe/Dhcp4Dxe.inf
    NetworkPkg/DnsDxe/DnsDxe.inf
    NetworkPkg/HttpUtilitiesDxe/HttpUtilitiesDxe.inf
    NetworkPkg/HttpDxe/HttpDxe.inf
  )
  for module in "${NETWORK_MODULES[@]}"; do
    build -a "$EDK2_ARCH" -t "$EDK2_TOOLCHAIN" -b "$EDK2_BUILD_TYPE" \
      -p NetworkPkg/NetworkPkg.dsc \
      -m "$module"
  done
)
