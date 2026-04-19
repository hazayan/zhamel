#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_ROOT="$ROOT/tmp"
EDK2_ROOT="${EDK2_ROOT:-$ROOT/tmp/edk2}"
EDK2_REPO="${EDK2_REPO:-https://github.com/tianocore/edk2.git}"
EDK2_ARCH="${EDK2_ARCH:-X64}"
EDK2_TOOLCHAIN="${EDK2_TOOLCHAIN:-CLANGPDB}"
EDK2_BUILD_TYPE="${EDK2_BUILD_TYPE:-RELEASE}"
BROTLI_REPO="${BROTLI_REPO:-https://github.com/google/brotli}"
BROTLI_TMP="$TMP_ROOT/brotli-src"
EDK2_SUBMODULES=(
  BaseTools/Source/C/BrotliCompress/brotli
  MdeModulePkg/Library/BrotliCustomDecompressLib/brotli
  MdePkg/Library/MipiSysTLib/mipisyst
  MdePkg/Library/BaseFdtLib/libfdt
)

if ! command -v git >/dev/null 2>&1; then
  echo "git is required to fetch edk2" >&2
  exit 1
fi

if [[ ! -d "$TMP_ROOT" ]]; then
  mkdir -p "$TMP_ROOT"
fi

if [[ -f "$EDK2_ROOT/edksetup.sh" ]]; then
  echo "using existing edk2 source tree at $EDK2_ROOT" >&2
elif [[ "${EDK2_PATCH_ONLY:-0}" == "1" ]]; then
  echo "EDK2_PATCH_ONLY requires an existing edk2 source tree with edksetup.sh: $EDK2_ROOT" >&2
  exit 1
elif [[ ! -d "$EDK2_ROOT/.git" ]]; then
  echo "cloning edk2 into $EDK2_ROOT" >&2
  git clone --recurse-submodules "$EDK2_REPO" "$EDK2_ROOT"
else
  echo "using existing edk2 checkout at $EDK2_ROOT" >&2
fi

if [[ ! -f "$EDK2_ROOT/edksetup.sh" ]]; then
  echo "edk2 root missing edksetup.sh: $EDK2_ROOT" >&2
  exit 1
fi

patch_networkpkg_dsc_for_standalone_http() {
  local dsc="$EDK2_ROOT/NetworkPkg/NetworkPkg.dsc"
  if [[ ! -f "$dsc" ]]; then
    echo "edk2 NetworkPkg.dsc missing: $dsc" >&2
    exit 1
  fi

  # Standalone DXE drivers link BasePcdLibNull, so HttpDxe must not use dynamic PCD reads.
  perl -0pi -e 's/^\s*gEfiNetworkPkgTokenSpaceGuid\.Pcd(HttpIoTimeout|AllowHttpConnections|HttpDnsRetryInterval|HttpDnsRetryCount|HttpTransferBufferSize)\|.*\n//mg' "$dsc"
  perl -0pi -e 's/(\[PcdsFixedAtBuild\]\r?\n)/$1  gEfiNetworkPkgTokenSpaceGuid.PcdAllowHttpConnections|TRUE\n  gEfiNetworkPkgTokenSpaceGuid.PcdHttpIoTimeout|5000\n  gEfiNetworkPkgTokenSpaceGuid.PcdHttpDnsRetryInterval|0\n  gEfiNetworkPkgTokenSpaceGuid.PcdHttpDnsRetryCount|0\n  gEfiNetworkPkgTokenSpaceGuid.PcdHttpTransferBufferSize|0x200000\n/s' "$dsc"

  if grep -A20 '^\[PcdsDynamicDefault\]' "$dsc" | grep -q 'gEfiNetworkPkgTokenSpaceGuid.PcdHttp'; then
    echo "edk2 NetworkPkg.dsc still has dynamic HttpDxe PCDs after patching" >&2
    exit 1
  fi
}

validate_networkpkg_dsc_http_pcds() {
  local dsc="$EDK2_ROOT/NetworkPkg/NetworkPkg.dsc"
  local pcd
  local pcds=(
    PcdAllowHttpConnections
    PcdHttpIoTimeout
    PcdHttpDnsRetryInterval
    PcdHttpDnsRetryCount
    PcdHttpTransferBufferSize
  )

  for pcd in "${pcds[@]}"; do
    if ! grep -Eq "^  gEfiNetworkPkgTokenSpaceGuid\\.${pcd}\\|" "$dsc"; then
      echo "edk2 NetworkPkg.dsc missing fixed HTTP PCD after patch: $pcd" >&2
      exit 1
    fi
    if awk '
      /^\[PcdsFixedAtBuild\]/ { fixed=1; next }
      /^\[/ { fixed=0 }
      fixed && index($0, pcd) { found=1 }
      END { exit(found ? 0 : 1) }
    ' pcd="gEfiNetworkPkgTokenSpaceGuid.${pcd}|" "$dsc"; then
      :
    else
      echo "edk2 NetworkPkg.dsc HTTP PCD is not under [PcdsFixedAtBuild]: $pcd" >&2
      exit 1
    fi
    if awk '
      /^\[PcdsDynamicDefault\]/ { dynamic=1; next }
      /^\[/ { dynamic=0 }
      dynamic && index($0, pcd) { found=1 }
      END { exit(found ? 0 : 1) }
    ' pcd="gEfiNetworkPkgTokenSpaceGuid.${pcd}|" "$dsc"; then
      echo "edk2 NetworkPkg.dsc HTTP PCD is still under [PcdsDynamicDefault]: $pcd" >&2
      exit 1
    fi
  done
}

patch_networkpkg_dsc_for_standalone_http
validate_networkpkg_dsc_http_pcds

if [[ "${EDK2_PATCH_ONLY:-0}" == "1" ]]; then
  echo "edk2 NetworkPkg.dsc standalone HttpDxe PCD patch validated" >&2
  exit 0
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

validate_httpdxe_fixed_pcds() {
  local autogen="$EDK2_ROOT/Build/NetworkPkg/${EDK2_BUILD_TYPE}_${EDK2_TOOLCHAIN}/${EDK2_ARCH}/NetworkPkg/HttpDxe/HttpDxe/DEBUG/AutoGen.h"
  if [[ ! -f "$autogen" ]]; then
    echo "HttpDxe AutoGen.h not found after build: $autogen" >&2
    exit 1
  fi

  if grep -E '_PCD_GET_MODE_(BOOL|32)_Pcd(AllowHttpConnections|HttpIoTimeout|HttpDnsRetryInterval|HttpDnsRetryCount|HttpTransferBufferSize)\s+LibPcdGet' "$autogen"; then
    echo "HttpDxe still has dynamic HTTP PCD reads; standalone driver would assert under BasePcdLibNull" >&2
    exit 1
  fi
}

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
  HTTP_PCDS=(
    --pcd gEfiNetworkPkgTokenSpaceGuid.PcdAllowHttpConnections=TRUE
  )
  build -a "$EDK2_ARCH" -t "$EDK2_TOOLCHAIN" -b "$EDK2_BUILD_TYPE" \
    -p OvmfPkg/OvmfPkgX64.dsc \
    "${OVMF_DEFINES[@]}" \
    "${HTTP_PCDS[@]}"

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
      "${HTTP_PCDS[@]}" \
      -m "$module"
  done

  validate_httpdxe_fixed_pcds
)
