# Zhamel (Rust UEFI Loader)

Zhamel is a Rust implementation of the FreeBSD `loader.efi` for amd64, with
feature parity against the standard loader and additional ZFS unlock features.
It targets the UEFI environment and produces a `zhamel.efi` that can boot
FreeBSD kernels in the same way as the original C loader.

## Goals

- Match FreeBSD `loader.efi` behavior on amd64.
- Keep feature parity with the upstream loader.
- Add ZFS unlock enhancements without weakening correctness.

## Feature Parity (amd64)

The parity roadmap is tracked in `docs/implementation-todo.md`. All items are
checked off, including:

- Device and filesystem breadth (UFS/ZFS)
- Boot manager integration and currdev selection
- Secure Boot manifest verification
- Kernel and module loading, handoff, and command handling

## ZFS Unlock Features Added

Zhamel adds native ZFS unlock support:

- **Passphrase unlock**
  - Triggered by `keyformat=passphrase` with `keylocation=prompt` or `file://...`
  - File fallback to prompt if the key file is missing
- **Tang/Clevis via kunci**
  - Reads `kunci:jwe` and `kunci:pin` from dataset properties
  - Performs JWE recovery and derives the dataset key
  - Uses UEFI HTTP with optional driver preload for full-network flow

See `docs/implementation-todo.md` and `docs/validation-log.md` for the
completion and validation status.

## Supported Encrypted-Root Layout

The currently validated layout is:

- UEFI system partition mounted by FreeBSD at `/boot/efi`
- Zhamel installed as `/boot/efi/EFI/FreeBSD/loader.efi`
- Optional loader environment at `/boot/efi/EFI/FreeBSD/loader.env`
- Optional kunci HTTP DXE drivers under `/boot/efi/EFI/FreeBSD/Drivers/`
- An unencrypted ZFS dataset with `mountpoint=/boot`
- A native-encrypted ZFS root dataset selected by `vfs.root.mountfrom`
- `zhamel_zfskey.ko` installed under `/boot/modules/zhamel_zfskey.ko`

The loader discovers the boot dataset by its ZFS `mountpoint=/boot` property.
It does not assume a dataset name such as `boot` or `BOOT`.

For passphrase unlock, the encrypted root dataset must expose:

- `keyformat=passphrase`
- `keylocation=prompt` or a readable `file://...` passphrase source
- `pbkdf2salt`
- `pbkdf2iters`

The passphrase path derives the native ZFS wrapping key in the loader, prepares
a `zhamel_zfskey` preload payload, consumes the temporary `kern.zfs.key` staging
variable before kernel `envp` construction, and relies on `zhamel_zfskey.ko` to
load the key once the kernel can see the pool.

The loader also supports raw key-file handoff for test and automation layouts
when the encrypted root dataset uses `keyformat=raw` and a readable
`keylocation=file://...`.

## Loader Diagnostics

Normal boots keep zhamel loader diagnostics quiet. Detailed loader traces are
enabled with either:

```
zhamel_debug="YES"
```

or FreeBSD's existing:

```
boot_verbose="YES"
```

Verbose mode restores module discovery, ZFS reads, modulep summaries, handoff
addresses, and similar development diagnostics.

## Build

The loader is built for the UEFI target:

```
make build
make release
```

`make release` produces a release build for the UEFI target
(`x86_64-unknown-uefi`).

## Tests

UEFI unit tests:

```
make test
```

Integration suite (QEMU + OVMF required):

```
make integration
```

Integration assets:

- `make integration` -> `tools/uefi-integration-assets.sh` -> `tools/uefi-integration-runner.sh`
- Kernel archives referenced by `tests/integration/scenarios/*/kernel.txz.url` are cached in
  `tmp/integration/assets/`.
- The integration runner will attempt to download missing assets and fail the scenario
  if the asset is unavailable.
- OVMF firmware is cached under `tmp/integration/assets/ovmf/` when available from
  system packages (e.g. `/usr/share/edk2/x64`).
- HTTP driver binaries for Tang unlock are built from edk2 into `tmp/edk2` when needed
  (see `tools/edk2-build-network-drivers.sh`, which will clone edk2 if missing). The build
  forces `gEfiNetworkPkgTokenSpaceGuid.PcdAllowHttpConnections=TRUE` because Tang unlock uses
  plain `http://` URLs unless TLS is configured separately. It also fixes the other `HttpDxe`
  HTTP timeout, DNS retry, and transfer buffer PCDs at build time so the standalone DXE driver
  can run without a platform PCD database.
- To prefetch assets ahead of a test session:

```
tools/uefi-integration-assets.sh
```

## Coverage

Coverage reporting (no threshold enforced):

```
make coverage
```

This runs host-based coverage with the `host-coverage` feature enabled.

## Validation

Recent full-suite runs (stock OVMF and HTTP-enabled OVMF) are logged in
`docs/validation-log.md`.
