Expected Warnings Per Scenario
==============================

Asset caching
-------------

Kernel archives referenced by `kernel.txz.url` are cached under
`tmp/integration/assets/`. Missing assets will cause the scenario to fail
after attempting a download.

OVMF firmware is cached under `tmp/integration/assets/ovmf/` when available
from system packages. HTTP drivers for the Tang unlock scenario are built from
edk2 into `tmp/edk2` (see `tools/edk2-build-network-drivers.sh`). The build
script will clone edk2 into `tmp/edk2` if missing.

These integration scenarios are focused on specific paths. Some warnings are
expected because we deliberately omit unrelated assets (for speed and scope).

Common, benign warnings
-----------------------

- "loader env missing: /efi/freebsd/loader.env"
  Happens when a scenario does not provide a `loader.env` file.

- "boot volume kernel read failed: /boot/kernel/kernel"
  Happens when a scenario does not include a kernel in the ESP. Only
  `kernel-load` is expected to include a kernel on the ESP.

Scenario-specific expectations
-------------------------------

- `memmap`, `mode`, `lsefi`, `rng-seed`
  - Kernel read warning is expected (no kernel in ESP).

- `fail-timeout`
  - "currdev not resolved (fail_timeout=0)" is expected.
  - Kernel read warning is expected (no kernel in ESP).

- `interactive-cmds`
  - Runs scripted interactive commands and exits cleanly.

- `kernel-load`
  - Should load kernel successfully (no kernel read warning).
  - Any kernel load warning is a failure to investigate.

- `secureboot-manifest`
  - Generates a manifest on the ESP and initializes secureboot handling.
  - Should load kernel successfully from the ESP.

- `secureboot-manifest-bad`
  - Corrupts a manifest entry and expects secureboot verification failure.

- `kernel-load-modules`
  - Extracts a small module subset (modules present).
  - `loader.env` missing warning is expected.

- `kernel-load-iso`
  - ISO9660 kernel + modules from attached CD-ROM.

- `zfs-probe`
  - ZFS label + bootenv probe from synthetic vdev label.

- `zfs-kernel-load`
  - Real ZFS pool bootfs kernel + modules on a file vdev.
  - Requires `zpool`/`zfs` and root or passwordless sudo.

- `zfs-passphrase-prompt`
  - Encrypted boot environment with preseeded passphrase in loader env.
  - Requires `zpool`/`zfs` and root or passwordless sudo.

- `zfs-tang-unlock`
  - Encrypted boot environment with Tang/Kunci binding.
  - Requires `zpool`/`zfs` and root or passwordless sudo.
  - Starts `kunci-server` locally and enables QEMU user networking.
  - Set `kunci_http=1` in `zfs-real.conf` to force HTTP-only unlock (no env key fallback).
  - Optional: set `kunci_http_driver=/abs/path/HttpDxe.efi` to preload HTTP driver.
  - Optional: comma-separate multiple drivers in `kunci_http_driver=...` to preload a driver chain.
  - Optional: set `kunci_trust=1` to allow TOFU for the Tang pin.
  - Optional: set `kunci_thp=<thumbprint>` to pin the Tang signing key instead of TOFU.

- `zfs-bootenvs-real`
  - Real ZFS pool on a file vdev; MOS/ZAP bootenv enumeration.
  - Requires `zpool`/`zfs` and root or passwordless sudo.
