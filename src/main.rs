#![cfg_attr(target_os = "uefi", no_main)]
#![cfg_attr(target_os = "uefi", no_std)]
#![cfg_attr(all(target_os = "uefi", test), allow(dead_code, unused_imports))]

#[cfg(target_os = "uefi")]
extern crate alloc;

#[cfg(target_os = "uefi")]
mod args;
#[cfg(target_os = "uefi")]
mod block_cache;
#[cfg(target_os = "uefi")]
mod bootmgr;
#[cfg(target_os = "uefi")]
mod commands;
#[cfg(target_os = "uefi")]
mod console;
#[cfg(target_os = "uefi")]
mod currdev;
#[cfg(target_os = "uefi")]
mod devsw;
#[cfg(target_os = "uefi")]
mod env;
#[cfg(target_os = "uefi")]
mod error;
#[cfg(target_os = "uefi")]
mod exit;
#[cfg(target_os = "uefi")]
mod fs;
#[cfg(target_os = "uefi")]
mod gpt;
#[cfg(target_os = "uefi")]
mod handoff;
#[cfg(target_os = "uefi")]
mod heap;
#[cfg(target_os = "uefi")]
mod interactive;
#[cfg(target_os = "uefi")]
mod kernel;
#[cfg(target_os = "uefi")]
mod mbr;
#[cfg(target_os = "uefi")]
mod secureboot;
#[cfg(target_os = "uefi")]
mod startup;
#[cfg(target_os = "uefi")]
mod tang;
#[cfg(target_os = "uefi")]
mod time;
#[cfg(target_os = "uefi")]
mod uefi_helpers;
#[cfg(all(target_os = "uefi", test))]
mod uefi_tests;
#[cfg(target_os = "uefi")]
mod version;
#[cfg(target_os = "uefi")]
mod zfs;

#[cfg(target_os = "uefi")]
use crate::kernel::types::ModuleType;
#[cfg(target_os = "uefi")]
use alloc::collections::BTreeMap;
#[cfg(target_os = "uefi")]
use alloc::string::ToString;
#[cfg(target_os = "uefi")]
use kernel::module::Module;
#[cfg(all(target_os = "uefi", not(test)))]
use uefi::boot;
#[cfg(target_os = "uefi")]
use uefi::prelude::*;

#[cfg(target_os = "uefi")]
fn parse_u32(value: &str) -> Option<u32> {
    let value = value.trim();
    if let Some(hex) = value.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).ok()
    } else {
        value.parse::<u32>().ok()
    }
}

#[cfg(target_os = "uefi")]
fn zfs_probe_devices_from_gpt(
    block_devices: &[uefi_helpers::BlockDeviceInfo],
    gpt_disks: &[gpt::GptDisk],
) -> alloc::vec::Vec<uefi_helpers::BlockDeviceInfo> {
    let mut zfs_guids = alloc::vec::Vec::new();
    for disk in gpt_disks {
        for partition in &disk.partitions {
            if gpt::partition_kind(partition.type_guid) == gpt::GptPartitionKind::FreeBsdZfs {
                zfs_guids.push(partition.unique_guid);
            }
        }
    }
    if zfs_guids.is_empty() {
        return alloc::vec::Vec::new();
    }

    let mut out = alloc::vec::Vec::new();
    for device in block_devices {
        if !device.logical_partition {
            continue;
        }
        let Some(guid) = uefi_helpers::device_path::partition_guid_for_handle(device.handle) else {
            continue;
        };
        if zfs_guids.iter().any(|candidate| *candidate == guid) {
            out.push(device.clone());
        }
    }
    out
}

#[cfg(target_os = "uefi")]
fn is_truthy(value: &str) -> bool {
    matches!(value, "1" | "YES" | "yes" | "true" | "TRUE" | "on" | "ON")
}

#[cfg(target_os = "uefi")]
fn boot_howto_from_env(env: &env::loader::LoaderEnv) -> u32 {
    let mut howto = env.get("boot_howto").and_then(parse_u32).unwrap_or(0);
    if env.get("boot_verbose").map_or(false, is_truthy) {
        howto |= RB_VERBOSE;
    }
    if env.get("boot_serial").map_or(false, is_truthy) {
        howto |= RB_SERIAL;
    }
    if env.get("boot_multicons").map_or(false, is_truthy) {
        howto |= RB_MULTIPLE;
    }
    if env.get("boot_askname").map_or(false, is_truthy) {
        howto |= RB_ASKNAME;
    }
    if env.get("boot_single").map_or(false, is_truthy) {
        howto |= RB_SINGLE;
    }
    if env.get("boot_pause").map_or(false, is_truthy) {
        howto |= RB_PAUSE;
    }
    if env.get("boot_cdrom").map_or(false, is_truthy) {
        howto |= RB_CDROM;
    }
    if env.get("boot_halt").map_or(false, is_truthy) {
        howto |= RB_HALT;
    }
    if env.get("boot_poweroff").map_or(false, is_truthy) {
        howto |= RB_POWEROFF;
    }
    if env.get("boot_kdb").map_or(false, is_truthy) {
        howto |= RB_KDB;
    }
    if env.get("boot_gdb").map_or(false, is_truthy) {
        howto |= RB_GDB;
    }
    if env.get("boot_mute").map_or(false, is_truthy) {
        howto |= RB_MUTE;
    }
    if env.get("boot_mutemsgs").map_or(false, is_truthy) {
        howto |= RB_MUTEMSGS;
    }
    if env.get("boot_probe").map_or(false, is_truthy) {
        howto |= RB_PROBE;
    }
    howto
}

#[cfg(target_os = "uefi")]
fn dump_env_if_requested(env: &env::loader::LoaderEnv) {
    let enabled = matches!(
        env.get("zhamel_env_dump"),
        Some("1") | Some("YES") | Some("yes") | Some("true")
    );
    if !enabled {
        return;
    }
    let mut merged: BTreeMap<&str, &str> = BTreeMap::new();
    for var in &env.conf_vars {
        merged.insert(var.key.as_str(), var.value.as_str());
    }
    for var in &env.env_vars {
        merged.insert(var.key.as_str(), var.value.as_str());
    }
    log::info!("ZENV-BEGIN");
    for (key, value) in merged {
        log::info!("{}={}", key, value);
    }
    log::info!("ZENV-END");
}

#[cfg(all(target_os = "uefi", not(test)))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(target_os = "uefi")]
fn zfs_module_preconditions_ok(modules: &[Module], zfskey_required: bool) -> bool {
    let zfs_loaded = modules.iter().any(|module| module_matches(module, "zfs"));
    if !zfs_loaded {
        log::warn!("zfs: required zfs.ko module was not loaded; refusing ZFS root handoff");
        return false;
    }
    if zfskey_required
        && !modules
            .iter()
            .any(|module| module_matches(module, "zhamel_zfskey"))
    {
        log::warn!(
            "zfs: native key handoff prepared but zhamel_zfskey.ko was not loaded; refusing ZFS root handoff"
        );
        return false;
    }
    true
}

#[cfg(target_os = "uefi")]
fn module_matches(module: &Module, base: &str) -> bool {
    let name = module.name.as_str();
    name == base
        || name == alloc::format!("{}.ko", base)
        || name.ends_with(&alloc::format!("/{}", base))
        || name.ends_with(&alloc::format!("/{}.ko", base))
}

#[cfg(target_os = "uefi")]
const RB_ASKNAME: u32 = 0x001;
#[cfg(target_os = "uefi")]
const RB_SINGLE: u32 = 0x002;
#[cfg(target_os = "uefi")]
const RB_HALT: u32 = 0x008;
#[cfg(target_os = "uefi")]
const RB_KDB: u32 = 0x040;
#[cfg(target_os = "uefi")]
const RB_VERBOSE: u32 = 0x800;
#[cfg(target_os = "uefi")]
const RB_SERIAL: u32 = 0x1000;
#[cfg(target_os = "uefi")]
const RB_CDROM: u32 = 0x2000;
#[cfg(target_os = "uefi")]
const RB_POWEROFF: u32 = 0x4000;
#[cfg(target_os = "uefi")]
const RB_GDB: u32 = 0x8000;
#[cfg(target_os = "uefi")]
const RB_MUTE: u32 = 0x10000;
#[cfg(target_os = "uefi")]
const RB_PAUSE: u32 = 0x100000;
#[cfg(target_os = "uefi")]
const RB_PROBE: u32 = 0x10000000;
#[cfg(target_os = "uefi")]
const RB_MULTIPLE: u32 = 0x20000000;
#[cfg(target_os = "uefi")]
const RB_MUTEMSGS: u32 = 0x800000;

#[cfg(all(target_os = "uefi", not(test)))]
fn handle_kernel_image(
    kernel: alloc::vec::Vec<u8>,
    mut modules: alloc::vec::Vec<crate::kernel::module::Module>,
    loader_env: &mut crate::env::loader::LoaderEnv,
    source_label: &str,
) -> Option<Status> {
    if let Err(err) = secureboot::verify_path(
        loader_env.get("kernel").unwrap_or("/boot/kernel/kernel"),
        &kernel,
    ) {
        log::warn!("secureboot kernel verify failed: {}", err);
        return Some(Status::SECURITY_VIOLATION);
    }
    for module in &modules {
        if matches!(&module.module_type, ModuleType::Raw(_)) {
            continue;
        }
        let path = if module.name.starts_with('/') {
            module.name.clone()
        } else {
            alloc::format!("/boot/kernel/{}", module.name)
        };
        if let Err(err) = secureboot::verify_path(&path, &module.data) {
            log::warn!("secureboot module verify failed: {} ({})", err, path);
            return Some(Status::SECURITY_VIOLATION);
        }
    }
    log::info!(
        "kernel image found on {}: {} bytes",
        source_label,
        kernel.len()
    );
    let loader = kernel::elf::ElfLoader;
    log::info!("kernel modules discovered: {}", modules.len());
    match loader.load_kernel_image(&kernel) {
        Ok(mut loaded) => {
            log::info!(
                "kernel ELF entry: 0x{:016x} phdrs: {}",
                loaded.entry,
                loaded.info.program_headers.len()
            );
            log::info!(
                "kernel image loaded: base=0x{:016x} size={}",
                loaded.base,
                loaded.image.len()
            );
            kernel::patch_headless_vga(&mut loaded, &kernel, loader_env);
            let envp = kernel::build_envp(loader_env);
            let howto = boot_howto_from_env(loader_env);
            log::info!("boot_howto: 0x{:x}", howto);
            let stage_copy = !matches!(
                loader_env.get("zhamel_stage_copy"),
                Some("0") | Some("NO") | Some("no") | Some("false")
            );
            let efi_map = match kernel::collect_efi_map_metadata() {
                Ok(map) => Some(map),
                Err(err) => {
                    log::warn!("efi map metadata unavailable: {}", err);
                    None
                }
            };
            if handoff::should_handoff(loader_env) && stage_copy {
                log::info!("stage_copy enabled; staging kernel/modules");
                return Some(handoff::handoff_to_kernel_staged(
                    &loaded,
                    &mut modules,
                    efi_map.as_deref(),
                    Some(envp.as_slice()),
                    howto,
                ));
            }

            if handoff::should_handoff(loader_env) {
                match kernel::load_kernel_to_memory_at(&loaded, kernel::KERNEL_PHYS_BASE) {
                    Ok(phys) => {
                        log::info!(
                            "kernel image copied to memory: base=0x{:016x} size={}",
                            phys.base,
                            phys.size
                        );
                        let module_base = phys.base.saturating_add(phys.size as u64);
                        if let Err(err) =
                            kernel::load_modules_to_memory_at(&mut modules, module_base)
                        {
                            log::warn!("module memory allocation failed: {}", err);
                        } else {
                            let allocated =
                                modules.iter().filter(|m| m.phys_addr.is_some()).count();
                            log::info!("kernel modules allocated: {}", allocated);
                        }
                        log::warn!("handoff requested; exiting boot services");
                        return Some(handoff::handoff_to_kernel(
                            phys,
                            &mut modules,
                            efi_map.as_deref(),
                            Some(envp.as_slice()),
                            howto,
                            false,
                        ));
                    }
                    Err(err) => {
                        log::warn!(
                            "kernel alloc at 0x{:x} failed: {}; falling back to staged handoff",
                            kernel::KERNEL_PHYS_BASE,
                            err
                        );
                        return Some(handoff::handoff_to_kernel_staged(
                            &loaded,
                            &mut modules,
                            efi_map.as_deref(),
                            Some(envp.as_slice()),
                            howto,
                        ));
                    }
                }
            }

            match kernel::load_kernel_to_memory(&loaded) {
                Ok(phys) => {
                    log::info!(
                        "kernel image copied to memory: base=0x{:016x} size={}",
                        phys.base,
                        phys.size
                    );
                    if let Some(modulep) = kernel::build_kernel_modulep_with_metadata(
                        loaded.base,
                        loaded.image.len() as u64,
                        &modules,
                        efi_map.as_deref(),
                        Some(envp.as_slice()),
                    ) {
                        log::info!("kernel modulep built: {} bytes", modulep.len());
                    } else {
                        log::warn!("kernel modulep not built (no load range)");
                    }
                }
                Err(err) => {
                    log::warn!("kernel memory allocation failed: {}", err);
                }
            }
        }
        Err(err) => {
            log::warn!("kernel ELF load failed: {}", err);
        }
    }
    None
}

#[cfg(all(target_os = "uefi", test))]
#[entry]
fn main() -> Status {
    if let Err(err) = heap::init() {
        return err.status();
    }
    uefi_tests::run()
}

#[cfg(all(target_os = "uefi", not(test)))]
#[entry]
fn main() -> Status {
    if let Err(err) = uefi::helpers::init() {
        return err.status();
    }
    if let Err(err) = heap::init() {
        log::error!("heap init failed: {}", err);
        return exit::finish(err.status());
    }

    console::banner();

    let load_options = boot::open_protocol_exclusive::<uefi::proto::loaded_image::LoadedImage>(
        boot::image_handle(),
    )
    .ok()
    .and_then(|loaded| {
        loaded
            .load_options_as_cstr16()
            .ok()
            .map(|opts| opts.to_u16_slice_with_nul().to_vec())
    });
    let argv = args::parse_load_options(load_options.as_deref(), true);
    if argv.is_empty() {
        log::info!("no load options provided");
    } else {
        log::info!("argv: {}", argv.join(" "));
    }

    if let Some(text) = uefi_helpers::device_path_text_for_loaded_image(boot::image_handle()) {
        log::info!("load path: {}", text);
    }

    let mut loader_env = env::loader::load_from_boot_volume();
    fs::uefi::cache_boot_fs_device();
    if let Some(path) = loader_env.get("zfs_kunci_http_driver") {
        tang::cache_http_drivers(path);
    }
    log::info!(
        "loader env vars: {} loader.conf vars: {}",
        loader_env.env_vars.len(),
        loader_env.conf_vars.len()
    );
    startup::init(&mut loader_env);
    env::hooks::init(&mut loader_env);
    let manifest_path = loader_env
        .get("veriexec.manifest_path")
        .or_else(|| loader_env.get("veriexec.manifest"))
        .map(|value| value.to_string());
    let manifest_bytes = manifest_path
        .as_deref()
        .and_then(|path| fs::uefi::read_file_from_boot_volume(path));
    secureboot::init(&mut loader_env, manifest_bytes, manifest_path.as_deref());
    dump_env_if_requested(&loader_env);
    let mut boot_volume_kernel: Option<alloc::vec::Vec<u8>> = None;
    time::init();
    let _block_cache = block_cache::init(&loader_env);
    let _devsw = devsw::init();
    if let Some(status) = commands::run_from_env(&loader_env) {
        return exit::finish(status);
    }
    if let Some(status) = interactive::run_shell(&loader_env) {
        return exit::finish(status);
    }

    let block_devices = uefi_helpers::enumerate_block_devices();
    log::info!("block devices: {}", block_devices.len());

    let gpt_disks = gpt::scan_gpt_disks(&block_devices);
    log::info!("gpt disks: {}", gpt_disks.len());
    let mut gpt_esp = 0usize;
    let mut gpt_ufs = 0usize;
    let mut gpt_zfs = 0usize;
    for disk in &gpt_disks {
        for part in &disk.partitions {
            match gpt::partition_kind(part.type_guid) {
                gpt::GptPartitionKind::EfiSystem => gpt_esp += 1,
                gpt::GptPartitionKind::FreeBsdUfs => gpt_ufs += 1,
                gpt::GptPartitionKind::FreeBsdZfs => gpt_zfs += 1,
                gpt::GptPartitionKind::Other => {}
            }
        }
    }
    log::info!(
        "gpt partitions: esp={} ufs={} zfs={}",
        gpt_esp,
        gpt_ufs,
        gpt_zfs
    );

    let ufs_volumes = fs::ufs::probe_from_gpt(&gpt_disks);
    let ufs_mbr = fs::ufs::probe_from_mbr(&block_devices);
    let ufs_raw = fs::ufs::probe_raw_devices(&block_devices);
    log::info!(
        "ufs volumes: {} (mbr {} raw {})",
        ufs_volumes.len(),
        ufs_mbr.len(),
        ufs_raw.len()
    );

    let zfs_probe_devices = zfs_probe_devices_from_gpt(&block_devices, &gpt_disks);
    let zfs_pools = if zfs_probe_devices.is_empty() {
        log::warn!("zfs: no GPT FreeBSD ZFS BlockIO handles matched; probing all block devices");
        zfs::probe_pools(&block_devices)
    } else {
        log::info!(
            "zfs: probing {} GPT FreeBSD ZFS BlockIO handle(s)",
            zfs_probe_devices.len()
        );
        let pools = zfs::probe_pools(&zfs_probe_devices);
        if pools.is_empty() {
            log::warn!("zfs: GPT ZFS candidates yielded no pools; probing all block devices");
            zfs::probe_pools(&block_devices)
        } else {
            pools
        }
    };
    log::info!("zfs pools: {}", zfs_pools.len());
    if let Err(err) = zfs::validate_bootenv(&zfs_pools) {
        log::warn!("zfs bootenv validation failed: {}", err);
    }
    zfs::log_bootenv(&zfs_pools);
    zfs::export_env(&mut loader_env, &zfs_pools);
    if let Err(err) = zfs::maybe_unlock_kunci(&zfs_pools, &mut loader_env) {
        log::warn!("zfs kunci unlock failed: {}", err);
    }
    if let Err(err) = zfs::maybe_prompt_passphrase(&zfs_pools, &mut loader_env) {
        log::warn!("zfs passphrase prompt failed: {}", err);
    }

    if let Some((pool_index, zfs_source, kernel)) =
        kernel::read_kernel_from_zfs_bootfs(&zfs_pools, &loader_env)
    {
        kernel::reload_loader_conf_from_zfs_bootfs(
            &zfs_pools,
            pool_index,
            &zfs_source,
            &mut loader_env,
        );
        if let Err(err) = zfs::maybe_unlock_kunci(&zfs_pools, &mut loader_env) {
            log::warn!("zfs kunci unlock failed after loader.conf reload: {}", err);
        }
        if let Err(err) = zfs::maybe_prompt_passphrase(&zfs_pools, &mut loader_env) {
            log::warn!(
                "zfs passphrase prompt failed after loader.conf reload: {}",
                err
            );
        }
        let zfskey_module = match zfs::maybe_prepare_zfskey_handoff(&zfs_pools, &mut loader_env) {
            Ok(module) => module,
            Err(err) => {
                log::warn!("zfs native key handoff preparation failed: {}", err);
                None
            }
        };
        log::info!("zfs: starting module discovery from boot dataset");
        let mut modules = kernel::discover_modules_from_zfs_bootfs(
            &zfs_pools,
            pool_index,
            &zfs_source,
            &mut loader_env,
        );
        log::info!("zfs: module discovery complete count={}", modules.len());
        let zfskey_required = zfskey_module.is_some();
        if !zfs_module_preconditions_ok(&modules, zfskey_required) {
            return Status::LOAD_ERROR;
        }
        if let Some(module) = zfskey_module {
            modules.push(module);
        }
        if let Some(status) = handle_kernel_image(kernel, modules, &mut loader_env, "zfs") {
            return status;
        }
    } else if let Some(bootonce) = zfs::bootonce_for_pools(&zfs_pools) {
        if let Some(kernel) = kernel::read_kernel_from_zfs(&zfs_pools, bootonce, &loader_env) {
            let zfskey_module = match zfs::maybe_prepare_zfskey_handoff(&zfs_pools, &mut loader_env)
            {
                Ok(module) => module,
                Err(err) => {
                    log::warn!("zfs native key handoff preparation failed: {}", err);
                    None
                }
            };
            log::info!("zfs: starting module discovery from bootenv {}", bootonce);
            let mut modules =
                kernel::discover_modules_from_zfs(&zfs_pools, bootonce, &mut loader_env);
            log::info!("zfs: module discovery complete count={}", modules.len());
            let zfskey_required = zfskey_module.is_some();
            if !zfs_module_preconditions_ok(&modules, zfskey_required) {
                return Status::LOAD_ERROR;
            }
            if let Some(module) = zfskey_module {
                modules.push(module);
            }
            if let Some(status) = handle_kernel_image(kernel, modules, &mut loader_env, "zfs") {
                return status;
            }
        } else {
            log::warn!("zfs kernel image not found for bootenv {}", bootonce);
        }
    }

    let boot_info = bootmgr::collect();
    let mut curr = currdev::select_currdev(&boot_info, &loader_env);
    if let Some(curr) = curr.as_mut() {
        log::info!("currdev selected: {} ({:?})", curr.description, curr.source);
        if curr.prefer_iso {
            log::info!("currdev prefers iso9660");
            if let Some(handle) = curr.iso_handle {
                if let Some(text) =
                    crate::uefi_helpers::device_path::device_path_text_for_handle(handle)
                {
                    log::info!("iso9660 handle: {}", text);
                } else {
                    log::info!("iso9660 handle resolved (no text)");
                }
            } else {
                log::warn!("iso9660 handle not resolved; will scan devices");
            }
        }
        if let Some(kernel_path) = curr.kernel_path.as_deref() {
            loader_env.set("kernel", kernel_path);
            log::info!("kernel override from boot entry: {}", kernel_path);
        }
        if let Some(guid) = curr.partition_guid {
            if let Some(match_info) = gpt::find_partition_by_guid(&gpt_disks, guid) {
                if gpt::partition_kind(match_info.partition.type_guid)
                    == gpt::GptPartitionKind::EfiSystem
                {
                    if let Some(ufs_part) =
                        gpt_disks[match_info.disk_index]
                            .partitions
                            .iter()
                            .find(|p| {
                                gpt::partition_kind(p.type_guid)
                                    == gpt::GptPartitionKind::FreeBsdUfs
                            })
                    {
                        log::info!(
                            "currdev ESP; switching to UFS partition {} on disk {}",
                            ufs_part.index,
                            match_info.disk_index
                        );
                        curr.partition_guid = Some(ufs_part.unique_guid);
                    }
                }
            }
        }
        if let Some(guid) = curr.partition_guid {
            if let Some(match_info) = gpt::find_partition_by_guid(&gpt_disks, guid) {
                log::info!(
                    "currdev mapped to gpt disk {} partition {}",
                    match_info.disk_index,
                    match_info.partition.index
                );
                if let Some(conf_vars) =
                    env::loader::load_loader_conf_from_partition_guid(guid, &loader_env.env_vars)
                {
                    log::info!(
                        "loader.conf reloaded from currdev: {} vars",
                        conf_vars.len()
                    );
                    loader_env.conf_vars = conf_vars;
                }
                if let Some(kernel) = kernel::read_kernel_from_currdev(guid, &loader_env) {
                    let modules = kernel::discover_modules_from_currdev(guid, &mut loader_env);
                    if let Some(status) =
                        handle_kernel_image(kernel, modules, &mut loader_env, "currdev")
                    {
                        return status;
                    }
                } else {
                    log::warn!("kernel image not found on currdev");
                }
                if let Some(ufs) = fs::ufs::probe_by_partition_guid(&gpt_disks, guid) {
                    log::info!(
                        "currdev ufs detected at disk {} partition {} ({:?})",
                        ufs.disk_index,
                        ufs.partition_index,
                        ufs.kind
                    );
                } else {
                    log::warn!("currdev partition not recognized as ufs");
                }
            } else {
                log::warn!("currdev partition guid not found in gpt");
            }
        }
        if curr.partition_guid.is_none() {
            if curr.prefer_iso {
                let iso_result = if let Some(handle) = curr.iso_handle {
                    kernel::read_kernel_from_iso_handle(handle, &loader_env)
                } else {
                    kernel::read_kernel_from_iso_devices(&loader_env)
                };
                if let Some((iso, kernel)) = iso_result {
                    let modules = kernel::discover_modules_from_iso(&iso, &mut loader_env);
                    if let Some(status) =
                        handle_kernel_image(kernel, modules, &mut loader_env, "iso9660")
                    {
                        return status;
                    }
                }
            }
            if let Some(kernel) = boot_volume_kernel
                .take()
                .or_else(|| kernel::read_kernel_from_boot_volume(&loader_env))
            {
                let modules = kernel::discover_modules_from_boot_volume(&mut loader_env);
                if let Some(status) =
                    handle_kernel_image(kernel, modules, &mut loader_env, "boot volume")
                {
                    return status;
                }
            }
            if !curr.prefer_iso {
                if let Some((iso, kernel)) = kernel::read_kernel_from_iso_devices(&loader_env) {
                    let modules = kernel::discover_modules_from_iso(&iso, &mut loader_env);
                    if let Some(status) =
                        handle_kernel_image(kernel, modules, &mut loader_env, "iso9660")
                    {
                        return status;
                    }
                }
            }
            log::warn!("kernel image not found on boot volume");
        }
    } else {
        if !interactive::fail_timeout_interrupt(&loader_env, "currdev not resolved") {
            return exit::finish(Status::NOT_FOUND);
        }
        log::warn!("currdev not resolved; continuing without override");
    }

    log::info!("loader initialized");

    exit::finish(Status::SUCCESS)
}

#[cfg(not(target_os = "uefi"))]
fn main() {
    println!("{}", host_main_message());
}

#[cfg(test)]
pub fn test_runner(tests: &[&dyn Fn()]) {
    for test in tests {
        test();
    }
    // Logic to signal success/exit would go here
}

#[cfg(all(test, not(target_os = "uefi"), feature = "host-coverage"))]
mod host_tests {
    #[test]
    fn test_host_main_runs() {
        super::main();
    }

    #[test]
    fn test_host_main_message() {
        assert_eq!(
            super::host_main_message(),
            "zhamel builds for UEFI targets only"
        );
    }
}

#[cfg(not(target_os = "uefi"))]
fn host_main_message() -> &'static str {
    "zhamel builds for UEFI targets only"
}
