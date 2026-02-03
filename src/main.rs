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
mod error;
#[cfg(target_os = "uefi")]
mod devsw;
#[cfg(target_os = "uefi")]
mod env;
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
mod tang;
#[cfg(target_os = "uefi")]
mod zfs;
#[cfg(all(target_os = "uefi", test))]
mod uefi_tests;
#[cfg(target_os = "uefi")]
mod uefi_helpers;
#[cfg(target_os = "uefi")]
mod startup;
#[cfg(target_os = "uefi")]
mod time;
#[cfg(target_os = "uefi")]
mod version;

#[cfg(all(target_os = "uefi", not(test)))]
use uefi::boot;
#[cfg(target_os = "uefi")]
use uefi::prelude::*;
#[cfg(target_os = "uefi")]
use alloc::string::ToString;

#[cfg(all(target_os = "uefi", not(test)))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(all(target_os = "uefi", not(test)))]
fn handle_kernel_image(
    kernel: alloc::vec::Vec<u8>,
    mut modules: alloc::vec::Vec<crate::kernel::module::Module>,
    loader_env: &crate::env::loader::LoaderEnv,
    source_label: &str,
) -> Option<Status> {
    if let Err(err) = secureboot::verify_path(
        loader_env
            .get("kernel")
            .unwrap_or("/boot/kernel/kernel"),
        &kernel,
    ) {
        log::warn!("secureboot kernel verify failed: {}", err);
        return Some(Status::SECURITY_VIOLATION);
    }
    for module in &modules {
        let path = alloc::format!("/boot/kernel/{}", module.name);
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
        Ok(loaded) => {
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
            let envp = kernel::build_envp(loader_env);
            let stage_copy = matches!(
                loader_env.get("zhamel_stage_copy"),
                Some("1") | Some("YES") | Some("yes") | Some("true")
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
                ));
            }

            match kernel::load_kernel_to_memory(&loaded) {
                Ok(phys) => {
                    log::info!(
                        "kernel image copied to memory: base=0x{:016x} size={}",
                        phys.base,
                        phys.size
                    );
                    if handoff::should_handoff(loader_env) {
                        if let Err(err) = kernel::load_modules_to_memory(&mut modules) {
                            log::warn!("module memory allocation failed: {}", err);
                        } else {
                            let allocated = modules
                                .iter()
                                .filter(|m| m.phys_addr.is_some())
                                .count();
                            log::info!("kernel modules allocated: {}", allocated);
                        }
                        log::warn!("handoff requested; exiting boot services");
                        return Some(handoff::handoff_to_kernel(
                            phys,
                            &mut modules,
                            efi_map.as_deref(),
                            Some(envp.as_slice()),
                            false,
                        ));
                    } else if let Some(modulep) = kernel::build_kernel_modulep_with_metadata(
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
    let mut boot_volume_kernel = kernel::read_kernel_from_boot_volume(&loader_env);
    let mut boot_volume_modules = if boot_volume_kernel.is_some() {
        Some(kernel::discover_modules_from_boot_volume())
    } else {
        None
    };
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
    log::info!("gpt partitions: esp={} ufs={} zfs={}", gpt_esp, gpt_ufs, gpt_zfs);

    let ufs_volumes = fs::ufs::probe_from_gpt(&gpt_disks);
    let ufs_mbr = fs::ufs::probe_from_mbr(&block_devices);
    let ufs_raw = fs::ufs::probe_raw_devices(&block_devices);
    log::info!(
        "ufs volumes: {} (mbr {} raw {})",
        ufs_volumes.len(),
        ufs_mbr.len(),
        ufs_raw.len()
    );

    let zfs_pools = zfs::probe_pools(&block_devices);
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

    if let Some((pool_index, kernel)) = kernel::read_kernel_from_zfs_bootfs(&zfs_pools, &loader_env)
    {
        let modules = kernel::discover_modules_from_zfs_bootfs(&zfs_pools, pool_index);
        if let Some(status) = handle_kernel_image(kernel, modules, &loader_env, "zfs") {
            return status;
        }
    } else if let Some(bootonce) = zfs::bootonce_for_pools(&zfs_pools) {
        if let Some(kernel) = kernel::read_kernel_from_zfs(&zfs_pools, bootonce, &loader_env) {
            let modules = kernel::discover_modules_from_zfs(&zfs_pools, bootonce);
            if let Some(status) = handle_kernel_image(kernel, modules, &loader_env, "zfs") {
                return status;
            }
        } else {
            log::warn!("zfs kernel image not found for bootenv {}", bootonce);
        }
    }

    let boot_info = bootmgr::collect();
    let curr = currdev::select_currdev(&boot_info, &loader_env);
    if let Some(curr) = curr {
        log::info!("currdev selected: {} ({:?})", curr.description, curr.source);
        if let Some(kernel_path) = curr.kernel_path.as_deref() {
            loader_env.set("kernel", kernel_path);
            log::info!("kernel override from boot entry: {}", kernel_path);
        }
        if let Some(guid) = curr.partition_guid {
            if let Some(match_info) = gpt::find_partition_by_guid(&gpt_disks, guid) {
                log::info!(
                    "currdev mapped to gpt disk {} partition {}",
                    match_info.disk_index,
                    match_info.partition.index
                );
                if let Some(conf_vars) = env::loader::load_loader_conf_from_partition_guid(guid) {
                    log::info!(
                        "loader.conf reloaded from currdev: {} vars",
                        conf_vars.len()
                    );
                    loader_env.conf_vars = conf_vars;
                }
                if let Some(kernel) = kernel::read_kernel_from_currdev(guid, &loader_env) {
                    let modules = kernel::discover_modules_from_currdev(guid);
                    if let Some(status) =
                        handle_kernel_image(kernel, modules, &loader_env, "currdev")
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
        } else if let Some(kernel) = boot_volume_kernel
            .take()
            .or_else(|| kernel::read_kernel_from_boot_volume(&loader_env))
        {
            let modules = boot_volume_modules
                .take()
                .unwrap_or_else(kernel::discover_modules_from_boot_volume);
            if let Some(status) = handle_kernel_image(kernel, modules, &loader_env, "boot volume") {
                return status;
            }
        } else if let Some((iso, kernel)) = kernel::read_kernel_from_iso_devices(&loader_env)
        {
            let modules = kernel::discover_modules_from_iso(&iso);
            if let Some(status) = handle_kernel_image(kernel, modules, &loader_env, "iso9660") {
                return status;
            }
        } else {
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
        assert_eq!(super::host_main_message(), "zhamel builds for UEFI targets only");
    }
}

#[cfg(not(target_os = "uefi"))]
fn host_main_message() -> &'static str {
    "zhamel builds for UEFI targets only"
}
