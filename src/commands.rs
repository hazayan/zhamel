extern crate alloc;

use alloc::string::String;

use uefi::boot::{self, MemoryType, SearchType};
use uefi::mem::memory_map::MemoryMap;
use uefi::runtime::{self, ResetType};
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::rng::{Rng, RngAlgorithmType};
use uefi::Identify;
use uefi::Status;
use uefi::system;

use crate::env::loader::LoaderEnv;

pub fn run_from_env(env: &LoaderEnv) -> Option<Status> {
    let cmd = env.get("zhamel_cmd")?;
    run_command(cmd, env)
}

pub fn run_command(cmd: &str, env: &LoaderEnv) -> Option<Status> {
    match cmd {
        "memmap" => {
            dump_memmap();
            Some(Status::SUCCESS)
        }
        "lsefi" => {
            list_loaded_image_handles();
            Some(Status::SUCCESS)
        }
        "mode" => {
            dump_text_modes(env);
            Some(Status::SUCCESS)
        }
        "efi-seed-entropy" | "rng-seed" => {
            seed_rng_entropy(env);
            Some(Status::SUCCESS)
        }
        "poweroff" => {
            runtime::reset(ResetType::SHUTDOWN, Status::SUCCESS, None);
        }
        "reboot" => {
            runtime::reset(ResetType::COLD, Status::SUCCESS, None);
        }
        other => {
            log::warn!("unknown command: {}", other);
            Some(Status::ABORTED)
        }
    }
}

fn dump_memmap() {
    let map = match boot::memory_map(MemoryType::LOADER_DATA) {
        Ok(map) => map,
        Err(err) => {
            log::warn!("memmap: failed to read memory map: {:?}", err.status());
            return;
        }
    };
    let meta = map.meta();
    log::info!(
        "memmap: entries={} desc_size={} desc_ver={}",
        meta.entry_count(),
        meta.desc_size,
        meta.desc_version
    );
    for (idx, desc) in map.entries().enumerate() {
        if idx >= 16 {
            log::info!("memmap: ...");
            break;
        }
        log::info!(
            "memmap[{}] type={:?} phys=0x{:016x} pages={} attr=0x{:x}",
            idx,
            desc.ty,
            desc.phys_start,
            desc.page_count,
            desc.att.bits()
        );
    }
}

fn list_loaded_image_handles() {
    let handles = match boot::locate_handle_buffer(SearchType::ByProtocol(&LoadedImage::GUID)) {
        Ok(handles) => handles,
        Err(err) => {
            log::warn!("lsefi: locate handles failed: {:?}", err.status());
            return;
        }
    };
    log::info!("lsefi: {} loaded image handles", handles.len());
    for (idx, handle) in handles.iter().enumerate() {
        if idx >= 16 {
            log::info!("lsefi: ...");
            break;
        }
        log::info!("lsefi[{}]: {:?}", idx, handle);
    }
}

fn dump_text_modes(env: &LoaderEnv) {
    system::with_stdout(|stdout| {
        match stdout.current_mode() {
            Ok(Some(mode)) => {
                log::info!(
                    "mode: current={} {}x{}",
                    mode.index(),
                    mode.columns(),
                    mode.rows()
                );
            }
            Ok(None) => log::info!("mode: current=unknown"),
            Err(err) => log::warn!("mode: current mode query failed: {:?}", err.status()),
        }

        let mut count = 0;
        for mode in stdout.modes() {
            log::info!("mode[{}] {}x{}", mode.index(), mode.columns(), mode.rows());
            count += 1;
        }
        if count == 0 {
            log::warn!("mode: no modes reported");
        }

        if let Some(value) = env.get("zhamel_mode") {
            if let Ok(index) = value.parse::<usize>() {
                let mut selected = None;
                for mode in stdout.modes() {
                    if mode.index() == index {
                        selected = Some(mode);
                        break;
                    }
                }
                if let Some(mode) = selected {
                    if let Err(err) = stdout.set_mode(mode) {
                        log::warn!("mode: set_mode failed: {:?}", err.status());
                    } else {
                        log::info!("mode: switched to {}", index);
                    }
                } else {
                    log::warn!("mode: invalid mode index {}", index);
                }
            } else {
                log::warn!("mode: invalid zhamel_mode value {}", value);
            }
        }
    });
}

fn seed_rng_entropy(env: &LoaderEnv) {
    let size = env
        .get("zhamel_rng_bytes")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1024)
        .min(1024 * 1024);
    if size == 0 {
        log::warn!("rng-seed: requested size is zero");
        return;
    }

    let handles = match boot::locate_handle_buffer(SearchType::ByProtocol(&Rng::GUID)) {
        Ok(handles) => handles,
        Err(err) => {
            log::warn!("rng-seed: locate handles failed: {:?}", err.status());
            return;
        }
    };
    let handle = match handles.iter().next().copied() {
        Some(handle) => handle,
        None => {
            log::warn!("rng-seed: no RNG protocol handles found");
            return;
        }
    };

    let mut rng = match boot::open_protocol_exclusive::<Rng>(handle) {
        Ok(rng) => rng,
        Err(err) => {
            log::warn!("rng-seed: open RNG protocol failed: {:?}", err.status());
            return;
        }
    };

    let mut algos = [RngAlgorithmType::EMPTY_ALGORITHM; 8];
    match rng.get_info(&mut algos) {
        Ok(list) => {
            log::info!("rng-seed: algorithms={}", list.len());
            for (idx, algo) in list.iter().enumerate() {
                if idx >= 8 {
                    log::info!("rng-seed: algorithms: ...");
                    break;
                }
                log::info!("rng-seed: algo[{}]={:?}", idx, algo);
            }
        }
        Err(err) => {
            log::warn!("rng-seed: get_info failed: {:?}", err.status());
        }
    }

    let mut buf = alloc::vec![0u8; size];
    if let Err(err) = rng.get_rng(None, &mut buf) {
        log::warn!("rng-seed: get_rng failed: {:?}", err.status());
        return;
    }

    let mut preview = String::new();
    for byte in buf.iter().take(16) {
        let _ = core::fmt::Write::write_fmt(&mut preview, format_args!("{:02x}", byte));
    }
    log::info!("rng-seed: read {} bytes (head={}...)", buf.len(), preview);
}
