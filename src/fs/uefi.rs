extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use uefi::CString16;
use uefi::Handle;
use uefi::boot;
use uefi::boot::{OpenProtocolAttributes, OpenProtocolParams};
use uefi::fs::FileSystem;
use uefi::fs::Path;
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::fs::SimpleFileSystem;

use crate::fs::ufs;
use crate::gpt;
use crate::uefi_helpers::block_io::{
    find_block_handle_by_device_path_exact, find_block_handle_by_device_path_prefix, open_block_io,
};
use crate::uefi_helpers::device_path::{
    device_path_bytes_for_handle, device_path_prefix_before_file_path,
    device_path_prefix_before_hard_drive,
};
use crate::uefi_helpers::enumerate_block_devices;
use crate::uefi_helpers::find_partition_handle_by_guid;

#[derive(Clone, Copy)]
struct UfsPartitionTarget {
    handle: Handle,
    first_lba: u64,
    last_lba: u64,
}

fn find_partition_by_guid_on_gpt(guid: [u8; 16]) -> Option<(Handle, u64, u64)> {
    let devices = enumerate_block_devices();
    let disks = gpt::scan_gpt_disks(&devices);
    let found = gpt::find_partition_by_guid(&disks, guid)?;
    let disk = disks.get(found.disk_index)?;
    Some((
        disk.device.handle,
        found.partition.first_lba,
        found.partition.last_lba,
    ))
}

fn pick_ufs_partition_from_disks(disks: &[gpt::GptDisk]) -> Option<UfsPartitionTarget> {
    let mut found: Option<UfsPartitionTarget> = None;
    for disk in disks {
        for partition in &disk.partitions {
            if gpt::partition_kind(partition.type_guid) != gpt::GptPartitionKind::FreeBsdUfs {
                continue;
            }
            let candidate = UfsPartitionTarget {
                handle: disk.device.handle,
                first_lba: partition.first_lba,
                last_lba: partition.last_lba,
            };
            if found.is_some() {
                log::warn!("boot volume ufs partition ambiguous; multiple candidates");
                return None;
            }
            found = Some(candidate);
        }
    }
    found
}

pub fn read_file_from_handle(handle: uefi::Handle, path: &str) -> Option<Vec<u8>> {
    let path = normalize_uefi_path(path);
    let path: CString16 = CString16::try_from(path.as_str()).ok()?;
    let mut fs = open_simple_fs(handle).ok()?;
    fs.read(path.as_ref()).ok()
}

pub fn read_file_from_partition_guid(guid: [u8; 16], path: &str) -> Option<Vec<u8>> {
    if let Some(handle) = find_partition_handle_by_guid(guid) {
        if let Some(bytes) = read_file_from_handle(handle, path) {
            return Some(bytes);
        }
        if let Some(bytes) = ufs::read_file_from_handle(handle, path) {
            return Some(bytes);
        }
    }
    if let Some((disk_handle, first_lba, last_lba)) = find_partition_by_guid_on_gpt(guid) {
        if let Some(bytes) = ufs::read_file_from_partition(disk_handle, first_lba, last_lba, path) {
            return Some(bytes);
        }
    }
    None
}

pub fn read_file_from_boot_volume(path: &str) -> Option<Vec<u8>> {
    let path = normalize_uefi_path(path);
    let path_str = path.as_str();
    let is_efi = is_efi_path(path_str);
    let ufs_part = if is_efi {
        None
    } else {
        ensure_boot_ufs_partition()
    };
    let path: CString16 = match CString16::try_from(path_str) {
        Ok(path) => path,
        Err(err) => {
            log::warn!("boot volume path invalid: {} ({:?})", path, err);
            return None;
        }
    };
    if let Some(part) = ufs_part {
        if let Some(bytes) =
            ufs::read_file_from_partition(part.handle, part.first_lba, part.last_lba, path_str)
        {
            return Some(bytes);
        }
        log::warn!("boot volume ufs read failed: {}", path_str);
        return None;
    }
    let mut fs = match open_boot_volume() {
        Some(fs) => fs,
        None => {
            log::warn!("boot volume unavailable; falling back to cached fs");
            if let Some(handle) = get_cached_boot_fs_device() {
                if let Some(bytes) = read_file_from_handle(handle, path_str) {
                    return Some(bytes);
                }
            }
            if let Some(handle) = find_boot_block_handle_from_image_path() {
                if let Some(bytes) = ufs::read_file_from_handle(handle, path_str) {
                    return Some(bytes);
                }
            }
            return None;
        }
    };
    match fs.read(path.as_ref()) {
        Ok(bytes) => Some(bytes),
        Err(err) => {
            log::info!("boot volume read failed: {:?} ({})", err, path);
            None
        }
    }
}

pub fn file_size_from_boot_volume(path: &str) -> Option<usize> {
    let path = normalize_uefi_path(path);
    let path_str = path.as_str();
    if is_efi_path(path_str) {
        return None;
    }
    let part = ensure_boot_ufs_partition()?;
    ufs::file_size_from_partition(part.handle, part.first_lba, part.last_lba, path_str)
}

pub fn read_file_from_boot_volume_into(path: &str, dst: *mut u8, size: usize) -> Option<()> {
    let path = normalize_uefi_path(path);
    let path_str = path.as_str();
    if is_efi_path(path_str) {
        return None;
    }
    let part = ensure_boot_ufs_partition()?;
    ufs::read_file_from_partition_into(
        part.handle,
        part.first_lba,
        part.last_lba,
        path_str,
        dst,
        size,
    )
}

pub fn read_file_from_any_fs(path: &str) -> Option<Vec<u8>> {
    if let Some(handle) = get_cached_boot_fs_device() {
        if let Some(bytes) = read_file_from_handle(handle, path) {
            return Some(bytes);
        }
    }
    let handles = boot::find_handles::<SimpleFileSystem>().ok()?;
    for handle in handles {
        if let Some(bytes) = read_file_from_handle(handle, path) {
            return Some(bytes);
        }
    }
    None
}

pub fn read_dir_entries_from_handle(handle: uefi::Handle, path: &str) -> Option<Vec<String>> {
    let path = normalize_uefi_path(path);
    let path: CString16 = CString16::try_from(path.as_str()).ok()?;
    let mut fs = open_simple_fs(handle).ok()?;
    let dir = fs.read_dir(Path::new(&path)).ok()?;
    let mut entries = Vec::new();
    for entry in dir {
        let Ok(info) = entry else {
            continue;
        };
        if !info.is_regular_file() {
            continue;
        }
        let name = info.file_name().to_string();
        if name == "." || name == ".." {
            continue;
        }
        entries.push(name);
    }
    Some(entries)
}

pub fn normalize_uefi_path(path: &str) -> String {
    let mut out = String::new();
    let mut last_was_sep = false;
    for ch in path.chars() {
        let next = if ch == '/' { '\\' } else { ch };
        if next == '\\' {
            if last_was_sep {
                continue;
            }
            last_was_sep = true;
        } else {
            last_was_sep = false;
        }
        out.push(next);
    }
    if !out.starts_with('\\') {
        out.insert(0, '\\');
    }
    out
}

pub fn read_dir_entries_from_partition_guid(guid: [u8; 16], path: &str) -> Option<Vec<String>> {
    if let Some(handle) = find_partition_handle_by_guid(guid) {
        if let Some(entries) = read_dir_entries_from_handle(handle, path) {
            return Some(entries);
        }
        if let Some(entries) = ufs::read_dir_entries_from_handle(handle, path) {
            return Some(entries);
        }
    }
    if let Some((disk_handle, first_lba, last_lba)) = find_partition_by_guid_on_gpt(guid) {
        if let Some(entries) =
            ufs::read_dir_entries_from_partition(disk_handle, first_lba, last_lba, path)
        {
            return Some(entries);
        }
    }
    None
}

pub fn read_dir_entries_from_boot_volume(path: &str) -> Option<Vec<String>> {
    let path = normalize_uefi_path(path);
    let path_str = path.as_str();
    let is_efi = is_efi_path(path_str);
    let ufs_part = if is_efi {
        None
    } else {
        ensure_boot_ufs_partition()
    };
    let path: CString16 = CString16::try_from(path_str).ok()?;
    if let Some(part) = ufs_part {
        let entries = ufs::read_dir_entries_from_partition(
            part.handle,
            part.first_lba,
            part.last_lba,
            path_str,
        );
        if entries.is_none() {
            log::warn!("boot volume ufs dir read failed: {}", path_str);
        }
        return entries;
    }
    let mut fs = match open_boot_volume() {
        Some(fs) => fs,
        None => {
            return None;
        }
    };
    let dir = match fs.read_dir(Path::new(&path)) {
        Ok(dir) => dir,
        Err(_) => {
            return None;
        }
    };
    let mut entries = Vec::new();
    for entry in dir {
        let Ok(info) = entry else {
            continue;
        };
        if !info.is_regular_file() {
            continue;
        }
        let name = info.file_name().to_string();
        if name == "." || name == ".." {
            continue;
        }
        entries.push(name);
    }
    Some(entries)
}

fn is_efi_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower == "\\efi" || lower.starts_with("\\efi\\")
}

pub fn read_dir_entries_from_any_fs(path: &str) -> Option<Vec<String>> {
    let handles = boot::find_handles::<SimpleFileSystem>().ok()?;
    for handle in handles {
        if let Some(entries) = read_dir_entries_from_handle(handle, path) {
            return Some(entries);
        }
    }
    None
}

fn open_boot_volume() -> Option<FileSystem> {
    match boot::get_image_file_system(boot::image_handle()) {
        Ok(fs) => return Some(FileSystem::new(fs)),
        Err(err) => {
            log::warn!(
                "boot volume get_image_file_system failed: {:?}",
                err.status()
            );
        }
    }
    if let Some(handle) = find_boot_fs_handle_from_image_path() {
        match open_simple_fs(handle) {
            Ok(fs) => return Some(fs),
            Err(err) => {
                log::warn!("boot volume fs open failed: {:?}", err.status());
            }
        }
    }
    let loaded = unsafe {
        boot::open_protocol::<LoadedImage>(
            OpenProtocolParams {
                handle: boot::image_handle(),
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    };
    let loaded = match loaded {
        Ok(loaded) => loaded,
        Err(err) => {
            log::warn!("boot volume loaded image open failed: {:?}", err.status());
            return None;
        }
    };
    let Some(device) = loaded.device() else {
        log::warn!("boot volume device handle missing");
        return None;
    };
    match open_simple_fs(device) {
        Ok(fs) => Some(fs),
        Err(err) => {
            log::warn!("boot volume fs open failed: {:?}", err.status());
            None
        }
    }
}

pub fn cache_boot_fs_device() {
    if get_cached_boot_fs_device().is_some() {
        return;
    }
    let device = if let Some(handle) = find_boot_fs_handle_from_image_path() {
        handle
    } else {
        let loaded = match unsafe {
            boot::open_protocol::<LoadedImage>(
                OpenProtocolParams {
                    handle: boot::image_handle(),
                    agent: boot::image_handle(),
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
        } {
            Ok(loaded) => loaded,
            Err(_) => return,
        };
        let Some(device) = loaded.device() else {
            return;
        };
        device
    };
    unsafe {
        BOOT_FS_DEVICE = Some(device);
    }
}

fn find_boot_fs_handle_from_image_path() -> Option<uefi::Handle> {
    let image_bytes = device_path_bytes_for_handle(boot::image_handle())?;
    let prefix = device_path_prefix_before_file_path(&image_bytes).unwrap_or(image_bytes);
    let target = strip_end_node(&prefix);
    if target.is_empty() {
        return None;
    }
    let handles = boot::find_handles::<SimpleFileSystem>().ok()?;
    for handle in handles {
        let Some(bytes) = device_path_bytes_for_handle(handle) else {
            continue;
        };
        let candidate = strip_end_node(&bytes);
        if target.starts_with(candidate) || candidate.starts_with(target) {
            return Some(handle);
        }
    }
    None
}

fn find_boot_block_handle_from_image_path() -> Option<Handle> {
    if let Some(part) = find_boot_ufs_partition() {
        return Some(part.handle);
    }
    let image_handle = boot::image_handle();
    let loaded = unsafe {
        boot::open_protocol::<LoadedImage>(
            OpenProtocolParams {
                handle: image_handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }
    .ok();
    if let Some(loaded) = loaded {
        if let Some(device) = loaded.device() {
            if open_block_io(device).is_ok() {
                return Some(device);
            }
            if let Some(bytes) = device_path_bytes_for_handle(device) {
                let target = strip_end_node(&bytes);
                if let Some(handle) = find_block_handle_by_device_path_exact(target) {
                    return Some(handle);
                }
                if let Some(handle) = find_block_handle_by_device_path_prefix(target) {
                    return Some(handle);
                }
            }
        }
    }
    let image_bytes = device_path_bytes_for_handle(image_handle)?;
    let prefix = device_path_prefix_before_file_path(&image_bytes).unwrap_or(image_bytes);
    let target = strip_end_node(&prefix);
    if target.is_empty() {
        return None;
    }
    if let Some(handle) = find_block_handle_by_device_path_exact(target) {
        return Some(handle);
    }
    find_block_handle_by_device_path_prefix(target)
}

fn find_boot_ufs_partition() -> Option<UfsPartitionTarget> {
    if let Some(part) = get_cached_boot_ufs_partition() {
        return Some(part);
    }
    if let Some(disk_handle) = find_boot_disk_handle() {
        let devices = enumerate_block_devices();
        if let Some(disk) = devices.iter().find(|d| d.handle == disk_handle) {
            let disks = gpt::scan_gpt_disks(&[disk.clone()]);
            if let Some(found) = pick_ufs_partition_from_disks(&disks) {
                cache_boot_ufs_partition(found);
                return Some(found);
            }
        }
    }
    let devices = enumerate_block_devices();
    let disks = gpt::scan_gpt_disks(&devices);
    if let Some(found) = pick_ufs_partition_from_disks(&disks) {
        cache_boot_ufs_partition(found);
        return Some(found);
    }
    None
}

fn find_boot_disk_handle() -> Option<Handle> {
    let image_handle = boot::image_handle();
    let loaded = unsafe {
        boot::open_protocol::<LoadedImage>(
            OpenProtocolParams {
                handle: image_handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }
    .ok();
    if let Some(loaded) = loaded {
        if let Some(device) = loaded.device() {
            if let Some(bytes) = device_path_bytes_for_handle(device) {
                if let Some(handle) = find_disk_handle_by_prefix_bytes(&bytes) {
                    return Some(handle);
                }
            }
        }
    }
    let image_bytes = device_path_bytes_for_handle(image_handle)?;
    find_disk_handle_by_prefix_bytes(&image_bytes)
}

fn find_disk_handle_by_prefix_bytes(bytes: &[u8]) -> Option<Handle> {
    let prefix = device_path_prefix_before_hard_drive(bytes)
        .or_else(|| device_path_prefix_before_file_path(bytes))
        .unwrap_or_else(|| bytes.to_vec());
    let target = strip_end_node(&prefix);
    if target.is_empty() {
        return None;
    }
    for device in enumerate_block_devices() {
        if device.logical_partition {
            continue;
        }
        let Some(bytes) = device_path_bytes_for_handle(device.handle) else {
            continue;
        };
        let candidate = strip_end_node(&bytes);
        if target.starts_with(candidate) || candidate.starts_with(target) {
            return Some(device.handle);
        }
    }
    None
}

fn strip_end_node(bytes: &[u8]) -> &[u8] {
    if bytes.len() >= 4 {
        let end = bytes.len() - 4;
        if bytes[end] == 0x7f
            && bytes[end + 1] == 0xff
            && bytes[end + 2] == 0x04
            && bytes[end + 3] == 0x00
        {
            return &bytes[..end];
        }
    }
    bytes
}

fn get_cached_boot_fs_device() -> Option<uefi::Handle> {
    unsafe { BOOT_FS_DEVICE }
}

fn get_cached_boot_ufs_partition() -> Option<UfsPartitionTarget> {
    unsafe { BOOT_UFS_PARTITION }
}

fn ensure_boot_ufs_partition() -> Option<UfsPartitionTarget> {
    if let Some(part) = get_cached_boot_ufs_partition() {
        if open_block_io(part.handle).is_ok() {
            return Some(part);
        }
        log::warn!("boot volume ufs handle BlockIO open failed; rescanning");
        unsafe {
            BOOT_UFS_PARTITION = None;
        }
    }
    if let Some(part) = find_boot_ufs_partition() {
        if open_block_io(part.handle).is_ok() {
            return Some(part);
        }
        log::warn!("boot volume ufs rescan handle BlockIO open failed");
    }
    None
}

fn cache_boot_ufs_partition(part: UfsPartitionTarget) {
    unsafe {
        BOOT_UFS_PARTITION = Some(part);
    }
}

static mut BOOT_FS_DEVICE: Option<uefi::Handle> = None;
static mut BOOT_UFS_PARTITION: Option<UfsPartitionTarget> = None;
fn open_simple_fs(handle: Handle) -> uefi::Result<FileSystem> {
    let fs = unsafe {
        boot::open_protocol::<SimpleFileSystem>(
            OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }?;
    Ok(FileSystem::new(fs))
}
