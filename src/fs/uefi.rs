extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use uefi::boot;
use uefi::fs::FileSystem;
use uefi::fs::Path;
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::CString16;

use crate::uefi_helpers::find_partition_handle_by_guid;

pub fn read_file_from_handle(handle: uefi::Handle, path: &str) -> Option<Vec<u8>> {
    let path = normalize_uefi_path(path);
    let path: CString16 = CString16::try_from(path.as_str()).ok()?;
    let fs = boot::open_protocol_exclusive::<SimpleFileSystem>(handle).ok()?;
    let mut fs = FileSystem::new(fs);
    fs.read(path.as_ref()).ok()
}

pub fn read_file_from_partition_guid(guid: [u8; 16], path: &str) -> Option<Vec<u8>> {
    let handle = find_partition_handle_by_guid(guid)?;
    read_file_from_handle(handle, path)
}

pub fn read_file_from_boot_volume(path: &str) -> Option<Vec<u8>> {
    let path = normalize_uefi_path(path);
    let path: CString16 = match CString16::try_from(path.as_str()) {
        Ok(path) => path,
        Err(err) => {
            log::warn!("boot volume path invalid: {} ({:?})", path, err);
            return None;
        }
    };
    let mut fs = match open_boot_volume() {
        Some(fs) => fs,
        None => return None,
    };
    match fs.read(path.as_ref()) {
        Ok(bytes) => Some(bytes),
        Err(err) => {
            log::warn!("boot volume read failed: {:?} ({})", err, path);
            None
        }
    }
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
    let fs = boot::open_protocol_exclusive::<SimpleFileSystem>(handle).ok()?;
    let mut fs = FileSystem::new(fs);
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

pub fn read_dir_entries_from_partition_guid(
    guid: [u8; 16],
    path: &str,
) -> Option<Vec<String>> {
    let handle = find_partition_handle_by_guid(guid)?;
    read_dir_entries_from_handle(handle, path)
}

pub fn read_dir_entries_from_boot_volume(path: &str) -> Option<Vec<String>> {
    let path = normalize_uefi_path(path);
    let path: CString16 = CString16::try_from(path.as_str()).ok()?;
    let mut fs = open_boot_volume()?;
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
            log::warn!("boot volume get_image_file_system failed: {:?}", err.status());
        }
    }
    let loaded = match boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle()) {
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
    let fs = match boot::open_protocol_exclusive::<SimpleFileSystem>(device) {
        Ok(fs) => fs,
        Err(err) => {
            log::warn!("boot volume fs open failed: {:?}", err.status());
            return None;
        }
    };
    Some(FileSystem::new(fs))
}

pub fn cache_boot_fs_device() {
    if get_cached_boot_fs_device().is_some() {
        return;
    }
    let loaded = match boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle()) {
        Ok(loaded) => loaded,
        Err(_) => return,
    };
    let Some(device) = loaded.device() else {
        return;
    };
    unsafe {
        BOOT_FS_DEVICE = Some(device);
    }
}

fn get_cached_boot_fs_device() -> Option<uefi::Handle> {
    unsafe { BOOT_FS_DEVICE }
}

static mut BOOT_FS_DEVICE: Option<uefi::Handle> = None;
