extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use uefi::boot::ScopedProtocol;
use uefi::boot::{self, OpenProtocolAttributes, OpenProtocolParams, SearchType};
use uefi::proto::media::block::BlockIO;
use uefi::{Handle, Identify};

use crate::uefi_helpers::device_path::device_path_bytes_for_handle;
use crate::uefi_helpers::device_path::device_path_text_for_handle;
use crate::uefi_helpers::device_path::partition_guid_for_handle;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct BlockDeviceInfo {
    pub handle: Handle,
    pub media_id: u32,
    pub block_size: u32,
    pub io_align: u32,
    pub last_block: u64,
    pub logical_partition: bool,
    pub removable: bool,
    pub read_only: bool,
}

pub fn enumerate_block_devices() -> Vec<BlockDeviceInfo> {
    let mut devices = Vec::new();
    let handles = match boot::locate_handle_buffer(SearchType::ByProtocol(&BlockIO::GUID)) {
        Ok(handles) => handles,
        Err(err) => {
            log::warn!("BlockIO handles unavailable: {:?}", err.status());
            return devices;
        }
    };

    for handle in handles.iter().copied() {
        let block = match open_block_io(handle) {
            Ok(block) => block,
            Err(err) => {
                log::warn!("BlockIO open failed: {:?}", err.status());
                continue;
            }
        };
        let media = block.media();
        if !media.is_media_present() {
            continue;
        }
        devices.push(BlockDeviceInfo {
            handle,
            media_id: media.media_id(),
            block_size: media.block_size(),
            io_align: media.io_align(),
            last_block: media.last_block(),
            logical_partition: media.is_logical_partition(),
            removable: media.is_removable_media(),
            read_only: media.is_read_only(),
        });
    }

    devices
}

pub fn find_partition_handle_by_guid(guid: [u8; 16]) -> Option<Handle> {
    for device in enumerate_block_devices() {
        if !device.logical_partition {
            continue;
        }
        if let Some(device_guid) = partition_guid_for_handle(device.handle) {
            if device_guid == guid {
                return Some(device.handle);
            }
        }
    }
    None
}

pub fn find_block_handle_by_device_path_prefix(target: &[u8]) -> Option<Handle> {
    for device in enumerate_block_devices() {
        let Some(bytes) = device_path_bytes_for_handle(device.handle) else {
            continue;
        };
        let prefix = strip_end_node(&bytes);
        if prefix.is_empty() {
            continue;
        }
        if target.starts_with(prefix) {
            return Some(device.handle);
        }
    }
    None
}

pub fn find_block_handle_by_device_path_exact(target: &[u8]) -> Option<Handle> {
    let target = strip_end_node(target);
    if target.is_empty() {
        return None;
    }
    for device in enumerate_block_devices() {
        let Some(bytes) = device_path_bytes_for_handle(device.handle) else {
            continue;
        };
        let prefix = strip_end_node(&bytes);
        if prefix == target {
            return Some(device.handle);
        }
    }
    None
}

pub fn find_block_handle_by_device_path_text_prefix(target: &str) -> Option<Handle> {
    for device in enumerate_block_devices() {
        let Some(text) = device_path_text_for_handle(device.handle) else {
            continue;
        };
        if target.starts_with(&text) {
            return Some(device.handle);
        }
    }
    None
}

pub fn open_block_io(handle: Handle) -> uefi::Result<ScopedProtocol<BlockIO>> {
    let result = unsafe {
        boot::open_protocol::<BlockIO>(
            OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    };
    if let Err(err) = &result {
        let path_text =
            device_path_text_for_handle(handle).unwrap_or_else(|| "<unavailable>".to_string());
        let path_len = device_path_bytes_for_handle(handle)
            .map(|bytes| bytes.len())
            .unwrap_or(0);
        let guid = partition_guid_for_handle(handle)
            .map(format_guid_bytes)
            .unwrap_or_else(|| "<none>".to_string());
        log::warn!(
            "BlockIO open failed: {:?} handle={:p} path={} guid={} path_len={}",
            err.status(),
            handle.as_ptr(),
            path_text,
            guid,
            path_len
        );
    }
    result
}

fn format_guid_bytes(guid: [u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        guid[0],
        guid[1],
        guid[2],
        guid[3],
        guid[4],
        guid[5],
        guid[6],
        guid[7],
        guid[8],
        guid[9],
        guid[10],
        guid[11],
        guid[12],
        guid[13],
        guid[14],
        guid[15]
    )
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
