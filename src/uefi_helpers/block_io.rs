extern crate alloc;

use alloc::vec::Vec;

use uefi::boot::{self, SearchType};
use uefi::proto::media::block::BlockIO;
use uefi::{Handle, Identify};

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
        let block = match boot::open_protocol_exclusive::<BlockIO>(handle) {
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
