extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use uefi::boot::{self, OpenProtocolAttributes, OpenProtocolParams, SearchType};
use uefi::proto::device_path::DevicePath;
use uefi::proto::device_path::text::{AllowShortcuts, DevicePathToText, DisplayOnly};
use uefi::proto::device_path::util::DevicePathUtilities;
use uefi::proto::loaded_image::LoadedImage;
use uefi::{Handle, Identify};

pub fn device_path_text_for_loaded_image(handle: Handle) -> Option<String> {
    let loaded = boot::open_protocol_exclusive::<LoadedImage>(handle).ok()?;
    let device_path = loaded.file_path()?;

    let handles =
        boot::locate_handle_buffer(SearchType::ByProtocol(&DevicePathToText::GUID)).ok()?;
    let converter_handle = *handles.first()?;
    let converter = boot::open_protocol_exclusive::<DevicePathToText>(converter_handle).ok()?;

    let text = converter
        .convert_device_path_to_text(device_path, DisplayOnly(true), AllowShortcuts(false))
        .ok()?;
    Some(text.to_string())
}

pub fn device_path_text_for_handle(handle: Handle) -> Option<String> {
    let device_path = unsafe {
        boot::open_protocol::<DevicePath>(
            boot::OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            },
            boot::OpenProtocolAttributes::GetProtocol,
        )
    }
    .ok()?;
    let handles =
        boot::locate_handle_buffer(SearchType::ByProtocol(&DevicePathToText::GUID)).ok()?;
    let converter_handle = *handles.first()?;
    let converter = boot::open_protocol_exclusive::<DevicePathToText>(converter_handle).ok()?;
    let text = converter
        .convert_device_path_to_text(&device_path, DisplayOnly(true), AllowShortcuts(true))
        .ok()?;
    Some(text.to_string())
}

pub fn device_path_text_from_bytes(bytes: &[u8]) -> Option<String> {
    let device_path = <&DevicePath>::try_from(bytes).ok()?;
    let handles =
        boot::locate_handle_buffer(SearchType::ByProtocol(&DevicePathToText::GUID)).ok()?;
    let converter_handle = *handles.first()?;
    let converter = boot::open_protocol_exclusive::<DevicePathToText>(converter_handle).ok()?;
    let text = converter
        .convert_device_path_to_text(device_path, DisplayOnly(true), AllowShortcuts(true))
        .ok()?;
    Some(text.to_string())
}

pub fn device_path_bytes_for_handle(handle: Handle) -> Option<Vec<u8>> {
    let device_path = unsafe {
        boot::open_protocol::<DevicePath>(
            OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    };
    let device_path = match device_path {
        Ok(device_path) => device_path,
        Err(err) => {
            log::warn!(
                "DevicePath open failed: {:?} handle={:p}",
                err.status(),
                handle.as_ptr()
            );
            return None;
        }
    };
    let handles =
        boot::locate_handle_buffer(SearchType::ByProtocol(&DevicePathUtilities::GUID)).ok()?;
    let util_handle = *handles.first()?;
    let util = unsafe {
        boot::open_protocol::<DevicePathUtilities>(
            OpenProtocolParams {
                handle: util_handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }
    .ok()?;
    let size = util.get_size(&device_path);
    if size == 0 {
        return None;
    }
    let ptr = device_path.as_ffi_ptr().cast::<u8>();
    let bytes = unsafe { core::slice::from_raw_parts(ptr, size) };
    Some(bytes.to_vec())
}

pub fn partition_guid_from_device_path_bytes(bytes: &[u8]) -> Option<[u8; 16]> {
    let mut offset = 0;
    while offset + 4 <= bytes.len() {
        let node_type = bytes[offset];
        let node_subtype = bytes[offset + 1];
        let length = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
        if length < 4 || offset + length > bytes.len() {
            break;
        }
        if node_type == 0x7f && node_subtype == 0xff {
            break;
        }
        if node_type == 0x04 && node_subtype == 0x01 {
            if length >= 4 + 4 + 8 + 8 + 16 + 1 + 1 {
                let sig_type = bytes[offset + 4 + 4 + 8 + 8 + 16 + 1];
                if sig_type == 0x02 {
                    let mut guid = [0u8; 16];
                    let start = offset + 4 + 4 + 8 + 8;
                    guid.copy_from_slice(&bytes[start..start + 16]);
                    return Some(guid);
                }
            }
        }
        offset += length;
    }
    None
}

pub fn device_path_has_cdrom(bytes: &[u8]) -> bool {
    let mut offset = 0;
    while offset + 4 <= bytes.len() {
        let node_type = bytes[offset];
        let node_subtype = bytes[offset + 1];
        let length = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
        if length < 4 || offset + length > bytes.len() {
            break;
        }
        if node_type == 0x7f && node_subtype == 0xff {
            break;
        }
        // Media Device Path -> CD-ROM
        if node_type == 0x04 && node_subtype == 0x02 {
            return true;
        }
        offset += length;
    }
    false
}

pub fn partition_guid_for_handle(handle: Handle) -> Option<[u8; 16]> {
    let bytes = device_path_bytes_for_handle(handle)?;
    partition_guid_from_device_path_bytes(&bytes)
}

pub fn device_path_prefix_before_file_path(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut offset = 0usize;
    while offset + 4 <= bytes.len() {
        let node_type = bytes[offset];
        let node_subtype = bytes[offset + 1];
        let length = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
        if length < 4 || offset + length > bytes.len() {
            break;
        }
        if node_type == 0x7f && node_subtype == 0xff {
            break;
        }
        if node_type == 0x04 && node_subtype == 0x04 {
            if offset == 0 {
                return None;
            }
            return Some(bytes[..offset].to_vec());
        }
        offset += length;
    }
    None
}

pub fn device_path_prefix_before_hard_drive(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut offset = 0usize;
    while offset + 4 <= bytes.len() {
        let node_type = bytes[offset];
        let node_subtype = bytes[offset + 1];
        let length = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
        if length < 4 || offset + length > bytes.len() {
            break;
        }
        if node_type == 0x7f && node_subtype == 0xff {
            break;
        }
        // Media Device Path -> Hard Drive
        if node_type == 0x04 && node_subtype == 0x01 {
            if offset == 0 {
                return None;
            }
            return Some(bytes[..offset].to_vec());
        }
        offset += length;
    }
    None
}
