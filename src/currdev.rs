extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::bootmgr::{BootEntry, BootInfo};
use crate::env::loader::LoaderEnv;
use crate::uefi_helpers::block_io::find_block_handle_by_device_path_exact;
use crate::uefi_helpers::block_io::find_block_handle_by_device_path_prefix;
use crate::uefi_helpers::block_io::find_block_handle_by_device_path_text_prefix;
use crate::uefi_helpers::device_path::{
    device_path_bytes_for_handle, device_path_has_cdrom, device_path_prefix_before_file_path,
};
use crate::uefi_helpers::partition_guid_from_device_path_bytes;
use uefi::boot::{self, OpenProtocolParams};
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::network::snp::SimpleNetwork;
use uefi::Handle;

#[derive(Debug, Clone, Copy)]
pub enum CurrDevSource {
    BootManager,
    Fallback,
}

pub struct CurrDev {
    pub source: CurrDevSource,
    pub description: String,
    pub partition_guid: Option<[u8; 16]>,
    pub kernel_path: Option<String>,
    pub prefer_iso: bool,
    pub iso_handle: Option<Handle>,
}

pub fn select_currdev(info: &BootInfo, env: &LoaderEnv) -> Option<CurrDev> {
    if matches!(
        env.get("zhamel_no_currdev"),
        Some("1") | Some("YES") | Some("yes") | Some("true")
    ) {
        return None;
    }
    if let Some(rootdev) = env.get("rootdev") {
        return Some(CurrDev {
            source: CurrDevSource::BootManager,
            description: alloc::format!("rootdev={}", rootdev),
            partition_guid: None,
            kernel_path: None,
            prefer_iso: false,
            iso_handle: None,
        });
    }
    if let Some(uefi_rootdev) = env.get("uefi_rootdev") {
        return Some(CurrDev {
            source: CurrDevSource::BootManager,
            description: alloc::format!("uefi_rootdev={}", uefi_rootdev),
            partition_guid: None,
            kernel_path: None,
            prefer_iso: false,
            iso_handle: None,
        });
    }

    if let Some(active) = env.get("zfs_be_active") {
        return Some(CurrDev {
            source: CurrDevSource::BootManager,
            description: alloc::format!("zfs bootenv {}", active),
            partition_guid: None,
            kernel_path: None,
            prefer_iso: false,
            iso_handle: None,
        });
    }
    if let Some(bootonce) = env.get("zfs_bootonce") {
        let active = alloc::format!("zfs:{}:", bootonce);
        return Some(CurrDev {
            source: CurrDevSource::BootManager,
            description: alloc::format!("zfs bootenv {}", active),
            partition_guid: None,
            kernel_path: None,
            prefer_iso: false,
            iso_handle: None,
        });
    }

    if let Some(entry) = select_boot_entry(info) {
        let desc = describe_boot_entry(entry.number, &info.entries);
        let guid = entry_partition_guid(entry.number, &info.entries);
        let kernel_path = kernel_path_from_entry(entry);
        let prefer_iso = entry_prefers_iso(entry);
        let iso_handle = entry_iso_handle(entry);
        if guid.is_none() {
            if let Some(mut fallback) = fallback_from_loaded_image() {
                if fallback.kernel_path.is_none() {
                    fallback.kernel_path = kernel_path;
                }
                if prefer_iso {
                    fallback.prefer_iso = true;
                }
                if fallback.iso_handle.is_none() && iso_handle.is_some() {
                    fallback.iso_handle = iso_handle;
                }
                return Some(fallback);
            }
        }
        return Some(CurrDev {
            source: CurrDevSource::BootManager,
            description: desc,
            partition_guid: guid,
            kernel_path,
            prefer_iso,
            iso_handle,
        });
    }

    fallback_from_loaded_image()
}

//#[cfg(test)]
#[cfg(any(test, not(target_os = "uefi")))]
mod tests {
    extern crate alloc;
    extern crate std;

    use alloc::string::ToString;
    use alloc::vec::Vec;

    use super::select_currdev;
    use crate::bootmgr::BootInfo;
    use crate::env::loader::LoaderEnv;
    use crate::env::parser::EnvVar;

    #[test]
    fn test_rootdev_precedence() {
        let info = BootInfo::empty();
        let env = LoaderEnv {
            env_vars: alloc::vec![EnvVar {
                key: "rootdev".to_string(),
                value: "disk0p1".to_string(),
            }],
            conf_vars: alloc::vec![EnvVar {
                key: "uefi_rootdev".to_string(),
                value: "ignored".to_string(),
            }],
        };
        let curr = select_currdev(&info, &env).expect("currdev");
        assert!(curr.description.contains("rootdev="));
        assert!(curr.partition_guid.is_none());
        assert!(curr.kernel_path.is_none());
    }

    #[test]
    fn test_uefi_rootdev_precedence_over_bootmgr() {
        let mut info = BootInfo::empty();
        info.boot_current = Some(1);
        let env = LoaderEnv {
            env_vars: alloc::vec![],
            conf_vars: alloc::vec![EnvVar {
                key: "uefi_rootdev".to_string(),
                value: "disk1p2".to_string(),
            }],
        };
        let curr = select_currdev(&info, &env).expect("currdev");
        assert!(curr.description.contains("uefi_rootdev="));
        assert!(curr.partition_guid.is_none());
        assert!(curr.kernel_path.is_none());
    }

    #[test]
    fn test_zfs_bootenv_precedence_over_bootmgr() {
        let mut info = BootInfo::empty();
        info.boot_current = Some(1);
        let env = LoaderEnv {
            env_vars: alloc::vec![EnvVar {
                key: "zfs_be_active".to_string(),
                value: "zfs:zroot/ROOT/default:".to_string(),
            }],
            conf_vars: alloc::vec![],
        };
        let curr = select_currdev(&info, &env).expect("currdev");
        assert!(curr.description.contains("zfs bootenv"));
        assert!(curr.partition_guid.is_none());
    }

    #[test]
    fn test_find_partition_guid() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x04, 0x01, 0x2A, 0x00]); // type/subtype/len 42
        bytes.extend_from_slice(&1u32.to_le_bytes()); // partition number
        bytes.extend_from_slice(&0u64.to_le_bytes()); // start
        bytes.extend_from_slice(&0u64.to_le_bytes()); // size
        let mut guid = [0u8; 16];
        guid[0] = 0x11;
        bytes.extend_from_slice(&guid);
        bytes.push(0x02); // signature type GUID
        bytes.push(0x02); // MBR type
        bytes.extend_from_slice(&[0x7f, 0xff, 0x04, 0x00]); // end node
        let parsed =
            crate::uefi_helpers::partition_guid_from_device_path_bytes(&bytes).expect("guid");
        assert_eq!(parsed[0], 0x11);
    }

    #[test]
    fn test_kernel_path_from_boot_entry() {
        let mut entry = crate::bootmgr::BootEntry {
            number: 1,
            attributes: 0,
            description: None,
            device_path: None,
            file_path_bytes: None,
            raw: Vec::new(),
        };
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x04, 0x04, 0x2A, 0x00]);
        let path = r"\boot\kernel\kernel";
        for ch in path.encode_utf16() {
            bytes.extend_from_slice(&ch.to_le_bytes());
        }
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&[0x7f, 0xff, 0x04, 0x00]);
        entry.file_path_bytes = Some(bytes);
        let parsed = super::kernel_path_from_entry(&entry).expect("path");
        assert_eq!(parsed, "/boot/kernel/kernel".to_string());
    }
}

fn describe_boot_entry(number: u16, entries: &[BootEntry]) -> String {
    if let Some(entry) = entries.iter().find(|e| e.number == number) {
        let mut desc = alloc::format!("bootmgr: Boot{:04X}", number);
        if let Some(label) = &entry.description {
            desc.push_str(" ");
            desc.push_str(label);
        }
        if let Some(path) = &entry.device_path {
            desc.push_str(" ");
            desc.push_str(path);
        }
        desc
    } else {
        alloc::format!("bootmgr: BootCurrent=0x{:04x}", number)
    }
}

fn entry_partition_guid(number: u16, entries: &[BootEntry]) -> Option<[u8; 16]> {
    let entry = entries.iter().find(|e| e.number == number)?;
    let bytes = entry.file_path_bytes.as_ref()?;
    partition_guid_from_device_path_bytes(bytes)
}

fn select_boot_entry<'a>(info: &'a BootInfo) -> Option<&'a BootEntry> {
    if let Some(current) = info.boot_current {
        if let Some(entry) = info.entries.iter().find(|e| e.number == current) {
            return Some(entry);
        }
    }
    for number in &info.boot_order {
        if let Some(entry) = info.entries.iter().find(|e| e.number == *number) {
            return Some(entry);
        }
    }
    None
}

fn kernel_path_from_entry(entry: &BootEntry) -> Option<String> {
    let bytes = entry.file_path_bytes.as_ref()?;
    let raw = device_path_file_path(bytes)?;
    let mut path = raw.replace('\\', "/");
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    let lower = path.to_ascii_lowercase();
    if lower.contains("/boot/kernel/") {
        Some(path)
    } else {
        None
    }
}

fn device_path_file_path(bytes: &[u8]) -> Option<String> {
    let mut offset = 0usize;
    while offset + 4 <= bytes.len() {
        let ty = bytes[offset];
        let subtype = bytes[offset + 1];
        let len = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
        if len < 4 || offset + len > bytes.len() {
            break;
        }
        if ty == 0x04 && subtype == 0x04 && len >= 6 {
            let mut u16s = Vec::new();
            let data = &bytes[offset + 4..offset + len];
            for chunk in data.chunks_exact(2) {
                let val = u16::from_le_bytes([chunk[0], chunk[1]]);
                if val == 0 {
                    break;
                }
                u16s.push(val);
            }
            return String::from_utf16(&u16s).ok();
        }
        if ty == 0x7f && subtype == 0xff {
            break;
        }
        offset += len;
    }
    None
}

fn fallback_from_loaded_image() -> Option<CurrDev> {
    let image_handle = boot::image_handle();
    let mut device_handle = image_handle;
    if let Ok(loaded) = boot::open_protocol_exclusive::<LoadedImage>(image_handle) {
        if let Some(device) = loaded.device() {
            device_handle = device;
        }
    }
    let guid = crate::uefi_helpers::device_path::partition_guid_for_handle(device_handle);
    if let Some(guid) = guid {
        return Some(CurrDev {
            source: CurrDevSource::Fallback,
            description: String::from("image_device"),
            partition_guid: Some(guid),
            kernel_path: None,
            prefer_iso: image_handle_is_cdrom(),
            iso_handle: image_iso_handle(),
        });
    }

    let has_net = boot::test_protocol::<SimpleNetwork>(OpenProtocolParams {
        handle: image_handle,
        agent: image_handle,
        controller: None,
    })
    .unwrap_or(false);
    if has_net {
        return Some(CurrDev {
            source: CurrDevSource::Fallback,
            description: String::from("netboot"),
            partition_guid: None,
            kernel_path: None,
            prefer_iso: false,
            iso_handle: None,
        });
    }

    None
}

fn entry_prefers_iso(entry: &BootEntry) -> bool {
    if entry
        .file_path_bytes
        .as_deref()
        .map(device_path_has_cdrom)
        .unwrap_or(false)
    {
        return true;
    }
    if let Some(desc) = entry.description.as_deref() {
        if text_prefers_iso(desc) {
            return true;
        }
    }
    if let Some(path) = entry.device_path.as_deref() {
        if text_prefers_iso(path) {
            return true;
        }
    }
    false
}

fn image_handle_is_cdrom() -> bool {
    let handle = boot::image_handle();
    let Some(bytes) = device_path_bytes_for_handle(handle) else {
        return false;
    };
    device_path_has_cdrom(&bytes)
}

fn entry_iso_handle(entry: &BootEntry) -> Option<Handle> {
    if let Some(bytes) = entry.file_path_bytes.as_ref() {
        if let Some(prefix) = device_path_prefix_before_file_path(bytes) {
            if let Some(handle) = find_block_handle_by_device_path_exact(&prefix) {
                return Some(handle);
            }
        }
        if let Some(handle) = find_block_handle_by_device_path_prefix(bytes) {
            return Some(handle);
        }
    }
    if let Some(text) = entry.device_path.as_deref() {
        if let Some(handle) = find_block_handle_by_device_path_text_prefix(text) {
            return Some(handle);
        }
    }
    None
}

fn image_iso_handle() -> Option<Handle> {
    let handle = boot::image_handle();
    if let Some(bytes) = device_path_bytes_for_handle(handle) {
        if let Some(found) = find_block_handle_by_device_path_prefix(&bytes) {
            return Some(found);
        }
    }
    if let Some(text) = crate::uefi_helpers::device_path::device_path_text_for_loaded_image(handle) {
        if let Some(found) = find_block_handle_by_device_path_text_prefix(&text) {
            return Some(found);
        }
    }
    None
}

fn text_prefers_iso(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("dvd") || lower.contains("cdrom")
}
