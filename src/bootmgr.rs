extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::{BootError, Result};
use uefi::CStr16;
use uefi::runtime::{self, VariableVendor};

use crate::uefi_helpers::device_path_text_from_bytes;

const EFI_GLOBAL_VARIABLE_GUID: [u8; 16] = [
    0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c,
];

pub trait FirmwareVariables {
    fn read(&self, name: &str, vendor: [u8; 16]) -> Result<Vec<u8>>;
}

pub struct BootEntry {
    pub number: u16,
    pub attributes: u32,
    pub description: Option<String>,
    pub device_path: Option<String>,
    pub file_path_bytes: Option<Vec<u8>>,
    pub raw: Vec<u8>,
}

pub struct BootInfo {
    pub boot_current: Option<u16>,
    pub boot_order: Vec<u16>,
    pub entries: Vec<BootEntry>,
}

impl BootInfo {
    pub fn empty() -> Self {
        Self {
            boot_current: None,
            boot_order: Vec::new(),
            entries: Vec::new(),
        }
    }
}

pub fn collect() -> BootInfo {
    let vars = UefiFirmwareVars;
    match collect_from_vars(&vars) {
        Ok(info) => info,
        Err(err) => {
            log::warn!("boot manager vars unavailable: {}", err);
            BootInfo::empty()
        }
    }
}

fn collect_from_vars(vars: &impl FirmwareVariables) -> Result<BootInfo> {
    let mut info = BootInfo::empty();

    if let Ok(data) = vars.read("BootCurrent", EFI_GLOBAL_VARIABLE_GUID) {
        info.boot_current = parse_u16("BootCurrent", &data)?;
    }

    if let Ok(data) = vars.read("BootOrder", EFI_GLOBAL_VARIABLE_GUID) {
        info.boot_order = parse_u16_list("BootOrder", &data)?;
    }

    for entry in &info.boot_order {
        let name = format!("Boot{:04X}", entry);
        match vars.read(&name, EFI_GLOBAL_VARIABLE_GUID) {
            Ok(raw) => {
                let mut parsed = parse_boot_entry(*entry, &raw);
                parsed.raw = raw;
                info.entries.push(parsed);
            }
            Err(err) => log::warn!("boot entry {} unreadable: {}", name, err),
        }
    }

    Ok(info)
}

fn parse_u16(name: &str, data: &[u8]) -> Result<Option<u16>> {
    if data.len() < 2 {
        log::warn!("{} too short ({} bytes)", name, data.len());
        return Ok(None);
    }
    Ok(Some(u16::from_le_bytes([data[0], data[1]])))
}

fn parse_u16_list(name: &str, data: &[u8]) -> Result<Vec<u16>> {
    if data.len() % 2 != 0 {
        return Err(BootError::InvalidData("u16 list not aligned"));
    }

    let mut list = Vec::new();
    for chunk in data.chunks_exact(2) {
        list.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }

    if list.is_empty() {
        log::warn!("{} empty", name);
    }

    Ok(list)
}

fn parse_boot_entry(number: u16, raw: &[u8]) -> BootEntry {
    let mut entry = BootEntry {
        number,
        attributes: 0,
        description: None,
        device_path: None,
        file_path_bytes: None,
        raw: Vec::new(),
    };

    if raw.len() < 6 {
        log::warn!("Boot{:04X} too short ({} bytes)", number, raw.len());
        return entry;
    }

    entry.attributes = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let file_path_len = u16::from_le_bytes([raw[4], raw[5]]) as usize;

    let mut cursor = 6;
    let mut name_u16 = Vec::new();
    while cursor + 1 < raw.len() {
        let val = u16::from_le_bytes([raw[cursor], raw[cursor + 1]]);
        cursor += 2;
        name_u16.push(val);
        if val == 0 {
            break;
        }
    }

    if let Ok(cstr) = CStr16::from_u16_until_nul(&name_u16) {
        entry.description = Some(cstr.to_string());
    }

    if file_path_len > 0 && cursor + file_path_len <= raw.len() {
        let path_bytes = &raw[cursor..cursor + file_path_len];
        entry.device_path = device_path_text_from_bytes(path_bytes)
            .or_else(|| Some(format!("device_path_bytes={}", file_path_len)));
        entry.file_path_bytes = Some(path_bytes.to_vec());
    }

    entry
}

struct UefiFirmwareVars;

impl FirmwareVariables for UefiFirmwareVars {
    fn read(&self, name: &str, _vendor: [u8; 16]) -> Result<Vec<u8>> {
        let mut buf = [0u16; 64];
        let name = CStr16::from_str_with_buf(name, &mut buf)
            .map_err(|_| BootError::InvalidData("bad var name"))?;
        let (data, _attrs) = runtime::get_variable_boxed(name, &VariableVendor::GLOBAL_VARIABLE)
            .map_err(|err| BootError::Uefi(err.status()))?;
        Ok(data.into_vec())
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    extern crate std;

    use alloc::string::ToString;
    use alloc::vec::Vec;

    use super::{FirmwareVariables, collect_from_vars, parse_boot_entry, parse_u16_list};
    use crate::error::Result;

    struct FakeVars {
        boot_current: Option<Vec<u8>>,
        boot_order: Option<Vec<u8>>,
        boot_entry: Option<Vec<u8>>,
    }

    impl FirmwareVariables for FakeVars {
        fn read(&self, name: &str, _vendor: [u8; 16]) -> Result<Vec<u8>> {
            match name {
                "BootCurrent" => Ok(self.boot_current.clone().unwrap_or_default()),
                "BootOrder" => Ok(self.boot_order.clone().unwrap_or_default()),
                "Boot0001" => Ok(self.boot_entry.clone().unwrap_or_default()),
                _ => Err(crate::error::BootError::InvalidData("unknown var")),
            }
        }
    }

    fn build_boot_entry_raw(attributes: u32, description: &str, device_path: &[u8]) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.extend_from_slice(&attributes.to_le_bytes());
        raw.extend_from_slice(&(device_path.len() as u16).to_le_bytes());
        for ch in description.encode_utf16() {
            raw.extend_from_slice(&ch.to_le_bytes());
        }
        raw.extend_from_slice(&0u16.to_le_bytes());
        raw.extend_from_slice(device_path);
        raw
    }

    #[test]
    fn test_parse_u16_list_rejects_unaligned() {
        let err = parse_u16_list("BootOrder", &[0x12])
            .err()
            .expect("expected error");
        let _ = err;
    }

    #[test]
    fn test_parse_boot_entry_basic_fields() {
        let raw = build_boot_entry_raw(0x00000001, "Test", &[0x01, 0x02, 0x03, 0x04]);
        let entry = parse_boot_entry(1, &raw);
        assert_eq!(entry.number, 1);
        assert_eq!(entry.attributes, 0x00000001);
        assert_eq!(entry.description, Some("Test".to_string()));
        assert_eq!(entry.device_path, Some("device_path_bytes=4".to_string()));
        assert_eq!(
            entry.file_path_bytes.as_deref(),
            Some(&[0x01, 0x02, 0x03, 0x04][..])
        );
    }

    #[test]
    fn test_collect_from_vars_boot_entry() {
        let boot_entry = build_boot_entry_raw(0x00000001, "Boot", &[0xaa, 0xbb]);
        let vars = FakeVars {
            boot_current: Some(1u16.to_le_bytes().to_vec()),
            boot_order: Some(1u16.to_le_bytes().to_vec()),
            boot_entry: Some(boot_entry),
        };
        let info = collect_from_vars(&vars).expect("collect");
        assert_eq!(info.boot_current, Some(1));
        assert_eq!(info.boot_order, alloc::vec![1]);
        assert_eq!(info.entries.len(), 1);
        assert_eq!(info.entries[0].number, 1);
    }
}
