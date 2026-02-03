extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use uefi::boot;
use uefi::fs::FileSystem;
use uefi::runtime::{self, VariableVendor};
use uefi::{CStr16, CString16, Guid};

use crate::env::parser::{parse_loader_conf_text, parse_loader_env_text, EnvVar};
use crate::fs::uefi::{normalize_uefi_path, read_file_from_partition_guid};

pub struct LoaderEnv {
    pub env_vars: Vec<EnvVar>,
    pub conf_vars: Vec<EnvVar>,
}

impl LoaderEnv {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.env_vars
            .iter()
            .find(|var| var.key == key)
            .map(|var| var.value.as_str())
            .or_else(|| {
                self.conf_vars
                    .iter()
                    .find(|var| var.key == key)
                    .map(|var| var.value.as_str())
            })
    }

    pub fn set(&mut self, key: &str, value: &str) {
        if let Some(var) = self.env_vars.iter_mut().find(|var| var.key == key) {
            var.value = value.to_string();
            return;
        }
        self.env_vars.push(EnvVar {
            key: key.to_string(),
            value: value.to_string(),
        });
    }

    pub fn set_if_unset(&mut self, key: &str, value: &str) {
        if self.get(key).is_none() {
            self.set(key, value);
        }
    }
}

pub fn load_from_boot_volume() -> LoaderEnv {
    let mut env_vars = Vec::new();
    let mut conf_vars = Vec::new();

    if let Some(path) = read_freebsd_var("LoaderEnv").or_else(|| Some(String::from(LOADER_ENV_DEFAULT))) {
        if let Some(bytes) = read_file(&path) {
            log::info!("loader env read {} bytes from {}", bytes.len(), path);
            if let Ok(text) = core::str::from_utf8(&bytes) {
                env_vars = parse_loader_env_text(text);
            }
        } else {
            log::warn!("loader env missing: {}", path);
        }
    }

    if let Some(path) = read_freebsd_var("NextLoaderEnv") {
        delete_freebsd_var("NextLoaderEnv");
        if let Some(bytes) = read_file(&path) {
            log::info!("next loader env read {} bytes from {}", bytes.len(), path);
            if let Ok(text) = core::str::from_utf8(&bytes) {
                env_vars = parse_loader_env_text(text);
            }
        } else {
            log::warn!("next loader env missing: {}", path);
        }
    }

    if let Some(bytes) = read_file("/boot/loader.conf") {
        log::info!("loader.conf read {} bytes", bytes.len());
        if let Ok(text) = core::str::from_utf8(&bytes) {
            conf_vars = parse_loader_conf_text(text);
        }
    } else {
        log::warn!("loader.conf missing");
    }

    LoaderEnv { env_vars, conf_vars }
}

pub fn load_loader_conf_from_partition_guid(guid: [u8; 16]) -> Option<Vec<EnvVar>> {
    let bytes = read_file_from_partition_guid(guid, "/boot/loader.conf")?;
    let text = core::str::from_utf8(&bytes).ok()?;
    Some(parse_loader_conf_text(text))
}

fn read_file(path: &str) -> Option<Vec<u8>> {
    let path = normalize_uefi_path(path);
    let path: CString16 = CString16::try_from(path.as_str()).ok()?;
    let fs = boot::get_image_file_system(boot::image_handle()).ok()?;
    let mut fs = FileSystem::new(fs);
    match fs.read(path.as_ref()) {
        Ok(bytes) => Some(bytes),
        Err(err) => {
            log::warn!("env read failed: {:?} ({})", err, path);
            None
        }
    }
}


fn read_freebsd_var(name: &str) -> Option<String> {
    let mut buf = [0u16; 64];
    let name = CStr16::from_str_with_buf(name, &mut buf).ok()?;
    let vendor = VariableVendor(FREEBSD_BOOT_VAR_GUID);
    let (data, _attrs) = runtime::get_variable_boxed(name, &vendor).ok()?;
    if data.len() % 2 != 0 {
        return None;
    }
    let mut u16s = Vec::with_capacity(data.len() / 2);
    for chunk in data.chunks_exact(2) {
        u16s.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    let cstr = CStr16::from_u16_until_nul(&u16s).ok()?;
    Some(String::from(cstr))
}

fn delete_freebsd_var(name: &str) {
    let mut buf = [0u16; 64];
    if let Ok(name) = CStr16::from_str_with_buf(name, &mut buf) {
        let vendor = VariableVendor(FREEBSD_BOOT_VAR_GUID);
        let _ = runtime::delete_variable(name, &vendor);
    }
}

const LOADER_ENV_DEFAULT: &str = "/efi/freebsd/loader.env";
const FREEBSD_BOOT_VAR_GUID: Guid = Guid::from_bytes([
    0xCF, 0xEE, 0x69, 0xAD, 0xA0, 0xDE, 0x47, 0xA9, 0x93, 0xA8, 0xF6, 0x31, 0x06, 0xF8,
    0xAE, 0x99,
]);
