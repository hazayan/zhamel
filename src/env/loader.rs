extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use uefi::runtime::{self, VariableVendor};
use uefi::{CStr16, Guid};

use crate::env::parser::{parse_loader_conf_text, parse_loader_env_text, EnvVar};
use crate::fs::uefi::{
    read_dir_entries_from_boot_volume, read_dir_entries_from_partition_guid,
    read_file_from_boot_volume, read_file_from_partition_guid,
};

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

    pub fn unset(&mut self, key: &str) {
        self.env_vars.retain(|var| var.key != key);
        self.conf_vars.retain(|var| var.key != key);
    }
}

pub fn load_from_boot_volume() -> LoaderEnv {
    let mut env_vars = Vec::new();

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

    let conf_vars = load_loader_conf_from_boot_volume(&env_vars);
    if conf_vars.is_empty() {
        log::warn!("loader.conf not found");
    } else {
        log::info!("loader.conf vars loaded: {}", conf_vars.len());
    }

    LoaderEnv { env_vars, conf_vars }
}

pub fn load_loader_conf_from_partition_guid(
    guid: [u8; 16],
    env_vars: &[EnvVar],
) -> Option<Vec<EnvVar>> {
    let conf_vars = load_loader_conf_with(
        env_vars,
        |path| read_file_from_partition_guid(guid, path),
        |path| read_dir_entries_from_partition_guid(guid, path),
    );
    if conf_vars.is_empty() {
        None
    } else {
        Some(conf_vars)
    }
}

fn read_file(path: &str) -> Option<Vec<u8>> {
    read_file_from_boot_volume(path)
}

fn load_loader_conf_from_boot_volume(env_vars: &[EnvVar]) -> Vec<EnvVar> {
    load_loader_conf_with(
        env_vars,
        |path| read_file(path),
        |path| read_dir_entries_from_boot_volume(path),
    )
}

fn load_loader_conf_with<F, D>(env_vars: &[EnvVar], read_file: F, read_dir: D) -> Vec<EnvVar>
where
    F: Fn(&str) -> Option<Vec<u8>>,
    D: Fn(&str) -> Option<Vec<String>>,
{
    let mut conf_vars = Vec::new();
    let mut loaded_files = BTreeSet::new();

    read_loader_conf_file(
        "/boot/defaults/loader.conf",
        &read_file,
        &mut conf_vars,
        &mut loaded_files,
    );

    if conf_vars.is_empty() {
        read_loader_conf_file(
            "/boot/loader.conf",
            &read_file,
            &mut conf_vars,
            &mut loaded_files,
        );
    }

    if get_env_value(env_vars, &conf_vars, "loader_conf_files").is_none() {
        let fallback = "/boot/device.hints /boot/loader.conf";
        log::warn!("loader_conf_files not set; falling back to {}", fallback);
        set_conf_var(
            &mut conf_vars,
            "loader_conf_files".to_string(),
            fallback.to_string(),
        );
        for name in fallback.split_whitespace() {
            read_loader_conf_file(name, &read_file, &mut conf_vars, &mut loaded_files);
        }
    }

    let mut loader_conf_dirs =
        get_env_value(env_vars, &conf_vars, "loader_conf_dirs").map(|value| value.to_string());
    let product_vars =
        get_env_value(env_vars, &conf_vars, "product_vars").map(|value| value.to_string());
    if let Some(product_vars) = product_vars {
        let mut product_conf_dirs = String::new();
        for var in product_vars.split_whitespace() {
            if let Some(product) = get_env_value(env_vars, &conf_vars, var) {
                if !product_conf_dirs.is_empty() {
                    product_conf_dirs.push(' ');
                }
                product_conf_dirs.push_str("/boot/loader.conf.d/");
                product_conf_dirs.push_str(product);
            }
        }
        if !product_conf_dirs.is_empty() {
            loader_conf_dirs = match loader_conf_dirs {
                Some(mut dirs) => {
                    dirs.push(' ');
                    dirs.push_str(&product_conf_dirs);
                    Some(dirs)
                }
                None => Some(product_conf_dirs),
            };
        }
    }

    if let Some(dirs) = loader_conf_dirs {
        for dir in dirs.split_whitespace() {
            load_loader_conf_dir(
                dir,
                &read_dir,
                &read_file,
                &mut conf_vars,
                &mut loaded_files,
            );
        }
    }

    load_nextboot_conf(env_vars, &read_file, &mut conf_vars, &mut loaded_files);

    let local_files =
        get_env_value(env_vars, &conf_vars, "local_loader_conf_files").map(|value| value.to_string());
    if let Some(local_files) = local_files {
        for name in local_files.split_whitespace() {
            read_loader_conf_file(name, &read_file, &mut conf_vars, &mut loaded_files);
        }
    }

    conf_vars
}

fn load_loader_conf_dir<F, D>(
    dir: &str,
    read_dir: &D,
    read_file: &F,
    conf_vars: &mut Vec<EnvVar>,
    loaded_files: &mut BTreeSet<String>,
)
where
    F: Fn(&str) -> Option<Vec<u8>>,
    D: Fn(&str) -> Option<Vec<String>>,
{
    let Some(entries) = read_dir(dir) else {
        return;
    };
    for entry in entries {
        if !entry.ends_with(".conf") {
            continue;
        }
        let path = if dir.ends_with('/') {
            format!("{}{}", dir, entry)
        } else {
            format!("{}/{}", dir, entry)
        };
        read_loader_conf_file(&path, read_file, conf_vars, loaded_files);
    }
}

fn read_loader_conf_file<F>(
    path: &str,
    read_file: &F,
    conf_vars: &mut Vec<EnvVar>,
    loaded_files: &mut BTreeSet<String>,
)
where
    F: Fn(&str) -> Option<Vec<u8>>,
{
    if loaded_files.contains(path) {
        return;
    }
    let Some(bytes) = read_file(path) else {
        return;
    };
    let Ok(text) = core::str::from_utf8(&bytes) else {
        return;
    };
    log::info!("loader.conf read {} bytes from {}", bytes.len(), path);
    let vars = parse_loader_conf_text(text);
    let mut loader_conf_files = None;
    for var in vars {
        if var.key == "exec" {
            apply_exec_command(&var.value, conf_vars);
            continue;
        }
        if var.key == "loader_conf_files" {
            loader_conf_files = Some(var.value.clone());
        }
        set_conf_var(conf_vars, var.key, var.value);
    }
    loaded_files.insert(path.to_string());
    if let Some(list) = loader_conf_files {
        for name in list.split_whitespace() {
            read_loader_conf_file(name, read_file, conf_vars, loaded_files);
        }
    }
}

fn set_conf_var(conf_vars: &mut Vec<EnvVar>, key: String, value: String) {
    if let Some(existing) = conf_vars.iter_mut().find(|var| var.key == key) {
        existing.value = value;
        return;
    }
    conf_vars.push(EnvVar { key, value });
}

fn unset_conf_var(conf_vars: &mut Vec<EnvVar>, key: &str) {
    conf_vars.retain(|var| var.key != key);
}

fn apply_exec_command(cmd: &str, conf_vars: &mut Vec<EnvVar>) {
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return;
    }
    if let Some(rest) = cmd.strip_prefix("set ") {
        if let Some((key, value)) = split_key_value_exec(rest.trim()) {
            set_conf_var(conf_vars, key, value);
        } else {
            log::warn!("loader.conf exec: invalid set syntax: {}", cmd);
        }
        return;
    }
    if let Some(rest) = cmd.strip_prefix("unset ") {
        let key = rest.trim();
        if !key.is_empty() {
            unset_conf_var(conf_vars, key);
        }
        return;
    }
    if let Some(rest) = cmd.strip_prefix("echo ") {
        log::info!("{}", rest.trim());
        return;
    }
    log::warn!("loader.conf exec: ignored command: {}", cmd);
}

fn split_key_value_exec(input: &str) -> Option<(String, String)> {
    let idx = input.find('=')?;
    let key = input[..idx].trim();
    if key.is_empty() {
        return None;
    }
    let mut value = input[idx + 1..].trim().to_string();
    if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        value = value[1..value.len() - 1].to_string();
    } else if value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2 {
        value = value[1..value.len() - 1].to_string();
    }
    Some((key.to_string(), value))
}

fn load_nextboot_conf<F>(
    env_vars: &[EnvVar],
    read_file: &F,
    conf_vars: &mut Vec<EnvVar>,
    loaded_files: &mut BTreeSet<String>,
) where
    F: Fn(&str) -> Option<Vec<u8>>,
{
    let enabled = get_env_value(env_vars, conf_vars, "nextboot_enable")
        .map(|value| is_yes(value))
        .unwrap_or(false);
    if !enabled {
        return;
    }
    let path = get_env_value(env_vars, conf_vars, "nextboot_conf")
        .unwrap_or("/boot/nextboot.conf")
        .to_string();
    read_loader_conf_file(&path, read_file, conf_vars, loaded_files);
    set_conf_var(conf_vars, "nextboot_enable".to_string(), "NO".to_string());
}

fn is_yes(value: &str) -> bool {
    matches!(value, "YES" | "yes" | "1" | "true" | "TRUE" | "on" | "ON")
}

fn get_env_value<'a>(env_vars: &'a [EnvVar], conf_vars: &'a [EnvVar], key: &str) -> Option<&'a str> {
    env_vars
        .iter()
        .find(|var| var.key == key)
        .map(|var| var.value.as_str())
        .or_else(|| {
            conf_vars
                .iter()
                .find(|var| var.key == key)
                .map(|var| var.value.as_str())
        })
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
