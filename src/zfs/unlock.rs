extern crate alloc;

use alloc::string::{String, ToString};

use uefi::boot;
use uefi::proto::media::block::BlockIO;
use uefi::system;

use crate::env::loader::LoaderEnv;
use crate::error::{BootError, Result};
use crate::tang;
use crate::zfs::fs::{DatasetProps, read_file_from_objset};
use crate::zfs::reader::objset::ObjsetPhys;

#[derive(Debug)]
pub enum KeyLocation {
    Prompt,
    File(String),
    Unknown,
}

pub fn maybe_prompt_passphrase(
    env: &mut LoaderEnv,
    props: &DatasetProps,
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    objset: &ObjsetPhys,
) -> Result<()> {
    if env.get("kern.zfs.passphrase").is_some() {
        log::info!("zfs: passphrase already provided via env");
        return Ok(());
    }
    let Some(keyformat) = props.keyformat.as_deref() else {
        return Ok(());
    };
    if !keyformat.eq_ignore_ascii_case("passphrase") {
        return Ok(());
    }

    let keylocation = props
        .keylocation
        .as_deref()
        .map(parse_keylocation)
        .unwrap_or(KeyLocation::Prompt);

    match keylocation {
        KeyLocation::Prompt => {
            let passphrase = prompt_passphrase("ZFS Passphrase: ")?;
            env.set("kern.zfs.passphrase", &passphrase);
            Ok(())
        }
        KeyLocation::File(path) => match read_keyfile(block, media_id, block_size, objset, &path) {
            Ok(passphrase) => {
                log::info!("zfs: passphrase loaded from keylocation file");
                env.set("kern.zfs.passphrase", &passphrase);
                Ok(())
            }
            Err(err) => {
                log::warn!("zfs: keylocation file read failed: {:?}, prompting", err);
                let passphrase = prompt_passphrase("ZFS Passphrase: ")?;
                env.set("kern.zfs.passphrase", &passphrase);
                Ok(())
            }
        },
        KeyLocation::Unknown => Ok(()),
    }
}

pub fn maybe_unlock_kunci(env: &mut LoaderEnv, props: &DatasetProps) -> Result<()> {
    if env.get("kern.zfs.key").is_some() {
        log::info!("zfs: key already provided via env");
        return Ok(());
    }
    let Some(jwe) = props.kunci_jwe.as_deref() else {
        return Ok(());
    };
    log::info!("zfs: kunci unlock start");
    let url_override = env.get("zfs_kunci_url");
    let http_driver = env.get("zfs_kunci_http_driver");
    let local_ip = env.get("zfs_kunci_ip").and_then(parse_ipv4);
    let netmask = env.get("zfs_kunci_netmask").and_then(parse_ipv4);
    let key = tang::decrypt_tang_jwe(jwe, url_override, http_driver, local_ip, netmask)?;
    if key.len() != 32 {
        return Err(BootError::InvalidData(
            "kunci zfs key must be exactly 32 bytes",
        ));
    }
    let hex = hex_encode(&key);
    env.set("kern.zfs.key", &hex);
    log::info!("zfs: kunci unlock ok (key_len={})", key.len());
    Ok(())
}

pub fn parse_keylocation(input: &str) -> KeyLocation {
    let trimmed = input.trim();
    if trimmed.eq_ignore_ascii_case("prompt") {
        return KeyLocation::Prompt;
    }
    if let Some(path) = trimmed.strip_prefix("file://") {
        return KeyLocation::File(path.to_string());
    }
    if let Some(path) = trimmed.strip_prefix("file:") {
        return KeyLocation::File(path.to_string());
    }
    if trimmed.starts_with('/') {
        return KeyLocation::File(trimmed.to_string());
    }
    KeyLocation::Unknown
}

fn hex_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        let hi = byte >> 4;
        let lo = byte & 0x0f;
        out.push(nibble_to_hex(hi));
        out.push(nibble_to_hex(lo));
    }
    out
}

fn nibble_to_hex(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => '0',
    }
}

fn parse_ipv4(value: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut idx = 0usize;
    for part in value.split('.') {
        if idx >= out.len() {
            return None;
        }
        let part = part.trim();
        let parsed = part.parse::<u8>().ok()?;
        out[idx] = parsed;
        idx += 1;
    }
    if idx != out.len() {
        return None;
    }
    Some(out)
}

fn read_keyfile(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    objset: &ObjsetPhys,
    path: &str,
) -> Result<String> {
    let data = read_file_from_objset(block, media_id, block_size, objset, path)?;
    if data.len() > 4096 {
        return Err(BootError::InvalidData("zfs keyfile too large"));
    }
    let text =
        core::str::from_utf8(&data).map_err(|_| BootError::InvalidData("zfs keyfile utf8"))?;
    Ok(text.trim().to_string())
}

fn prompt_passphrase(prompt: &str) -> Result<String> {
    uefi::println!("{}", prompt);
    let mut out = String::new();
    if !read_line(&mut out) {
        return Err(BootError::InvalidData("zfs passphrase input failed"));
    }
    Ok(out)
}

fn read_line(out: &mut String) -> bool {
    let mut hit = false;
    system::with_stdin(|stdin| {
        let Some(key_event) = stdin.wait_for_key_event() else {
            return;
        };
        loop {
            let mut events = [unsafe { key_event.unsafe_clone() }];
            if boot::wait_for_event(&mut events).is_err() {
                return;
            }
            let Ok(Some(key)) = stdin.read_key() else {
                continue;
            };
            match key {
                uefi::proto::console::text::Key::Printable(ch) => {
                    let ch: char = ch.into();
                    match ch {
                        '\r' | '\n' => {
                            hit = true;
                            return;
                        }
                        '\u{8}' => {
                            out.pop();
                        }
                        _ => out.push(ch),
                    }
                }
                uefi::proto::console::text::Key::Special(_) => {}
            }
        }
    });
    hit
}

#[cfg(test)]
mod tests {
    use super::{KeyLocation, parse_keylocation};

    #[test]
    fn parse_keylocation_prompt() {
        match parse_keylocation("prompt") {
            KeyLocation::Prompt => {}
            _ => panic!("expected prompt"),
        }
    }

    #[test]
    fn parse_keylocation_file_prefix() {
        match parse_keylocation("file:///boot/keys/key") {
            KeyLocation::File(path) => assert_eq!(path, "/boot/keys/key"),
            _ => panic!("expected file path"),
        }
    }

    #[test]
    fn parse_keylocation_plain_path() {
        match parse_keylocation("/boot/keys/key") {
            KeyLocation::File(path) => assert_eq!(path, "/boot/keys/key"),
            _ => panic!("expected file path"),
        }
    }
}
