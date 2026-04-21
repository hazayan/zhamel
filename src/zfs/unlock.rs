extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::ptr;

use uefi::boot;
use uefi::proto::media::block::BlockIO;
use uefi::system;

use crate::env::loader::LoaderEnv;
use crate::error::{BootError, Result};
use crate::tang;
use crate::zfs::fs::{DatasetProps, read_file_from_objset};
use crate::zfs::reader::objset::ObjsetPhys;
use crate::zfs::sha1::Sha1;

const DEFAULT_PASSPHRASE_ATTEMPTS: u32 = 3;
const MAX_PASSPHRASE_ATTEMPTS: u32 = 10;

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
    if env.get("kern.zfs.key").is_some() {
        log::info!("zfs: key already provided via env");
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
        KeyLocation::Prompt => set_prompted_passphrase_key(env, props),
        KeyLocation::File(path) => match read_keyfile(block, media_id, block_size, objset, &path) {
            Ok(mut passphrase) => {
                log::info!("zfs: passphrase loaded from keylocation file");
                let result = set_passphrase_key(env, props, &passphrase);
                scrub_string(&mut passphrase);
                result?;
                Ok(())
            }
            Err(err) => {
                log::warn!("zfs: keylocation file read failed: {:?}, prompting", err);
                set_prompted_passphrase_key(env, props)
            }
        },
        KeyLocation::Unknown => Err(BootError::Unsupported("zfs passphrase keylocation")),
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
    let mut key = tang::decrypt_tang_jwe(jwe, url_override, http_driver, local_ip, netmask)?;
    if key.len() != 32 {
        return Err(BootError::InvalidData(
            "kunci zfs key must be exactly 32 bytes",
        ));
    }
    let mut hex = hex_encode(&key);
    scrub_vec(&mut key);
    env.set("kern.zfs.key", &hex);
    scrub_string(&mut hex);
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

pub fn hex_decode(input: &str) -> Result<Vec<u8>> {
    let input = input.trim();
    if input.len() % 2 != 0 {
        return Err(BootError::InvalidData("hex key length invalid"));
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    let mut idx = 0usize;
    while idx < bytes.len() {
        let hi = hex_nibble(bytes[idx]).ok_or(BootError::InvalidData("hex key invalid"))?;
        let lo = hex_nibble(bytes[idx + 1]).ok_or(BootError::InvalidData("hex key invalid"))?;
        out.push((hi << 4) | lo);
        idx += 2;
    }
    Ok(out)
}

fn nibble_to_hex(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => '0',
    }
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn set_prompted_passphrase_key(env: &mut LoaderEnv, props: &DatasetProps) -> Result<()> {
    if let Some(mut passphrase) = env.take("kern.zfs.passphrase") {
        log::info!("zfs: using preseeded passphrase from env");
        let result = set_passphrase_key(env, props, &passphrase);
        scrub_string(&mut passphrase);
        return result;
    }

    let attempts = passphrase_attempts(env);
    let mut last_err = BootError::InvalidData("zfs passphrase input failed");
    for attempt in 1..=attempts {
        let mut passphrase = prompt_passphrase("ZFS Passphrase: ")?;
        let result = set_passphrase_key(env, props, &passphrase);
        scrub_string(&mut passphrase);
        match result {
            Ok(()) => return Ok(()),
            Err(BootError::InvalidData(msg)) => {
                last_err = BootError::InvalidData(msg);
                if attempt < attempts {
                    log::warn!(
                        "zfs: passphrase attempt {}/{} rejected: {}",
                        attempt,
                        attempts,
                        msg
                    );
                }
            }
            Err(err) => return Err(err),
        }
    }
    Err(last_err)
}

fn passphrase_attempts(env: &LoaderEnv) -> u32 {
    env.get("zfs_passphrase_attempts")
        .and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|value| *value > 0)
        .map(|value| value.min(MAX_PASSPHRASE_ATTEMPTS))
        .unwrap_or(DEFAULT_PASSPHRASE_ATTEMPTS)
}

fn set_passphrase_key(env: &mut LoaderEnv, props: &DatasetProps, passphrase: &str) -> Result<()> {
    let Some(salt) = props.pbkdf2_salt else {
        return Err(BootError::InvalidData("zfs passphrase salt missing"));
    };
    let Some(iters) = props.pbkdf2_iters else {
        return Err(BootError::InvalidData("zfs passphrase pbkdf2iters missing"));
    };
    let mut key = derive_passphrase_key(passphrase, salt, iters)?;
    let Some(crypto_key) = props.crypto_key.as_ref() else {
        scrub_vec(&mut key);
        return Err(BootError::InvalidData("zfs crypto key metadata missing"));
    };
    let validation = super::crypt::validate_wrapping_key(&key, crypto_key);
    if validation.is_err() {
        scrub_vec(&mut key);
    }
    validation?;
    let mut key_hex = hex_encode(&key);
    scrub_vec(&mut key);
    env.set("kern.zfs.key", &key_hex);
    scrub_string(&mut key_hex);
    env.unset("kern.zfs.passphrase");
    log::info!("zfs: passphrase key derived and validated (key_len=32)");
    Ok(())
}

pub fn derive_passphrase_key(passphrase: &str, salt: u64, iters: u64) -> Result<Vec<u8>> {
    let passphrase = passphrase.as_bytes();
    if passphrase.len() < 8 || passphrase.len() > 512 {
        return Err(BootError::InvalidData("zfs passphrase length invalid"));
    }
    if iters == 0 || iters > u32::MAX as u64 {
        return Err(BootError::InvalidData("zfs pbkdf2 iteration count invalid"));
    }

    let mut salt_bytes = salt.to_le_bytes().to_vec();
    let key = pbkdf2_hmac_sha1(passphrase, &mut salt_bytes, iters as u32, 32);
    scrub_vec(&mut salt_bytes);
    Ok(key)
}

fn pbkdf2_hmac_sha1(
    password: &[u8],
    salt: &mut Vec<u8>,
    iterations: u32,
    out_len: usize,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len);
    let blocks = out_len.div_ceil(20);
    for block_idx in 1..=blocks {
        let original_salt_len = salt.len();
        salt.extend_from_slice(&(block_idx as u32).to_be_bytes());
        let mut u = hmac_sha1(password, salt);
        salt.truncate(original_salt_len);
        let mut t = u;
        for _ in 1..iterations {
            u = hmac_sha1(password, &u);
            for idx in 0..t.len() {
                t[idx] ^= u[idx];
            }
        }
        let remaining = out_len - out.len();
        out.extend_from_slice(&t[..remaining.min(t.len())]);
        scrub_array(&mut u);
        scrub_array(&mut t);
    }
    out
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut key_block = [0u8; 64];
    if key.len() > key_block.len() {
        key_block[..20].copy_from_slice(&sha1_bytes(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for idx in 0..64 {
        ipad[idx] ^= key_block[idx];
        opad[idx] ^= key_block[idx];
    }

    let mut inner = Sha1::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_digest = inner.finalize();

    let mut outer = Sha1::new();
    outer.update(&opad);
    outer.update(&inner_digest);
    let digest = outer.finalize();
    scrub_array(&mut key_block);
    scrub_array(&mut ipad);
    scrub_array(&mut opad);
    digest
}

fn sha1_bytes(data: &[u8]) -> [u8; 20] {
    let mut sha = Sha1::new();
    sha.update(data);
    sha.finalize()
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

pub(crate) fn scrub_string(value: &mut String) {
    unsafe {
        scrub_slice(value.as_mut_vec());
    }
    value.clear();
}

fn scrub_vec(value: &mut Vec<u8>) {
    scrub_slice(value.as_mut_slice());
    value.clear();
}

fn scrub_array<const N: usize>(value: &mut [u8; N]) {
    scrub_slice(value.as_mut_slice());
}

fn scrub_slice(value: &mut [u8]) {
    for byte in value {
        unsafe {
            ptr::write_volatile(byte, 0);
        }
    }
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
    use super::{
        KeyLocation, derive_passphrase_key, hex_decode, parse_keylocation, passphrase_attempts,
        pbkdf2_hmac_sha1, scrub_string,
    };
    use crate::env::loader::LoaderEnv;
    use crate::env::parser::EnvVar;
    use alloc::string::ToString;

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

    #[test]
    fn pbkdf2_hmac_sha1_rfc6070_iteration_1() {
        let mut salt = b"salt".to_vec();
        let out = pbkdf2_hmac_sha1(b"password", &mut salt, 1, 20);
        let expected = [
            0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60,
            0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6,
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn pbkdf2_hmac_sha1_rfc6070_iteration_2() {
        let mut salt = b"salt".to_vec();
        let out = pbkdf2_hmac_sha1(b"password", &mut salt, 2, 20);
        let expected = [
            0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d,
            0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57,
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn derive_passphrase_key_uses_little_endian_salt() {
        let out = derive_passphrase_key("password", 0x0102030405060708, 1).expect("key");
        let mut salt = 0x0102030405060708u64.to_le_bytes().to_vec();
        let expected = pbkdf2_hmac_sha1(b"password", &mut salt, 1, 32);
        assert_eq!(out, expected);
    }

    #[test]
    fn hex_decode_accepts_upper_and_lowercase() {
        assert_eq!(hex_decode("00aAFf").expect("hex"), [0x00, 0xaa, 0xff]);
    }

    #[test]
    fn passphrase_attempts_defaults_and_clamps() {
        let mut env = LoaderEnv {
            env_vars: alloc::vec::Vec::new(),
            conf_vars: alloc::vec::Vec::new(),
        };
        assert_eq!(passphrase_attempts(&env), 3);
        env.env_vars.push(EnvVar {
            key: "zfs_passphrase_attempts".to_string(),
            value: "99".to_string(),
        });
        assert_eq!(passphrase_attempts(&env), 10);
    }

    #[test]
    fn scrub_string_clears_value() {
        let mut value = "secret-value".to_string();
        scrub_string(&mut value);
        assert!(value.is_empty());
    }
}
