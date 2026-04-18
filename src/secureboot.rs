extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use core::cell::UnsafeCell;
use uefi::CStr16;
use uefi::Guid;
use uefi::runtime::{self, VariableVendor};

use crate::env::loader::LoaderEnv;
use crate::error::{BootError, Result};
use crate::zfs::sha256::Sha256;

const EFI_CERT_SHA256_GUID: Guid = Guid::from_bytes([
    0x26, 0x16, 0xC4, 0xC1, 0x4C, 0x50, 0x92, 0x40, 0xAC, 0xA9, 0x41, 0xF9, 0x36, 0x93, 0x43, 0x28,
]);
const EFI_IMAGE_SECURITY_DATABASE_GUID: Guid = Guid::from_bytes([
    0xCB, 0xB2, 0x19, 0xD7, 0x3A, 0x3D, 0x96, 0x45, 0xA3, 0xBC, 0xDA, 0xD0, 0x0E, 0x67, 0x65, 0x6F,
]);

struct SecureBootCell(UnsafeCell<Option<SecureBootState>>);

unsafe impl Sync for SecureBootCell {}

static SECUREBOOT_STATE: SecureBootCell = SecureBootCell(UnsafeCell::new(None));

#[derive(Clone)]
struct SecureBootState {
    enabled: bool,
    db_hashes: Vec<[u8; 32]>,
    dbx_hashes: Vec<[u8; 32]>,
    manifest: Option<Manifest>,
}

#[derive(Clone)]
struct Manifest {
    entries: Vec<(String, [u8; 32])>,
}

pub fn init(
    loader_env: &mut LoaderEnv,
    manifest_bytes: Option<Vec<u8>>,
    manifest_path: Option<&str>,
) {
    let forced = matches!(
        loader_env.get("secureboot_force"),
        Some("1") | Some("YES") | Some("yes") | Some("true")
    );
    let enabled = forced || secure_boot_enabled();
    loader_env.set("secureboot", if enabled { "1" } else { "0" });
    log::info!(
        "secureboot: enabled={} forced={}",
        enabled as u8,
        forced as u8
    );
    if let Some(path) = manifest_path {
        log::info!(
            "secureboot: manifest path {} (bytes={})",
            path,
            if manifest_bytes.is_some() {
                "yes"
            } else {
                "no"
            }
        );
    }
    if !enabled {
        set_state(SecureBootState {
            enabled: false,
            db_hashes: Vec::new(),
            dbx_hashes: Vec::new(),
            manifest: None,
        });
        return;
    }
    let db_hashes = read_signature_db("db");
    let dbx_hashes = read_signature_db("dbx");
    let manifest = match (manifest_bytes, manifest_path) {
        (Some(bytes), Some(path)) => match parse_manifest(path, &bytes) {
            Ok(manifest) => {
                if verify_manifest_hash(&db_hashes, &dbx_hashes, &bytes) {
                    log::info!("secureboot: manifest trusted");
                    Some(manifest)
                } else {
                    log::warn!("secureboot: manifest hash not trusted");
                    None
                }
            }
            Err(err) => {
                log::warn!("secureboot: manifest parse failed: {}", err);
                None
            }
        },
        _ => {
            log::warn!("secureboot: manifest not provided");
            None
        }
    };
    set_state(SecureBootState {
        enabled: true,
        db_hashes,
        dbx_hashes,
        manifest,
    });
}

pub fn verify_path(path: &str, data: &[u8]) -> Result<()> {
    let Some(state) = get_state() else {
        return Ok(());
    };
    if !state.enabled {
        return Ok(());
    }
    let manifest = state
        .manifest
        .as_ref()
        .ok_or(BootError::InvalidData("secureboot manifest missing"))?;
    let expected = manifest
        .entries
        .iter()
        .find(|(entry_path, _)| entry_path == path)
        .map(|(_, hash)| *hash)
        .ok_or(BootError::InvalidData("secureboot manifest entry missing"))?;
    let actual = sha256_bytes(data);
    if expected != actual {
        return Err(BootError::InvalidData("secureboot manifest hash mismatch"));
    }
    if !state.dbx_hashes.is_empty() && state.dbx_hashes.iter().any(|h| h == &actual) {
        return Err(BootError::InvalidData("secureboot hash forbidden"));
    }
    if !state.db_hashes.is_empty() && !state.db_hashes.iter().any(|h| h == &actual) {
        return Err(BootError::InvalidData("secureboot hash untrusted"));
    }
    Ok(())
}

fn secure_boot_enabled() -> bool {
    let secure_boot = read_global_u8("SecureBoot").unwrap_or(0);
    let setup_mode = read_global_u8("SetupMode").unwrap_or(1);
    secure_boot == 1 && setup_mode == 0
}

fn read_global_u8(name: &str) -> Option<u8> {
    let mut buf = [0u16; 16];
    let name = CStr16::from_str_with_buf(name, &mut buf).ok()?;
    let (data, _) = runtime::get_variable_boxed(name, &VariableVendor::GLOBAL_VARIABLE).ok()?;
    data.first().copied()
}

fn read_signature_db(name: &str) -> Vec<[u8; 32]> {
    let mut buf = [0u16; 8];
    let name = match CStr16::from_str_with_buf(name, &mut buf) {
        Ok(name) => name,
        Err(_) => return Vec::new(),
    };
    let vendor = VariableVendor(EFI_IMAGE_SECURITY_DATABASE_GUID);
    let Ok((data, _attrs)) = runtime::get_variable_boxed(name, &vendor) else {
        return Vec::new();
    };
    parse_signature_list(&data)
}

fn parse_signature_list(data: &[u8]) -> Vec<[u8; 32]> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset + 28 <= data.len() {
        let sig_type = &data[offset..offset + 16];
        let list_size =
            u32::from_le_bytes(data[offset + 16..offset + 20].try_into().unwrap()) as usize;
        let header_size =
            u32::from_le_bytes(data[offset + 20..offset + 24].try_into().unwrap()) as usize;
        let sig_size =
            u32::from_le_bytes(data[offset + 24..offset + 28].try_into().unwrap()) as usize;
        if list_size < 28 || sig_size < 16 || offset + list_size > data.len() {
            break;
        }
        if sig_type == EFI_CERT_SHA256_GUID.to_bytes() {
            let mut sig_off = offset + 28 + header_size;
            let sig_end = offset + list_size;
            while sig_off + sig_size <= sig_end {
                let hash_start = sig_off + 16;
                if hash_start + 32 <= sig_off + sig_size {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&data[hash_start..hash_start + 32]);
                    out.push(hash);
                }
                sig_off += sig_size;
            }
        }
        offset += list_size;
    }
    out
}

fn verify_manifest_hash(db: &[[u8; 32]], dbx: &[[u8; 32]], bytes: &[u8]) -> bool {
    let hash = sha256_bytes(bytes);
    if !dbx.is_empty() && dbx.iter().any(|h| h == &hash) {
        return false;
    }
    if db.is_empty() {
        return true;
    }
    db.iter().any(|h| h == &hash)
}

fn parse_manifest(_path: &str, bytes: &[u8]) -> Result<Manifest> {
    let text = core::str::from_utf8(bytes).map_err(|_| BootError::InvalidData("manifest utf8"))?;
    let mut entries = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let hash_hex = parts
            .next()
            .ok_or(BootError::InvalidData("manifest line"))?;
        let entry_path = parts
            .next()
            .ok_or(BootError::InvalidData("manifest line"))?;
        let hash = parse_hex_hash(hash_hex)?;
        entries.push((entry_path.to_string(), hash));
    }
    Ok(Manifest { entries })
}

fn parse_hex_hash(hex: &str) -> Result<[u8; 32]> {
    if hex.len() != 64 {
        return Err(BootError::InvalidData("manifest hash length"));
    }
    let mut out = [0u8; 32];
    let bytes = hex.as_bytes();
    for idx in 0..32 {
        let hi = from_hex(bytes[idx * 2])?;
        let lo = from_hex(bytes[idx * 2 + 1])?;
        out[idx] = (hi << 4) | lo;
    }
    Ok(out)
}

fn from_hex(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(BootError::InvalidData("manifest hash char")),
    }
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

fn set_state(state: SecureBootState) {
    unsafe {
        *SECUREBOOT_STATE.0.get() = Some(state);
    }
}

fn get_state() -> Option<SecureBootState> {
    unsafe { (*SECUREBOOT_STATE.0.get()).clone() }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::{parse_hex_hash, parse_manifest, parse_signature_list};

    #[test]
    fn parse_manifest_lines() {
        let manifest = b"\
            # comment\n\
            e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 /boot/kernel/kernel\n\
            ";
        let parsed = parse_manifest("/boot/manifest", manifest).expect("manifest");
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].0, "/boot/kernel/kernel");
    }

    #[test]
    fn parse_signature_list_sha256() {
        let mut data = Vec::new();
        data.extend_from_slice(&super::EFI_CERT_SHA256_GUID.to_bytes());
        let list_size = 28 + 16 + 32;
        data.extend_from_slice(&(list_size as u32).to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&(48u32).to_le_bytes());
        data.extend_from_slice(&[0u8; 16]); // owner
        data.extend_from_slice(&[0x11u8; 32]);
        let hashes = parse_signature_list(&data);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0], [0x11u8; 32]);
    }

    #[test]
    fn parse_hex_hash_ok() {
        let hash =
            parse_hex_hash("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .expect("hash");
        assert_eq!(hash, [0xffu8; 32]);
    }
}
