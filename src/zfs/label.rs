extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::zfs::sha256::Sha256;
use uefi::proto::media::block::BlockIO;

use crate::error::{BootError, Result};

const ZEC_MAGIC: u64 = 0x0210da7ab10c7a11;
const ZIO_ECK_SIZE: usize = 40;
pub(crate) const VDEV_PAD_SIZE: usize = 8 * 1024;
pub(crate) const VDEV_PHYS_SIZE: usize = 112 * 1024;
pub(crate) const VDEV_LABEL_SIZE: usize = 256 * 1024;
pub(crate) const VDEV_LABELS: usize = 4;
pub(crate) const VDEV_UBERBLOCK_RING: usize = 128 * 1024;
pub(crate) const VDEV_BOOT_SIZE: usize = 7 * (1 << 19);
pub(crate) const VDEV_LABEL_START_SIZE: usize = VDEV_LABEL_SIZE * 2 + VDEV_BOOT_SIZE;

const VDEV_BOOTENV_DATA_SIZE: usize = VDEV_PAD_SIZE - 8 - ZIO_ECK_SIZE;

#[derive(Debug, Clone)]
pub struct VdevLabel {
    pub pool_guid: u64,
    pub pool_txg: u64,
    pub ashift: Option<u64>,
    pub pool_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BootEnv {
    pub version: u64,
    pub bootonce: Option<String>,
    pub raw_envmap: Option<String>,
}

pub fn probe_vdev_labels(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    last_block: u64,
) -> Result<Vec<VdevLabel>> {
    let mut labels = Vec::new();
    let mut last_err: Option<BootError> = None;
    let psize = (last_block + 1)
        .checked_mul(block_size as u64)
        .ok_or(BootError::InvalidData("vdev size overflow"))?;
    for label in 0..VDEV_LABELS {
        let offset = vdev_label_offset(psize, label, vdev_phys_offset())?;
        let buf = read_bytes(block, media_id, block_size, offset, VDEV_PHYS_SIZE)?;
        match parse_vdev_phys(&buf, offset) {
            Ok(info) => labels.push(info),
            Err(err) => last_err = Some(err),
        }
    }
    if labels.is_empty() {
        return Err(last_err.unwrap_or(BootError::InvalidData("vdev labels not found")));
    }
    Ok(labels)
}

pub fn read_bootenv(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    last_block: u64,
) -> Result<Option<BootEnv>> {
    let psize = (last_block + 1)
        .checked_mul(block_size as u64)
        .ok_or(BootError::InvalidData("vdev size overflow"))?;
    for label in 0..VDEV_LABELS {
        let offset = vdev_label_offset(psize, label, vdev_bootenv_offset())?;
        let buf = read_bytes(block, media_id, block_size, offset, VDEV_PAD_SIZE)?;
        if let Ok(env) = parse_bootenv_block(&buf, offset) {
            return Ok(Some(env));
        }
    }
    Ok(None)
}

pub(crate) fn vdev_label_offset(psize: u64, label: usize, offset: u64) -> Result<u64> {
    let label_size = VDEV_LABEL_SIZE as u64;
    let label_offset = if label < 2 {
        0
    } else {
        psize
            .checked_sub((VDEV_LABELS as u64) * label_size)
            .ok_or(BootError::InvalidData("vdev label offset underflow"))?
    };
    let label_off = offset
        .checked_add(label as u64 * label_size)
        .and_then(|value| value.checked_add(label_offset))
        .ok_or(BootError::InvalidData("vdev label offset overflow"))?;
    Ok(label_off)
}

fn vdev_phys_offset() -> u64 {
    (VDEV_PAD_SIZE * 2) as u64
}

fn vdev_bootenv_offset() -> u64 {
    VDEV_PAD_SIZE as u64
}

fn parse_vdev_phys(buf: &[u8], offset: u64) -> Result<VdevLabel> {
    if buf.len() != VDEV_PHYS_SIZE {
        return Err(BootError::InvalidData("vdev phys size mismatch"));
    }
    verify_label_checksum(buf, offset)?;
    let nvlist_bytes = &buf[..VDEV_PHYS_SIZE - ZIO_ECK_SIZE];
    let nvlist = crate::zfs::nvlist::NvList::parse(nvlist_bytes)?;
    let pool_guid = nvlist
        .find_u64("pool_guid")?
        .ok_or(BootError::InvalidData("pool_guid missing"))?;
    let pool_txg = nvlist
        .find_u64("txg")?
        .ok_or(BootError::InvalidData("pool_txg missing"))?;
    let ashift = nvlist
        .find_nvlist("vdev_tree")?
        .and_then(|tree| tree.find_u64("ashift").ok().flatten());
    let pool_name = nvlist.find_string("name").ok().flatten();
    Ok(VdevLabel {
        pool_guid,
        pool_txg,
        ashift,
        pool_name,
    })
}

fn parse_bootenv_block(buf: &[u8], offset: u64) -> Result<BootEnv> {
    if buf.len() != VDEV_PAD_SIZE {
        return Err(BootError::InvalidData("bootenv size mismatch"));
    }
    verify_label_checksum(buf, offset)?;
    let version = u64::from_be_bytes(buf[0..8].try_into().unwrap_or([0; 8]));
    let env_bytes = &buf[8..8 + VDEV_BOOTENV_DATA_SIZE];
    match version {
        0 => parse_bootenv_raw(env_bytes),
        1 => parse_bootenv_nvlist(env_bytes),
        _ => Err(BootError::InvalidData("bootenv version unsupported")),
    }
}

fn parse_bootenv_raw(env_bytes: &[u8]) -> Result<BootEnv> {
    let mut end = env_bytes.len();
    while end > 0 && env_bytes[end - 1] == 0 {
        end -= 1;
    }
    let raw = if end == 0 {
        None
    } else {
        let text = core::str::from_utf8(&env_bytes[..end])
            .map_err(|_| BootError::InvalidData("bootenv raw not utf8"))?;
        Some(text.to_string())
    };
    Ok(BootEnv {
        version: 0,
        bootonce: None,
        raw_envmap: raw,
    })
}

fn parse_bootenv_nvlist(env_bytes: &[u8]) -> Result<BootEnv> {
    let nvlist = crate::zfs::nvlist::NvList::parse(env_bytes)?;
    let bootonce = nvlist.find_string("freebsd:bootonce")?;
    Ok(BootEnv {
        version: 1,
        bootonce,
        raw_envmap: None,
    })
}

pub(crate) fn verify_label_checksum(buf: &[u8], offset: u64) -> Result<()> {
    if buf.len() < ZIO_ECK_SIZE {
        return Err(BootError::InvalidData("label too short"));
    }
    let eck_offset = buf.len() - ZIO_ECK_SIZE;
    let eck = &buf[eck_offset..];
    let magic_le = u64::from_le_bytes(eck[0..8].try_into().unwrap_or([0; 8]));
    let magic_be = u64::from_be_bytes(eck[0..8].try_into().unwrap_or([0; 8]));
    let byteswap = if magic_le == ZEC_MAGIC {
        false
    } else if magic_be == ZEC_MAGIC {
        true
    } else {
        return Err(BootError::InvalidData("label checksum magic mismatch"));
    };
    let mut expected = [0u64; 4];
    for (idx, word) in expected.iter_mut().enumerate() {
        let start = 8 + idx * 8;
        let bytes: [u8; 8] = eck[start..start + 8]
            .try_into()
            .map_err(|_| BootError::InvalidData("label checksum read"))?;
        *word = u64::from_le_bytes(bytes);
    }
    let mut verifier = [offset, 0, 0, 0];
    if byteswap {
        for word in verifier.iter_mut() {
            *word = word.swap_bytes();
        }
        for word in expected.iter_mut() {
            *word = word.swap_bytes();
        }
    }
    let checksum_offset = eck_offset + 8;
    let mut hasher = Sha256::new();
    hasher.update(&buf[..checksum_offset]);
    let mut verifier_bytes = [0u8; 32];
    for (idx, word) in verifier.iter().enumerate() {
        let bytes = if byteswap {
            word.to_be_bytes()
        } else {
            word.to_le_bytes()
        };
        verifier_bytes[idx * 8..idx * 8 + 8].copy_from_slice(&bytes);
    }
    hasher.update(&verifier_bytes);
    if checksum_offset + 32 < buf.len() {
        hasher.update(&buf[checksum_offset + 32..]);
    }
    let digest = hasher.finalize();
    let mut actual = [0u64; 4];
    for idx in 0..4 {
        actual[idx] = u64::from_be_bytes(
            digest[idx * 8..idx * 8 + 8]
                .try_into()
                .map_err(|_| BootError::InvalidData("label checksum digest"))?,
        );
    }
    if actual != expected {
        return Err(BootError::InvalidData("label checksum mismatch"));
    }
    Ok(())
}

fn read_bytes(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>> {
    if block_size == 0 {
        return Err(BootError::InvalidData("block size zero"));
    }
    let start_lba = offset / block_size as u64;
    let end = offset + len as u64;
    let end_lba = (end + block_size as u64 - 1) / block_size as u64;
    let blocks = end_lba.saturating_sub(start_lba) as usize;
    if blocks == 0 {
        return Err(BootError::InvalidData("block read size zero"));
    }
    let mut buf = alloc::vec![0u8; blocks * block_size];
    block
        .read_blocks(media_id, start_lba, &mut buf)
        .map_err(|err| BootError::Uefi(err.status()))?;
    let start_off = (offset % block_size as u64) as usize;
    let end_off = start_off + len;
    if end_off > buf.len() {
        return Err(BootError::InvalidData("block read out of range"));
    }
    Ok(buf[start_off..end_off].to_vec())
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    extern crate std;

    use alloc::vec;
    use alloc::vec::Vec;

    use super::{
        BootEnv, VDEV_BOOTENV_DATA_SIZE, VDEV_PAD_SIZE, VDEV_PHYS_SIZE, ZIO_ECK_SIZE,
        parse_bootenv_block, parse_vdev_phys,
    };
    use crate::zfs::sha256::Sha256;

    fn build_label_block(payload: &[u8], offset: u64) -> Vec<u8> {
        let mut buf = payload.to_vec();
        buf.resize(payload.len() + ZIO_ECK_SIZE, 0);
        let eck_offset = payload.len();
        buf[eck_offset..eck_offset + 8].copy_from_slice(&super::ZEC_MAGIC.to_le_bytes());
        let checksum_offset = eck_offset + 8;
        let mut verifier = [offset, 0, 0, 0];
        let mut verifier_bytes = [0u8; 32];
        for (idx, word) in verifier.iter_mut().enumerate() {
            verifier_bytes[idx * 8..idx * 8 + 8].copy_from_slice(&word.to_be_bytes());
        }
        let mut hasher = Sha256::new();
        hasher.update(&buf[..checksum_offset]);
        hasher.update(&verifier_bytes);
        let digest = hasher.finalize();
        for idx in 0..4 {
            let word = u64::from_be_bytes(digest[idx * 8..idx * 8 + 8].try_into().unwrap());
            buf[checksum_offset + idx * 8..checksum_offset + idx * 8 + 8]
                .copy_from_slice(&word.to_le_bytes());
        }
        buf
    }

    fn build_nvlist(pool_guid: u64, pool_txg: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[1, 0, 0, 0]);
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&build_nvpair_u64("pool_guid", pool_guid));
        buf.extend_from_slice(&build_nvpair_u64("txg", pool_txg));
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf
    }

    fn build_nvpair_u64(name: &str, value: u64) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&((name.len() + 1) as u32).to_be_bytes());
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        while body.len() % 4 != 0 {
            body.push(0);
        }
        body.extend_from_slice(&8u32.to_be_bytes());
        body.extend_from_slice(&1u32.to_be_bytes());
        body.extend_from_slice(&value.to_be_bytes());
        let mut pair = Vec::new();
        let size = (8 + body.len()) as u32;
        pair.extend_from_slice(&size.to_be_bytes());
        pair.extend_from_slice(&size.to_be_bytes());
        pair.extend_from_slice(&body);
        pair
    }

    #[test]
    fn parse_vdev_phys_nvlist() {
        let nvlist = build_nvlist(0xabc, 42);
        let mut payload = vec![0u8; VDEV_PHYS_SIZE - ZIO_ECK_SIZE];
        payload[..nvlist.len()].copy_from_slice(&nvlist);
        let buf = build_label_block(&payload, 0x10000);
        let parsed = parse_vdev_phys(&buf, 0x10000).expect("parse");
        assert_eq!(parsed.pool_guid, 0xabc);
        assert_eq!(parsed.pool_txg, 42);
    }

    #[test]
    fn parse_bootenv_raw() {
        let mut payload = vec![0u8; VDEV_PAD_SIZE - ZIO_ECK_SIZE];
        payload[..8].copy_from_slice(&0u64.to_be_bytes());
        payload[8..20].copy_from_slice(b"envmap=test");
        let buf = build_label_block(&payload, 0x20000);
        let env = parse_bootenv_block(&buf, 0x20000).expect("bootenv");
        assert_eq!(env.version, 0);
        assert_eq!(env.raw_envmap.as_deref(), Some("envmap=test"));
    }

    #[test]
    fn parse_bootenv_nvlist() {
        let mut payload = vec![0u8; VDEV_PAD_SIZE - ZIO_ECK_SIZE];
        payload[..8].copy_from_slice(&1u64.to_be_bytes());
        let nvlist = {
            let mut buf = Vec::new();
            buf.extend_from_slice(&[1, 0, 0, 0]);
            buf.extend_from_slice(&0u32.to_be_bytes());
            buf.extend_from_slice(&0u32.to_be_bytes());
            buf.extend_from_slice(&build_nvpair_string("freebsd:bootonce", "zroot/ROOT"));
            buf.extend_from_slice(&0u32.to_be_bytes());
            buf.extend_from_slice(&0u32.to_be_bytes());
            buf
        };
        let copy_len = core::cmp::min(nvlist.len(), VDEV_BOOTENV_DATA_SIZE);
        payload[8..8 + copy_len].copy_from_slice(&nvlist[..copy_len]);
        let buf = build_label_block(&payload, 0x30000);
        let env = parse_bootenv_block(&buf, 0x30000).expect("bootenv");
        assert_eq!(env.version, 1);
        assert_eq!(env.bootonce.as_deref(), Some("zroot/ROOT"));
    }

    fn build_nvpair_string(name: &str, value: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&((name.len() + 1) as u32).to_be_bytes());
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        while body.len() % 4 != 0 {
            body.push(0);
        }
        body.extend_from_slice(&9u32.to_be_bytes());
        body.extend_from_slice(&1u32.to_be_bytes());
        body.extend_from_slice(&((value.len() + 1) as u32).to_be_bytes());
        body.extend_from_slice(value.as_bytes());
        body.push(0);
        while body.len() % 4 != 0 {
            body.push(0);
        }
        let mut pair = Vec::new();
        let size = (8 + body.len()) as u32;
        pair.extend_from_slice(&size.to_be_bytes());
        pair.extend_from_slice(&size.to_be_bytes());
        pair.extend_from_slice(&body);
        pair
    }
}
