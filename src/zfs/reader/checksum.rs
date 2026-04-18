extern crate alloc;

use crate::error::{BootError, Result};
use crate::zfs::reader::types::{BlkPtr, ZioCksum, bp_should_byteswap};
use crate::zfs::sha256::Sha256;

pub const ZIO_CHECKSUM_FLETCHER_4: u64 = 7;
pub const ZIO_CHECKSUM_SHA256: u64 = 8;

pub fn verify_checksum(bp: &BlkPtr, data: &[u8]) -> Result<()> {
    match bp.checksum() {
        ZIO_CHECKSUM_FLETCHER_4 => {
            let actual = fletcher4(data, bp_should_byteswap(bp));
            if actual.word != bp.cksum.word {
                return Err(BootError::InvalidData("fletcher4 checksum mismatch"));
            }
        }
        ZIO_CHECKSUM_SHA256 => {
            let actual = sha256_cksum(data, bp_should_byteswap(bp));
            if actual.word != bp.cksum.word {
                return Err(BootError::InvalidData("sha256 checksum mismatch"));
            }
        }
        _other => {
            return Err(BootError::Unsupported("checksum unsupported"));
        }
    }
    Ok(())
}

fn fletcher4(data: &[u8], byteswap: bool) -> ZioCksum {
    let mut a: u64 = 0;
    let mut b: u64 = 0;
    let mut c: u64 = 0;
    let mut d: u64 = 0;
    for chunk in data.chunks_exact(4) {
        let mut word = u32::from_le_bytes(chunk.try_into().unwrap());
        if byteswap {
            word = word.swap_bytes();
        }
        a = a.wrapping_add(word as u64);
        b = b.wrapping_add(a);
        c = c.wrapping_add(b);
        d = d.wrapping_add(c);
    }
    ZioCksum { word: [a, b, c, d] }
}

fn sha256_cksum(data: &[u8], byteswap: bool) -> ZioCksum {
    let mut hasher = Sha256::new();
    if byteswap {
        let mut tmp = alloc::vec![0u8; data.len()];
        let mut offset = 0;
        for chunk in data.chunks_exact(8) {
            let word = u64::from_le_bytes(chunk.try_into().unwrap()).swap_bytes();
            tmp[offset..offset + 8].copy_from_slice(&word.to_le_bytes());
            offset += 8;
        }
        if offset < data.len() {
            tmp[offset..].copy_from_slice(&data[offset..]);
        }
        hasher.update(&tmp);
    } else {
        hasher.update(data);
    }
    let digest = hasher.finalize();
    let mut words = [0u64; 4];
    for idx in 0..4 {
        words[idx] = u64::from_be_bytes(digest[idx * 8..idx * 8 + 8].try_into().unwrap());
    }
    ZioCksum { word: words }
}

#[cfg(test)]
mod tests {
    use super::fletcher4;

    #[test]
    fn fletcher4_basic() {
        let data = [1u8, 0, 0, 0, 2, 0, 0, 0];
        let cksum = fletcher4(&data, false);
        assert_eq!(cksum.word[0], 3);
    }
}
