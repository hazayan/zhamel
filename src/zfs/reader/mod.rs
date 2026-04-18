extern crate alloc;

use alloc::vec::Vec;

use uefi::proto::media::block::BlockIO;

use crate::error::{BootError, Result};
use crate::zfs::label::{self, VDEV_LABELS, VDEV_UBERBLOCK_RING};
use crate::zfs::reader::types::{
    UBERBLOCK_MAGIC, UBERBLOCK_SIZE, Uberblock, mmp_seq, mmp_seq_valid, mmp_valid,
};

pub mod checksum;
pub mod dnode;
pub mod io;
pub mod lz4;
pub mod mos;
pub mod objset;
pub mod types;
pub mod zap;

const MAX_UBERBLOCK_SHIFT: u64 = 13;
const UBERBLOCK_SHIFT: u64 = 10;

pub fn read_best_uberblock(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    last_block: u64,
    ashift: Option<u64>,
) -> Result<Option<Uberblock>> {
    let psize = (last_block + 1)
        .checked_mul(block_size as u64)
        .ok_or(BootError::InvalidData("vdev size overflow"))?;
    let ub_shift = uberblock_shift(ashift);
    let ub_size = 1u64 << ub_shift;
    let count = VDEV_UBERBLOCK_RING as u64 / ub_size;
    if count == 0 {
        return Err(BootError::InvalidData("uberblock ring size invalid"));
    }
    let mut best: Option<Uberblock> = None;
    for label_idx in 0..VDEV_LABELS {
        for ring_idx in 0..count {
            let offset =
                label::vdev_label_offset(psize, label_idx, uberblock_offset(ub_shift, ring_idx))?;
            let buf = read_bytes(block, media_id, block_size, offset, ub_size as usize)?;
            if let Some(ub) = parse_uberblock(&buf) {
                if !ub.is_valid() {
                    continue;
                }
                if let Some(current) = best {
                    if uberblock_compare(&ub, &current) > 0 {
                        best = Some(ub);
                    } else {
                        best = Some(current);
                    }
                } else {
                    best = Some(ub);
                }
            }
        }
    }
    Ok(best)
}

fn uberblock_shift(ashift: Option<u64>) -> u64 {
    let shift = ashift.unwrap_or(UBERBLOCK_SHIFT);
    shift.clamp(UBERBLOCK_SHIFT, MAX_UBERBLOCK_SHIFT)
}

fn uberblock_offset(ub_shift: u64, ring_index: u64) -> u64 {
    (label::VDEV_PAD_SIZE as u64 * 2 + label::VDEV_PHYS_SIZE as u64)
        + (ring_index * (1u64 << ub_shift))
}

fn parse_uberblock(buf: &[u8]) -> Option<Uberblock> {
    let slice = if buf.len() < UBERBLOCK_SIZE {
        return None;
    } else {
        &buf[..UBERBLOCK_SIZE]
    };
    let mut ub = Uberblock::from_bytes(slice).ok()?;
    if ub.magic == UBERBLOCK_MAGIC.swap_bytes() {
        let mut swapped = [0u8; UBERBLOCK_SIZE];
        swapped.copy_from_slice(slice);
        byteswap_u64_array(&mut swapped);
        ub = Uberblock::from_bytes(&swapped).ok()?;
    }
    Some(ub)
}

fn uberblock_compare(left: &Uberblock, right: &Uberblock) -> i32 {
    if left.txg != right.txg {
        return if left.txg > right.txg { 1 } else { -1 };
    }
    if left.timestamp != right.timestamp {
        return if left.timestamp > right.timestamp {
            1
        } else {
            -1
        };
    }
    let seq_left = if mmp_valid(left) && mmp_seq_valid(left) {
        mmp_seq(left)
    } else {
        0
    };
    let seq_right = if mmp_valid(right) && mmp_seq_valid(right) {
        mmp_seq(right)
    } else {
        0
    };
    if seq_left == seq_right {
        0
    } else if seq_left > seq_right {
        1
    } else {
        -1
    }
}

fn byteswap_u64_array(buf: &mut [u8]) {
    for chunk in buf.chunks_exact_mut(8) {
        let value = u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8]));
        chunk.copy_from_slice(&value.swap_bytes().to_le_bytes());
    }
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
    use super::{uberblock_compare, uberblock_shift};
    use crate::zfs::reader::types::Uberblock;

    fn make_ub(txg: u64, timestamp: u64) -> Uberblock {
        Uberblock {
            magic: super::UBERBLOCK_MAGIC,
            version: 1,
            txg,
            guid_sum: 0,
            timestamp,
            rootbp: super::types::BlkPtr::from_bytes(&[0u8; super::types::BLK_PTR_SIZE]).unwrap(),
            software_version: 0,
            mmp_magic: 0,
            mmp_delay: 0,
            mmp_config: 0,
            checkpoint_txg: 0,
        }
    }

    #[test]
    fn compare_uberblock_txg() {
        let a = make_ub(2, 0);
        let b = make_ub(1, 10);
        assert!(uberblock_compare(&a, &b) > 0);
    }

    #[test]
    fn compare_uberblock_timestamp() {
        let a = make_ub(1, 2);
        let b = make_ub(1, 1);
        assert!(uberblock_compare(&a, &b) > 0);
    }

    #[test]
    fn uberblock_shift_clamp() {
        assert_eq!(uberblock_shift(Some(0)), super::UBERBLOCK_SHIFT);
        assert_eq!(uberblock_shift(Some(14)), super::MAX_UBERBLOCK_SHIFT);
    }
}
