extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::error::{BootError, Result};
use crate::zfs::reader::io::read_block;
use crate::zfs::reader::types::{bp_is_hole, BlkPtr, SPA_MINBLOCKSHIFT, SPA_BLKPTRSHIFT};
use uefi::proto::media::block::BlockIO;

const DNODE_CORE_SIZE: usize = 64;
const DNODE_SIZE_SHIFT: usize = 9; // 512 bytes

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct DnodePhys {
    pub dn_type: u8,
    pub dn_indblkshift: u8,
    pub dn_nlevels: u8,
    pub dn_nblkptr: u8,
    pub dn_bonustype: u8,
    pub dn_checksum: u8,
    pub dn_compress: u8,
    pub dn_flags: u8,
    pub dn_datablkszsec: u16,
    pub dn_bonuslen: u16,
    pub dn_extra_slots: u8,
    pub dn_maxblkid: u64,
    pub dn_used: u64,
    pub blkptrs: Vec<BlkPtr>,
    pub bonus: Vec<u8>,
}

impl DnodePhys {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < (1 << DNODE_SIZE_SHIFT) {
            return Err(BootError::InvalidData("dnode buffer too small"));
        }
        let parsed = match parse_dnode(bytes) {
            Ok(parsed) => parsed,
            Err(err) => {
                let swapped = swap_dnode_bytes(bytes);
                return parse_dnode(&swapped).map_err(|_| err);
            }
        };
        if parsed.dn_datablkszsec == 0 || !dnode_plausible(&parsed) {
            let swapped = swap_dnode_bytes(bytes);
            if let Ok(swapped_parsed) = parse_dnode(&swapped) {
                if swapped_parsed.dn_datablkszsec != 0 && dnode_plausible(&swapped_parsed) {
                    return Ok(swapped_parsed);
                }
            }
        }
        Ok(parsed)
    }

    pub fn block_size(&self) -> usize {
        (self.dn_datablkszsec as usize) << SPA_MINBLOCKSHIFT
    }
}

pub fn dnode_capacity_blocks(dnode: &DnodePhys) -> Option<u64> {
    let ibshift = dnode.dn_indblkshift as i64 - SPA_BLKPTRSHIFT as i64;
    if ibshift < 0 || ibshift > 63 {
        return None;
    }
    let ptrs_per_block = 1u64 << ibshift;
    let mut level_blocks = 1u64;
    for _ in 1..dnode.dn_nlevels {
        level_blocks = level_blocks.checked_mul(ptrs_per_block)?;
    }
    (dnode.dn_nblkptr as u64).checked_mul(level_blocks)
}

fn dnode_plausible(dnode: &DnodePhys) -> bool {
    if dnode.dn_datablkszsec == 0 || dnode.dn_datablkszsec > 32768 {
        return false;
    }
    if dnode.dn_nlevels == 0 || dnode.dn_nlevels > 16 {
        return false;
    }
    if dnode.dn_nblkptr == 0 || dnode.dn_nblkptr > 16 {
        return false;
    }
    if dnode.dn_extra_slots > 32 {
        return false;
    }
    if dnode.dn_nlevels > 1 && dnode.dn_indblkshift < SPA_MINBLOCKSHIFT as u8 {
        return false;
    }
    if dnode.dn_indblkshift > 16 {
        return false;
    }
    let max_blocks = match dnode_capacity_blocks(dnode) {
        Some(value) => value,
        None => return false,
    };
    if max_blocks > 0 && dnode.dn_maxblkid >= max_blocks {
        return false;
    }
    let total_slots = 1usize + dnode.dn_extra_slots as usize;
    let total_size = total_slots << DNODE_SIZE_SHIFT;
    let blkptr_count = dnode.dn_nblkptr.max(1) as usize;
    let bonus_start = DNODE_CORE_SIZE + (blkptr_count * super::types::BLK_PTR_SIZE);
    if bonus_start > total_size {
        return false;
    }
    let bonus_end = bonus_start + dnode.dn_bonuslen as usize;
    if bonus_end > total_size {
        return false;
    }
    true
}

fn swap_dnode_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut swapped = bytes.to_vec();
    for chunk in swapped.chunks_exact_mut(8) {
        let value = u64::from_le_bytes(chunk.try_into().unwrap()).swap_bytes();
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    swapped
}

fn parse_dnode(bytes: &[u8]) -> Result<DnodePhys> {
    let dn_type = bytes[0];
    let dn_indblkshift = bytes[1];
    let dn_nlevels = bytes[2];
    let dn_nblkptr = bytes[3];
    let dn_bonustype = bytes[4];
    let dn_checksum = bytes[5];
    let dn_compress = bytes[6];
    let dn_flags = bytes[7];
    let dn_datablkszsec = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
    let dn_bonuslen = u16::from_le_bytes(bytes[10..12].try_into().unwrap());
    let dn_extra_slots = bytes[12];

    let dn_maxblkid = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
    let dn_used = u64::from_le_bytes(bytes[32..40].try_into().unwrap());

    let total_slots = 1usize + dn_extra_slots as usize;
    let total_size = total_slots << DNODE_SIZE_SHIFT;
    if bytes.len() < total_size {
        return Err(BootError::InvalidData("dnode slots truncated"));
    }

    let blkptr_count = dn_nblkptr.max(1) as usize;
    let mut blkptrs = Vec::new();
    let mut offset = DNODE_CORE_SIZE;
    for _ in 0..blkptr_count {
        if offset + super::types::BLK_PTR_SIZE > total_size {
            return Err(BootError::InvalidData("dnode blkptr overflow"));
        }
        blkptrs.push(BlkPtr::from_bytes(&bytes[offset..offset + super::types::BLK_PTR_SIZE])?);
        offset += super::types::BLK_PTR_SIZE;
    }

    let bonus_start = DNODE_CORE_SIZE + (blkptr_count * super::types::BLK_PTR_SIZE);
    let bonus_end = bonus_start + dn_bonuslen as usize;
    let bonus = if dn_bonuslen == 0 {
        Vec::new()
    } else if bonus_end <= total_size {
        bytes[bonus_start..bonus_end].to_vec()
    } else {
        return Err(BootError::InvalidData("dnode bonus overflow"));
    };

    Ok(DnodePhys {
        dn_type,
        dn_indblkshift,
        dn_nlevels,
        dn_nblkptr,
        dn_bonustype,
        dn_checksum,
        dn_compress,
        dn_flags,
        dn_datablkszsec,
        dn_bonuslen,
        dn_extra_slots,
        dn_maxblkid,
        dn_used,
        blkptrs,
        bonus,
    })
}

pub fn dnode_read(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    dnode: &DnodePhys,
    offset: u64,
    size: usize,
) -> Result<Vec<u8>> {
    let bsize = dnode.block_size();
    if bsize == 0 {
        return Err(BootError::InvalidData("dnode block size zero"));
    }
    if offset / bsize as u64 > dnode.dn_maxblkid {
        return Err(BootError::InvalidData("dnode block id out of range"));
    }
    let mut out = vec![0u8; size];
    let mut cursor = 0usize;
    let mut off = offset;
    let ibshift = dnode.dn_indblkshift as i32 - SPA_BLKPTRSHIFT as i32;
    while cursor < size {
        let bn = off / bsize as u64;
        let boff = (off % bsize as u64) as usize;
        let data_block = read_indirect_block(block, media_id, block_size, dnode, bn, ibshift)?;
        let remaining = size - cursor;
        let to_copy = core::cmp::min(bsize - boff, remaining);
        out[cursor..cursor + to_copy].copy_from_slice(&data_block[boff..boff + to_copy]);
        cursor += to_copy;
        off += to_copy as u64;
    }
    Ok(out)
}

fn read_indirect_block(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    dnode: &DnodePhys,
    bn: u64,
    ibshift: i32,
) -> Result<Vec<u8>> {
    let mut ind_bps = dnode.blkptrs.clone();
    for level in 0..dnode.dn_nlevels {
        let shift = ((dnode.dn_nlevels - level - 1) as i32) * ibshift;
        if shift < 0 {
            return Err(BootError::InvalidData("dnode shift invalid"));
        }
        let ibn = (bn >> shift) & ((1u64 << ibshift) - 1);
        let bp = match ind_bps.get(ibn as usize) {
            Some(bp) => bp,
            None => {
                log::warn!(
                    "dnode blkptr index: bn={} ibn={} nlevels={} nblkptr={} indblkshift={} maxblkid={} block_size={} blkptrs_len={}",
                    bn,
                    ibn,
                    dnode.dn_nlevels,
                    dnode.dn_nblkptr,
                    dnode.dn_indblkshift,
                    dnode.dn_maxblkid,
                    dnode.block_size(),
                    ind_bps.len()
                );
                return Err(BootError::InvalidData("dnode blkptr index"));
            }
        };
        if bp_is_hole(bp) {
            return Ok(vec![0u8; dnode.block_size()]);
        }
        let data = read_block(block, media_id, block_size, bp)?;
        if level + 1 == dnode.dn_nlevels {
            return Ok(data);
        }
        ind_bps = parse_blkptrs(&data)?;
    }
    Err(BootError::InvalidData("dnode read failed"))
}

fn parse_blkptrs(data: &[u8]) -> Result<Vec<BlkPtr>> {
    if data.len() % super::types::BLK_PTR_SIZE != 0 {
        return Err(BootError::InvalidData("blkptr block size invalid"));
    }
    let out = parse_blkptrs_with_data(data)?;
    if out.iter().all(|bp| super::types::bp_is_hole(bp)) {
        let mut swapped = data.to_vec();
        for chunk in swapped.chunks_exact_mut(8) {
            let value = u64::from_le_bytes(chunk.try_into().unwrap()).swap_bytes();
            chunk.copy_from_slice(&value.to_le_bytes());
        }
        let swapped_out = parse_blkptrs_with_data(&swapped)?;
        if !swapped_out.iter().all(|bp| super::types::bp_is_hole(bp)) {
            return Ok(swapped_out);
        }
    }
    Ok(out)
}

fn parse_blkptrs_with_data(data: &[u8]) -> Result<Vec<BlkPtr>> {
    let mut out = Vec::new();
    for chunk in data.chunks_exact(super::types::BLK_PTR_SIZE) {
        out.push(BlkPtr::from_bytes(chunk)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use super::DnodePhys;

    #[test]
    fn parse_dnode_header() {
        let mut buf = vec![0u8; 512];
        buf[0] = 1;
        buf[1] = 12;
        buf[2] = 1;
        buf[3] = 1;
        buf[8..10].copy_from_slice(&1u16.to_le_bytes());
        let dn = DnodePhys::from_bytes(&buf).expect("parse");
        assert_eq!(dn.dn_type, 1);
        assert_eq!(dn.dn_indblkshift, 12);
        assert_eq!(dn.block_size(), 512);
    }
}
