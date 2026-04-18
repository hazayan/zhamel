extern crate alloc;

use crate::error::{BootError, Result};
use crate::zfs::reader::dnode::{DnodePhys, dnode_read};
use uefi::proto::media::block::BlockIO;

const DNODE_SIZE: usize = 512;

#[derive(Debug, Clone)]
pub struct ObjsetPhys {
    pub meta_dnode: DnodePhys,
}

impl ObjsetPhys {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < DNODE_SIZE {
            return Err(BootError::InvalidData("objset buffer too small"));
        }
        let meta_dnode = DnodePhys::from_bytes(&bytes[..DNODE_SIZE])?;
        Ok(Self { meta_dnode })
    }
}

pub fn objset_get_dnode(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    os: &ObjsetPhys,
    objnum: u64,
) -> Result<DnodePhys> {
    let offset = objnum
        .checked_mul(DNODE_SIZE as u64)
        .ok_or(BootError::InvalidData("dnode offset overflow"))?;
    let header = dnode_read(block, media_id, block_size, &os.meta_dnode, offset, DNODE_SIZE)
        .map_err(|err| {
            log::warn!(
                "dnode read header failed: objnum={} offset={} nlevels={} nblkptr={} indblkshift={} maxblkid={} block_size={}",
                objnum,
                offset,
                os.meta_dnode.dn_nlevels,
                os.meta_dnode.dn_nblkptr,
                os.meta_dnode.dn_indblkshift,
                os.meta_dnode.dn_maxblkid,
                os.meta_dnode.block_size()
            );
            err
        })?;
    let extra_raw = *header
        .get(12)
        .ok_or(BootError::InvalidData("dnode header truncated"))?;
    let mut swapped = header.clone();
    for chunk in swapped.chunks_exact_mut(8) {
        let value = u64::from_le_bytes(chunk.try_into().unwrap()).swap_bytes();
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    let extra_swapped = swapped[12];
    let extra_slots = core::cmp::min(extra_raw.max(extra_swapped) as usize, 32);
    let total_size = DNODE_SIZE * (1usize + extra_slots);
    let bytes = if total_size == DNODE_SIZE {
        header
    } else {
        dnode_read(
            block,
            media_id,
            block_size,
            &os.meta_dnode,
            offset,
            total_size,
        )
        .map_err(|err| {
            log::warn!(
                "dnode read full failed: objnum={} offset={} size={} nlevels={} nblkptr={} indblkshift={} maxblkid={} block_size={}",
                objnum,
                offset,
                total_size,
                os.meta_dnode.dn_nlevels,
                os.meta_dnode.dn_nblkptr,
                os.meta_dnode.dn_indblkshift,
                os.meta_dnode.dn_maxblkid,
                os.meta_dnode.block_size()
            );
            err
        })?
    };
    DnodePhys::from_bytes(&bytes)
}
