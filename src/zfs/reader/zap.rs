extern crate alloc;

use crate::error::{BootError, Result};
use crate::zfs::reader::dnode::{DnodePhys, dnode_capacity_blocks, dnode_read};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use uefi::proto::media::block::BlockIO;

const ZBT_MICRO: u64 = (1u64 << 63) + 3;
const ZBT_HEADER: u64 = (1u64 << 63) + 1;
const ZBT_LEAF: u64 = (1u64 << 63) + 0;
const ZAP_MAGIC: u64 = 0x2F52AB2AB;
const ZAP_LEAF_MAGIC: u32 = 0x2AB1EAF;
const ZAP_LEAF_CHUNKSIZE: usize = 24;
const ZAP_LEAF_ARRAY_BYTES: usize = ZAP_LEAF_CHUNKSIZE - 3;
const CHAIN_END: u16 = 0xffff;
const MZAP_ENT_LEN: usize = 64;
const MZAP_NAME_LEN: usize = MZAP_ENT_LEN - 8 - 4 - 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct MzapEntPhys {
    mze_value: u64,
    mze_cd: u32,
    mze_pad: u16,
    mze_name: [u8; MZAP_NAME_LEN],
}

pub fn zap_lookup_u64(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    dnode: &DnodePhys,
    name: &str,
) -> Result<u64> {
    let size = dnode.block_size();
    let data = dnode_read(block, media_id, block_size, dnode, 0, size)?;
    let block_type = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let value = match block_type {
        ZBT_MICRO => mzap_lookup(&data, name),
        ZBT_HEADER => fzap_lookup(block, media_id, block_size, dnode, &data, name),
        _ => Err(BootError::InvalidData("zap type invalid")),
    }?;
    Ok(value)
}

pub fn zap_lookup_string(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    dnode: &DnodePhys,
    name: &str,
) -> Result<String> {
    let size = dnode.block_size();
    let data = dnode_read(block, media_id, block_size, dnode, 0, size)?;
    let block_type = u64::from_le_bytes(data[0..8].try_into().unwrap());
    match block_type {
        ZBT_MICRO => Err(BootError::InvalidData("mzap does not store strings")),
        ZBT_HEADER => fzap_lookup_string(block, media_id, block_size, dnode, &data, name),
        _ => Err(BootError::InvalidData("zap type invalid")),
    }
}

pub fn zap_lookup_bytes(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    dnode: &DnodePhys,
    name: &str,
) -> Result<Vec<u8>> {
    let size = dnode.block_size();
    let data = dnode_read(block, media_id, block_size, dnode, 0, size)?;
    match u64::from_le_bytes(data[0..8].try_into().unwrap()) {
        ZBT_MICRO => Err(BootError::InvalidData("mzap does not store byte arrays")),
        ZBT_HEADER => fzap_lookup_bytes(block, media_id, block_size, dnode, &data, name),
        _ => Err(BootError::InvalidData("zap type invalid")),
    }
}

pub fn zap_lookup_u64_normalized(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    dnode: &DnodePhys,
    name: &str,
) -> Result<u64> {
    let value = zap_lookup_u64(block, media_id, block_size, dnode, name)?;
    Ok(normalize_zap_value(value))
}

pub fn zap_list(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    dnode: &DnodePhys,
) -> Result<Vec<String>> {
    let size = dnode.block_size();
    let data = dnode_read(block, media_id, block_size, dnode, 0, size)?;
    let block_type = u64::from_le_bytes(data[0..8].try_into().unwrap());
    match block_type {
        ZBT_MICRO => mzap_list(&data),
        ZBT_HEADER => fzap_list(block, media_id, block_size, dnode, &data),
        _ => Err(BootError::InvalidData("zap type invalid")),
    }
}

#[allow(dead_code)]
pub fn zap_list_entries(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    dnode: &DnodePhys,
) -> Result<Vec<(String, u64)>> {
    let size = dnode.block_size();
    let data = dnode_read(block, media_id, block_size, dnode, 0, size)?;
    let block_type = u64::from_le_bytes(data[0..8].try_into().unwrap());
    match block_type {
        ZBT_MICRO => mzap_entries(&data),
        ZBT_HEADER => fzap_entries(block, media_id, block_size, dnode, &data),
        _ => Err(BootError::InvalidData("zap type invalid")),
    }
}

#[allow(dead_code)]
pub fn zap_rlookup(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    dnode: &DnodePhys,
    value: u64,
) -> Result<String> {
    let size = dnode.block_size();
    let data = dnode_read(block, media_id, block_size, dnode, 0, size)?;
    let block_type = u64::from_le_bytes(data[0..8].try_into().unwrap());
    match block_type {
        ZBT_MICRO => mzap_rlookup(&data, value),
        ZBT_HEADER => fzap_rlookup(block, media_id, block_size, dnode, &data, value),
        _ => Err(BootError::InvalidData("zap type invalid")),
    }
}

fn mzap_lookup(data: &[u8], name: &str) -> Result<u64> {
    let chunks = data.len() / MZAP_ENT_LEN - 1;
    let mut offset = 64usize;
    for _ in 0..chunks {
        if offset + MZAP_ENT_LEN > data.len() {
            break;
        }
        let raw_entry = &data[offset..offset + MZAP_ENT_LEN];
        let ent = parse_mzap_entry(raw_entry)?;
        if let Some(entry_name) = ent.name() {
            if entry_name == name {
                return Ok(ent.mze_value);
            }
        }
        offset += MZAP_ENT_LEN;
    }
    Err(BootError::InvalidData("mzap entry not found"))
}

fn normalize_zap_value(value: u64) -> u64 {
    if value > (1u64 << 40) {
        value.swap_bytes()
    } else {
        value
    }
}

fn mzap_list(data: &[u8]) -> Result<Vec<String>> {
    let chunks = data.len() / MZAP_ENT_LEN - 1;
    let mut offset = 64usize;
    let mut names = Vec::new();
    for _ in 0..chunks {
        if offset + MZAP_ENT_LEN > data.len() {
            break;
        }
        let ent = parse_mzap_entry(&data[offset..offset + MZAP_ENT_LEN])?;
        if let Some(entry_name) = ent.name() {
            names.push(entry_name.to_string());
        }
        offset += MZAP_ENT_LEN;
    }
    Ok(names)
}

#[allow(dead_code)]
fn mzap_entries(data: &[u8]) -> Result<Vec<(String, u64)>> {
    let chunks = data.len() / MZAP_ENT_LEN - 1;
    let mut offset = 64usize;
    let mut entries = Vec::new();
    for _ in 0..chunks {
        if offset + MZAP_ENT_LEN > data.len() {
            break;
        }
        let ent = parse_mzap_entry(&data[offset..offset + MZAP_ENT_LEN])?;
        if let Some(entry_name) = ent.name() {
            entries.push((entry_name.to_string(), ent.mze_value));
        }
        offset += MZAP_ENT_LEN;
    }
    Ok(entries)
}

#[allow(dead_code)]
fn mzap_rlookup(data: &[u8], value: u64) -> Result<String> {
    let chunks = data.len() / MZAP_ENT_LEN - 1;
    let mut offset = 64usize;
    for _ in 0..chunks {
        if offset + MZAP_ENT_LEN > data.len() {
            break;
        }
        let ent = parse_mzap_entry(&data[offset..offset + MZAP_ENT_LEN])?;
        if ent.mze_value == value {
            if let Some(entry_name) = ent.name() {
                return Ok(entry_name.to_string());
            }
        }
        offset += MZAP_ENT_LEN;
    }
    Err(BootError::InvalidData("mzap entry not found"))
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
struct ZapPhys {
    block_type: u64,
    magic: u64,
    ptrtbl_blk: u64,
    ptrtbl_numblks: u64,
    ptrtbl_shift: u64,
    salt: u64,
    normflags: u64,
}

fn parse_zap_phys(data: &[u8]) -> Result<ZapPhys> {
    if data.len() < 88 {
        return Err(BootError::InvalidData("zap header truncated"));
    }
    let block_type = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let magic = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let ptrtbl_blk = u64::from_le_bytes(data[16..24].try_into().unwrap());
    let ptrtbl_numblks = u64::from_le_bytes(data[24..32].try_into().unwrap());
    let ptrtbl_shift = u64::from_le_bytes(data[32..40].try_into().unwrap());
    let salt = u64::from_le_bytes(data[64..72].try_into().unwrap());
    let normflags = u64::from_le_bytes(data[72..80].try_into().unwrap());
    Ok(ZapPhys {
        block_type,
        magic,
        ptrtbl_blk,
        ptrtbl_numblks,
        ptrtbl_shift,
        salt,
        normflags,
    })
}

fn fzap_lookup(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    dnode: &DnodePhys,
    data: &[u8],
    name: &str,
) -> Result<u64> {
    let entries = fzap_entries(block, media_id, block_size, dnode, data)?;
    for (entry_name, value) in entries {
        if entry_name == name {
            return Ok(value);
        }
    }
    Err(BootError::InvalidData("fzap entry not found"))
}

fn fzap_lookup_string(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    dnode: &DnodePhys,
    data: &[u8],
    name: &str,
) -> Result<String> {
    let bytes = fzap_lookup_bytes(block, media_id, block_size, dnode, data, name)?;
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    let text = core::str::from_utf8(&bytes[..end])
        .map_err(|_| BootError::InvalidData("fzap value not utf8"))?;
    Ok(text.to_string())
}

fn fzap_lookup_bytes(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    dnode: &DnodePhys,
    data: &[u8],
    name: &str,
) -> Result<Vec<u8>> {
    let zap = parse_zap_phys(data)?;
    if zap.block_type != ZBT_HEADER || zap.magic != ZAP_MAGIC {
        return Err(BootError::InvalidData("zap header invalid"));
    }
    let bsize = dnode.block_size();
    let block_shift = ilog2(bsize)?;
    let ptrtbl_entries = 1u64 << zap.ptrtbl_shift;
    let mut leaf_blocks = Vec::new();
    let max_blocks = dnode_capacity_blocks(dnode).unwrap_or(u64::MAX);
    if zap.ptrtbl_numblks == 0 {
        let embedded_shift = block_shift - 3 - 1;
        let start_word = 1u64 << embedded_shift;
        for idx in 0..ptrtbl_entries {
            let word_index = (start_word + idx) as usize;
            let offset = word_index * 8;
            if offset + 8 > data.len() {
                break;
            }
            let blk = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
            if blk != 0 {
                leaf_blocks.push(blk);
            }
        }
    } else {
        let entries_per_block = (1u64 << block_shift) / 8;
        for blk in 0..zap.ptrtbl_numblks {
            let table_blk = zap.ptrtbl_blk + blk;
            if table_blk >= max_blocks {
                log::warn!(
                    "zap ptrtbl block out of range: blk={} max_blocks={}",
                    table_blk,
                    max_blocks
                );
                continue;
            }
            let table_offset = table_blk << block_shift;
            let table = dnode_read(
                block,
                media_id,
                block_size,
                dnode,
                table_offset,
                1usize << block_shift,
            )?;
            for idx in 0..entries_per_block {
                let off = (idx * 8) as usize;
                if off + 8 > table.len() {
                    break;
                }
                let val = u64::from_le_bytes(table[off..off + 8].try_into().unwrap());
                if val != 0 {
                    leaf_blocks.push(val);
                }
            }
        }
    }

    leaf_blocks.sort();
    leaf_blocks.dedup();

    for blk in leaf_blocks {
        if blk >= max_blocks {
            log::warn!(
                "zap leaf block out of range: blk={} max_blocks={}",
                blk,
                max_blocks
            );
            continue;
        }
        let leaf_offset = blk << block_shift;
        let leaf = dnode_read(
            block,
            media_id,
            block_size,
            dnode,
            leaf_offset,
            1usize << block_shift,
        )?;
        if leaf.len() < 16 {
            continue;
        }
        let leaf_type = u64::from_le_bytes(leaf[0..8].try_into().unwrap());
        if leaf_type != ZBT_LEAF {
            continue;
        }
        let leaf_magic = u32::from_le_bytes(leaf[24..28].try_into().unwrap());
        if leaf_magic != ZAP_LEAF_MAGIC {
            continue;
        }
        if let Ok(bytes) = find_leaf_entry_bytes(&leaf, block_shift, name) {
            return Ok(bytes);
        }
    }

    let bytes = fzap_scan_bytes(block, media_id, block_size, dnode, block_shift, name)?;
    Ok(bytes)
}

fn fzap_scan_bytes(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    dnode: &DnodePhys,
    block_shift: u64,
    name: &str,
) -> Result<Vec<u8>> {
    let max_blk = dnode_capacity_blocks(dnode)
        .and_then(|max| max.checked_sub(1))
        .unwrap_or(dnode.dn_maxblkid)
        .min(1024);
    let block_size_bytes = 1usize << block_shift;
    for blk in 0..=max_blk {
        let offset = blk << block_shift;
        let leaf = dnode_read(block, media_id, block_size, dnode, offset, block_size_bytes)?;
        if leaf.len() < 16 {
            continue;
        }
        let leaf_type = u64::from_le_bytes(leaf[0..8].try_into().unwrap());
        if leaf_type != ZBT_LEAF {
            continue;
        }
        let leaf_magic = u32::from_le_bytes(leaf[24..28].try_into().unwrap());
        if leaf_magic != ZAP_LEAF_MAGIC {
            continue;
        }
        if let Ok(bytes) = find_leaf_entry_bytes(&leaf, block_shift, name) {
            return Ok(bytes);
        }
    }
    Err(BootError::InvalidData("fzap entry not found"))
}

fn find_leaf_entry_bytes(leaf: &[u8], block_shift: u64, name: &str) -> Result<Vec<u8>> {
    let block_size = 1usize << block_shift;
    if leaf.len() < block_size {
        return Err(BootError::InvalidData("leaf block truncated"));
    }
    let hash_entries = 1usize << (block_shift - 5);
    let hash_bytes = hash_entries * 2;
    let chunk_start = 48 + hash_bytes;
    let num_chunks = ((block_size - 2 * hash_entries) / ZAP_LEAF_CHUNKSIZE) - 2;
    for chunk_idx in 0..num_chunks {
        let offset = chunk_start + chunk_idx * ZAP_LEAF_CHUNKSIZE;
        if offset + ZAP_LEAF_CHUNKSIZE > leaf.len() {
            break;
        }
        let chunk = &leaf[offset..offset + ZAP_LEAF_CHUNKSIZE];
        if chunk[0] != 252 {
            continue;
        }
        let name_chunk = u16::from_le_bytes([chunk[4], chunk[5]]);
        let name_len = u16::from_le_bytes([chunk[6], chunk[7]]) as usize;
        let value_chunk = u16::from_le_bytes([chunk[8], chunk[9]]);
        let value_intlen = chunk[1] as usize;
        let value_numints = u16::from_le_bytes([chunk[10], chunk[11]]) as usize;
        let entry_name = read_leaf_string(leaf, block_shift, name_chunk, name_len)?;
        if entry_name == name {
            let size = value_intlen * value_numints;
            return read_leaf_bytes(leaf, block_shift, value_chunk, size);
        }
    }
    Err(BootError::InvalidData("fzap entry not found"))
}
#[allow(dead_code)]
fn fzap_rlookup(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    dnode: &DnodePhys,
    data: &[u8],
    value: u64,
) -> Result<String> {
    let entries = fzap_entries(block, media_id, block_size, dnode, data)?;
    for (entry_name, entry_value) in entries {
        if entry_value == value {
            return Ok(entry_name);
        }
    }
    Err(BootError::InvalidData("fzap entry not found"))
}

fn fzap_list(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    dnode: &DnodePhys,
    data: &[u8],
) -> Result<Vec<String>> {
    let entries = fzap_entries(block, media_id, block_size, dnode, data)?;
    Ok(entries.into_iter().map(|(name, _)| name).collect())
}

fn fzap_entries(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    dnode: &DnodePhys,
    data: &[u8],
) -> Result<Vec<(String, u64)>> {
    let zap = parse_zap_phys(data)?;
    if zap.block_type != ZBT_HEADER || zap.magic != ZAP_MAGIC {
        return Err(BootError::InvalidData("zap header invalid"));
    }
    let bsize = dnode.block_size();
    let block_shift = ilog2(bsize)?;
    let ptrtbl_entries = 1u64 << zap.ptrtbl_shift;
    let mut leaf_blocks = Vec::new();
    if zap.ptrtbl_numblks == 0 {
        let embedded_shift = block_shift - 3 - 1;
        let start_word = 1u64 << embedded_shift;
        for idx in 0..ptrtbl_entries {
            let word_index = (start_word + idx) as usize;
            let offset = word_index * 8;
            if offset + 8 > data.len() {
                break;
            }
            let blk = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
            if blk != 0 {
                leaf_blocks.push(blk);
            }
        }
    } else {
        let entries_per_block = (1u64 << block_shift) / 8;
        for blk in 0..zap.ptrtbl_numblks {
            let table_offset = (zap.ptrtbl_blk + blk) << block_shift;
            let table = dnode_read(
                block,
                media_id,
                block_size,
                dnode,
                table_offset,
                1usize << block_shift,
            )?;
            for idx in 0..entries_per_block {
                let off = (idx * 8) as usize;
                if off + 8 > table.len() {
                    break;
                }
                let val = u64::from_le_bytes(table[off..off + 8].try_into().unwrap());
                if val != 0 {
                    leaf_blocks.push(val);
                }
            }
        }
    }

    leaf_blocks.sort();
    leaf_blocks.dedup();

    let mut entries = Vec::new();
    for blk in leaf_blocks {
        let leaf_offset = blk << block_shift;
        let leaf = dnode_read(
            block,
            media_id,
            block_size,
            dnode,
            leaf_offset,
            1usize << block_shift,
        )?;
        if leaf.len() < 16 {
            continue;
        }
        let leaf_type = u64::from_le_bytes(leaf[0..8].try_into().unwrap());
        if leaf_type != ZBT_LEAF {
            continue;
        }
        let leaf_magic = u32::from_le_bytes(leaf[24..28].try_into().unwrap());
        if leaf_magic != ZAP_LEAF_MAGIC {
            continue;
        }
        entries.extend(parse_leaf_entries(&leaf, block_shift)?);
    }

    if entries.is_empty() {
        entries = fzap_scan_entries(block, media_id, block_size, dnode, block_shift)?;
    }

    Ok(entries)
}

fn fzap_scan_entries(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    dnode: &DnodePhys,
    block_shift: u64,
) -> Result<Vec<(String, u64)>> {
    let mut entries = Vec::new();
    let max_blk = dnode.dn_maxblkid.min(1024);
    let block_size_bytes = 1usize << block_shift;
    for blk in 0..=max_blk {
        let offset = blk << block_shift;
        let leaf = dnode_read(block, media_id, block_size, dnode, offset, block_size_bytes)?;
        if leaf.len() < 16 {
            continue;
        }
        let leaf_type = u64::from_le_bytes(leaf[0..8].try_into().unwrap());
        if leaf_type != ZBT_LEAF {
            continue;
        }
        let leaf_magic = u32::from_le_bytes(leaf[24..28].try_into().unwrap());
        if leaf_magic != ZAP_LEAF_MAGIC {
            continue;
        }
        entries.extend(parse_leaf_entries(&leaf, block_shift)?);
    }
    Ok(entries)
}

fn parse_leaf_entries(leaf: &[u8], block_shift: u64) -> Result<Vec<(String, u64)>> {
    let block_size = 1usize << block_shift;
    if leaf.len() < block_size {
        return Err(BootError::InvalidData("leaf block truncated"));
    }
    let hash_entries = 1usize << (block_shift - 5);
    let hash_bytes = hash_entries * 2;
    let chunk_start = 48 + hash_bytes;
    let num_chunks = ((block_size - 2 * hash_entries) / ZAP_LEAF_CHUNKSIZE) - 2;
    let mut entries = Vec::new();
    for chunk_idx in 0..num_chunks {
        let offset = chunk_start + chunk_idx * ZAP_LEAF_CHUNKSIZE;
        if offset + ZAP_LEAF_CHUNKSIZE > leaf.len() {
            break;
        }
        let chunk = &leaf[offset..offset + ZAP_LEAF_CHUNKSIZE];
        let chunk_type = chunk[0];
        if chunk_type != 252 {
            continue;
        }
        let name_chunk = u16::from_le_bytes([chunk[4], chunk[5]]);
        let name_len = u16::from_le_bytes([chunk[6], chunk[7]]) as usize;
        let value_chunk = u16::from_le_bytes([chunk[8], chunk[9]]);
        let value_intlen = chunk[1] as usize;
        let value_numints = u16::from_le_bytes([chunk[10], chunk[11]]) as usize;
        let name = read_leaf_string(leaf, block_shift, name_chunk, name_len)?;
        let value_bytes =
            read_leaf_bytes(leaf, block_shift, value_chunk, value_intlen * value_numints)?;
        if value_bytes.len() >= 8 {
            let value = u64::from_le_bytes(value_bytes[0..8].try_into().unwrap());
            entries.push((name, value));
        }
    }
    Ok(entries)
}

fn read_leaf_bytes(
    leaf: &[u8],
    block_shift: u64,
    start_chunk: u16,
    bytes: usize,
) -> Result<Vec<u8>> {
    let mut remaining = bytes;
    let mut chunk = start_chunk;
    let mut out = Vec::new();
    let block_size = 1usize << block_shift;
    let hash_entries = 1usize << (block_shift - 5);
    let hash_bytes = hash_entries * 2;
    let chunk_start = 48 + hash_bytes;
    while remaining > 0 && chunk != CHAIN_END {
        let offset = chunk_start + chunk as usize * ZAP_LEAF_CHUNKSIZE;
        if offset + ZAP_LEAF_CHUNKSIZE > block_size {
            return Err(BootError::InvalidData("leaf array out of range"));
        }
        let entry = &leaf[offset..offset + ZAP_LEAF_CHUNKSIZE];
        if entry[0] != 251 && entry[0] != 252 {
            return Err(BootError::InvalidData("leaf array chunk invalid"));
        }
        let to_copy = core::cmp::min(remaining, ZAP_LEAF_ARRAY_BYTES);
        out.extend_from_slice(&entry[1..1 + to_copy]);
        remaining -= to_copy;
        chunk = u16::from_le_bytes([entry[ZAP_LEAF_CHUNKSIZE - 2], entry[ZAP_LEAF_CHUNKSIZE - 1]]);
    }
    if remaining != 0 {
        return Err(BootError::InvalidData("leaf array truncated"));
    }
    Ok(out)
}

fn read_leaf_string(
    leaf: &[u8],
    block_shift: u64,
    start_chunk: u16,
    bytes: usize,
) -> Result<String> {
    let out = read_leaf_bytes(leaf, block_shift, start_chunk, bytes)?;
    let end = out.iter().position(|b| *b == 0).unwrap_or(out.len());
    let text =
        core::str::from_utf8(&out[..end]).map_err(|_| BootError::InvalidData("leaf array utf8"))?;
    Ok(text.to_string())
}

fn ilog2(value: usize) -> Result<u64> {
    if !value.is_power_of_two() {
        return Err(BootError::InvalidData("block size not power of two"));
    }
    Ok(value.trailing_zeros() as u64)
}

impl MzapEntPhys {
    fn name(&self) -> Option<&str> {
        let mut end = 0usize;
        while end < self.mze_name.len() && self.mze_name[end] != 0 {
            end += 1;
        }
        if end == 0 {
            return None;
        }
        core::str::from_utf8(&self.mze_name[..end]).ok()
    }
}

fn parse_mzap_entry(bytes: &[u8]) -> Result<MzapEntPhys> {
    if bytes.len() < MZAP_ENT_LEN {
        return Err(BootError::InvalidData("mzap entry truncated"));
    }
    let mze_value = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let mze_cd = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let mze_pad = u16::from_le_bytes(bytes[12..14].try_into().unwrap());
    let mut name = [0u8; MZAP_NAME_LEN];
    name.copy_from_slice(&bytes[14..14 + MZAP_NAME_LEN]);
    Ok(MzapEntPhys {
        mze_value,
        mze_cd,
        mze_pad,
        mze_name: name,
    })
}

#[cfg(test)]
mod tests {
    use super::mzap_lookup;
    use super::normalize_zap_value;
    use super::{CHAIN_END, ZAP_LEAF_CHUNKSIZE, ZAP_LEAF_MAGIC, ZBT_LEAF, parse_leaf_entries};
    use alloc::vec;

    #[test]
    fn mzap_lookup_basic() {
        let mut buf = vec![0u8; 128];
        buf[0..8].copy_from_slice(&super::ZBT_MICRO.to_le_bytes());
        let name = b"root_dataset";
        let offset = 64;
        buf[offset..offset + 8].copy_from_slice(&42u64.to_le_bytes());
        buf[offset + 14..offset + 14 + name.len()].copy_from_slice(name);
        let value = mzap_lookup(&buf, "root_dataset").expect("lookup");
        assert_eq!(value, 42);
    }

    #[test]
    fn normalize_zap_value_swaps_large_values() {
        let value = 0x8100000000000000u64;
        assert_eq!(normalize_zap_value(value), 0x0000000000000081u64);
    }

    #[test]
    fn normalize_zap_value_keeps_small_values() {
        let value = 0x1234u64;
        assert_eq!(normalize_zap_value(value), value);
    }

    #[test]
    fn fzap_leaf_parse_entry() {
        let block_shift = 9u64;
        let block_size = 1usize << block_shift;
        let hash_entries = 1usize << (block_shift - 5);
        let hash_bytes = hash_entries * 2;
        let chunk_start = 48 + hash_bytes;
        let mut leaf = vec![0u8; block_size];
        leaf[0..8].copy_from_slice(&ZBT_LEAF.to_le_bytes());
        leaf[24..28].copy_from_slice(&ZAP_LEAF_MAGIC.to_le_bytes());
        leaf[48..50].copy_from_slice(&0u16.to_le_bytes());

        let entry_offset = chunk_start;
        leaf[entry_offset] = 252;
        leaf[entry_offset + 1] = 8;
        leaf[entry_offset + 2..entry_offset + 4].copy_from_slice(&CHAIN_END.to_le_bytes());
        leaf[entry_offset + 4..entry_offset + 6].copy_from_slice(&1u16.to_le_bytes());
        let name = b"root_dataset";
        leaf[entry_offset + 6..entry_offset + 8]
            .copy_from_slice(&((name.len() + 1) as u16).to_le_bytes());
        leaf[entry_offset + 8..entry_offset + 10].copy_from_slice(&2u16.to_le_bytes());
        leaf[entry_offset + 10..entry_offset + 12].copy_from_slice(&1u16.to_le_bytes());

        let name_offset = chunk_start + ZAP_LEAF_CHUNKSIZE;
        leaf[name_offset] = 251;
        leaf[name_offset + 1..name_offset + 1 + name.len()].copy_from_slice(name);
        leaf[name_offset + 1 + name.len()] = 0;
        leaf[name_offset + ZAP_LEAF_CHUNKSIZE - 2..name_offset + ZAP_LEAF_CHUNKSIZE]
            .copy_from_slice(&CHAIN_END.to_le_bytes());

        let value_offset = name_offset + ZAP_LEAF_CHUNKSIZE;
        leaf[value_offset] = 251;
        leaf[value_offset + 1..value_offset + 9].copy_from_slice(&42u64.to_le_bytes());
        leaf[value_offset + ZAP_LEAF_CHUNKSIZE - 2..value_offset + ZAP_LEAF_CHUNKSIZE]
            .copy_from_slice(&CHAIN_END.to_le_bytes());

        let entries = parse_leaf_entries(&leaf, block_shift).expect("parse");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "root_dataset");
        assert_eq!(entries[0].1, 42);
    }
}
