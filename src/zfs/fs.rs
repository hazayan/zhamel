extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use uefi::boot;
use uefi::proto::media::block::BlockIO;

use crate::error::{BootError, Result};
use crate::zfs::reader::dnode::{dnode_read, DnodePhys};
use crate::zfs::reader::io::read_block;
use crate::zfs::reader::mos;
use crate::zfs::reader::objset::{objset_get_dnode, ObjsetPhys};
use crate::zfs::reader::types::{BlkPtr, BLK_PTR_SIZE};
use crate::zfs::reader::zap::{
    zap_list,
    zap_list_entries,
    zap_lookup_u64,
    zap_lookup_u64_normalized,
};
use crate::zfs::ZfsPool;

const DMU_POOL_DIRECTORY_OBJECT: u64 = 1;
const DMU_POOL_ROOT_DATASET: &str = "root_dataset";
const MASTER_NODE_OBJ: u64 = 1;
const ZFS_ROOT_OBJ: &str = "ROOT";
const ZFS_DIRENT_OBJ_MASK: u64 = (1u64 << 48) - 1;
const DSL_DIR_HEAD_DATASET_OFFSET: usize = 8;
const DSL_DIR_CHILD_ZAP_OFFSET: usize = 32;
const DSL_DIR_PROPS_ZAP_OFFSET: usize = 80;
const DSL_DATASET_BP_OFFSET: usize = 128;
const DSL_DATASET_PROPS_OFFSET: usize = 264;
const ZNODE_SIZE_OFFSET: usize = 80;
const SA_MAGIC: u32 = 0x2F505A;
const SA_SIZE_OFFSET: usize = 8;

#[derive(Clone, Debug, Default)]
pub struct DatasetProps {
    pub keyformat: Option<String>,
    pub keylocation: Option<String>,
    pub kunci_jwe: Option<String>,
}

pub fn read_file_from_bootenv(pool: &ZfsPool, bootenv: &str, path: &str) -> Result<Vec<u8>> {
    let block = boot::open_protocol_exclusive::<BlockIO>(pool.handle)
        .map_err(|err| BootError::Uefi(err.status()))?;
    let uber = pool
        .uber
        .ok_or(BootError::InvalidData("uberblock missing"))?;
    let objset = mount_dataset(&block, pool.media_id, pool.block_size, uber, bootenv)?;
    read_file_from_objset(&block, pool.media_id, pool.block_size, &objset, path)
}

pub fn list_dir_from_bootenv(pool: &ZfsPool, bootenv: &str, path: &str) -> Result<Vec<String>> {
    let block = boot::open_protocol_exclusive::<BlockIO>(pool.handle)
        .map_err(|err| BootError::Uefi(err.status()))?;
    let uber = pool
        .uber
        .ok_or(BootError::InvalidData("uberblock missing"))?;
    let objset = mount_dataset(&block, pool.media_id, pool.block_size, uber, bootenv)?;
    list_dir_from_objset(&block, pool.media_id, pool.block_size, &objset, path)
}

pub fn bootfs_objset(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    uber: crate::zfs::reader::types::Uberblock,
) -> Result<ObjsetPhys> {
    let bootfs = mos::bootfs_objid(block, media_id, block_size, &uber)?
        .ok_or(BootError::InvalidData("bootfs not set"))?;
    log::info!("zfs bootfs objid: {}", bootfs);
    mount_dataset_obj(block, media_id, block_size, uber, bootfs)
}

pub fn bootenv_dataset_props(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    uber: crate::zfs::reader::types::Uberblock,
    bootenv: &str,
) -> Result<DatasetProps> {
    let mos_bytes = read_block(block, media_id, block_size, &uber.rootbp)?;
    let mos = ObjsetPhys::from_bytes(&mos_bytes)?;
    let dir_obj = lookup_dataset_dir_obj(block, media_id, block_size, &mos, bootenv)?;
    let dir_dnode = objset_get_dnode(block, media_id, block_size, &mos, dir_obj)?;
    let props_zap = parse_dsl_dir_props_zap(&dir_dnode)?;
    if props_zap != 0 {
        match objset_get_dnode(block, media_id, block_size, &mos, props_zap) {
            Ok(props_dnode) => {
                let keyformat = zap_lookup_string_opt(
                    block,
                    media_id,
                    block_size,
                    &props_dnode,
                    "keyformat",
                )?;
                let keylocation = zap_lookup_string_opt(
                    block,
                    media_id,
                    block_size,
                    &props_dnode,
                    "keylocation",
                )?;
                let kunci_jwe =
                    zap_lookup_string_opt(block, media_id, block_size, &props_dnode, "kunci:jwe")?;
                return Ok(DatasetProps {
                    keyformat,
                    keylocation,
                    kunci_jwe,
                });
            }
            Err(err) => {
                log::warn!(
                    "zfs: dataset props zap read failed: {} (fallback to dataset props)",
                    err
                );
            }
        }
    }
    let dataset_obj = parse_dsl_dir_head_dataset(&dir_dnode)?;
    dataset_props_from_objid(block, media_id, block_size, &mos, dataset_obj)
}

fn mount_dataset(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    uber: crate::zfs::reader::types::Uberblock,
    bootenv: &str,
) -> Result<ObjsetPhys> {
    let mos_bytes = read_block(block, media_id, block_size, &uber.rootbp)?;
    let mos = ObjsetPhys::from_bytes(&mos_bytes)?;
    let dataset_obj = lookup_dataset_obj(block, media_id, block_size, &mos, bootenv)?;
    mount_dataset_objset(block, media_id, block_size, &mos, dataset_obj)
}

fn mount_dataset_obj(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    uber: crate::zfs::reader::types::Uberblock,
    objid: u64,
) -> Result<ObjsetPhys> {
    let mos_bytes = read_block(block, media_id, block_size, &uber.rootbp)?;
    let mos = ObjsetPhys::from_bytes(&mos_bytes)?;
    mount_dataset_objset(block, media_id, block_size, &mos, objid)
}

fn mount_dataset_objset(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    mos: &ObjsetPhys,
    objid: u64,
) -> Result<ObjsetPhys> {
    let dataset_dnode = objset_get_dnode(block, media_id, block_size, mos, objid)?;
    let ds_bp = parse_dsl_dataset_bp(&dataset_dnode)?;
    let objset_bytes = read_block(block, media_id, block_size, &ds_bp)?;
    ObjsetPhys::from_bytes(&objset_bytes)
}

fn dataset_props_from_objid(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    mos: &ObjsetPhys,
    objid: u64,
) -> Result<DatasetProps> {
    let dataset_dnode = objset_get_dnode(block, media_id, block_size, mos, objid)?;
    let props_obj = parse_dsl_dataset_props_obj(&dataset_dnode)?;
    if props_obj == 0 {
        return Ok(DatasetProps::default());
    }
    let props_dnode = objset_get_dnode(block, media_id, block_size, mos, props_obj)?;
    let keyformat = zap_lookup_string_opt(block, media_id, block_size, &props_dnode, "keyformat")?;
    let keylocation =
        zap_lookup_string_opt(block, media_id, block_size, &props_dnode, "keylocation")?;
    let kunci_jwe =
        zap_lookup_string_opt(block, media_id, block_size, &props_dnode, "kunci:jwe")?;
    Ok(DatasetProps {
        keyformat,
        keylocation,
        kunci_jwe,
    })
}

fn zap_lookup_string_opt(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    dnode: &DnodePhys,
    name: &str,
) -> Result<Option<String>> {
    match crate::zfs::reader::zap::zap_lookup_string(block, media_id, block_size, dnode, name) {
        Ok(value) => Ok(Some(value)),
        Err(BootError::InvalidData(msg))
            if msg == "fzap entry not found" || msg == "mzap does not store strings" =>
        {
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

fn lookup_dataset_obj(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    mos: &ObjsetPhys,
    bootenv: &str,
) -> Result<u64> {
    let dir_obj = lookup_dataset_dir_obj(block, media_id, block_size, mos, bootenv)?;
    let dir = objset_get_dnode(block, media_id, block_size, mos, dir_obj)?;
    parse_dsl_dir_head_dataset(&dir)
}

fn lookup_dataset_dir_obj(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    mos: &ObjsetPhys,
    bootenv: &str,
) -> Result<u64> {
    let dir_dnode = objset_get_dnode(block, media_id, block_size, mos, DMU_POOL_DIRECTORY_OBJECT)?;
    let root_dir = zap_lookup_u64_normalized(
        block,
        media_id,
        block_size,
        &dir_dnode,
        DMU_POOL_ROOT_DATASET,
    )?;
    let mut dir_obj = root_dir & ZFS_DIRENT_OBJ_MASK;
    for segment in bootenv.split('/').filter(|s| !s.is_empty()) {
        let dir = objset_get_dnode(block, media_id, block_size, mos, dir_obj)?;
        let child_zap_obj = parse_dsl_dir_child_zap(&dir)?;
        let child_zap = objset_get_dnode(block, media_id, block_size, mos, child_zap_obj)?;
        let child_obj =
            zap_lookup_u64_normalized(block, media_id, block_size, &child_zap, segment)?;
        dir_obj = child_obj & ZFS_DIRENT_OBJ_MASK;
    }
    Ok(dir_obj)
}

fn parse_dsl_dir_child_zap(dir: &DnodePhys) -> Result<u64> {
    let bonus = dir.bonus.as_slice();
    if bonus.len() < DSL_DIR_CHILD_ZAP_OFFSET + 8 {
        return Err(BootError::InvalidData("dsl dir bonus too small"));
    }
    let raw = u64::from_le_bytes(
        bonus[DSL_DIR_CHILD_ZAP_OFFSET..DSL_DIR_CHILD_ZAP_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    Ok(normalize_objid(raw) & ZFS_DIRENT_OBJ_MASK)
}

fn parse_dsl_dir_head_dataset(dir: &DnodePhys) -> Result<u64> {
    let bonus = dir.bonus.as_slice();
    if bonus.len() < DSL_DIR_HEAD_DATASET_OFFSET + 8 {
        return Err(BootError::InvalidData("dsl dir bonus too small"));
    }
    let raw = u64::from_le_bytes(
        bonus[DSL_DIR_HEAD_DATASET_OFFSET..DSL_DIR_HEAD_DATASET_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    Ok(normalize_objid(raw) & ZFS_DIRENT_OBJ_MASK)
}

fn parse_dsl_dir_props_zap(dir: &DnodePhys) -> Result<u64> {
    let bonus = dir.bonus.as_slice();
    if bonus.len() < DSL_DIR_PROPS_ZAP_OFFSET + 8 {
        return Err(BootError::InvalidData("dsl dir bonus too small for props"));
    }
    let raw = u64::from_le_bytes(
        bonus[DSL_DIR_PROPS_ZAP_OFFSET..DSL_DIR_PROPS_ZAP_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    let value = normalize_objid(raw) & ZFS_DIRENT_OBJ_MASK;
    Ok(value)
}

fn parse_dsl_dataset_bp(dnode: &DnodePhys) -> Result<BlkPtr> {
    let bonus = dnode.bonus.as_slice();
    if bonus.len() < DSL_DATASET_BP_OFFSET + BLK_PTR_SIZE {
        return Err(BootError::InvalidData("dsl dataset bonus too small"));
    }
    BlkPtr::from_bytes(&bonus[DSL_DATASET_BP_OFFSET..DSL_DATASET_BP_OFFSET + BLK_PTR_SIZE])
}

fn parse_dsl_dataset_props_obj(dnode: &DnodePhys) -> Result<u64> {
    let bonus = dnode.bonus.as_slice();
    if bonus.len() < DSL_DATASET_PROPS_OFFSET + 8 {
        return Err(BootError::InvalidData("dsl dataset bonus too small for props"));
    }
    let raw = u64::from_le_bytes(
        bonus[DSL_DATASET_PROPS_OFFSET..DSL_DATASET_PROPS_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    let value = normalize_objid(raw) & ZFS_DIRENT_OBJ_MASK;
    Ok(value)
}

fn normalize_objid(raw: u64) -> u64 {
    let mut value = raw;
    if value > (1u64 << 40) {
        value = value.swap_bytes();
    }
    if value > (1u64 << 40) {
        0
    } else {
        value
    }
}

pub fn read_file_from_objset(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    objset: &ObjsetPhys,
    path: &str,
) -> Result<Vec<u8>> {
    log::info!("zfs read file start: {}", path);
    let file = lookup_file_dnode(block, media_id, block_size, objset, path)?;
    let size = znode_size(&file)? as usize;
    log::info!("zfs file size: {}", size);
    if size > 512 * 1024 * 1024 {
        return Err(BootError::InvalidData("zfs file size unreasonable"));
    }
    let data = dnode_read(block, media_id, block_size, &file, 0, size)?;
    log::info!("zfs read file done: {}", path);
    Ok(data)
}

pub fn list_dir_from_objset(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    objset: &ObjsetPhys,
    path: &str,
) -> Result<Vec<String>> {
    let dir = lookup_file_dnode(block, media_id, block_size, objset, path)?;
    zap_list(block, media_id, block_size, &dir)
}

pub fn list_dir_entries_with_ids(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    objset: &ObjsetPhys,
    path: &str,
) -> Result<Vec<(String, u64)>> {
    let dir = lookup_file_dnode(block, media_id, block_size, objset, path)?;
    let entries = zap_list_entries(block, media_id, block_size, &dir)?;
    Ok(entries
        .into_iter()
        .map(|(name, value)| (name, value & ZFS_DIRENT_OBJ_MASK))
        .collect())
}

pub fn read_file_from_objset_objid(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    objset: &ObjsetPhys,
    objid: u64,
) -> Result<Vec<u8>> {
    let file = objset_get_dnode(block, media_id, block_size, objset, objid)?;
    let size = znode_size(&file)? as usize;
    log::info!("zfs file size: {}", size);
    if size > 512 * 1024 * 1024 {
        return Err(BootError::InvalidData("zfs file size unreasonable"));
    }
    dnode_read(block, media_id, block_size, &file, 0, size)
}

fn lookup_file_dnode(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    objset: &ObjsetPhys,
    path: &str,
) -> Result<DnodePhys> {
    let master = objset_get_dnode(block, media_id, block_size, objset, MASTER_NODE_OBJ)?;
    let root_obj = zap_lookup_u64(block, media_id, block_size, &master, ZFS_ROOT_OBJ)?;
    let mut objnum = root_obj;
    for segment in path.split('/').filter(|s| !s.is_empty()) {
        let dir = objset_get_dnode(block, media_id, block_size, objset, objnum)?;
        let entry = zap_lookup_u64(block, media_id, block_size, &dir, segment)?;
        objnum = entry & ZFS_DIRENT_OBJ_MASK;
    }
    objset_get_dnode(block, media_id, block_size, objset, objnum)
}

fn znode_size(dnode: &DnodePhys) -> Result<u64> {
    let bonus = dnode.bonus.as_slice();
    if bonus.len() >= 4 {
        let magic = u32::from_le_bytes(bonus[0..4].try_into().unwrap());
        if magic == SA_MAGIC {
            if bonus.len() < 6 {
                return Err(BootError::InvalidData("sa header truncated"));
            }
            let layout_info = u16::from_le_bytes(bonus[4..6].try_into().unwrap());
            let hdrsize = (((layout_info >> 10) & 0x3f) as usize) << 3;
            let size_off = hdrsize + SA_SIZE_OFFSET;
            if bonus.len() < size_off + 8 {
                return Err(BootError::InvalidData("sa size offset invalid"));
            }
            let mut size = u64::from_le_bytes(
                bonus[size_off..size_off + 8].try_into().unwrap(),
            );
            if size > (1u64 << 40) {
                let swapped = size.swap_bytes();
                if swapped < size {
                    size = swapped;
                }
            }
            if size > (1u64 << 40) {
                return Err(BootError::InvalidData("znode size unreasonable"));
            }
            return Ok(size);
        }
    }
    if bonus.len() < ZNODE_SIZE_OFFSET + 8 {
        return Err(BootError::InvalidData("znode bonus too small"));
    }
    let mut size = u64::from_le_bytes(
        bonus[ZNODE_SIZE_OFFSET..ZNODE_SIZE_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    if size > (1u64 << 40) {
        let swapped = size.swap_bytes();
        if swapped < size {
            size = swapped;
        }
    }
    if size > (1u64 << 40) {
        return Err(BootError::InvalidData("znode size unreasonable"));
    }
    Ok(size)
}
