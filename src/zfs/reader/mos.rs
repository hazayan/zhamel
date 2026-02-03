extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use uefi::proto::media::block::BlockIO;

use crate::error::{BootError, Result};
use crate::zfs::reader::io::read_block;
use crate::zfs::reader::objset::{objset_get_dnode, ObjsetPhys};
use crate::zfs::reader::types::Uberblock;
use crate::zfs::reader::zap::{zap_list, zap_lookup_u64_normalized};

const DMU_POOL_DIRECTORY_OBJECT: u64 = 1;
const DMU_POOL_ROOT_DATASET: &str = "root_dataset";
const DMU_POOL_PROPS: &str = "pool_props";
const DMU_POOL_BOOTFS: &str = "bootfs";

pub fn bootfs_objid(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    uber: &Uberblock,
) -> Result<Option<u64>> {
    let mos_data = read_block(block, media_id, block_size, &uber.rootbp)?;
    let mos = ObjsetPhys::from_bytes(&mos_data)?;
    let dir_dnode =
        objset_get_dnode(block, media_id, block_size, &mos, DMU_POOL_DIRECTORY_OBJECT)?;
    let props_obj = match zap_lookup_u64_normalized(block, media_id, block_size, &dir_dnode, DMU_POOL_PROPS) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let props_dnode = objset_get_dnode(block, media_id, block_size, &mos, props_obj)?;
    let bootfs = match zap_lookup_u64_normalized(block, media_id, block_size, &props_dnode, DMU_POOL_BOOTFS) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    if bootfs == 0 {
        Ok(None)
    } else {
        Ok(Some(bootfs))
    }
}

pub fn list_bootenvs(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    uber: &Uberblock,
) -> Result<Vec<String>> {
    let mos_data = read_block(block, media_id, block_size, &uber.rootbp)?;
    let mos = ObjsetPhys::from_bytes(&mos_data)?;
    let dir_dnode =
        objset_get_dnode(block, media_id, block_size, &mos, DMU_POOL_DIRECTORY_OBJECT)?;
    let root_dir_obj =
        zap_lookup_u64_normalized(block, media_id, block_size, &dir_dnode, DMU_POOL_ROOT_DATASET)?;
    let root_children = list_child_dirs(block, media_id, block_size, &mos, root_dir_obj)?;
    if root_children.iter().any(|name| name == "ROOT") {
        let dir_dnode = objset_get_dnode(block, media_id, block_size, &mos, root_dir_obj)?;
        let child_zap = parse_dsl_dir_child_zap(&dir_dnode)?;
        let child_dnode = objset_get_dnode(block, media_id, block_size, &mos, child_zap)?;
        let root_dir_obj =
            zap_lookup_u64_normalized(block, media_id, block_size, &child_dnode, "ROOT")?;
        let root_children = list_child_dirs(block, media_id, block_size, &mos, root_dir_obj)?;
        if !root_children.is_empty() {
            return Ok(root_children
                .into_iter()
                .map(|name| format!("ROOT/{}", name))
                .collect());
        }
    }
    Ok(root_children)
}

fn list_child_dirs(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    mos: &ObjsetPhys,
    dir_obj: u64,
) -> Result<Vec<String>> {
    let dir_dnode = objset_get_dnode(block, media_id, block_size, mos, dir_obj)?;
    let child_zap = parse_dsl_dir_child_zap(&dir_dnode)?;
    let child_dnode = objset_get_dnode(block, media_id, block_size, mos, child_zap)?;
    let names = zap_list(block, media_id, block_size, &child_dnode)?;
    Ok(names)
}
#[allow(dead_code)]
fn parse_dsl_dataset_dir(dnode: &crate::zfs::reader::dnode::DnodePhys) -> Result<u64> {
    if dnode.bonus.len() < 8 {
        return Err(BootError::InvalidData("dsl_dataset bonus too small"));
    }
    Ok(u64::from_le_bytes(dnode.bonus[0..8].try_into().unwrap()))
}

fn parse_dsl_dir_child_zap(dnode: &crate::zfs::reader::dnode::DnodePhys) -> Result<u64> {
    if dnode.bonus.len() < 40 {
        return Err(BootError::InvalidData("dsl_dir bonus too small"));
    }
    Ok(u64::from_le_bytes(dnode.bonus[32..40].try_into().unwrap()))
}
