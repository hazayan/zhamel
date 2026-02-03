extern crate alloc;

use alloc::vec::Vec;

use crate::gpt::GptDisk;
use crate::mbr::parse_mbr;
use crate::uefi_helpers::BlockDeviceInfo;
use uefi::boot;
use uefi::proto::media::block::BlockIO;

#[derive(Debug, Clone)]
pub struct UfsVolume {
    pub disk_index: usize,
    pub partition_index: u32,
    pub kind: UfsKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UfsKind {
    Ufs1,
    Ufs2,
}

pub fn probe_from_gpt(disks: &[GptDisk]) -> Vec<UfsVolume> {
    let mut volumes = Vec::new();
    for (disk_index, disk) in disks.iter().enumerate() {
        if disk.device.io_align > 1 {
            log::warn!("skip disk with io_align {}", disk.device.io_align);
            continue;
        }
        let block = match boot::open_protocol_exclusive::<BlockIO>(disk.device.handle) {
            Ok(block) => block,
            Err(err) => {
                log::warn!("ufs: open BlockIO failed: {:?}", err.status());
                continue;
            }
        };
        let media = block.media();
        let block_size = media.block_size() as usize;
        if block_size == 0 {
            continue;
        }
        for partition in &disk.partitions {
            if let Some(kind) = probe_partition(&block, media.media_id(), block_size, partition) {
                volumes.push(UfsVolume {
                    disk_index,
                    partition_index: partition.index,
                    kind,
                });
            }
        }
    }
    volumes
}

pub fn probe_from_mbr(devices: &[BlockDeviceInfo]) -> Vec<UfsVolume> {
    let mut volumes = Vec::new();
    for (disk_index, device) in devices.iter().enumerate() {
        if device.logical_partition {
            continue;
        }
        if device.io_align > 1 {
            log::warn!("skip disk with io_align {}", device.io_align);
            continue;
        }
        let block = match boot::open_protocol_exclusive::<BlockIO>(device.handle) {
            Ok(block) => block,
            Err(err) => {
                log::warn!("ufs: open BlockIO failed: {:?}", err.status());
                continue;
            }
        };
        let media = block.media();
        let block_size = media.block_size() as usize;
        if block_size == 0 {
            continue;
        }
        let mbr = match read_at(&block, media.media_id(), block_size, 0, block_size) {
            Some(buf) => buf,
            None => continue,
        };
        let Some(parts) = parse_mbr(&mbr) else {
            continue;
        };
        for part in parts {
            let kind = probe_partition_at_lba(
                &block,
                media.media_id(),
                block_size,
                part.first_lba as u64,
            );
            if let Some(kind) = kind {
                volumes.push(UfsVolume {
                    disk_index,
                    partition_index: part.index as u32,
                    kind,
                });
            }
        }
    }
    volumes
}

pub fn probe_raw_devices(devices: &[BlockDeviceInfo]) -> Vec<UfsVolume> {
    let mut volumes = Vec::new();
    for (idx, device) in devices.iter().enumerate() {
        if device.logical_partition {
            continue;
        }
        match probe_device(device) {
            Some(kind) => volumes.push(UfsVolume {
                disk_index: idx,
                partition_index: 0,
                kind,
            }),
            None => {}
        }
    }
    volumes
}

pub fn probe_by_partition_guid(disks: &[GptDisk], guid: [u8; 16]) -> Option<UfsVolume> {
    let match_info = crate::gpt::find_partition_by_guid(disks, guid)?;
    let disk = &disks[match_info.disk_index];
    if disk.device.io_align > 1 {
        log::warn!("skip disk with io_align {}", disk.device.io_align);
        return None;
    }
    let block = boot::open_protocol_exclusive::<BlockIO>(disk.device.handle).ok()?;
    let media = block.media();
    let block_size = media.block_size() as usize;
    if block_size == 0 {
        return None;
    }
    let kind = probe_partition(&block, media.media_id(), block_size, match_info.partition)?;
    Some(UfsVolume {
        disk_index: match_info.disk_index,
        partition_index: match_info.partition.index,
        kind,
    })
}

fn probe_device(device: &BlockDeviceInfo) -> Option<UfsKind> {
    if device.io_align > 1 {
        log::warn!("skip device with io_align {}", device.io_align);
        return None;
    }
    let block = boot::open_protocol_exclusive::<BlockIO>(device.handle).ok()?;
    let media = block.media();
    let block_size = media.block_size() as usize;

    for &offset in SBLOCK_OFFSETS.iter() {
        if offset as usize % block_size != 0 {
            continue;
        }
        let buf = read_at(&block, media.media_id(), block_size, offset, SBLOCKSIZE)?;
        if let Some(kind) = parse_superblock(&buf, offset) {
            return Some(kind);
        }
    }
    None
}

fn probe_partition(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    partition: &crate::gpt::GptPartition,
) -> Option<UfsKind> {
    probe_partition_at_lba(block, media_id, block_size, partition.first_lba)
}

fn probe_partition_at_lba(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    first_lba: u64,
) -> Option<UfsKind> {
    let base = first_lba * block_size as u64;
    for &offset in SBLOCK_OFFSETS.iter() {
        if offset as usize % block_size != 0 {
            continue;
        }
        let sblock_loc = base + offset;
        let buf = read_at(block, media_id, block_size, sblock_loc, SBLOCKSIZE)?;
        if let Some(kind) = parse_superblock(&buf, sblock_loc) {
            return Some(kind);
        }
    }
    None
}

fn read_at(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    offset: u64,
    size: usize,
) -> Option<Vec<u8>> {
    if size % block_size != 0 {
        return None;
    }
    let lba = offset / block_size as u64;
    let mut buf = alloc::vec![0u8; size];
    block.read_blocks(media_id, lba, &mut buf).ok()?;
    Some(buf)
}

fn parse_superblock(buf: &[u8], sblock_loc: u64) -> Option<UfsKind> {
    if buf.len() < FS_MAGIC_OFFSET + 4 {
        return None;
    }
    let magic = u32::from_le_bytes([
        buf[FS_MAGIC_OFFSET],
        buf[FS_MAGIC_OFFSET + 1],
        buf[FS_MAGIC_OFFSET + 2],
        buf[FS_MAGIC_OFFSET + 3],
    ]);
    match magic {
        FS_UFS1_MAGIC => Some(UfsKind::Ufs1),
        FS_UFS2_MAGIC => {
            if validate_sblockloc(buf, sblock_loc) {
                Some(UfsKind::Ufs2)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn validate_sblockloc(buf: &[u8], expected: u64) -> bool {
    let offset = core::mem::offset_of!(FsHeader, fs_sblockloc);
    if buf.len() < offset + 8 {
        return false;
    }
    let value = i64::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
        buf[offset + 4],
        buf[offset + 5],
        buf[offset + 6],
        buf[offset + 7],
    ]);
    if value < 0 {
        return false;
    }
    value as u64 == expected
}

pub(crate) const SBLOCKSIZE: usize = 8192;
pub(crate) const SBLOCK_OFFSETS: [u64; 4] = [65536, 8192, 0, 262144];
pub(crate) const FS_MAGIC_OFFSET: usize = 1372;
pub(crate) const FS_UFS1_MAGIC: u32 = 0x011954;
pub(crate) const FS_UFS2_MAGIC: u32 = 0x19540119;

const MAXMNTLEN: usize = 468;
const MAXVOLLEN: usize = 32;
const NOCSPTRS: usize = (128 / core::mem::size_of::<u64>()) - 1;

#[repr(C)]
struct Csum {
    _cs_ndir: i32,
    _cs_nbfree: i32,
    _cs_nifree: i32,
    _cs_nffree: i32,
}

#[repr(C)]
struct CsumTotal {
    _cs_ndir: i64,
    _cs_nbfree: i64,
    _cs_nifree: i64,
    _cs_nffree: i64,
    _cs_numclusters: i64,
    _cs_spare: [i64; 3],
}

type UfsTime = i64;
type Ufs2Daddr = i64;

#[repr(C)]
pub(crate) struct FsHeader {
    _fs_firstfield: i32,
    _fs_unused_1: i32,
    _fs_sblkno: i32,
    _fs_cblkno: i32,
    _fs_iblkno: i32,
    _fs_dblkno: i32,
    _fs_old_cgoffset: i32,
    _fs_old_cgmask: i32,
    _fs_old_time: i32,
    _fs_old_size: i32,
    _fs_old_dsize: i32,
    _fs_ncg: u32,
    _fs_bsize: i32,
    _fs_fsize: i32,
    _fs_frag: i32,
    _fs_minfree: i32,
    _fs_old_rotdelay: i32,
    _fs_old_rps: i32,
    _fs_bmask: i32,
    _fs_fmask: i32,
    _fs_bshift: i32,
    _fs_fshift: i32,
    _fs_maxcontig: i32,
    _fs_maxbpg: i32,
    _fs_fragshift: i32,
    _fs_fsbtodb: i32,
    _fs_sbsize: i32,
    _fs_spare1: [i32; 2],
    _fs_nindir: i32,
    _fs_inopb: u32,
    _fs_old_nspf: i32,
    _fs_optim: i32,
    _fs_old_npsect: i32,
    _fs_old_interleave: i32,
    _fs_old_trackskew: i32,
    _fs_id: [i32; 2],
    _fs_old_csaddr: i32,
    _fs_cssize: i32,
    _fs_cgsize: i32,
    _fs_spare2: i32,
    _fs_old_nsect: i32,
    _fs_old_spc: i32,
    _fs_old_ncyl: i32,
    _fs_old_cpg: i32,
    _fs_ipg: u32,
    _fs_fpg: i32,
    _fs_old_cstotal: Csum,
    _fs_fmod: i8,
    _fs_clean: i8,
    _fs_ronly: i8,
    _fs_old_flags: i8,
    _fs_fsmnt: [u8; MAXMNTLEN],
    _fs_volname: [u8; MAXVOLLEN],
    _fs_swuid: u64,
    _fs_pad: i32,
    _fs_cgrotor: i32,
    _fs_ocsp: [u64; NOCSPTRS],
    _fs_si: u64,
    _fs_old_cpc: i32,
    _fs_maxbsize: i32,
    _fs_unrefs: i64,
    _fs_providersize: i64,
    _fs_metaspace: i64,
    _fs_save_maxfilesize: u64,
    _fs_sparecon64: [i64; 12],
    _fs_sblockactualloc: i64,
    fs_sblockloc: i64,
    _fs_cstotal: CsumTotal,
    _fs_time: UfsTime,
    _fs_size: i64,
    _fs_dsize: i64,
    _fs_csaddr: Ufs2Daddr,
    _fs_pendingblocks: i64,
    _fs_pendinginodes: u32,
    _fs_snapinum: [u32; 20],
    _fs_avgfilesize: u32,
    _fs_avgfpdir: u32,
    _fs_available_spare: u32,
    _fs_mtime: UfsTime,
    _fs_sujfree: i32,
    _fs_sparecon32: [i32; 21],
    _fs_ckhash: u32,
    _fs_metackhash: u32,
    _fs_flags: i32,
    _fs_contigsumsize: i32,
    _fs_maxsymlinklen: i32,
    _fs_old_inodefmt: i32,
    _fs_maxfilesize: u64,
    _fs_qbmask: i64,
    _fs_qfmask: i64,
    _fs_state: i32,
    _fs_old_postblformat: i32,
    _fs_old_nrpos: i32,
    _fs_spare5: [i32; 2],
    _fs_magic: i32,
}

#[allow(dead_code)]
pub(crate) const FS_SBLOCKLOC_OFFSET: usize = core::mem::offset_of!(FsHeader, fs_sblockloc);

#[cfg(test)]
pub(crate) fn test_parse_superblock(buf: &[u8], sblock_loc: u64) -> Option<UfsKind> {
    parse_superblock(buf, sblock_loc)
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    extern crate std;

    use super::{
        parse_superblock, probe_from_gpt, FsHeader, SBLOCKSIZE, SBLOCK_OFFSETS, FS_MAGIC_OFFSET,
        FS_SBLOCKLOC_OFFSET, FS_UFS1_MAGIC, FS_UFS2_MAGIC, UfsKind,
    };

    fn apply_fixture(text: &str, size: usize) -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec![0u8; size];
        let mut offset: usize = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(label) = line.strip_prefix('@') {
                let label = label.trim();
                offset = match label {
                    "magic" => FS_MAGIC_OFFSET,
                    "sblockloc" => FS_SBLOCKLOC_OFFSET,
                    other => {
                        if let Some(hex) = other.strip_prefix("0x") {
                            usize::from_str_radix(hex, 16).expect("offset hex")
                        } else {
                            other.parse::<usize>().expect("offset decimal")
                        }
                    }
                };
                continue;
            }
            for token in line.split_whitespace() {
                let byte = u8::from_str_radix(token, 16).expect("hex byte");
                if offset >= buf.len() {
                    panic!("fixture write out of range");
                }
                buf[offset] = byte;
                offset += 1;
            }
        }
        buf
    }

    #[test]
    fn test_probe_from_gpt_empty() {
        let volumes = probe_from_gpt(&[]);
        assert!(volumes.is_empty());
    }

    #[test]
    fn test_parse_superblock_magic() {
        let mut buf = alloc::vec![0u8; SBLOCKSIZE];
        buf[FS_MAGIC_OFFSET..FS_MAGIC_OFFSET + 4].copy_from_slice(&FS_UFS2_MAGIC.to_le_bytes());
        let offset = core::mem::offset_of!(FsHeader, fs_sblockloc);
        buf[offset..offset + 8].copy_from_slice(&SBLOCK_OFFSETS[0].to_le_bytes());
        let kind = parse_superblock(&buf, SBLOCK_OFFSETS[0]);
        assert_eq!(kind, Some(UfsKind::Ufs2));
    }

    #[test]
    fn test_parse_superblock_invalid_sblockloc() {
        let mut buf = alloc::vec![0u8; SBLOCKSIZE];
        buf[FS_MAGIC_OFFSET..FS_MAGIC_OFFSET + 4].copy_from_slice(&FS_UFS2_MAGIC.to_le_bytes());
        let offset = core::mem::offset_of!(FsHeader, fs_sblockloc);
        buf[offset..offset + 8].copy_from_slice(&SBLOCK_OFFSETS[0].to_le_bytes());
        let kind = parse_superblock(&buf, SBLOCK_OFFSETS[1]);
        assert_eq!(kind, None);
    }

    #[test]
    fn test_parse_superblock_ufs1() {
        let mut buf = alloc::vec![0u8; SBLOCKSIZE];
        buf[FS_MAGIC_OFFSET..FS_MAGIC_OFFSET + 4].copy_from_slice(&FS_UFS1_MAGIC.to_le_bytes());
        let kind = parse_superblock(&buf, SBLOCK_OFFSETS[1]);
        assert_eq!(kind, Some(UfsKind::Ufs1));
    }

    #[test]
    fn test_fixture_ufs2_superblock() {
        let fixture = include_str!("fixtures/ufs2-superblock.fixture");
        let buf = apply_fixture(fixture, SBLOCKSIZE);
        let kind = parse_superblock(&buf, SBLOCK_OFFSETS[0]);
        assert_eq!(kind, Some(UfsKind::Ufs2));
    }

    #[test]
    fn test_fixture_ufs1_superblock() {
        let fixture = include_str!("fixtures/ufs1-superblock.fixture");
        let buf = apply_fixture(fixture, SBLOCKSIZE);
        let kind = parse_superblock(&buf, SBLOCK_OFFSETS[1]);
        assert_eq!(kind, Some(UfsKind::Ufs1));
    }
}
