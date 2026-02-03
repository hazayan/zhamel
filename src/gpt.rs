extern crate alloc;

use alloc::vec::Vec;

use crate::uefi_helpers::BlockDeviceInfo;
use uefi::boot;
use uefi::proto::media::block::BlockIO;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct GptPartition {
    pub index: u32,
    pub type_guid: [u8; 16],
    pub unique_guid: [u8; 16],
    pub first_lba: u64,
    pub last_lba: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GptPartitionKind {
    EfiSystem,
    FreeBsdUfs,
    FreeBsdZfs,
    Other,
}

#[derive(Debug, Clone)]
pub struct GptDisk {
    pub device: BlockDeviceInfo,
    pub partitions: Vec<GptPartition>,
}

pub struct GptMatch<'a> {
    pub disk_index: usize,
    pub partition: &'a GptPartition,
}

pub fn scan_gpt_disks(devices: &[BlockDeviceInfo]) -> Vec<GptDisk> {
    let mut disks = Vec::new();
    for device in devices {
        if device.logical_partition {
            continue;
        }
        let partitions = scan_partitions(device);
        disks.push(GptDisk {
            device: device.clone(),
            partitions,
        });
    }
    disks
}

pub fn find_partition_by_guid<'a>(
    disks: &'a [GptDisk],
    guid: [u8; 16],
) -> Option<GptMatch<'a>> {
    for (disk_index, disk) in disks.iter().enumerate() {
        for partition in &disk.partitions {
            if partition.unique_guid == guid {
                return Some(GptMatch {
                    disk_index,
                    partition,
                });
            }
        }
    }
    None
}

pub fn partition_kind(type_guid: [u8; 16]) -> GptPartitionKind {
    if type_guid == GPT_TYPE_EFI_SYSTEM {
        return GptPartitionKind::EfiSystem;
    }
    if type_guid == GPT_TYPE_FREEBSD_UFS {
        return GptPartitionKind::FreeBsdUfs;
    }
    if type_guid == GPT_TYPE_FREEBSD_ZFS {
        return GptPartitionKind::FreeBsdZfs;
    }
    GptPartitionKind::Other
}

fn scan_partitions(device: &BlockDeviceInfo) -> Vec<GptPartition> {
    let block = match boot::open_protocol_exclusive::<BlockIO>(device.handle) {
        Ok(block) => block,
        Err(err) => {
            log::warn!("gpt: open BlockIO failed: {:?}", err.status());
            return Vec::new();
        }
    };
    let media = block.media();
    let block_size = media.block_size() as usize;
    if block_size == 0 {
        return Vec::new();
    }
    let header = match read_lba(&block, media.media_id(), GPT_HEADER_LBA, block_size) {
        Some(buf) => buf,
        None => return Vec::new(),
    };
    let hdr = match parse_header(&header) {
        Some(hdr) => hdr,
        None => return Vec::new(),
    };

    let entry_bytes = hdr
        .num_entries
        .saturating_mul(hdr.entry_size as u64) as usize;
    let capped_entries = core::cmp::min(hdr.num_entries, GPT_ENTRY_LIMIT);
    if capped_entries != hdr.num_entries {
        log::warn!(
            "gpt: truncating entries {} -> {}",
            hdr.num_entries,
            capped_entries
        );
    }
    let capped_bytes = capped_entries as usize * hdr.entry_size as usize;
    let read_bytes = round_up(capped_bytes, block_size);

    let entries = match read_lba_bulk(
        &block,
        media.media_id(),
        hdr.entries_lba,
        block_size,
        read_bytes,
    ) {
        Some(buf) => buf,
        None => return Vec::new(),
    };

    let mut partitions = Vec::new();
    for idx in 0..capped_entries {
        let offset = idx as usize * hdr.entry_size as usize;
        let slice = &entries[offset..offset + hdr.entry_size as usize];
        if let Some(partition) = parse_partition(idx as u32 + 1, slice) {
            partitions.push(partition);
        }
    }

    if partitions.is_empty() && entry_bytes != 0 {
        log::warn!("gpt: no partitions detected");
    }

    partitions
}

fn parse_header(buf: &[u8]) -> Option<GptHeader> {
    if buf.len() < GPT_HEADER_MIN_SIZE {
        return None;
    }
    if &buf[0..8] != GPT_SIGNATURE {
        return None;
    }

    let header_size = le_u32(buf, 12)? as usize;
    if header_size < GPT_HEADER_MIN_SIZE {
        return None;
    }
    let entries_lba = le_u64(buf, 72)?;
    let num_entries = le_u32(buf, 80)? as u64;
    let entry_size = le_u32(buf, 84)? as usize;
    if entry_size < GPT_ENTRY_MIN_SIZE {
        return None;
    }

    Some(GptHeader {
        entries_lba,
        num_entries,
        entry_size: entry_size as u32,
    })
}

fn parse_partition(index: u32, buf: &[u8]) -> Option<GptPartition> {
    if buf.len() < GPT_ENTRY_MIN_SIZE {
        return None;
    }
    let mut type_guid = [0u8; 16];
    type_guid.copy_from_slice(&buf[0..16]);
    if type_guid.iter().all(|b| *b == 0) {
        return None;
    }
    let mut unique_guid = [0u8; 16];
    unique_guid.copy_from_slice(&buf[16..32]);
    let first_lba = le_u64(buf, 32)?;
    let last_lba = le_u64(buf, 40)?;
    Some(GptPartition {
        index,
        type_guid,
        unique_guid,
        first_lba,
        last_lba,
    })
}

fn read_lba(block: &BlockIO, media_id: u32, lba: u64, block_size: usize) -> Option<Vec<u8>> {
    let mut buf = alloc::vec![0u8; block_size];
    block.read_blocks(media_id, lba, &mut buf).ok()?;
    Some(buf)
}

fn read_lba_bulk(
    block: &BlockIO,
    media_id: u32,
    lba: u64,
    block_size: usize,
    bytes: usize,
) -> Option<Vec<u8>> {
    if bytes == 0 {
        return Some(Vec::new());
    }
    let mut buf = alloc::vec![0u8; bytes];
    if bytes % block_size != 0 {
        return None;
    }
    block.read_blocks(media_id, lba, &mut buf).ok()?;
    Some(buf)
}

fn le_u32(buf: &[u8], offset: usize) -> Option<u32> {
    if buf.len() < offset + 4 {
        return None;
    }
    Some(u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ]))
}

fn le_u64(buf: &[u8], offset: usize) -> Option<u64> {
    if buf.len() < offset + 8 {
        return None;
    }
    Some(u64::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
        buf[offset + 4],
        buf[offset + 5],
        buf[offset + 6],
        buf[offset + 7],
    ]))
}

fn round_up(value: usize, align: usize) -> usize {
    if align == 0 {
        return value;
    }
    let rem = value % align;
    if rem == 0 {
        value
    } else {
        value + (align - rem)
    }
}

struct GptHeader {
    entries_lba: u64,
    num_entries: u64,
    entry_size: u32,
}

const GPT_HEADER_LBA: u64 = 1;
const GPT_HEADER_MIN_SIZE: usize = 92;
pub(crate) const GPT_ENTRY_MIN_SIZE: usize = 128;
const GPT_ENTRY_LIMIT: u64 = 128;
const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";
const GPT_TYPE_EFI_SYSTEM: [u8; 16] = [
    0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11,
    0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
];
const GPT_TYPE_FREEBSD_UFS: [u8; 16] = [
    0x16, 0xFF, 0x9D, 0x6E, 0xC0, 0x8F, 0xD1, 0x11,
    0x8A, 0x3B, 0x00, 0xA0, 0xC9, 0x94, 0xA2, 0x4B,
];
const GPT_TYPE_FREEBSD_ZFS: [u8; 16] = [
    0x2F, 0xC7, 0x91, 0x8D, 0xCE, 0xC5, 0xD1, 0x11,
    0x88, 0x4F, 0x00, 0xA0, 0xC9, 0x5C, 0xB1, 0xB1,
];

#[cfg(test)]
pub(crate) fn test_parse_header_ok(buf: &[u8]) -> bool {
    parse_header(buf).is_some()
}

#[cfg(test)]
pub(crate) fn test_parse_partition_ok(index: u32, buf: &[u8]) -> bool {
    parse_partition(index, buf).is_some()
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    extern crate std;

    use super::{
        parse_header,
        parse_partition,
        partition_kind,
        GptPartitionKind,
        GPT_ENTRY_MIN_SIZE,
        GPT_SIGNATURE,
        GPT_TYPE_EFI_SYSTEM,
        GPT_TYPE_FREEBSD_UFS,
        GPT_TYPE_FREEBSD_ZFS,
    };

    #[test]
    fn test_parse_header_basic() {
        let mut buf = alloc::vec![0u8; 512];
        buf[0..8].copy_from_slice(GPT_SIGNATURE);
        buf[12..16].copy_from_slice(&92u32.to_le_bytes());
        buf[72..80].copy_from_slice(&2u64.to_le_bytes());
        buf[80..84].copy_from_slice(&128u32.to_le_bytes());
        buf[84..88].copy_from_slice(&128u32.to_le_bytes());

        let header = parse_header(&buf);
        assert!(header.is_some());
    }

    #[test]
    fn test_parse_partition_guid() {
        let mut buf = alloc::vec![0u8; GPT_ENTRY_MIN_SIZE];
        buf[0] = 0xAA;
        buf[16] = 0xBB;
        let part = parse_partition(1, &buf).expect("partition");
        assert_eq!(part.type_guid[0], 0xAA);
        assert_eq!(part.unique_guid[0], 0xBB);
    }

    #[test]
    fn test_partition_kind() {
        assert_eq!(partition_kind(GPT_TYPE_EFI_SYSTEM), GptPartitionKind::EfiSystem);
        assert_eq!(partition_kind(GPT_TYPE_FREEBSD_UFS), GptPartitionKind::FreeBsdUfs);
        assert_eq!(partition_kind(GPT_TYPE_FREEBSD_ZFS), GptPartitionKind::FreeBsdZfs);
        assert_eq!(partition_kind([0u8; 16]), GptPartitionKind::Other);
    }

}
