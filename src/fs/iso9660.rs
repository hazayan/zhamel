extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use uefi::proto::media::block::BlockIO;

const ISO_SECTOR_SIZE: usize = 2048;
const PVD_LBA: u64 = 16;
const PVD_SIZE: usize = ISO_SECTOR_SIZE;
const PVD_ID: &[u8; 5] = b"CD001";

#[derive(Debug, Clone, Copy)]
pub struct IsoVolume {
    root_lba: u32,
    root_size: u32,
}

#[derive(Debug, Clone)]
struct DirEntry {
    name: String,
    extent_lba: u32,
    size: u32,
    flags: u8,
}

pub fn probe_iso9660(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
) -> Option<IsoVolume> {
    if block_size == 0 || ISO_SECTOR_SIZE % block_size != 0 {
        return None;
    }
    let buf = read_bytes(block, media_id, block_size, PVD_LBA * ISO_SECTOR_SIZE as u64, PVD_SIZE)?;
    parse_pvd(&buf)
}

pub fn read_file(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    volume: IsoVolume,
    path: &str,
) -> Option<Vec<u8>> {
    let entry = find_entry(block, media_id, block_size, volume, path)?;
    if entry.flags & 0x02 != 0 {
        return None;
    }
    let offset = entry.extent_lba as u64 * ISO_SECTOR_SIZE as u64;
    read_bytes(block, media_id, block_size, offset, entry.size as usize)
}

pub fn read_dir_entries(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    volume: IsoVolume,
    path: &str,
) -> Option<Vec<String>> {
    let entry = find_entry(block, media_id, block_size, volume, path)?;
    if entry.flags & 0x02 == 0 {
        return None;
    }
    let entries = read_directory(block, media_id, block_size, entry.extent_lba, entry.size)?;
    let mut names = Vec::new();
    for entry in entries {
        if entry.name == "." || entry.name == ".." {
            continue;
        }
        names.push(normalize_name(&entry.name));
    }
    Some(names)
}

fn parse_pvd(buf: &[u8]) -> Option<IsoVolume> {
    if buf.len() < PVD_SIZE {
        return None;
    }
    if buf[0] != 0x01 || &buf[1..6] != PVD_ID || buf[6] != 0x01 {
        return None;
    }
    let root = parse_dir_record(buf, 156)?;
    Some(IsoVolume {
        root_lba: root.extent_lba,
        root_size: root.size,
    })
}

fn find_entry(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    volume: IsoVolume,
    path: &str,
) -> Option<DirEntry> {
    let mut current = DirEntry {
        name: String::from("/"),
        extent_lba: volume.root_lba,
        size: volume.root_size,
        flags: 0x02,
    };
    for part in path.split('/') {
        if part.is_empty() {
            continue;
        }
        if current.flags & 0x02 == 0 {
            return None;
        }
        let entries = read_directory(block, media_id, block_size, current.extent_lba, current.size)?;
        let needle = normalize_name(part);
        let mut found = None;
        for entry in entries {
            if normalize_name(&entry.name) == needle {
                found = Some(entry);
                break;
            }
        }
        current = found?;
    }
    Some(current)
}

fn read_directory(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    extent_lba: u32,
    size: u32,
) -> Option<Vec<DirEntry>> {
    let offset = extent_lba as u64 * ISO_SECTOR_SIZE as u64;
    let buf = read_bytes(block, media_id, block_size, offset, size as usize)?;
    let mut entries = Vec::new();
    let mut idx = 0usize;
    while idx < buf.len() {
        let len = buf[idx] as usize;
        if len == 0 {
            let next = ((idx / ISO_SECTOR_SIZE) + 1) * ISO_SECTOR_SIZE;
            if next <= idx {
                break;
            }
            idx = next;
            continue;
        }
        if idx + len > buf.len() {
            break;
        }
        if let Some(entry) = parse_dir_record(&buf, idx) {
            entries.push(entry);
        }
        idx += len;
    }
    Some(entries)
}

fn parse_dir_record(buf: &[u8], offset: usize) -> Option<DirEntry> {
    if buf.len() < offset + 34 {
        return None;
    }
    let len = buf[offset] as usize;
    if len < 34 || buf.len() < offset + len {
        return None;
    }
    let extent_lba = u32::from_le_bytes([
        buf[offset + 2],
        buf[offset + 3],
        buf[offset + 4],
        buf[offset + 5],
    ]);
    let size = u32::from_le_bytes([
        buf[offset + 10],
        buf[offset + 11],
        buf[offset + 12],
        buf[offset + 13],
    ]);
    let flags = buf[offset + 25];
    let name_len = buf[offset + 32] as usize;
    let name_off = offset + 33;
    if buf.len() < name_off + name_len {
        return None;
    }
    let name_bytes = &buf[name_off..name_off + name_len];
    let name = if name_len == 1 && name_bytes[0] == 0 {
        ".".to_string()
    } else if name_len == 1 && name_bytes[0] == 1 {
        "..".to_string()
    } else {
        String::from_utf8_lossy(name_bytes).to_string()
    };
    Some(DirEntry {
        name,
        extent_lba,
        size,
        flags,
    })
}

fn normalize_name(name: &str) -> String {
    let mut upper = name.to_ascii_uppercase();
    if let Some(idx) = upper.rfind(";1") {
        if idx + 2 == upper.len() {
            upper.truncate(idx);
        }
    }
    if upper.ends_with('.') {
        upper.pop();
    }
    upper
}

fn read_bytes(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    offset: u64,
    len: usize,
) -> Option<Vec<u8>> {
    if len == 0 || block_size == 0 {
        return Some(Vec::new());
    }
    let start_lba = offset / block_size as u64;
    let end = offset + len as u64;
    let end_lba = (end + block_size as u64 - 1) / block_size as u64;
    let blocks = end_lba.saturating_sub(start_lba) as usize;
    if blocks == 0 {
        return None;
    }
    let mut buf = alloc::vec![0u8; blocks * block_size];
    block.read_blocks(media_id, start_lba, &mut buf).ok()?;
    let start_off = (offset % block_size as u64) as usize;
    let end_off = start_off + len;
    if end_off > buf.len() {
        return None;
    }
    Some(buf[start_off..end_off].to_vec())
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    extern crate std;

    use alloc::vec::Vec;
    use super::{normalize_name, parse_dir_record, parse_pvd};

    fn make_dir_record(name: &str, extent_lba: u32, size: u32, flags: u8) -> Vec<u8> {
        let name_bytes = name.as_bytes();
        let len = 33 + name_bytes.len();
        let mut buf = alloc::vec![0u8; len];
        buf[0] = len as u8;
        buf[2..6].copy_from_slice(&extent_lba.to_le_bytes());
        buf[10..14].copy_from_slice(&size.to_le_bytes());
        buf[25] = flags;
        buf[32] = name_bytes.len() as u8;
        buf[33..33 + name_bytes.len()].copy_from_slice(name_bytes);
        buf
    }

    #[test]
    fn test_parse_pvd() {
        let mut buf = alloc::vec![0u8; 2048];
        buf[0] = 1;
        buf[1..6].copy_from_slice(b"CD001");
        buf[6] = 1;
        let record = make_dir_record("\0", 20, 4096, 0x02);
        buf[156..156 + record.len()].copy_from_slice(&record);
        let vol = parse_pvd(&buf).expect("pvd");
        assert_eq!(vol.root_lba, 20);
        assert_eq!(vol.root_size, 4096);
    }

    #[test]
    fn test_parse_dir_record_name() {
        let record = make_dir_record("BOOT", 5, 128, 0);
        let entry = parse_dir_record(&record, 0).expect("entry");
        assert_eq!(entry.name, "BOOT");
        assert_eq!(entry.extent_lba, 5);
        assert_eq!(entry.size, 128);
        assert_eq!(entry.flags, 0);
    }

    #[test]
    fn test_normalize_name() {
        assert_eq!(normalize_name("kernel;1"), "KERNEL");
        assert_eq!(normalize_name("FOO."), "FOO");
        assert_eq!(normalize_name("boot"), "BOOT");
    }
}
