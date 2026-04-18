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

pub fn probe_iso9660(block: &BlockIO, media_id: u32, block_size: usize) -> Option<IsoVolume> {
    if block_size == 0 || ISO_SECTOR_SIZE % block_size != 0 {
        return None;
    }
    let buf = read_bytes(
        block,
        media_id,
        block_size,
        PVD_LBA * ISO_SECTOR_SIZE as u64,
        PVD_SIZE,
    )?;
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

pub fn file_size(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    volume: IsoVolume,
    path: &str,
) -> Option<usize> {
    let entry = find_entry(block, media_id, block_size, volume, path)?;
    if entry.flags & 0x02 != 0 {
        return None;
    }
    Some(entry.size as usize)
}

pub fn read_file_into(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    volume: IsoVolume,
    path: &str,
    dst: *mut u8,
    dst_len: usize,
) -> Option<usize> {
    let entry = find_entry(block, media_id, block_size, volume, path)?;
    if entry.flags & 0x02 != 0 {
        return None;
    }
    let size = entry.size as usize;
    if size > dst_len {
        return None;
    }
    let file_offset = entry.extent_lba as u64 * ISO_SECTOR_SIZE as u64;
    read_into(block, media_id, block_size, file_offset, dst, size)?;
    Some(size)
}

#[allow(dead_code)]
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
        let entries = read_directory(
            block,
            media_id,
            block_size,
            current.extent_lba,
            current.size,
        )?;
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
    let mut out = alloc::vec::Vec::with_capacity(len);
    // SAFETY: we fully overwrite every byte before returning.
    unsafe {
        out.set_len(len);
    }
    read_into(block, media_id, block_size, offset, out.as_mut_ptr(), len)?;
    Some(out)
}

fn read_into(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    offset: u64,
    dst: *mut u8,
    len: usize,
) -> Option<()> {
    // Dynamically size reads based on file size and media type.
    let mut max_blocks_per_read = compute_max_blocks_per_read(len, block_size, block);

    if len == 0 || block_size == 0 {
        return Some(());
    }
    let start_lba = offset / block_size as u64;
    let end = offset + len as u64;
    let end_lba = (end + block_size as u64 - 1) / block_size as u64;
    let mut blocks_left = end_lba.saturating_sub(start_lba) as usize;
    if blocks_left == 0 {
        return None;
    }
    let last_block = block.media().last_block();
    if end_lba == 0 || end_lba - 1 > last_block {
        log::warn!(
            "iso9660: read beyond media (start_lba=0x{:x} end_lba=0x{:x} last=0x{:x})",
            start_lba,
            end_lba.saturating_sub(1),
            last_block
        );
        return None;
    }
    let io_align = block.media().io_align() as usize;
    let max_chunk_size = max_blocks_per_read * block_size;
    let mut raw = alloc::vec![0u8; max_chunk_size + io_align.max(1)];
    let base = raw.as_mut_ptr() as usize;
    let align_off = if io_align <= 1 {
        0
    } else {
        (io_align - (base % io_align)) % io_align
    };
    if align_off + max_chunk_size > raw.len() {
        return None;
    }
    let mut out_offset = 0usize;
    let mut current_lba = start_lba;
    let mut start_skip = (offset % block_size as u64) as usize;
    let mut _chunk_index = 0usize;
    let _log_progress = false;

    while blocks_left > 0 {
        let mut chunk_blocks = core::cmp::min(blocks_left, max_blocks_per_read);
        let mut chunk_size = chunk_blocks * block_size;
        loop {
            let aligned = &mut raw[align_off..align_off + chunk_size];
            if let Err(err) = block.read_blocks(media_id, current_lba, aligned) {
                if chunk_blocks <= 1 {
                    log::warn!("iso9660: read_blocks failed: {:?}", err.status());
                    return None;
                }
                // Some firmware is sensitive to large transfer sizes; back off.
                chunk_blocks = core::cmp::max(1, chunk_blocks / 2);
                chunk_size = chunk_blocks * block_size;
                max_blocks_per_read = chunk_blocks;
                continue;
            }
            break;
        }
        let aligned = &mut raw[align_off..align_off + chunk_size];

        let chunk_start = start_skip;
        let mut chunk_end = chunk_size;
        if blocks_left == chunk_blocks {
            let end_off = ((offset + len as u64) - current_lba * block_size as u64) as usize;
            if end_off <= chunk_size {
                chunk_end = end_off;
            }
        }
        if chunk_end < chunk_start {
            return None;
        }
        let chunk_len = chunk_end - chunk_start;
        if out_offset + chunk_len > len {
            return None;
        }
        unsafe {
            core::ptr::copy_nonoverlapping(
                aligned.as_ptr().add(chunk_start),
                dst.add(out_offset),
                chunk_len,
            );
        }
        out_offset += chunk_len;

        _chunk_index += 1;

        current_lba = current_lba.saturating_add(chunk_blocks as u64);
        blocks_left -= chunk_blocks;
        start_skip = 0;
    }
    if out_offset != len {
        return None;
    }
    Some(())
}

fn compute_max_blocks_per_read(len: usize, block_size: usize, block: &BlockIO) -> usize {
    if block_size == 0 {
        return 1;
    }
    let min_bytes = 32 * 1024;
    let max_bytes = if block.media().is_removable_media() {
        16 * 1024 * 1024
    } else {
        4 * 1024 * 1024
    };
    let target_calls = if len >= 128 * 1024 * 1024 {
        16usize
    } else if len >= 32 * 1024 * 1024 {
        256usize
    } else {
        1024usize
    };
    let mut desired = if len <= min_bytes {
        len
    } else {
        len / target_calls
    };
    if desired < min_bytes {
        desired = min_bytes;
    }
    if desired > max_bytes {
        desired = max_bytes;
    }
    if desired < block_size {
        desired = block_size;
    }
    let blocks = desired / block_size;
    if blocks == 0 { 1 } else { blocks }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    extern crate std;

    use super::{normalize_name, parse_dir_record, parse_pvd};
    use alloc::vec::Vec;

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
