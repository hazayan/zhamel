extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::gpt::GptDisk;
use crate::mbr::parse_mbr;
use crate::uefi_helpers::block_io::{
    find_block_handle_by_device_path_exact, find_block_handle_by_device_path_prefix, open_block_io,
};
use crate::uefi_helpers::device_path::device_path_bytes_for_handle;
use crate::uefi_helpers::{BlockDeviceInfo, find_partition_handle_by_guid};
use core::sync::atomic::{AtomicUsize, Ordering};
use uefi::boot::{self, ScopedProtocol};
use uefi::proto::media::block::BlockIO;
use uefi::{Handle, Status};

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
        let block = match open_block_io(disk.device.handle) {
            Ok(block) => block,
            Err(err) => {
                log::warn!("ufs: open BlockIO failed: {:?}", err.status());
                continue;
            }
        };
        let media = block.media();
        if !media.is_media_present() {
            continue;
        }
        let block_size = media.block_size() as usize;
        if block_size == 0 {
            continue;
        }
        for partition in &disk.partitions {
            if let Some(kind) =
                probe_partition_at_lba(&block, media.media_id(), block_size, partition.first_lba)
            {
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
        let block = match open_block_io(device.handle) {
            Ok(block) => block,
            Err(err) => {
                log::warn!("ufs: open BlockIO failed: {:?}", err.status());
                continue;
            }
        };
        let media = block.media();
        if !media.is_media_present() {
            continue;
        }
        let block_size = media.block_size() as usize;
        if block_size == 0 {
            continue;
        }
        let mbr = match read_raw(
            &block,
            media.media_id(),
            block_size,
            media.io_align() as usize,
            media.last_block(),
            0,
            block_size,
        ) {
            Some(buf) => buf,
            None => continue,
        };
        let Some(parts) = parse_mbr(&mbr) else {
            continue;
        };
        for part in parts {
            let kind =
                probe_partition_at_lba(&block, media.media_id(), block_size, part.first_lba as u64);
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
        if let Some(kind) = probe_device(device) {
            volumes.push(UfsVolume {
                disk_index: idx,
                partition_index: 0,
                kind,
            });
        }
    }
    volumes
}

pub fn probe_by_partition_guid(disks: &[GptDisk], guid: [u8; 16]) -> Option<UfsVolume> {
    let match_info = crate::gpt::find_partition_by_guid(disks, guid)?;
    if let Some(handle) = find_partition_handle_by_guid(guid) {
        if let Some(kind) = probe_partition_handle(handle) {
            return Some(UfsVolume {
                disk_index: match_info.disk_index,
                partition_index: match_info.partition.index,
                kind,
            });
        }
    }
    let disk = &disks[match_info.disk_index];
    let block = open_block_io(disk.device.handle).ok()?;
    let media = block.media();
    if !media.is_media_present() {
        return None;
    }
    let block_size = media.block_size() as usize;
    if block_size == 0 {
        return None;
    }
    let kind = probe_partition_at_lba(
        &block,
        media.media_id(),
        block_size,
        match_info.partition.first_lba,
    )?;
    Some(UfsVolume {
        disk_index: match_info.disk_index,
        partition_index: match_info.partition.index,
        kind,
    })
}

pub fn read_file_from_handle(handle: Handle, path: &str) -> Option<Vec<u8>> {
    let mut reader = match UfsReader::new(handle) {
        Some(reader) => reader,
        None => {
            log::warn!("ufs: reader init failed for {}", path);
            return None;
        }
    };
    reader.read_file(path)
}

pub fn read_dir_entries_from_handle(handle: Handle, path: &str) -> Option<Vec<String>> {
    let mut reader = UfsReader::new(handle)?;
    reader.read_dir_entries(path)
}

pub fn read_file_from_partition(
    handle: Handle,
    first_lba: u64,
    last_lba: u64,
    path: &str,
) -> Option<Vec<u8>> {
    let mut reader = match UfsReader::new_with_bounds(handle, first_lba, last_lba) {
        Some(reader) => reader,
        None => {
            log::warn!("ufs: reader init failed for {}", path);
            return None;
        }
    };
    reader.read_file(path)
}

pub fn read_dir_entries_from_partition(
    handle: Handle,
    first_lba: u64,
    last_lba: u64,
    path: &str,
) -> Option<Vec<String>> {
    let mut reader = UfsReader::new_with_bounds(handle, first_lba, last_lba)?;
    reader.read_dir_entries(path)
}

pub fn file_size_from_partition(
    handle: Handle,
    first_lba: u64,
    last_lba: u64,
    path: &str,
) -> Option<usize> {
    let mut reader = UfsReader::new_with_bounds(handle, first_lba, last_lba)?;
    let inode = reader.lookup_path(path)?;
    if is_dir(inode.mode) {
        return None;
    }
    usize::try_from(inode.size).ok()
}

pub fn read_file_from_partition_into(
    handle: Handle,
    first_lba: u64,
    last_lba: u64,
    path: &str,
    dst: *mut u8,
    size: usize,
) -> Option<()> {
    let mut reader = UfsReader::new_with_bounds(handle, first_lba, last_lba)?;
    reader.read_file_into(path, dst, size)
}

struct UfsDevice {
    block: ScopedProtocol<BlockIO>,
    media_id: u32,
    block_size: usize,
    io_align: usize,
    last_block: u64,
    base_offset: u64,
}

impl UfsDevice {
    fn new(handle: Handle) -> Option<Self> {
        let block = match open_block_io(handle) {
            Ok(block) => block,
            Err(err) => {
                log::warn!("ufs: open BlockIO failed: {:?}", err.status());
                if err.status() == Status::INVALID_PARAMETER {
                    if let Ok(block) = boot::open_protocol_exclusive::<BlockIO>(handle) {
                        log::warn!("ufs: BlockIO opened exclusive on original handle");
                        block
                    } else {
                        let alt = device_path_bytes_for_handle(handle).and_then(|bytes| {
                            find_block_handle_by_device_path_exact(&bytes)
                                .or_else(|| find_block_handle_by_device_path_prefix(&bytes))
                        });
                        if let Some(alt) = alt {
                            match open_block_io(alt) {
                                Ok(block) => {
                                    log::warn!("ufs: recovered BlockIO via device path match");
                                    block
                                }
                                Err(err) => {
                                    if err.status() == Status::INVALID_PARAMETER {
                                        if let Ok(block) =
                                            boot::open_protocol_exclusive::<BlockIO>(alt)
                                        {
                                            log::warn!(
                                                "ufs: BlockIO opened exclusive via device path match"
                                            );
                                            block
                                        } else {
                                            log::warn!(
                                                "ufs: BlockIO retry failed: {:?}",
                                                err.status()
                                            );
                                            return None;
                                        }
                                    } else {
                                        log::warn!("ufs: BlockIO retry failed: {:?}", err.status());
                                        return None;
                                    }
                                }
                            }
                        } else {
                            return None;
                        }
                    }
                } else {
                    return None;
                }
            }
        };
        let (media_id, block_size, io_align, last_block) = {
            let media = block.media();
            if !media.is_media_present() {
                log::warn!("ufs: media not present");
                return None;
            }
            let block_size = media.block_size() as usize;
            if block_size == 0 {
                log::warn!("ufs: block size is zero");
                return None;
            }
            (
                media.media_id(),
                block_size,
                media.io_align() as usize,
                media.last_block(),
            )
        };
        Some(UfsDevice {
            block,
            media_id,
            block_size,
            io_align: if io_align == 0 { 1 } else { io_align },
            last_block,
            base_offset: 0,
        })
    }

    fn new_with_bounds(handle: Handle, first_lba: u64, last_lba: u64) -> Option<Self> {
        let mut device = UfsDevice::new(handle)?;
        if first_lba > last_lba {
            log::warn!("ufs: invalid partition bounds {}..{}", first_lba, last_lba);
            return None;
        }
        if last_lba > device.last_block {
            log::warn!(
                "ufs: partition end {} beyond disk last {}",
                last_lba,
                device.last_block
            );
            return None;
        }
        device.base_offset = match first_lba.checked_mul(device.block_size as u64) {
            Some(value) => value,
            None => {
                log::warn!("ufs: partition base offset overflow");
                return None;
            }
        };
        device.last_block = last_lba;
        Some(device)
    }

    fn read_at(&mut self, offset: u64, size: usize) -> Option<Vec<u8>> {
        let offset = self.base_offset.checked_add(offset)?;
        read_raw(
            &self.block,
            self.media_id,
            self.block_size,
            self.io_align,
            self.last_block,
            offset,
            size,
        )
    }
}

struct UfsReader {
    device: UfsDevice,
    fs: UfsFs,
}

impl UfsReader {
    fn new(handle: Handle) -> Option<Self> {
        let mut device = UfsDevice::new(handle)?;
        let fs = match read_superblock(&mut device) {
            Some(fs) => fs,
            None => {
                log::warn!("ufs: superblock not found");
                return None;
            }
        };
        log::info!(
            "ufs: superblock ok kind={:?} bsize={} fsize={} ipg={} fpg={}",
            fs.kind,
            fs.bsize,
            fs.fsize,
            fs.ipg,
            fs.fpg
        );
        Some(UfsReader { device, fs })
    }

    fn new_with_bounds(handle: Handle, first_lba: u64, last_lba: u64) -> Option<Self> {
        let mut device = UfsDevice::new_with_bounds(handle, first_lba, last_lba)?;
        let fs = match read_superblock(&mut device) {
            Some(fs) => fs,
            None => {
                log::warn!("ufs: superblock not found");
                return None;
            }
        };
        log::info!(
            "ufs: superblock ok kind={:?} bsize={} fsize={} ipg={} fpg={}",
            fs.kind,
            fs.bsize,
            fs.fsize,
            fs.ipg,
            fs.fpg
        );
        Some(UfsReader { device, fs })
    }

    fn read_file(&mut self, path: &str) -> Option<Vec<u8>> {
        let inode = self.lookup_path(path)?;
        if is_dir(inode.mode) {
            log::warn!("ufs: path is directory: {}", path);
            return None;
        }
        let mut file = UfsFile::new(inode);
        file.debug_name = Some(path.to_string());
        let size = file.size() as usize;
        if size >= UFS_PROGRESS_THRESHOLD {
            log::info!("ufs: reading {} ({} bytes)", path, size);
            file.debug_steps_left = UFS_DEBUG_STEPS;
        }
        let bytes = self.read_all(&mut file);
        if bytes.is_none() {
            log::warn!("ufs: read_all failed: {}", path);
        }
        bytes
    }

    fn read_file_into(&mut self, path: &str, dst: *mut u8, size: usize) -> Option<()> {
        let inode = self.lookup_path(path)?;
        if is_dir(inode.mode) {
            log::warn!("ufs: path is directory: {}", path);
            return None;
        }
        let total = usize::try_from(inode.size).ok()?;
        if size < total {
            log::warn!(
                "ufs: read_into buffer too small: {} < {} ({})",
                size,
                total,
                path
            );
            return None;
        }
        let mut file = UfsFile::new(inode);
        file.debug_name = Some(path.to_string());
        if total >= UFS_PROGRESS_THRESHOLD {
            log::info!("ufs: reading {} ({} bytes)", path, total);
            file.debug_steps_left = UFS_DEBUG_STEPS;
        }
        self.read_into(&mut file, dst, total)
    }

    fn read_dir_entries(&mut self, path: &str) -> Option<Vec<String>> {
        let inode = self.lookup_path(path)?;
        if !is_dir(inode.mode) {
            return None;
        }
        let mut file = UfsFile::new(inode);
        let mut entries = Vec::new();
        let oldfmt = self.fs.old_dirfmt();
        while file.seekp < file.size() {
            let (start, end) = self.buf_read_file(&mut file)?;
            let size = end.saturating_sub(start);
            if size < 8 {
                return None;
            }
            let buf = &file.buf[start..end];
            let d_ino = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
            let d_reclen = u16::from_le_bytes([buf[4], buf[5]]) as usize;
            let d_type = buf[6];
            let d_namlen = buf[7] as usize;
            let namlen = if oldfmt { d_type as usize } else { d_namlen };
            if d_reclen == 0 || d_reclen > size {
                return None;
            }
            if d_ino != 0 && namlen > 0 && 8 + namlen <= d_reclen && d_reclen <= size {
                let name = &buf[8..8 + namlen];
                if name != b"." && name != b".." {
                    if oldfmt || d_type == DT_REG || d_type == DT_UNKNOWN {
                        entries.push(String::from_utf8_lossy(name).into_owned());
                    }
                }
            }
            file.seekp = file.seekp.saturating_add(d_reclen as u64);
        }
        Some(entries)
    }

    fn lookup_path(&mut self, path: &str) -> Option<UfsInode> {
        let mut nlinks = 0usize;
        let mut current_ino = UFS_ROOTINO;
        let mut inode = self.read_inode(current_ino)?;
        let mut path = normalize_path(path);
        loop {
            while path.starts_with('/') {
                path.remove(0);
            }
            if path.is_empty() {
                return Some(inode);
            }
            let (component, rest) = split_first_component(&path);
            if component.is_empty() {
                path = rest.to_string();
                continue;
            }
            if component.len() > UFS_MAXNAMLEN {
                log::warn!("ufs: component too long: {}", component);
                return None;
            }
            if !is_dir(inode.mode) {
                log::warn!("ufs: component not a directory: {}", component);
                return None;
            }
            let parent_ino = current_ino;
            current_ino = match self.search_directory(&inode, component) {
                Some(ino) => ino,
                None => {
                    log::warn!("ufs: component not found: {}", component);
                    return None;
                }
            };
            inode = self.read_inode(current_ino)?;
            if is_symlink(inode.mode) {
                nlinks += 1;
                if nlinks > MAXSYMLINKS {
                    log::warn!("ufs: too many symlinks");
                    return None;
                }
                let link = match self.read_link(&inode) {
                    Some(link) => link,
                    None => {
                        log::warn!("ufs: symlink read failed");
                        return None;
                    }
                };
                let mut new_path = String::new();
                if link.starts_with('/') {
                    current_ino = UFS_ROOTINO;
                    inode = self.read_inode(current_ino)?;
                    new_path.push_str(&link);
                } else {
                    current_ino = parent_ino;
                    inode = self.read_inode(current_ino)?;
                    new_path.push_str(&link);
                }
                if !rest.is_empty() {
                    if !new_path.ends_with('/') {
                        new_path.push('/');
                    }
                    new_path.push_str(rest.trim_start_matches('/'));
                }
                if new_path.len() > MAXPATHLEN {
                    log::warn!("ufs: resolved path too long");
                    return None;
                }
                path = new_path;
                continue;
            }
            path = rest.to_string();
        }
    }

    fn search_directory(&mut self, dir_inode: &UfsInode, name: &str) -> Option<u64> {
        let mut file = UfsFile::new(dir_inode.clone());
        let target = name.as_bytes();
        let oldfmt = self.fs.old_dirfmt();
        loop {
            if file.seekp >= file.size() {
                return None;
            }
            let (start, end) = match self.buf_read_file(&mut file) {
                Some(span) => span,
                None => {
                    log::warn!("ufs: dir read failed: {}", name);
                    return None;
                }
            };
            let size = end.saturating_sub(start);
            if size < 8 {
                log::warn!("ufs: dir entry truncated: {}", name);
                return None;
            }
            let buf = &file.buf[start..end];
            let d_ino = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
            let d_reclen = u16::from_le_bytes([buf[4], buf[5]]) as usize;
            let d_type = buf[6];
            let d_namlen = buf[7] as usize;
            let namlen = if oldfmt { d_type as usize } else { d_namlen };
            if d_reclen == 0 || d_reclen > size {
                log::warn!("ufs: dir entry invalid: {}", name);
                return None;
            }
            if d_ino != 0 && namlen > 0 && 8 + namlen <= d_reclen && d_reclen <= size {
                let entry = &buf[8..8 + namlen];
                if entry == target {
                    return Some(d_ino as u64);
                }
            }
            file.seekp = file.seekp.saturating_add(d_reclen as u64);
        }
    }

    fn read_link(&mut self, inode: &UfsInode) -> Option<String> {
        let link_len = inode.size as usize;
        if link_len == 0 {
            return Some(String::new());
        }
        if inode.shortlink.len() >= link_len && (link_len as i32) < self.fs.maxsymlinklen {
            let bytes = &inode.shortlink[..link_len];
            return Some(String::from_utf8_lossy(bytes).into_owned());
        }
        let mut file = UfsFile::new(inode.clone());
        let data = self.read_all(&mut file)?;
        let bytes = data.get(..link_len)?;
        Some(String::from_utf8_lossy(bytes).into_owned())
    }

    fn read_all(&mut self, file: &mut UfsFile) -> Option<Vec<u8>> {
        let total = usize::try_from(file.size()).ok()?;
        if total == 0 {
            return Some(Vec::new());
        }
        let mut out = Vec::with_capacity(total);
        unsafe {
            out.set_len(total);
        }
        let mut out_pos = 0usize;
        let mut next_log = if total >= UFS_PROGRESS_THRESHOLD {
            UFS_PROGRESS_STEP
        } else {
            usize::MAX
        };
        let mut run_logs_left = if total >= UFS_PROGRESS_THRESHOLD {
            UFS_RUN_LOGS
        } else {
            0
        };
        let full_block = self.fs.bsize as usize;
        let mut max_blocks = UFS_READ_AHEAD_BYTES / full_block;
        if max_blocks == 0 {
            max_blocks = 1;
        }
        while file.seekp < file.size() {
            let off = self.fs.blkoff(file.seekp) as usize;
            let file_block = self.fs.lblkno(file.seekp);
            let block_size = self.fs.sblksize(file.size(), file_block)? as usize;
            if block_size == 0 {
                log::warn!("ufs: read window invalid");
                return None;
            }
            let remaining = (file.size() - file.seekp) as usize;
            let size_to_copy = block_size.saturating_sub(off).min(remaining);
            if size_to_copy == 0 {
                log::warn!("ufs: read window invalid");
                return None;
            }
            if file.debug_steps_left > 0 {
                let label = file.debug_name.as_deref().unwrap_or("<file>");
                log::info!(
                    "ufs: map start file_block={} off={} remaining={} ({})",
                    file_block,
                    off,
                    remaining,
                    label
                );
            }
            let disk_block = match self.block_map(file, file_block) {
                Some(block) => block,
                None => {
                    log::warn!("ufs: block_map failed (block={})", file_block);
                    return None;
                }
            };
            if file.debug_steps_left > 0 {
                let label = file.debug_name.as_deref().unwrap_or("<file>");
                log::info!(
                    "ufs: map done file_block={} disk_block={} ({})",
                    file_block,
                    disk_block,
                    label
                );
            }
            let mut log_read_bytes = size_to_copy;
            let mut log_run_blocks = 1usize;
            if disk_block == 0 {
                out[out_pos..out_pos + size_to_copy].fill(0);
                file.seekp = file.seekp.saturating_add(size_to_copy as u64);
                out_pos += size_to_copy;
            } else if off == 0 && block_size == full_block && remaining >= full_block {
                let max_blocks_by_size = remaining / full_block;
                let mut run_blocks = 1usize;
                let run_limit = core::cmp::min(max_blocks, max_blocks_by_size);
                while run_blocks < run_limit {
                    let next_file_block = file_block + run_blocks as u64;
                    let next_block_size = self.fs.sblksize(file.size(), next_file_block)? as usize;
                    if next_block_size != full_block {
                        break;
                    }
                    let next_disk_block = match self.block_map(file, next_file_block) {
                        Some(block) => block,
                        None => {
                            log::warn!("ufs: block_map failed (block={})", next_file_block);
                            return None;
                        }
                    };
                    let frag = self.fs.frag;
                    if next_disk_block == 0
                        || next_disk_block != disk_block + run_blocks as u64 * frag
                    {
                        break;
                    }
                    run_blocks += 1;
                }
                let read_bytes = run_blocks * full_block;
                if file.debug_steps_left > 0 {
                    let label = file.debug_name.as_deref().unwrap_or("<file>");
                    log::info!(
                        "ufs: data start fsb={} bytes={} blocks={} ({})",
                        disk_block,
                        read_bytes,
                        run_blocks,
                        label
                    );
                }
                let buf = self.read_fs_block(disk_block, read_bytes)?;
                out[out_pos..out_pos + read_bytes].copy_from_slice(&buf[..read_bytes]);
                file.seekp = file.seekp.saturating_add(read_bytes as u64);
                out_pos += read_bytes;
                if file.debug_steps_left > 0 {
                    let label = file.debug_name.as_deref().unwrap_or("<file>");
                    log::info!(
                        "ufs: data done fsb={} bytes={} blocks={} ({})",
                        disk_block,
                        read_bytes,
                        run_blocks,
                        label
                    );
                }
                log_read_bytes = read_bytes;
                log_run_blocks = run_blocks;
            } else {
                if file.debug_steps_left > 0 {
                    let label = file.debug_name.as_deref().unwrap_or("<file>");
                    log::info!(
                        "ufs: data start fsb={} bytes={} blocks=1 ({})",
                        disk_block,
                        block_size,
                        label
                    );
                }
                let buf = self.read_fs_block(disk_block, block_size)?;
                out[out_pos..out_pos + size_to_copy].copy_from_slice(&buf[off..off + size_to_copy]);
                file.seekp = file.seekp.saturating_add(size_to_copy as u64);
                out_pos += size_to_copy;
                if file.debug_steps_left > 0 {
                    let label = file.debug_name.as_deref().unwrap_or("<file>");
                    log::info!(
                        "ufs: data done fsb={} bytes={} blocks=1 ({})",
                        disk_block,
                        block_size,
                        label
                    );
                }
            }
            if run_logs_left > 0 {
                let label = file.debug_name.as_deref().unwrap_or("<file>");
                log::info!(
                    "ufs: run blocks={} bytes={} file_block={} disk_block={} off={} ({})",
                    log_run_blocks,
                    log_read_bytes,
                    file_block,
                    disk_block,
                    off,
                    label
                );
                run_logs_left -= 1;
            }
            if out_pos >= next_log {
                let label = file.debug_name.as_deref().unwrap_or("<file>");
                log::info!("ufs: read {} / {} bytes ({})", out_pos, total, label);
                next_log = next_log.saturating_add(UFS_PROGRESS_STEP);
            }
            if file.debug_steps_left > 0 {
                file.debug_steps_left -= 1;
            }
        }
        Some(out)
    }

    fn read_into(&mut self, file: &mut UfsFile, dst: *mut u8, total: usize) -> Option<()> {
        if total == 0 {
            return Some(());
        }
        let out = unsafe { core::slice::from_raw_parts_mut(dst, total) };
        let mut out_pos = 0usize;
        let mut next_log = if total >= UFS_PROGRESS_THRESHOLD {
            UFS_PROGRESS_STEP
        } else {
            usize::MAX
        };
        let full_block = self.fs.bsize as usize;
        let mut max_blocks = UFS_READ_AHEAD_BYTES / full_block;
        if max_blocks == 0 {
            max_blocks = 1;
        }
        while file.seekp < file.size() {
            let off = self.fs.blkoff(file.seekp) as usize;
            let file_block = self.fs.lblkno(file.seekp);
            let block_size = self.fs.sblksize(file.size(), file_block)? as usize;
            if block_size == 0 {
                log::warn!("ufs: read window invalid");
                return None;
            }
            let remaining = (file.size() - file.seekp) as usize;
            let size_to_copy = block_size.saturating_sub(off).min(remaining);
            if size_to_copy == 0 {
                log::warn!("ufs: read window invalid");
                return None;
            }
            if file.debug_steps_left > 0 {
                let label = file.debug_name.as_deref().unwrap_or("<file>");
                log::info!(
                    "ufs: map start file_block={} off={} remaining={} ({})",
                    file_block,
                    off,
                    remaining,
                    label
                );
            }
            let disk_block = match self.block_map(file, file_block) {
                Some(block) => block,
                None => {
                    log::warn!("ufs: block_map failed (block={})", file_block);
                    return None;
                }
            };
            if file.debug_steps_left > 0 {
                let label = file.debug_name.as_deref().unwrap_or("<file>");
                log::info!(
                    "ufs: map done file_block={} disk_block={} ({})",
                    file_block,
                    disk_block,
                    label
                );
            }
            let mut log_read_bytes = size_to_copy;
            let mut log_run_blocks = 1usize;
            if disk_block == 0 {
                out[out_pos..out_pos + size_to_copy].fill(0);
                file.seekp = file.seekp.saturating_add(size_to_copy as u64);
                out_pos += size_to_copy;
            } else if off == 0 && block_size == full_block && remaining >= full_block {
                let max_blocks_by_size = remaining / full_block;
                let mut run_blocks = 1usize;
                let run_limit = core::cmp::min(max_blocks, max_blocks_by_size);
                while run_blocks < run_limit {
                    let next_file_block = file_block + run_blocks as u64;
                    let next_block_size = self.fs.sblksize(file.size(), next_file_block)? as usize;
                    if next_block_size != full_block {
                        break;
                    }
                    let next_disk_block = match self.block_map(file, next_file_block) {
                        Some(block) => block,
                        None => {
                            log::warn!("ufs: block_map failed (block={})", next_file_block);
                            return None;
                        }
                    };
                    let frag = self.fs.frag;
                    if next_disk_block == 0
                        || next_disk_block != disk_block + run_blocks as u64 * frag
                    {
                        break;
                    }
                    run_blocks += 1;
                }
                let read_bytes = run_blocks * full_block;
                if file.debug_steps_left > 0 {
                    let label = file.debug_name.as_deref().unwrap_or("<file>");
                    log::info!(
                        "ufs: data start fsb={} bytes={} blocks={} ({})",
                        disk_block,
                        read_bytes,
                        run_blocks,
                        label
                    );
                }
                let buf = self.read_fs_block(disk_block, read_bytes)?;
                out[out_pos..out_pos + read_bytes].copy_from_slice(&buf[..read_bytes]);
                file.seekp = file.seekp.saturating_add(read_bytes as u64);
                out_pos += read_bytes;
                if file.debug_steps_left > 0 {
                    let label = file.debug_name.as_deref().unwrap_or("<file>");
                    log::info!(
                        "ufs: data done fsb={} bytes={} blocks={} ({})",
                        disk_block,
                        read_bytes,
                        run_blocks,
                        label
                    );
                }
                log_read_bytes = read_bytes;
                log_run_blocks = run_blocks;
            } else {
                if file.debug_steps_left > 0 {
                    let label = file.debug_name.as_deref().unwrap_or("<file>");
                    log::info!(
                        "ufs: data start fsb={} bytes={} blocks=1 ({})",
                        disk_block,
                        block_size,
                        label
                    );
                }
                let buf = self.read_fs_block(disk_block, block_size)?;
                out[out_pos..out_pos + size_to_copy].copy_from_slice(&buf[off..off + size_to_copy]);
                file.seekp = file.seekp.saturating_add(size_to_copy as u64);
                out_pos += size_to_copy;
                if file.debug_steps_left > 0 {
                    let label = file.debug_name.as_deref().unwrap_or("<file>");
                    log::info!(
                        "ufs: data done fsb={} bytes={} blocks=1 ({})",
                        disk_block,
                        block_size,
                        label
                    );
                }
            }
            if file.debug_steps_left > 0 {
                let label = file.debug_name.as_deref().unwrap_or("<file>");
                log::info!(
                    "ufs: run blocks={} bytes={} file_block={} disk_block={} off={} ({})",
                    log_run_blocks,
                    log_read_bytes,
                    file_block,
                    disk_block,
                    off,
                    label
                );
            }
            if out_pos >= next_log {
                let label = file.debug_name.as_deref().unwrap_or("<file>");
                log::info!("ufs: read {} / {} bytes ({})", out_pos, total, label);
                next_log = next_log.saturating_add(UFS_PROGRESS_STEP);
            }
            if file.debug_steps_left > 0 {
                file.debug_steps_left -= 1;
            }
        }
        Some(())
    }

    fn buf_read_file(&mut self, file: &mut UfsFile) -> Option<(usize, usize)> {
        if file.seekp >= file.size() {
            return None;
        }
        let off = self.fs.blkoff(file.seekp);
        let file_block = self.fs.lblkno(file.seekp);
        let block_size = self.fs.sblksize(file.size(), file_block)? as usize;
        if block_size == 0 {
            return None;
        }
        let disk_block = match self.block_map(file, file_block) {
            Some(block) => block,
            None => {
                log::warn!("ufs: block_map failed (block={})", file_block);
                return None;
            }
        };
        if file.buf_blkno != Some(file_block) || file.buf_size != block_size {
            if disk_block == 0 {
                file.buf = alloc::vec![0u8; block_size];
            } else {
                file.buf = match self.read_fs_block(disk_block, block_size) {
                    Some(buf) => buf,
                    None => {
                        log::warn!("ufs: read block failed (fsb={})", disk_block);
                        return None;
                    }
                };
            }
            file.buf_blkno = Some(file_block);
            file.buf_size = block_size;
        }
        let mut size = block_size.saturating_sub(off as usize);
        let remaining = (file.size() - file.seekp) as usize;
        if size > remaining {
            size = remaining;
        }
        let start = off as usize;
        let end = start + size;
        Some((start, end))
    }

    fn read_inode(&mut self, ino: u64) -> Option<UfsInode> {
        let fsb = self.fs.ino_to_fsba(ino);
        let buf = match self.read_fs_block(fsb, self.fs.bsize as usize) {
            Some(buf) => buf,
            None => {
                log::warn!("ufs: inode read failed (ino={}, fsb={})", ino, fsb);
                return None;
            }
        };
        let inode_size = self.fs.inode_size()? as usize;
        let index = (ino % self.fs.inopb) as usize;
        let offset = index.saturating_mul(inode_size);
        if offset + inode_size > buf.len() {
            log::warn!("ufs: inode offset out of range (ino={})", ino);
            return None;
        }
        let slice = &buf[offset..offset + inode_size];
        parse_inode(slice, self.fs.kind)
    }

    fn block_map(&mut self, file: &mut UfsFile, mut file_block: u64) -> Option<u64> {
        if file_block < UFS_NDADDR as u64 {
            let value = file.inode.db[file_block as usize];
            return Some(if value > 0 { value as u64 } else { 0 });
        }
        file_block -= UFS_NDADDR as u64;
        let mut level = 0usize;
        while level < UFS_NIADDR {
            let span = self.fs.nindir_levels[level];
            if file_block < span {
                break;
            }
            file_block -= span;
            level += 1;
        }
        if level == UFS_NIADDR {
            return None;
        }
        let mut ind_block_num = file.inode.ib[level];
        let mut lvl: i32 = level as i32;
        while lvl >= 0 {
            if ind_block_num <= 0 {
                return Some(0);
            }
            let table = self.get_indirect_block(file, lvl as usize, ind_block_num)?;
            let idx = if lvl > 0 {
                let div = self.fs.nindir_levels[lvl as usize - 1];
                let idx = (file_block / div) as usize;
                file_block %= div;
                idx
            } else {
                file_block as usize
            };
            let next = *table.get(idx).unwrap_or(&0);
            if next <= 0 {
                return Some(0);
            }
            ind_block_num = next;
            lvl -= 1;
        }
        if ind_block_num <= 0 {
            return Some(0);
        }
        Some(ind_block_num as u64)
    }

    fn get_indirect_block<'a>(
        &mut self,
        file: &'a mut UfsFile,
        level: usize,
        fsb: i64,
    ) -> Option<&'a [i64]> {
        if fsb <= 0 {
            return None;
        }
        if file.indirect_block_no[level] == fsb {
            return file.indirect_block[level].as_deref();
        }
        let buf = self.read_fs_block(fsb as u64, self.fs.bsize as usize)?;
        let mut out = Vec::with_capacity(self.fs.nindir_levels[0] as usize);
        for chunk in buf.chunks_exact(8) {
            out.push(i64::from_le_bytes([
                chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
            ]));
        }
        file.indirect_block_no[level] = fsb;
        file.indirect_block[level] = Some(out);
        file.indirect_block[level].as_deref()
    }

    fn read_fs_block(&mut self, fsb: u64, size: usize) -> Option<Vec<u8>> {
        let offset_bytes = self.fs.fsb_to_bytes(fsb)?;
        self.device.read_at(offset_bytes, size)
    }
}

#[derive(Clone)]
struct UfsFile {
    inode: UfsInode,
    seekp: u64,
    buf: Vec<u8>,
    buf_blkno: Option<u64>,
    buf_size: usize,
    indirect_block_no: [i64; UFS_NIADDR],
    indirect_block: [Option<Vec<i64>>; UFS_NIADDR],
    debug_name: Option<String>,
    debug_steps_left: usize,
}

impl UfsFile {
    fn new(inode: UfsInode) -> Self {
        UfsFile {
            inode,
            seekp: 0,
            buf: Vec::new(),
            buf_blkno: None,
            buf_size: 0,
            indirect_block_no: [0i64; UFS_NIADDR],
            indirect_block: core::array::from_fn(|_| None),
            debug_name: None,
            debug_steps_left: 0,
        }
    }

    fn size(&self) -> u64 {
        self.inode.size
    }
}

#[derive(Clone)]
struct UfsInode {
    mode: u16,
    size: u64,
    db: [i64; UFS_NDADDR],
    ib: [i64; UFS_NIADDR],
    shortlink: Vec<u8>,
}

struct UfsFs {
    kind: UfsKind,
    magic: u32,
    bsize: u64,
    fsize: u64,
    frag: u64,
    inopb: u64,
    nindir_levels: [u64; UFS_NIADDR],
    fsbtodb_shift: u32,
    bshift: u32,
    qbmask: i64,
    ipg: u64,
    fpg: u64,
    iblkno: u64,
    inode_size: u64,
    maxsymlinklen: i32,
    old_cgoffset: i32,
    old_cgmask: i32,
}

impl UfsFs {
    fn from_header(header: FsHeader, kind: UfsKind) -> Option<Self> {
        let magic = header._fs_magic as u32;
        let bsize = header._fs_bsize as i64;
        let fsize = header._fs_fsize as i64;
        let frag = header._fs_frag as i64;
        if bsize <= 0 || fsize <= 0 || frag <= 0 {
            return None;
        }
        let inode_size = match kind {
            UfsKind::Ufs2 => UFS2_DINODE_SIZE as i64,
            UfsKind::Ufs1 => UFS1_DINODE_SIZE as i64,
        };
        let inopb = if header._fs_inopb > 0 {
            header._fs_inopb as i64
        } else {
            bsize.checked_div(inode_size)?
        };
        let nindir = if header._fs_nindir > 0 {
            header._fs_nindir as i64
        } else {
            bsize.checked_div(8)?
        };
        let fsbtodb_shift = if header._fs_fsbtodb > 0 {
            header._fs_fsbtodb
        } else {
            compute_fsbtodb_shift(fsize)?
        };
        let bshift = if header._fs_bshift > 0 {
            header._fs_bshift
        } else {
            compute_log2(bsize)?
        };
        let qbmask = if header._fs_qbmask != 0 {
            header._fs_qbmask
        } else {
            !(bsize - 1)
        };
        let ipg = header._fs_ipg as i64;
        let fpg = header._fs_fpg as i64;
        let iblkno = header._fs_iblkno as i64;
        if inopb <= 0 || nindir <= 0 || ipg <= 0 || fpg <= 0 || iblkno < 0 {
            return None;
        }
        let n0 = nindir as u64;
        let n1 = n0.saturating_mul(n0);
        let n2 = n1.saturating_mul(n0);
        Some(UfsFs {
            kind,
            magic,
            bsize: bsize as u64,
            fsize: fsize as u64,
            frag: frag as u64,
            inopb: inopb as u64,
            nindir_levels: [n0, n1, n2],
            fsbtodb_shift: fsbtodb_shift as u32,
            bshift: bshift as u32,
            qbmask,
            ipg: ipg as u64,
            fpg: fpg as u64,
            iblkno: iblkno as u64,
            inode_size: inode_size as u64,
            maxsymlinklen: header._fs_maxsymlinklen,
            old_cgoffset: header._fs_old_cgoffset,
            old_cgmask: header._fs_old_cgmask,
        })
    }

    fn inode_size(&self) -> Option<usize> {
        if self.inode_size == 0 {
            None
        } else {
            Some(self.inode_size as usize)
        }
    }

    fn fsb_to_bytes(&self, fsb: u64) -> Option<u64> {
        let disk_blocks_512 = fsb.checked_shl(self.fsbtodb_shift)?;
        disk_blocks_512.checked_mul(512)
    }

    fn blkoff(&self, loc: u64) -> u64 {
        (loc as i64 & self.qbmask) as u64
    }

    fn lblkno(&self, loc: u64) -> u64 {
        loc >> self.bshift
    }

    fn sblksize(&self, size: u64, lbn: u64) -> Option<u64> {
        let next_block_end = (lbn + 1).checked_shl(self.bshift)?;
        if lbn >= UFS_NDADDR as u64 || size >= next_block_end {
            return Some(self.bsize);
        }
        let blkoff = self.blkoff(size);
        let rounded = self.fragroundup(blkoff)?;
        if rounded == 0 {
            Some(self.fsize)
        } else {
            Some(rounded)
        }
    }

    fn fragroundup(&self, size: u64) -> Option<u64> {
        if self.fsize == 0 {
            return None;
        }
        Some((size + self.fsize - 1) & !(self.fsize - 1))
    }

    fn ino_to_fsba(&self, ino: u64) -> u64 {
        let cg = ino / self.ipg;
        let blk = (ino % self.ipg) / self.inopb;
        let cgimin = self.cgstart(cg) + self.iblkno;
        cgimin + (blk * self.frag)
    }

    fn old_dirfmt(&self) -> bool {
        self.maxsymlinklen <= 0
    }

    fn cgstart(&self, cg: u64) -> u64 {
        if self.magic == FS_UFS2_MAGIC {
            self.fpg * cg
        } else {
            let base = self.fpg * cg;
            base + (self.old_cgoffset as u64 * (cg & !(self.old_cgmask as u64)))
        }
    }
}

fn normalize_path(path: &str) -> String {
    let mut out = String::new();
    let mut last_sep = false;
    for ch in path.chars() {
        let next = if ch == '\\' { '/' } else { ch };
        if next == '/' {
            if last_sep {
                continue;
            }
            last_sep = true;
        } else {
            last_sep = false;
        }
        out.push(next);
    }
    if !out.starts_with('/') {
        out.insert(0, '/');
    }
    out
}

fn split_first_component(path: &str) -> (&str, &str) {
    if let Some(pos) = path.find('/') {
        (&path[..pos], &path[pos + 1..])
    } else {
        (path, "")
    }
}

fn read_superblock(device: &mut UfsDevice) -> Option<UfsFs> {
    for &offset in SBLOCK_OFFSETS.iter() {
        let buf = device.read_at(offset, SBLOCKSIZE)?;
        let kind = parse_superblock(&buf, offset)?;
        let header = read_fs_header(&buf)?;
        return UfsFs::from_header(header, kind);
    }
    None
}

fn parse_inode(buf: &[u8], kind: UfsKind) -> Option<UfsInode> {
    match kind {
        UfsKind::Ufs2 => parse_ufs2_inode(buf),
        UfsKind::Ufs1 => parse_ufs1_inode(buf),
    }
}

fn parse_ufs2_inode(buf: &[u8]) -> Option<UfsInode> {
    if buf.len() < UFS2_DINODE_SIZE {
        return None;
    }
    let mode = u16::from_le_bytes([buf[0], buf[1]]);
    let size = u64::from_le_bytes([
        buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
    ]);
    let mut db = [0i64; UFS_NDADDR];
    let mut ib = [0i64; UFS_NIADDR];
    let db_start = 112;
    for idx in 0..UFS_NDADDR {
        let off = db_start + idx * 8;
        db[idx] = i64::from_le_bytes([
            buf[off],
            buf[off + 1],
            buf[off + 2],
            buf[off + 3],
            buf[off + 4],
            buf[off + 5],
            buf[off + 6],
            buf[off + 7],
        ]);
    }
    let ib_start = db_start + UFS_NDADDR * 8;
    for idx in 0..UFS_NIADDR {
        let off = ib_start + idx * 8;
        ib[idx] = i64::from_le_bytes([
            buf[off],
            buf[off + 1],
            buf[off + 2],
            buf[off + 3],
            buf[off + 4],
            buf[off + 5],
            buf[off + 6],
            buf[off + 7],
        ]);
    }
    let shortlink_len = (UFS_NDADDR + UFS_NIADDR) * 8;
    let shortlink = buf[db_start..db_start + shortlink_len].to_vec();
    Some(UfsInode {
        mode,
        size,
        db,
        ib,
        shortlink,
    })
}

fn parse_ufs1_inode(buf: &[u8]) -> Option<UfsInode> {
    if buf.len() < UFS1_DINODE_SIZE {
        return None;
    }
    let mode = u16::from_le_bytes([buf[0], buf[1]]);
    let size = u64::from_le_bytes([
        buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
    ]);
    let mut db = [0i64; UFS_NDADDR];
    let mut ib = [0i64; UFS_NIADDR];
    let db_start = 40;
    for idx in 0..UFS_NDADDR {
        let off = db_start + idx * 4;
        db[idx] = i32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) as i64;
    }
    let ib_start = db_start + UFS_NDADDR * 4;
    for idx in 0..UFS_NIADDR {
        let off = ib_start + idx * 4;
        ib[idx] = i32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) as i64;
    }
    let shortlink_len = (UFS_NDADDR + UFS_NIADDR) * 4;
    let shortlink = buf[db_start..db_start + shortlink_len].to_vec();
    Some(UfsInode {
        mode,
        size,
        db,
        ib,
        shortlink,
    })
}

fn is_dir(mode: u16) -> bool {
    (mode & IFMT) == IFDIR
}

fn is_symlink(mode: u16) -> bool {
    (mode & IFMT) == IFLNK
}

fn read_fs_header(buf: &[u8]) -> Option<FsHeader> {
    if buf.len() < core::mem::size_of::<FsHeader>() {
        return None;
    }
    let mut out = core::mem::MaybeUninit::<FsHeader>::uninit();
    unsafe {
        core::ptr::copy_nonoverlapping(
            buf.as_ptr(),
            out.as_mut_ptr() as *mut u8,
            core::mem::size_of::<FsHeader>(),
        );
        Some(out.assume_init())
    }
}

fn probe_device(device: &BlockDeviceInfo) -> Option<UfsKind> {
    let block = open_block_io(device.handle).ok()?;
    let media = block.media();
    if !media.is_media_present() {
        return None;
    }
    let block_size = media.block_size() as usize;
    if block_size == 0 {
        return None;
    }
    for &offset in SBLOCK_OFFSETS.iter() {
        let buf = read_raw(
            &block,
            media.media_id(),
            block_size,
            media.io_align() as usize,
            media.last_block(),
            offset,
            SBLOCKSIZE,
        )?;
        if let Some(kind) = parse_superblock(&buf, offset) {
            return Some(kind);
        }
    }
    None
}

fn probe_partition_handle(handle: Handle) -> Option<UfsKind> {
    let block = open_block_io(handle).ok()?;
    let media = block.media();
    if !media.is_media_present() {
        return None;
    }
    let block_size = media.block_size() as usize;
    if block_size == 0 {
        return None;
    }
    probe_partition_at_lba(&block, media.media_id(), block_size, 0)
}

fn probe_partition_at_lba(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    first_lba: u64,
) -> Option<UfsKind> {
    let base = first_lba * block_size as u64;
    let media = block.media();
    for &offset in SBLOCK_OFFSETS.iter() {
        let sblock_loc = base + offset;
        let buf = read_raw(
            block,
            media_id,
            block_size,
            media.io_align() as usize,
            media.last_block(),
            sblock_loc,
            SBLOCKSIZE,
        )?;
        if let Some(kind) = parse_superblock(&buf, sblock_loc) {
            return Some(kind);
        }
    }
    None
}

fn read_raw(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    io_align: usize,
    last_block: u64,
    offset: u64,
    size: usize,
) -> Option<Vec<u8>> {
    if size == 0 {
        return Some(Vec::new());
    }
    let bs = block_size as u64;
    let start_block = offset / bs;
    let block_off = (offset % bs) as usize;
    let end = offset.checked_add(size as u64)?;
    let last = end.saturating_sub(1) / bs;
    if last > last_block {
        return None;
    }
    let blocks = last.checked_sub(start_block)?.saturating_add(1);
    let total = (blocks as usize).checked_mul(block_size)?;
    let align = if io_align == 0 { 1 } else { io_align };
    let mut raw = alloc::vec![0u8; total + align];
    let base = raw.as_ptr() as usize;
    let align_off = (align - (base % align)) % align;
    let aligned = &mut raw[align_off..align_off + total];
    let log_large = size >= UFS_TRACE_BYTES && READ_RAW_LOG_BUDGET.load(Ordering::Relaxed) > 0;
    if log_large {
        let remaining = READ_RAW_LOG_BUDGET.fetch_sub(1, Ordering::Relaxed);
        if remaining > 0 {
            log::info!(
                "ufs: read_raw start lba={} blocks={} size={}",
                start_block,
                blocks,
                size
            );
        }
    }
    block.read_blocks(media_id, start_block, aligned).ok()?;
    if log_large {
        log::info!(
            "ufs: read_raw done lba={} blocks={} size={}",
            start_block,
            blocks,
            size
        );
    }
    let start = block_off;
    let end_off = start.checked_add(size)?;
    aligned.get(start..end_off).map(|slice| slice.to_vec())
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
            let header = read_fs_header(buf)?;
            if header.fs_sblockloc as u64 != sblock_loc {
                return None;
            }
            Some(UfsKind::Ufs2)
        }
        _ => None,
    }
}

fn compute_fsbtodb_shift(fsize: i64) -> Option<i32> {
    if fsize <= 0 || fsize % 512 != 0 {
        return None;
    }
    let mut shift = 0i32;
    let mut value = fsize / 512;
    while value > 1 {
        if value % 2 != 0 {
            return None;
        }
        value /= 2;
        shift += 1;
    }
    Some(shift)
}

fn compute_log2(value: i64) -> Option<i32> {
    if value <= 0 {
        return None;
    }
    let mut shift = 0i32;
    let mut cur = value;
    while cur > 1 {
        if cur % 2 != 0 {
            return None;
        }
        cur /= 2;
        shift += 1;
    }
    Some(shift)
}

const UFS_ROOTINO: u64 = 2;
const UFS_NDADDR: usize = 12;
const UFS_NIADDR: usize = 3;
const UFS_MAXNAMLEN: usize = 255;
const MAXPATHLEN: usize = 1024;
const MAXSYMLINKS: usize = 32;
const UFS_READ_AHEAD_BYTES: usize = 8 * 1024 * 1024;
const UFS_PROGRESS_THRESHOLD: usize = 8 * 1024 * 1024;
const UFS_PROGRESS_STEP: usize = 8 * 1024 * 1024;
const UFS_RUN_LOGS: usize = 8;
const UFS_DEBUG_STEPS: usize = 6;
const UFS_TRACE_BYTES: usize = 8 * 1024 * 1024;
static READ_RAW_LOG_BUDGET: AtomicUsize = AtomicUsize::new(6);

const IFMT: u16 = 0o170000;
const IFDIR: u16 = 0o040000;
const IFLNK: u16 = 0o120000;

const DT_UNKNOWN: u8 = 0;
const DT_REG: u8 = 8;

const UFS1_DINODE_SIZE: usize = 128;
const UFS2_DINODE_SIZE: usize = 256;

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
        FS_MAGIC_OFFSET, FS_SBLOCKLOC_OFFSET, FS_UFS1_MAGIC, FS_UFS2_MAGIC, FsHeader,
        SBLOCK_OFFSETS, SBLOCKSIZE, UfsKind, parse_superblock, probe_from_gpt,
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
        let offset = core::mem::offset_of!(FsHeader, fs_sblockloc);
        buf[offset..offset + 8].copy_from_slice(&SBLOCK_OFFSETS[1].to_le_bytes());
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
