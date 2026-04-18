extern crate alloc;

use alloc::vec::Vec;

use uefi::proto::media::block::BlockIO;

use crate::error::{BootError, Result};
use crate::zfs::label::VDEV_LABEL_START_SIZE;
use crate::zfs::reader::checksum::verify_checksum;
use crate::zfs::reader::lz4;
use crate::zfs::reader::types::{BlkPtr, Dva, bp_should_byteswap, dva_get_asize, dva_get_offset};

const ZIO_COMPRESS_OFF: u64 = 2;
const ZIO_COMPRESS_LZ4: u64 = 15;
const BP_EMBEDDED_TYPE_DATA: u64 = 0;
const BPE_PAYLOAD_SIZE: usize = 14 * 8;

pub fn read_block(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    bp: &BlkPtr,
) -> Result<Vec<u8>> {
    if bp.is_embedded() {
        return read_embedded_block(bp);
    }
    let mut last_err = BootError::InvalidData("blkptr DVA size zero");
    for (dva_idx, dva) in bp.dvas.iter().enumerate() {
        if dva_is_hole(dva) {
            continue;
        }
        for base in [VDEV_LABEL_START_SIZE as u64, 0] {
            match read_block_at_dva(block, media_id, block_size, bp, dva, base) {
                Ok(mut out) => {
                    if base == 0 {
                        log::warn!(
                            "zfs: block checksum ok without label offset dva={} raw_offset=0x{:x}",
                            dva_idx,
                            dva_get_offset(dva)
                        );
                    }
                    if bp_should_byteswap(bp) {
                        byteswap_u64s(&mut out);
                    }
                    return Ok(out);
                }
                Err(err) => {
                    last_err = err;
                }
            }
        }
    }
    Err(last_err)
}

fn read_block_at_dva(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    bp: &BlkPtr,
    dva: &Dva,
    base: u64,
) -> Result<Vec<u8>> {
    let asize = dva_get_asize(dva);
    if asize == 0 {
        return Err(BootError::InvalidData("blkptr DVA size zero"));
    }
    let offset = dva_get_offset(dva)
        .checked_add(base)
        .ok_or(BootError::InvalidData("blkptr offset overflow"))?;
    let psize = bp.psize() as usize;
    let lsize = bp.lsize() as usize;
    let raw = read_bytes(block, media_id, block_size, offset, psize)?;

    match bp.compress() {
        ZIO_COMPRESS_OFF => {
            verify_checksum(bp, &raw)?;
            if lsize <= raw.len() {
                Ok(raw[..lsize].to_vec())
            } else {
                Err(BootError::InvalidData("blkptr size mismatch"))
            }
        }
        ZIO_COMPRESS_LZ4 => {
            if verify_checksum(bp, &raw).is_ok() {
                lz4::decompress(&raw, lsize)
            } else {
                let data = lz4::decompress(&raw, lsize)?;
                if verify_checksum(bp, &data).is_ok() {
                    log::warn!("zfs: checksum verified after decompression");
                    Ok(data)
                } else {
                    Err(BootError::InvalidData("fletcher4 checksum mismatch"))
                }
            }
        }
        compression => {
            log::warn!("zfs: unsupported compression id {}", compression);
            Err(BootError::Unsupported("compression unsupported"))
        }
    }
}

fn dva_is_hole(dva: &Dva) -> bool {
    dva.word[0] == 0 && dva.word[1] == 0
}

fn read_embedded_block(bp: &BlkPtr) -> Result<Vec<u8>> {
    let etype = (bp.prop >> 40) & 0xff;
    if etype != BP_EMBEDDED_TYPE_DATA {
        return Err(BootError::Unsupported("embedded blkptr type"));
    }
    let psize = bp.psize() as usize;
    let lsize = bp.lsize() as usize;
    if psize == 0 || lsize == 0 {
        return Err(BootError::InvalidData("embedded blkptr size zero"));
    }
    if psize > BPE_PAYLOAD_SIZE {
        return Err(BootError::InvalidData("embedded blkptr size invalid"));
    }
    let payload = decode_embedded_payload(bp, psize)?;
    match bp.compress() {
        ZIO_COMPRESS_OFF => {
            if lsize <= payload.len() {
                Ok(payload[..lsize].to_vec())
            } else {
                Err(BootError::InvalidData("embedded blkptr size mismatch"))
            }
        }
        ZIO_COMPRESS_LZ4 => lz4::decompress(&payload, lsize),
        compression => {
            log::warn!("zfs: unsupported embedded compression id {}", compression);
            Err(BootError::Unsupported("embedded blkptr compression"))
        }
    }
}

fn decode_embedded_payload(bp: &BlkPtr, psize: usize) -> Result<Vec<u8>> {
    let words = blkptr_words(bp);
    let mut out = Vec::with_capacity(psize);
    for (idx, word) in words.iter().enumerate() {
        if idx == 6 || idx == 10 {
            continue;
        }
        for byte in word.to_le_bytes() {
            if out.len() == psize {
                return Ok(out);
            }
            out.push(byte);
        }
    }
    Ok(out)
}

fn blkptr_words(bp: &BlkPtr) -> [u64; 16] {
    [
        bp.dvas[0].word[0],
        bp.dvas[0].word[1],
        bp.dvas[1].word[0],
        bp.dvas[1].word[1],
        bp.dvas[2].word[0],
        bp.dvas[2].word[1],
        bp.prop,
        bp.pad[0],
        bp.pad[1],
        bp.phys_birth,
        bp.birth,
        bp.fill,
        bp.cksum.word[0],
        bp.cksum.word[1],
        bp.cksum.word[2],
        bp.cksum.word[3],
    ]
}

fn byteswap_u64s(buf: &mut [u8]) {
    for chunk in buf.chunks_exact_mut(8) {
        let value = u64::from_le_bytes(chunk.try_into().unwrap()).swap_bytes();
        chunk.copy_from_slice(&value.to_le_bytes());
    }
}

fn read_bytes(
    block: &BlockIO,
    media_id: u32,
    block_size: usize,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>> {
    if block_size == 0 {
        return Err(BootError::InvalidData("block size zero"));
    }
    let start_lba = offset / block_size as u64;
    let end = offset + len as u64;
    let end_lba = (end + block_size as u64 - 1) / block_size as u64;
    let blocks = end_lba.saturating_sub(start_lba) as usize;
    if blocks == 0 {
        return Err(BootError::InvalidData("block read size zero"));
    }
    let mut buf = alloc::vec![0u8; blocks * block_size];
    block
        .read_blocks(media_id, start_lba, &mut buf)
        .map_err(|err| BootError::Uefi(err.status()))?;
    let start_off = (offset % block_size as u64) as usize;
    let end_off = start_off + len;
    if end_off > buf.len() {
        return Err(BootError::InvalidData("block read out of range"));
    }
    Ok(buf[start_off..end_off].to_vec())
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::vec;

    use crate::zfs::reader::types::{BlkPtr, Dva, ZioCksum};

    use super::{BP_EMBEDDED_TYPE_DATA, BPE_PAYLOAD_SIZE, ZIO_COMPRESS_OFF, read_embedded_block};

    fn build_embedded_bp(payload: &[u8]) -> BlkPtr {
        let lsize = payload.len() as u64;
        let psize = payload.len() as u64;
        let lsize_field = (lsize - 1) & ((1u64 << 25) - 1);
        let psize_field = (psize - 1) & ((1u64 << 7) - 1);
        let mut prop = lsize_field | (psize_field << 25);
        prop |= ZIO_COMPRESS_OFF << 32;
        prop |= 1u64 << 39; // embedded flag
        prop |= BP_EMBEDDED_TYPE_DATA << 40;

        let mut words = [0u64; 16];
        let mut cursor = 0usize;
        for idx in 0..words.len() {
            if idx == 6 || idx == 10 {
                continue;
            }
            let mut chunk = [0u8; 8];
            if cursor < payload.len() {
                let end = core::cmp::min(cursor + 8, payload.len());
                chunk[..end - cursor].copy_from_slice(&payload[cursor..end]);
                cursor = end;
            }
            words[idx] = u64::from_le_bytes(chunk);
        }
        words[6] = prop;

        BlkPtr {
            dvas: [
                Dva {
                    word: [words[0], words[1]],
                },
                Dva {
                    word: [words[2], words[3]],
                },
                Dva {
                    word: [words[4], words[5]],
                },
            ],
            prop: words[6],
            pad: [words[7], words[8]],
            phys_birth: words[9],
            birth: words[10],
            fill: words[11],
            cksum: ZioCksum {
                word: [words[12], words[13], words[14], words[15]],
            },
        }
    }

    #[test]
    fn embedded_blkptr_payload_roundtrip() {
        let payload = vec![1u8, 2, 3, 4, 5, 6, 7];
        let bp = build_embedded_bp(&payload);
        let out = read_embedded_block(&bp).expect("embedded read");
        assert_eq!(out, payload);
    }

    #[test]
    fn embedded_blkptr_payload_size_limit() {
        let payload = vec![0u8; BPE_PAYLOAD_SIZE + 1];
        let bp = build_embedded_bp(&payload);
        let err = read_embedded_block(&bp).expect_err("embedded size");
        assert!(format!("{}", err).contains("embedded blkptr size invalid"));
    }
}
