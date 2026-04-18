extern crate alloc;

use crate::error::{BootError, Result};

pub const SPA_MINBLOCKSHIFT: u64 = 9;
pub const SPA_LSIZEBITS: u64 = 16;
pub const SPA_ASIZEBITS: u64 = 24;
pub const SPA_BLKPTRSHIFT: u64 = 7;
pub const UBERBLOCK_MAGIC: u64 = 0x00bab10c;
pub const MMP_MAGIC: u64 = 0xa11cea11;

pub const SPA_DVAS_PER_BP: usize = 3;
pub const BLK_PTR_SIZE: usize = 128;
pub const UBERBLOCK_SIZE: usize = 1024;

#[derive(Debug, Clone, Copy)]
pub struct Dva {
    pub word: [u64; 2],
}

#[derive(Debug, Clone, Copy)]
pub struct ZioCksum {
    pub word: [u64; 4],
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct BlkPtr {
    pub dvas: [Dva; SPA_DVAS_PER_BP],
    pub prop: u64,
    pub pad: [u64; 2],
    pub phys_birth: u64,
    pub birth: u64,
    pub fill: u64,
    pub cksum: ZioCksum,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct Uberblock {
    pub magic: u64,
    pub version: u64,
    pub txg: u64,
    pub guid_sum: u64,
    pub timestamp: u64,
    pub rootbp: BlkPtr,
    pub software_version: u64,
    pub mmp_magic: u64,
    pub mmp_delay: u64,
    pub mmp_config: u64,
    pub checkpoint_txg: u64,
}

impl BlkPtr {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < BLK_PTR_SIZE {
            return Err(BootError::InvalidData("blkptr buffer too small"));
        }
        let le = parse_blkptr(bytes, Endian::Little)?;
        if blkptr_plausible(&le) {
            return Ok(le);
        }
        let be = parse_blkptr(bytes, Endian::Big)?;
        if blkptr_plausible(&be) {
            return Ok(be);
        }
        Ok(le)
    }

    pub fn lsize(&self) -> u64 {
        bp_get_lsize(self)
    }

    pub fn psize(&self) -> u64 {
        bp_get_psize(self)
    }

    pub fn checksum(&self) -> u64 {
        bf64_get(self.prop, 40, 8)
    }

    pub fn compress(&self) -> u64 {
        bf64_get(self.prop, 32, 7)
    }

    #[allow(dead_code)]
    pub fn level(&self) -> u64 {
        bf64_get(self.prop, 56, 5)
    }

    pub fn is_embedded(&self) -> bool {
        bf64_get(self.prop, 39, 1) == 1
    }

    pub fn byteorder(&self) -> u64 {
        bf64_get(self.prop, 63, 1)
    }

    #[allow(dead_code)]
    pub fn logical_birth(&self) -> u64 {
        self.birth
    }
}

#[derive(Copy, Clone)]
enum Endian {
    Little,
    Big,
}

fn parse_blkptr(bytes: &[u8], endian: Endian) -> Result<BlkPtr> {
    let mut offset = 0usize;
    let mut read_u64 = |buf: &[u8]| -> Result<u64> {
        if buf.len() < offset + 8 {
            return Err(BootError::InvalidData("blkptr parse overflow"));
        }
        let slice: [u8; 8] = buf[offset..offset + 8]
            .try_into()
            .map_err(|_| BootError::InvalidData("blkptr parse"))?;
        let value = match endian {
            Endian::Little => u64::from_le_bytes(slice),
            Endian::Big => u64::from_be_bytes(slice),
        };
        offset += 8;
        Ok(value)
    };

    let mut dvas = [Dva { word: [0; 2] }; SPA_DVAS_PER_BP];
    for dva in &mut dvas {
        dva.word[0] = read_u64(bytes)?;
        dva.word[1] = read_u64(bytes)?;
    }
    let prop = read_u64(bytes)?;
    let pad0 = read_u64(bytes)?;
    let pad1 = read_u64(bytes)?;
    let phys_birth = read_u64(bytes)?;
    let birth = read_u64(bytes)?;
    let fill = read_u64(bytes)?;
    let mut cksum_words = [0u64; 4];
    for word in &mut cksum_words {
        *word = read_u64(bytes)?;
    }

    Ok(BlkPtr {
        dvas,
        prop,
        pad: [pad0, pad1],
        phys_birth,
        birth,
        fill,
        cksum: ZioCksum { word: cksum_words },
    })
}

fn blkptr_plausible(bp: &BlkPtr) -> bool {
    if bp_is_hole(bp) {
        return false;
    }
    let psize = bp.psize();
    let lsize = bp.lsize();
    if psize == 0 || lsize == 0 {
        return false;
    }
    if psize > (1 << 24) || lsize > (1 << 24) {
        return false;
    }
    if bp.checksum() > 16 {
        return false;
    }
    if bp.compress() > 16 {
        return false;
    }
    true
}

pub fn dva_get_asize(dva: &Dva) -> u64 {
    bf64_get_sb(dva.word[0], 0, SPA_ASIZEBITS, SPA_MINBLOCKSHIFT, 0)
}

pub fn dva_get_offset(dva: &Dva) -> u64 {
    bf64_get_sb(dva.word[1], 0, 63, SPA_MINBLOCKSHIFT, 0)
}

pub fn bp_is_hole(bp: &BlkPtr) -> bool {
    bp.dvas
        .iter()
        .all(|dva| dva.word[0] == 0 && dva.word[1] == 0)
}

pub fn bp_should_byteswap(bp: &BlkPtr) -> bool {
    bp.byteorder() != host_byteorder()
}

fn host_byteorder() -> u64 {
    if cfg!(target_endian = "little") { 1 } else { 0 }
}

impl Uberblock {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < UBERBLOCK_SIZE {
            return Err(BootError::InvalidData("uberblock buffer too small"));
        }
        let mut offset = 0usize;
        let read_u64 = |buf: &[u8], offset: &mut usize| -> Result<u64> {
            if buf.len() < *offset + 8 {
                return Err(BootError::InvalidData("uberblock parse overflow"));
            }
            let value = u64::from_le_bytes(
                buf[*offset..*offset + 8]
                    .try_into()
                    .map_err(|_| BootError::InvalidData("uberblock parse"))?,
            );
            *offset += 8;
            Ok(value)
        };
        let magic = read_u64(bytes, &mut offset)?;
        let version = read_u64(bytes, &mut offset)?;
        let txg = read_u64(bytes, &mut offset)?;
        let guid_sum = read_u64(bytes, &mut offset)?;
        let timestamp = read_u64(bytes, &mut offset)?;
        let rootbp = BlkPtr::from_bytes(&bytes[offset..offset + BLK_PTR_SIZE])?;
        offset += BLK_PTR_SIZE;
        let software_version = read_u64(bytes, &mut offset)?;
        let mmp_magic = read_u64(bytes, &mut offset)?;
        let mmp_delay = read_u64(bytes, &mut offset)?;
        let mmp_config = read_u64(bytes, &mut offset)?;
        let checkpoint_txg = read_u64(bytes, &mut offset)?;
        Ok(Self {
            magic,
            version,
            txg,
            guid_sum,
            timestamp,
            rootbp,
            software_version,
            mmp_magic,
            mmp_delay,
            mmp_config,
            checkpoint_txg,
        })
    }

    pub fn is_valid(&self) -> bool {
        self.magic == UBERBLOCK_MAGIC
    }
}

pub fn mmp_valid(ub: &Uberblock) -> bool {
    ub.magic == UBERBLOCK_MAGIC && ub.mmp_magic == MMP_MAGIC
}

pub fn mmp_seq_valid(ub: &Uberblock) -> bool {
    mmp_valid(ub) && (ub.mmp_config & 0x0000000000000002) != 0
}

pub fn mmp_seq(ub: &Uberblock) -> u64 {
    (ub.mmp_config & 0x0000FFFF00000000) >> 32
}

fn bf64_get(value: u64, low: u64, len: u64) -> u64 {
    (value >> low) & ((1u64 << len) - 1)
}

fn bf64_get_sb(value: u64, low: u64, len: u64, shift: u64, bias: u64) -> u64 {
    (bf64_get(value, low, len) + bias) << shift
}

fn bp_get_lsize(bp: &BlkPtr) -> u64 {
    if bp.is_embedded() {
        let etype = bf64_get(bp.prop, 40, 8);
        if etype == 0 {
            bf64_get_sb(bp.prop, 0, 25, 0, 1)
        } else {
            0
        }
    } else {
        bf64_get_sb(bp.prop, 0, SPA_LSIZEBITS, SPA_MINBLOCKSHIFT, 1)
    }
}

fn bp_get_psize(bp: &BlkPtr) -> u64 {
    if bp.is_embedded() {
        bf64_get_sb(bp.prop, 25, 7, 0, 1)
    } else {
        bf64_get_sb(bp.prop, 16, SPA_LSIZEBITS, SPA_MINBLOCKSHIFT, 1)
    }
}

#[cfg(test)]
mod tests {
    use super::{BlkPtr, Dva, ZioCksum, bf64_get, bp_get_lsize, bp_get_psize};

    #[test]
    fn bf64_get_basic() {
        assert_eq!(bf64_get(0b1010, 1, 2), 0b01);
    }

    #[test]
    fn bp_sizes_non_embedded() {
        let mut bp = BlkPtr {
            dvas: [Dva { word: [0; 2] }; 3],
            prop: 0,
            pad: [0; 2],
            phys_birth: 0,
            birth: 0,
            fill: 0,
            cksum: ZioCksum { word: [0; 4] },
        };
        bp.prop |= 4u64 << 0; // lsize bits
        bp.prop |= 5u64 << 16; // psize bits
        assert_eq!(bp_get_lsize(&bp), (4 + 1) << 9);
        assert_eq!(bp_get_psize(&bp), (5 + 1) << 9);
    }
}
