extern crate alloc;

use alloc::vec::Vec;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct MbrPartition {
    pub index: u8,
    pub type_id: u8,
    pub first_lba: u32,
    pub size_lba: u32,
}

pub fn parse_mbr(buf: &[u8]) -> Option<Vec<MbrPartition>> {
    if buf.len() < 512 {
        return None;
    }
    if buf[510] != 0x55 || buf[511] != 0xAA {
        return None;
    }
    let mut parts = Vec::new();
    let base = 446;
    for idx in 0..4u8 {
        let off = base + (idx as usize) * 16;
        let type_id = buf[off + 4];
        let first_lba =
            u32::from_le_bytes([buf[off + 8], buf[off + 9], buf[off + 10], buf[off + 11]]);
        let size_lba =
            u32::from_le_bytes([buf[off + 12], buf[off + 13], buf[off + 14], buf[off + 15]]);
        if type_id == 0 || size_lba == 0 {
            continue;
        }
        parts.push(MbrPartition {
            index: idx + 1,
            type_id,
            first_lba,
            size_lba,
        });
    }
    Some(parts)
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    extern crate std;

    use super::parse_mbr;

    #[test]
    fn test_parse_mbr_single_partition() {
        let mut buf = alloc::vec![0u8; 512];
        buf[510] = 0x55;
        buf[511] = 0xAA;
        let off = 446;
        buf[off + 4] = 0xA5;
        buf[off + 8..off + 12].copy_from_slice(&1u32.to_le_bytes());
        buf[off + 12..off + 16].copy_from_slice(&2048u32.to_le_bytes());
        let parts = parse_mbr(&buf).expect("parts");
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].index, 1);
        assert_eq!(parts[0].type_id, 0xA5);
        assert_eq!(parts[0].first_lba, 1);
        assert_eq!(parts[0].size_lba, 2048);
    }

    #[test]
    fn test_parse_mbr_missing_signature() {
        let buf = alloc::vec![0u8; 512];
        assert!(parse_mbr(&buf).is_none());
    }

    #[test]
    fn test_parse_mbr_skips_empty() {
        let mut buf = alloc::vec![0u8; 512];
        buf[510] = 0x55;
        buf[511] = 0xAA;
        let parts = parse_mbr(&buf).expect("parts");
        assert!(parts.is_empty());
    }
}
