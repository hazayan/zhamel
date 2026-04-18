extern crate alloc;

use alloc::vec::Vec;

use crate::error::{BootError, Result};

pub fn decompress(src: &[u8], expected_size: usize) -> Result<Vec<u8>> {
    if src.len() < 4 {
        return Err(BootError::InvalidData("lz4 header truncated"));
    }
    let encoded_size = u32::from_be_bytes(src[0..4].try_into().unwrap()) as usize;
    if encoded_size + 4 > src.len() {
        return Err(BootError::InvalidData("lz4 encoded size invalid"));
    }
    let src = &src[4..4 + encoded_size];
    let mut dst = Vec::with_capacity(expected_size);
    let mut cursor = 0usize;

    while cursor < src.len() {
        let token = src[cursor];
        cursor += 1;

        let mut lit_len = (token >> 4) as usize;
        if lit_len == 15 {
            loop {
                if cursor >= src.len() {
                    return Err(BootError::InvalidData("lz4 literal length overflow"));
                }
                let val = src[cursor] as usize;
                cursor += 1;
                lit_len = lit_len
                    .checked_add(val)
                    .ok_or(BootError::InvalidData("lz4 length overflow"))?;
                if val != 255 {
                    break;
                }
            }
        }

        if cursor + lit_len > src.len() {
            return Err(BootError::InvalidData("lz4 literal out of range"));
        }
        dst.extend_from_slice(&src[cursor..cursor + lit_len]);
        cursor += lit_len;

        if cursor >= src.len() {
            break;
        }
        if cursor + 2 > src.len() {
            return Err(BootError::InvalidData("lz4 match offset missing"));
        }
        let offset = u16::from_le_bytes([src[cursor], src[cursor + 1]]) as usize;
        cursor += 2;
        if offset == 0 || offset > dst.len() {
            return Err(BootError::InvalidData("lz4 match offset invalid"));
        }

        let mut match_len = (token & 0x0f) as usize;
        if match_len == 15 {
            loop {
                if cursor >= src.len() {
                    return Err(BootError::InvalidData("lz4 match length overflow"));
                }
                let val = src[cursor] as usize;
                cursor += 1;
                match_len = match_len
                    .checked_add(val)
                    .ok_or(BootError::InvalidData("lz4 length overflow"))?;
                if val != 255 {
                    break;
                }
            }
        }
        match_len = match_len
            .checked_add(4)
            .ok_or(BootError::InvalidData("lz4 match length overflow"))?;

        let start = dst
            .len()
            .checked_sub(offset)
            .ok_or(BootError::InvalidData("lz4 offset underflow"))?;
        for idx in 0..match_len {
            let value = dst[start + (idx % offset)];
            dst.push(value);
        }
    }

    if dst.len() != expected_size {
        return Err(BootError::InvalidData("lz4 output size mismatch"));
    }
    Ok(dst)
}

#[cfg(test)]
mod tests {
    use super::decompress;

    #[test]
    fn lz4_literals_only() {
        let src = [0x00, 0x00, 0x00, 0x04, 0x30, b'a', b'b', b'c'];
        let out = decompress(&src, 3).expect("decompress");
        assert_eq!(out, b"abc");
    }
}
