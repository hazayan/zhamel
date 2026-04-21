use alloc::vec::Vec;
use core::convert::TryInto;

use crate::error::{BootError, Result};
use crate::zfs::fs::CryptoKeyInfo;

const ZIO_CRYPT_KEY_CURRENT_VERSION: u64 = 1;
const ZIO_CRYPT_AES_256_CCM: u64 = 5;
const ZIO_CRYPT_AES_256_GCM: u64 = 8;
const AES_256_KEY_LEN: usize = 32;
const SHA512_HMAC_KEY_LEN: usize = 64;
const WRAPPING_IV_LEN: usize = 12;
const WRAPPING_MAC_LEN: usize = 16;

pub fn validate_wrapping_key(wrapping_key: &[u8], info: &CryptoKeyInfo) -> Result<()> {
    if wrapping_key.len() != AES_256_KEY_LEN {
        return Err(BootError::InvalidData("zfs wrapping key length invalid"));
    }
    if info.crypt != ZIO_CRYPT_AES_256_CCM && info.crypt != ZIO_CRYPT_AES_256_GCM {
        log::warn!(
            "zfs: unsupported passphrase validation crypto suite {}",
            info.crypt
        );
        return Err(BootError::Unsupported(
            "zfs passphrase validation crypto suite",
        ));
    }
    if info.version != 0 && info.version != ZIO_CRYPT_KEY_CURRENT_VERSION {
        return Err(BootError::Unsupported("zfs crypto key version"));
    }
    if info.master_key.len() != AES_256_KEY_LEN {
        return Err(BootError::InvalidData("zfs encrypted master key invalid"));
    }
    if info.hmac_key.len() != SHA512_HMAC_KEY_LEN {
        return Err(BootError::InvalidData("zfs encrypted hmac key invalid"));
    }
    if info.iv.len() != WRAPPING_IV_LEN {
        return Err(BootError::InvalidData("zfs wrapping iv invalid"));
    }
    if info.mac.len() != WRAPPING_MAC_LEN {
        return Err(BootError::InvalidData("zfs wrapping mac invalid"));
    }

    let mut aad = Vec::new();
    aad.extend_from_slice(&info.guid.to_le_bytes());
    if info.version != 0 {
        aad.extend_from_slice(&info.crypt.to_le_bytes());
        aad.extend_from_slice(&info.version.to_le_bytes());
    }

    let mut ciphertext = Vec::with_capacity(AES_256_KEY_LEN + SHA512_HMAC_KEY_LEN);
    ciphertext.extend_from_slice(&info.master_key);
    ciphertext.extend_from_slice(&info.hmac_key);
    let valid = match info.crypt {
        ZIO_CRYPT_AES_256_CCM => {
            aes256_ccm_tag_matches(wrapping_key, &info.iv, &aad, &ciphertext, &info.mac)
        }
        ZIO_CRYPT_AES_256_GCM => {
            aes256_gcm_tag_matches(wrapping_key, &info.iv, &aad, &ciphertext, &info.mac)
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(BootError::InvalidData("zfs passphrase incorrect"))
    }
}

fn aes256_ccm_tag_matches(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> bool {
    if nonce.len() != 12 || tag.len() != 16 || ciphertext.len() >= (1 << 24) {
        return false;
    }
    let round_keys = aes256_expand_key(key);
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    for (idx, chunk) in ciphertext.chunks(16).enumerate() {
        let stream = ccm_ctr_block(&round_keys, nonce, (idx + 1) as u32);
        for byte_idx in 0..chunk.len() {
            plaintext.push(chunk[byte_idx] ^ stream[byte_idx]);
        }
    }
    let mac = ccm_cbc_mac(&round_keys, nonce, aad, &plaintext);
    let s0 = ccm_ctr_block(&round_keys, nonce, 0);
    let mut expected = [0u8; 16];
    for idx in 0..16 {
        expected[idx] = mac[idx] ^ s0[idx];
    }
    constant_time_eq(&expected, tag)
}

fn ccm_cbc_mac(round_keys: &[u32; 60], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> [u8; 16] {
    let mut x = [0u8; 16];
    let mut b0 = [0u8; 16];
    b0[0] = if aad.is_empty() { 0x39 } else { 0x79 };
    b0[1..13].copy_from_slice(nonce);
    let len = plaintext.len() as u32;
    b0[13] = ((len >> 16) & 0xff) as u8;
    b0[14] = ((len >> 8) & 0xff) as u8;
    b0[15] = (len & 0xff) as u8;
    ccm_mac_block(round_keys, &mut x, &b0);

    if !aad.is_empty() {
        let mut aad_prefix = Vec::with_capacity(2 + aad.len());
        aad_prefix.extend_from_slice(&(aad.len() as u16).to_be_bytes());
        aad_prefix.extend_from_slice(aad);
        for chunk in aad_prefix.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            ccm_mac_block(round_keys, &mut x, &block);
        }
    }

    for chunk in plaintext.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        ccm_mac_block(round_keys, &mut x, &block);
    }
    x
}

fn ccm_mac_block(round_keys: &[u32; 60], x: &mut [u8; 16], block: &[u8; 16]) {
    for idx in 0..16 {
        x[idx] ^= block[idx];
    }
    *x = aes256_encrypt_block(round_keys, x);
}

fn ccm_ctr_block(round_keys: &[u32; 60], nonce: &[u8], counter: u32) -> [u8; 16] {
    let mut block = [0u8; 16];
    block[0] = 0x02;
    block[1..13].copy_from_slice(nonce);
    block[13] = ((counter >> 16) & 0xff) as u8;
    block[14] = ((counter >> 8) & 0xff) as u8;
    block[15] = (counter & 0xff) as u8;
    aes256_encrypt_block(round_keys, &block)
}

fn aes256_gcm_tag_matches(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> bool {
    let round_keys = aes256_expand_key(key);
    let h = aes256_encrypt_block(&round_keys, &[0u8; 16]);
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(iv);
    j0[15] = 1;
    let s = ghash(&h, aad, ciphertext);
    let encrypted_j0 = aes256_encrypt_block(&round_keys, &j0);
    let mut expected = [0u8; 16];
    for idx in 0..16 {
        expected[idx] = encrypted_j0[idx] ^ s[idx];
    }
    constant_time_eq(&expected, tag)
}

fn constant_time_eq(lhs: &[u8], rhs: &[u8]) -> bool {
    if lhs.len() != rhs.len() {
        return false;
    }
    let mut diff = 0u8;
    for idx in 0..lhs.len() {
        diff |= lhs[idx] ^ rhs[idx];
    }
    diff == 0
}

fn ghash(h: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let h = u128::from_be_bytes(*h);
    let mut y = 0u128;
    for chunk in aad.chunks(16) {
        y ^= padded_block(chunk);
        y = gf_mul(y, h);
    }
    for chunk in ciphertext.chunks(16) {
        y ^= padded_block(chunk);
        y = gf_mul(y, h);
    }
    let mut lengths = [0u8; 16];
    lengths[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    lengths[8..].copy_from_slice(&((ciphertext.len() as u64) * 8).to_be_bytes());
    y ^= u128::from_be_bytes(lengths);
    y = gf_mul(y, h);
    y.to_be_bytes()
}

fn padded_block(chunk: &[u8]) -> u128 {
    let mut block = [0u8; 16];
    block[..chunk.len()].copy_from_slice(chunk);
    u128::from_be_bytes(block)
}

fn gf_mul(x: u128, mut v: u128) -> u128 {
    let mut z = 0u128;
    for bit in 0..128 {
        if ((x >> (127 - bit)) & 1) != 0 {
            z ^= v;
        }
        let lsb = v & 1;
        v >>= 1;
        if lsb != 0 {
            v ^= 0xe1000000000000000000000000000000u128;
        }
    }
    z
}

fn aes256_expand_key(key: &[u8]) -> [u32; 60] {
    let mut w = [0u32; 60];
    for idx in 0..8 {
        w[idx] = u32::from_be_bytes(key[idx * 4..idx * 4 + 4].try_into().unwrap());
    }
    for idx in 8..60 {
        let mut temp = w[idx - 1];
        if idx % 8 == 0 {
            temp = sub_word(rot_word(temp)) ^ ((RCON[(idx / 8) - 1] as u32) << 24);
        } else if idx % 8 == 4 {
            temp = sub_word(temp);
        }
        w[idx] = w[idx - 8] ^ temp;
    }
    w
}

fn aes256_encrypt_block(round_keys: &[u32; 60], input: &[u8; 16]) -> [u8; 16] {
    let mut state = *input;
    add_round_key(&mut state, round_keys, 0);
    for round in 1..14 {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, round_keys, round);
    }
    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, round_keys, 14);
    state
}

fn add_round_key(state: &mut [u8; 16], round_keys: &[u32; 60], round: usize) {
    for col in 0..4 {
        let word = round_keys[round * 4 + col].to_be_bytes();
        for row in 0..4 {
            state[col * 4 + row] ^= word[row];
        }
    }
}

fn sub_bytes(state: &mut [u8; 16]) {
    for byte in state {
        *byte = SBOX[*byte as usize];
    }
}

fn shift_rows(state: &mut [u8; 16]) {
    let old = *state;
    for row in 0..4 {
        for col in 0..4 {
            state[col * 4 + row] = old[((col + row) % 4) * 4 + row];
        }
    }
}

fn mix_columns(state: &mut [u8; 16]) {
    for col in 0..4 {
        let idx = col * 4;
        let a0 = state[idx];
        let a1 = state[idx + 1];
        let a2 = state[idx + 2];
        let a3 = state[idx + 3];
        state[idx] = gmul2(a0) ^ gmul3(a1) ^ a2 ^ a3;
        state[idx + 1] = a0 ^ gmul2(a1) ^ gmul3(a2) ^ a3;
        state[idx + 2] = a0 ^ a1 ^ gmul2(a2) ^ gmul3(a3);
        state[idx + 3] = gmul3(a0) ^ a1 ^ a2 ^ gmul2(a3);
    }
}

fn gmul2(value: u8) -> u8 {
    let shifted = value << 1;
    if (value & 0x80) != 0 {
        shifted ^ 0x1b
    } else {
        shifted
    }
}

fn gmul3(value: u8) -> u8 {
    gmul2(value) ^ value
}

fn rot_word(value: u32) -> u32 {
    value.rotate_left(8)
}

fn sub_word(value: u32) -> u32 {
    let bytes = value.to_be_bytes();
    u32::from_be_bytes([
        SBOX[bytes[0] as usize],
        SBOX[bytes[1] as usize],
        SBOX[bytes[2] as usize],
        SBOX[bytes[3] as usize],
    ])
}

const RCON: [u8; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

#[cfg(test)]
mod tests {
    use super::{
        aes256_ccm_tag_matches, aes256_encrypt_block, aes256_expand_key, aes256_gcm_tag_matches,
    };

    #[test]
    fn aes256_encrypt_block_nist_vector() {
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let input = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let expected = [
            0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1,
            0x81, 0xf8,
        ];
        let round_keys = aes256_expand_key(&key);
        assert_eq!(aes256_encrypt_block(&round_keys, &input), expected);
    }

    #[test]
    fn aes256_gcm_tag_nist_vector() {
        let key = [0u8; 32];
        let iv = [0u8; 12];
        let ciphertext = [
            0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3,
            0x9d, 0x18,
        ];
        let tag = [
            0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a,
            0xb9, 0x19,
        ];
        assert!(aes256_gcm_tag_matches(&key, &iv, &[], &ciphertext, &tag));
    }

    #[test]
    fn aes256_ccm_tag_vector() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let ciphertext = [
            0xc1, 0x94, 0x40, 0x44, 0xc8, 0xe7, 0xaa, 0x95, 0xd2, 0xde, 0x95, 0x13, 0xc7, 0xf3,
            0xdd, 0x8c,
        ];
        let tag = [
            0x4b, 0x0a, 0x3e, 0x5e, 0x51, 0xf1, 0x51, 0xeb, 0x0f, 0xfa, 0xe7, 0xc4, 0x3d, 0x01,
            0x0f, 0xdb,
        ];
        assert!(aes256_ccm_tag_matches(&key, &nonce, &[], &ciphertext, &tag));
    }
}
