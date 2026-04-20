pub struct Sha1 {
    state: [u32; 5],
    buffer: [u8; 64],
    buffer_len: usize,
    length_bits: u64,
}

impl Sha1 {
    pub fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
            buffer: [0u8; 64],
            buffer_len: 0,
            length_bits: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut input = data;
        self.length_bits = self.length_bits.wrapping_add((input.len() as u64) * 8);
        if self.buffer_len > 0 {
            let needed = 64 - self.buffer_len;
            if input.len() >= needed {
                self.buffer[self.buffer_len..64].copy_from_slice(&input[..needed]);
                let block = self.buffer;
                self.transform(&block);
                self.buffer_len = 0;
                input = &input[needed..];
            } else {
                self.buffer[self.buffer_len..self.buffer_len + input.len()].copy_from_slice(input);
                self.buffer_len += input.len();
                return;
            }
        }
        while input.len() >= 64 {
            let block: [u8; 64] = input[..64].try_into().unwrap_or([0u8; 64]);
            self.transform(&block);
            input = &input[64..];
        }
        if !input.is_empty() {
            self.buffer[..input.len()].copy_from_slice(input);
            self.buffer_len = input.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 20] {
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            for byte in &mut self.buffer[self.buffer_len..] {
                *byte = 0;
            }
            let block = self.buffer;
            self.transform(&block);
            self.buffer_len = 0;
        }

        for byte in &mut self.buffer[self.buffer_len..56] {
            *byte = 0;
        }
        self.buffer[56..64].copy_from_slice(&self.length_bits.to_be_bytes());
        let block = self.buffer;
        self.transform(&block);

        let mut out = [0u8; 20];
        for (idx, word) in self.state.iter().enumerate() {
            out[idx * 4..idx * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn transform(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 80];
        for t in 0..16 {
            let start = t * 4;
            w[t] = u32::from_be_bytes(block[start..start + 4].try_into().unwrap_or([0; 4]));
        }
        for t in 16..80 {
            w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];

        for (t, word) in w.iter().enumerate() {
            let (f, k) = match t {
                0..=19 => ((b & c) | ((!b) & d), 0x5a827999),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }
}

#[cfg(test)]
mod tests {
    use super::Sha1;

    #[test]
    fn sha1_empty() {
        let digest = Sha1::new().finalize();
        let expected = [
            0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
            0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn sha1_abc() {
        let mut sha = Sha1::new();
        sha.update(b"abc");
        let digest = sha.finalize();
        let expected = [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
            0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
        ];
        assert_eq!(digest, expected);
    }
}
