//! # Poly1305 Message Authentication Code
//!
//! High-performance Poly1305 MAC implementation.

use crate::constants::POLY1305_TAG_SIZE;

/// Poly1305 message authentication code
pub struct Poly1305 {
    r: [u32; 5],
    s: [u32; 4],
    h: [u32; 5],
    buffer: [u8; 16],
    buffer_len: usize,
}

impl Poly1305 {
    /// Create new Poly1305 instance with 32-byte key
    pub fn new(key: &[u8; 32]) -> Self {
        let r_bytes = &key[0..16];
        let t0 = u32::from_le_bytes([r_bytes[0], r_bytes[1], r_bytes[2], r_bytes[3]]);
        let t1 = u32::from_le_bytes([r_bytes[4], r_bytes[5], r_bytes[6], r_bytes[7]]);
        let t2 = u32::from_le_bytes([r_bytes[8], r_bytes[9], r_bytes[10], r_bytes[11]]);
        let t3 = u32::from_le_bytes([r_bytes[12], r_bytes[13], r_bytes[14], r_bytes[15]]);

        // Clamp r
        let r = [
            t0 & 0x03ffffff,
            ((t0 >> 26) | (t1 << 6)) & 0x03ffff03,
            ((t1 >> 20) | (t2 << 12)) & 0x03ffc0ff,
            ((t2 >> 14) | (t3 << 18)) & 0x03f03fff,
            (t3 >> 8) & 0x000fffff,
        ];

        let s_bytes = &key[16..32];
        let s = [
            u32::from_le_bytes([s_bytes[0], s_bytes[1], s_bytes[2], s_bytes[3]]),
            u32::from_le_bytes([s_bytes[4], s_bytes[5], s_bytes[6], s_bytes[7]]),
            u32::from_le_bytes([s_bytes[8], s_bytes[9], s_bytes[10], s_bytes[11]]),
            u32::from_le_bytes([s_bytes[12], s_bytes[13], s_bytes[14], s_bytes[15]]),
        ];

        Poly1305 {
            r,
            s,
            h: [0; 5],
            buffer: [0; 16],
            buffer_len: 0,
        }
    }

    /// Update MAC with additional data
    pub fn update(&mut self, mut data: &[u8]) {
        // Handle buffered data
        if self.buffer_len > 0 {
            let needed = 16 - self.buffer_len;
            let take = data.len().min(needed);
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&data[..take]);
            self.buffer_len += take;
            data = &data[take..];

            if self.buffer_len == 16 {
                self.process_block(&self.buffer.clone(), false);
                self.buffer_len = 0;
            }
        }

        // Process full blocks
        while data.len() >= 16 {
            let block: [u8; 16] = data[..16].try_into().unwrap();
            self.process_block(&block, false);
            data = &data[16..];
        }

        // Buffer remaining
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    #[inline]
    fn process_block(&mut self, block: &[u8; 16], is_final: bool) {
        let hibit = if is_final { 0 } else { 1u32 << 24 };

        let t0 = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
        let t1 = u32::from_le_bytes([block[4], block[5], block[6], block[7]]);
        let t2 = u32::from_le_bytes([block[8], block[9], block[10], block[11]]);
        let t3 = u32::from_le_bytes([block[12], block[13], block[14], block[15]]);

        self.h[0] = self.h[0].wrapping_add(t0 & 0x03ffffff);
        self.h[1] = self.h[1].wrapping_add(((t0 >> 26) | (t1 << 6)) & 0x03ffffff);
        self.h[2] = self.h[2].wrapping_add(((t1 >> 20) | (t2 << 12)) & 0x03ffffff);
        self.h[3] = self.h[3].wrapping_add(((t2 >> 14) | (t3 << 18)) & 0x03ffffff);
        self.h[4] = self.h[4].wrapping_add((t3 >> 8) | hibit);

        self.multiply_r();
    }

    #[inline]
    fn multiply_r(&mut self) {
        let (r, h) = (self.r, self.h);

        let d0 = (h[0] as u64) * (r[0] as u64)
            + (h[1] as u64) * (r[4] as u64 * 5)
            + (h[2] as u64) * (r[3] as u64 * 5)
            + (h[3] as u64) * (r[2] as u64 * 5)
            + (h[4] as u64) * (r[1] as u64 * 5);

        let mut d1 = (h[0] as u64) * (r[1] as u64)
            + (h[1] as u64) * (r[0] as u64)
            + (h[2] as u64) * (r[4] as u64 * 5)
            + (h[3] as u64) * (r[3] as u64 * 5)
            + (h[4] as u64) * (r[2] as u64 * 5);

        let mut d2 = (h[0] as u64) * (r[2] as u64)
            + (h[1] as u64) * (r[1] as u64)
            + (h[2] as u64) * (r[0] as u64)
            + (h[3] as u64) * (r[4] as u64 * 5)
            + (h[4] as u64) * (r[3] as u64 * 5);

        let mut d3 = (h[0] as u64) * (r[3] as u64)
            + (h[1] as u64) * (r[2] as u64)
            + (h[2] as u64) * (r[1] as u64)
            + (h[3] as u64) * (r[0] as u64)
            + (h[4] as u64) * (r[4] as u64 * 5);

        let mut d4 = (h[0] as u64) * (r[4] as u64)
            + (h[1] as u64) * (r[3] as u64)
            + (h[2] as u64) * (r[2] as u64)
            + (h[3] as u64) * (r[1] as u64)
            + (h[4] as u64) * (r[0] as u64);

        let mut c: u32;
        c = (d0 >> 26) as u32;
        self.h[0] = (d0 as u32) & 0x03ffffff;
        d1 += c as u64;
        c = (d1 >> 26) as u32;
        self.h[1] = (d1 as u32) & 0x03ffffff;
        d2 += c as u64;
        c = (d2 >> 26) as u32;
        self.h[2] = (d2 as u32) & 0x03ffffff;
        d3 += c as u64;
        c = (d3 >> 26) as u32;
        self.h[3] = (d3 as u32) & 0x03ffffff;
        d4 += c as u64;
        c = (d4 >> 26) as u32;
        self.h[4] = (d4 as u32) & 0x03ffffff;
        self.h[0] = self.h[0].wrapping_add(c * 5);
        c = self.h[0] >> 26;
        self.h[0] &= 0x03ffffff;
        self.h[1] = self.h[1].wrapping_add(c);
    }

    /// Finalize and return the authentication tag
    pub fn finalize(mut self) -> [u8; POLY1305_TAG_SIZE] {
        if self.buffer_len > 0 {
            let mut final_block = [0u8; 16];
            final_block[..self.buffer_len].copy_from_slice(&self.buffer[..self.buffer_len]);
            final_block[self.buffer_len] = 1;
            self.process_block(&final_block, true);
        }

        // Final reduction
        let mut h = self.h;
        let mut c = h[1] >> 26;
        h[1] &= 0x03ffffff;
        h[2] = h[2].wrapping_add(c);
        c = h[2] >> 26;
        h[2] &= 0x03ffffff;
        h[3] = h[3].wrapping_add(c);
        c = h[3] >> 26;
        h[3] &= 0x03ffffff;
        h[4] = h[4].wrapping_add(c);
        c = h[4] >> 26;
        h[4] &= 0x03ffffff;
        h[0] = h[0].wrapping_add(c * 5);
        c = h[0] >> 26;
        h[0] &= 0x03ffffff;
        h[1] = h[1].wrapping_add(c);

        let mut g = [0u32; 5];
        c = 5;
        for i in 0..5 {
            g[i] = h[i].wrapping_add(c);
            c = g[i] >> 26;
            g[i] &= 0x03ffffff;
        }

        let mask = (c.wrapping_sub(1)) & 0x03ffffff;
        let nmask = !mask;
        for i in 0..5 {
            h[i] = (h[i] & mask) | (g[i] & nmask);
        }

        let mut f0 = ((h[0]) | (h[1] << 26)) as u64;
        let mut f1 = ((h[1] >> 6) | (h[2] << 20)) as u64;
        let mut f2 = ((h[2] >> 12) | (h[3] << 14)) as u64;
        let mut f3 = ((h[3] >> 18) | (h[4] << 8)) as u64;

        f0 = f0.wrapping_add(self.s[0] as u64);
        f1 = f1.wrapping_add(self.s[1] as u64);
        f2 = f2.wrapping_add(self.s[2] as u64);
        f3 = f3.wrapping_add(self.s[3] as u64);
        f1 = f1.wrapping_add(f0 >> 32);
        f2 = f2.wrapping_add(f1 >> 32);
        f3 = f3.wrapping_add(f2 >> 32);

        let mut tag = [0u8; 16];
        tag[0..4].copy_from_slice(&(f0 as u32).to_le_bytes());
        tag[4..8].copy_from_slice(&(f1 as u32).to_le_bytes());
        tag[8..12].copy_from_slice(&(f2 as u32).to_le_bytes());
        tag[12..16].copy_from_slice(&(f3 as u32).to_le_bytes());
        tag
    }
}
