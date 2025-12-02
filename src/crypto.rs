//! # Криптографический модуль
//!
//! ЛУЧШАЯ ПРАКТИКА: Выбор криптографии
//! ChaCha20-Poly1305 AEAD - быстрый, безопасный, простой в реализации
//! Используется в WireGuard, TLS 1.3, SSH
//!
//! ВАЖНО: Это образовательная реализация!
//! Для production используйте ring, RustCrypto

use crate::error::{CryptoError, Result};
use crate::{CHACHA20_KEY_SIZE, CHACHA20_NONCE_SIZE, POLY1305_TAG_SIZE};

// ЛУЧШАЯ ПРАКТИКА: Constant-time операции против timing attacks

/// Constant-time сравнение
#[inline(never)]
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Безопасное обнуление памяти
#[inline(never)]
pub fn secure_zero(data: &mut [u8]) {
    for byte in data.iter_mut() {
        unsafe { std::ptr::write_volatile(byte, 0); }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// ChaCha20 потоковый шифр
pub struct ChaCha20 {
    state: [u32; 16],
}

impl ChaCha20 {
    const CONSTANTS: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

    pub fn new(key: &[u8; CHACHA20_KEY_SIZE], nonce: &[u8; CHACHA20_NONCE_SIZE]) -> Self {
        let mut state = [0u32; 16];
        state[0..4].copy_from_slice(&Self::CONSTANTS);
        
        for i in 0..8 {
            state[4 + i] = u32::from_le_bytes([
                key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3],
            ]);
        }
        
        state[12] = 0;
        for i in 0..3 {
            state[13 + i] = u32::from_le_bytes([
                nonce[i * 4], nonce[i * 4 + 1], nonce[i * 4 + 2], nonce[i * 4 + 3],
            ]);
        }
        
        ChaCha20 { state }
    }

    #[inline(always)]
    fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]); state[d] ^= state[a]; state[d] = state[d].rotate_left(16);
        state[c] = state[c].wrapping_add(state[d]); state[b] ^= state[c]; state[b] = state[b].rotate_left(12);
        state[a] = state[a].wrapping_add(state[b]); state[d] ^= state[a]; state[d] = state[d].rotate_left(8);
        state[c] = state[c].wrapping_add(state[d]); state[b] ^= state[c]; state[b] = state[b].rotate_left(7);
    }

    fn generate_block(&self, counter: u32) -> [u8; 64] {
        let mut working = self.state;
        working[12] = counter;

        for _ in 0..10 {
            Self::quarter_round(&mut working, 0, 4, 8, 12);
            Self::quarter_round(&mut working, 1, 5, 9, 13);
            Self::quarter_round(&mut working, 2, 6, 10, 14);
            Self::quarter_round(&mut working, 3, 7, 11, 15);
            Self::quarter_round(&mut working, 0, 5, 10, 15);
            Self::quarter_round(&mut working, 1, 6, 11, 12);
            Self::quarter_round(&mut working, 2, 7, 8, 13);
            Self::quarter_round(&mut working, 3, 4, 9, 14);
        }

        let mut initial = self.state;
        initial[12] = counter;
        for i in 0..16 { working[i] = working[i].wrapping_add(initial[i]); }

        let mut output = [0u8; 64];
        for i in 0..16 {
            output[i * 4..i * 4 + 4].copy_from_slice(&working[i].to_le_bytes());
        }
        output
    }

    pub fn apply_keystream(&self, data: &mut [u8]) {
        let mut counter = 0u32;
        let mut offset = 0;
        while offset < data.len() {
            let keystream = self.generate_block(counter);
            let block_size = (data.len() - offset).min(64);
            for i in 0..block_size { data[offset + i] ^= keystream[i]; }
            offset += block_size;
            counter = counter.wrapping_add(1);
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut ciphertext = plaintext.to_vec();
        self.apply_keystream(&mut ciphertext);
        ciphertext
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        self.encrypt(ciphertext) // symmetric
    }
}

/// Poly1305 MAC
pub struct Poly1305 {
    r: [u32; 5],
    s: [u32; 4],
    h: [u32; 5],
    buffer: [u8; 16],
    buffer_len: usize,
}

impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        let r_bytes = &key[0..16];
        let t0 = u32::from_le_bytes([r_bytes[0], r_bytes[1], r_bytes[2], r_bytes[3]]);
        let t1 = u32::from_le_bytes([r_bytes[4], r_bytes[5], r_bytes[6], r_bytes[7]]);
        let t2 = u32::from_le_bytes([r_bytes[8], r_bytes[9], r_bytes[10], r_bytes[11]]);
        let t3 = u32::from_le_bytes([r_bytes[12], r_bytes[13], r_bytes[14], r_bytes[15]]);

        let mut r = [0u32; 5];
        r[0] = t0 & 0x03ffffff;
        r[1] = ((t0 >> 26) | (t1 << 6)) & 0x03ffff03;
        r[2] = ((t1 >> 20) | (t2 << 12)) & 0x03ffc0ff;
        r[3] = ((t2 >> 14) | (t3 << 18)) & 0x03f03fff;
        r[4] = (t3 >> 8) & 0x000fffff;

        let s_bytes = &key[16..32];
        let s = [
            u32::from_le_bytes([s_bytes[0], s_bytes[1], s_bytes[2], s_bytes[3]]),
            u32::from_le_bytes([s_bytes[4], s_bytes[5], s_bytes[6], s_bytes[7]]),
            u32::from_le_bytes([s_bytes[8], s_bytes[9], s_bytes[10], s_bytes[11]]),
            u32::from_le_bytes([s_bytes[12], s_bytes[13], s_bytes[14], s_bytes[15]]),
        ];

        Poly1305 { r, s, h: [0; 5], buffer: [0; 16], buffer_len: 0 }
    }

    pub fn update(&mut self, mut data: &[u8]) {
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
        while data.len() >= 16 {
            let block: [u8; 16] = data[..16].try_into().unwrap();
            self.process_block(&block, false);
            data = &data[16..];
        }
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

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

    fn multiply_r(&mut self) {
        let (r, h) = (self.r, self.h);
        let d0 = (h[0] as u64) * (r[0] as u64) + (h[1] as u64) * (r[4] as u64 * 5) + (h[2] as u64) * (r[3] as u64 * 5) + (h[3] as u64) * (r[2] as u64 * 5) + (h[4] as u64) * (r[1] as u64 * 5);
        let mut d1 = (h[0] as u64) * (r[1] as u64) + (h[1] as u64) * (r[0] as u64) + (h[2] as u64) * (r[4] as u64 * 5) + (h[3] as u64) * (r[3] as u64 * 5) + (h[4] as u64) * (r[2] as u64 * 5);
        let mut d2 = (h[0] as u64) * (r[2] as u64) + (h[1] as u64) * (r[1] as u64) + (h[2] as u64) * (r[0] as u64) + (h[3] as u64) * (r[4] as u64 * 5) + (h[4] as u64) * (r[3] as u64 * 5);
        let mut d3 = (h[0] as u64) * (r[3] as u64) + (h[1] as u64) * (r[2] as u64) + (h[2] as u64) * (r[1] as u64) + (h[3] as u64) * (r[0] as u64) + (h[4] as u64) * (r[4] as u64 * 5);
        let mut d4 = (h[0] as u64) * (r[4] as u64) + (h[1] as u64) * (r[3] as u64) + (h[2] as u64) * (r[2] as u64) + (h[3] as u64) * (r[1] as u64) + (h[4] as u64) * (r[0] as u64);

        let mut c: u32;
        c = (d0 >> 26) as u32; self.h[0] = (d0 as u32) & 0x03ffffff; d1 += c as u64;
        c = (d1 >> 26) as u32; self.h[1] = (d1 as u32) & 0x03ffffff; d2 += c as u64;
        c = (d2 >> 26) as u32; self.h[2] = (d2 as u32) & 0x03ffffff; d3 += c as u64;
        c = (d3 >> 26) as u32; self.h[3] = (d3 as u32) & 0x03ffffff; d4 += c as u64;
        c = (d4 >> 26) as u32; self.h[4] = (d4 as u32) & 0x03ffffff;
        self.h[0] = self.h[0].wrapping_add(c * 5);
        c = self.h[0] >> 26; self.h[0] &= 0x03ffffff; self.h[1] = self.h[1].wrapping_add(c);
    }

    pub fn finalize(mut self) -> [u8; POLY1305_TAG_SIZE] {
        if self.buffer_len > 0 {
            let mut final_block = [0u8; 16];
            final_block[..self.buffer_len].copy_from_slice(&self.buffer[..self.buffer_len]);
            final_block[self.buffer_len] = 1;
            self.process_block(&final_block, true);
        }

        let mut h = self.h;
        let mut c = h[1] >> 26; h[1] &= 0x03ffffff; h[2] = h[2].wrapping_add(c);
        c = h[2] >> 26; h[2] &= 0x03ffffff; h[3] = h[3].wrapping_add(c);
        c = h[3] >> 26; h[3] &= 0x03ffffff; h[4] = h[4].wrapping_add(c);
        c = h[4] >> 26; h[4] &= 0x03ffffff; h[0] = h[0].wrapping_add(c * 5);
        c = h[0] >> 26; h[0] &= 0x03ffffff; h[1] = h[1].wrapping_add(c);

        let mut g = [0u32; 5];
        c = 5;
        for i in 0..5 { g[i] = h[i].wrapping_add(c); c = g[i] >> 26; g[i] &= 0x03ffffff; }
        let mask = (c.wrapping_sub(1)) & 0x03ffffff;
        let nmask = !mask;
        for i in 0..5 { h[i] = (h[i] & mask) | (g[i] & nmask); }

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

/// ChaCha20-Poly1305 AEAD
pub struct ChaCha20Poly1305 {
    key: [u8; CHACHA20_KEY_SIZE],
}

impl ChaCha20Poly1305 {
    pub fn new(key: &[u8; CHACHA20_KEY_SIZE]) -> Self {
        ChaCha20Poly1305 { key: *key }
    }

    pub fn encrypt(&self, nonce: &[u8; CHACHA20_NONCE_SIZE], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let mut poly_key = [0u8; 32];
        let chacha = ChaCha20::new(&self.key, nonce);
        let first_block = chacha.encrypt(&[0u8; 32]);
        poly_key.copy_from_slice(&first_block[..32]);

        let mut ciphertext = plaintext.to_vec();
        let mut offset = 0;
        let mut counter = 1u32;
        while offset < ciphertext.len() {
            let keystream = {
                let mut state = [0u32; 16];
                state[0..4].copy_from_slice(&ChaCha20::CONSTANTS);
                for i in 0..8 {
                    state[4 + i] = u32::from_le_bytes([self.key[i*4], self.key[i*4+1], self.key[i*4+2], self.key[i*4+3]]);
                }
                state[12] = counter;
                for i in 0..3 {
                    state[13 + i] = u32::from_le_bytes([nonce[i*4], nonce[i*4+1], nonce[i*4+2], nonce[i*4+3]]);
                }
                let chacha_block = ChaCha20 { state };
                chacha_block.generate_block(0)
            };
            let to_process = (ciphertext.len() - offset).min(64);
            for i in 0..to_process { ciphertext[offset + i] ^= keystream[i]; }
            offset += to_process;
            counter += 1;
        }

        let mut poly = Poly1305::new(&poly_key);
        poly.update(aad);
        if aad.len() % 16 != 0 { poly.update(&[0u8; 16][..16 - (aad.len() % 16)]); }
        poly.update(&ciphertext);
        if ciphertext.len() % 16 != 0 { poly.update(&[0u8; 16][..16 - (ciphertext.len() % 16)]); }
        poly.update(&(aad.len() as u64).to_le_bytes());
        poly.update(&(ciphertext.len() as u64).to_le_bytes());
        let tag = poly.finalize();

        ciphertext.extend_from_slice(&tag);
        secure_zero(&mut poly_key);
        Ok(ciphertext)
    }

    pub fn decrypt(&self, nonce: &[u8; CHACHA20_NONCE_SIZE], ciphertext_with_tag: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if ciphertext_with_tag.len() < POLY1305_TAG_SIZE {
            return Err(CryptoError::AuthenticationFailed.into());
        }
        let (ciphertext, tag) = ciphertext_with_tag.split_at(ciphertext_with_tag.len() - POLY1305_TAG_SIZE);

        let mut poly_key = [0u8; 32];
        let chacha = ChaCha20::new(&self.key, nonce);
        let first_block = chacha.encrypt(&[0u8; 32]);
        poly_key.copy_from_slice(&first_block[..32]);

        let mut poly = Poly1305::new(&poly_key);
        poly.update(aad);
        if aad.len() % 16 != 0 { poly.update(&[0u8; 16][..16 - (aad.len() % 16)]); }
        poly.update(ciphertext);
        if ciphertext.len() % 16 != 0 { poly.update(&[0u8; 16][..16 - (ciphertext.len() % 16)]); }
        poly.update(&(aad.len() as u64).to_le_bytes());
        poly.update(&(ciphertext.len() as u64).to_le_bytes());
        let expected_tag = poly.finalize();

        if !constant_time_compare(&expected_tag, tag) {
            secure_zero(&mut poly_key);
            return Err(CryptoError::AuthenticationFailed.into());
        }

        let mut plaintext = ciphertext.to_vec();
        let mut offset = 0;
        let mut counter = 1u32;
        while offset < plaintext.len() {
            let keystream = {
                let mut state = [0u32; 16];
                state[0..4].copy_from_slice(&ChaCha20::CONSTANTS);
                for i in 0..8 {
                    state[4 + i] = u32::from_le_bytes([self.key[i*4], self.key[i*4+1], self.key[i*4+2], self.key[i*4+3]]);
                }
                state[12] = counter;
                for i in 0..3 {
                    state[13 + i] = u32::from_le_bytes([nonce[i*4], nonce[i*4+1], nonce[i*4+2], nonce[i*4+3]]);
                }
                let chacha_block = ChaCha20 { state };
                chacha_block.generate_block(0)
            };
            let to_process = (plaintext.len() - offset).min(64);
            for i in 0..to_process { plaintext[offset + i] ^= keystream[i]; }
            offset += to_process;
            counter += 1;
        }

        secure_zero(&mut poly_key);
        Ok(plaintext)
    }
}

impl Drop for ChaCha20Poly1305 {
    fn drop(&mut self) { secure_zero(&mut self.key); }
}

// ═══════════════════════════════════════════════════════════════════════════
// CIPHER TRAIT - Unified interface for different AEAD ciphers
// ═══════════════════════════════════════════════════════════════════════════

/// Trait for AEAD ciphers
pub trait Cipher: Send + Sync {
    fn encrypt(&self, nonce: &[u8; CHACHA20_NONCE_SIZE], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, nonce: &[u8; CHACHA20_NONCE_SIZE], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
    fn name(&self) -> &'static str;
}

impl Cipher for ChaCha20Poly1305 {
    fn encrypt(&self, nonce: &[u8; CHACHA20_NONCE_SIZE], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        ChaCha20Poly1305::encrypt(self, nonce, plaintext, aad)
    }
    
    fn decrypt(&self, nonce: &[u8; CHACHA20_NONCE_SIZE], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        ChaCha20Poly1305::decrypt(self, nonce, ciphertext, aad)
    }
    
    fn name(&self) -> &'static str { "ChaCha20-Poly1305" }
}

// ═══════════════════════════════════════════════════════════════════════════
// AES-256-GCM Implementation
// ═══════════════════════════════════════════════════════════════════════════
//
// AES-256-GCM is an alternative AEAD cipher.
// NOTE: This is a simplified educational implementation.
// For production, use a hardware-accelerated library.

/// AES-256-GCM AEAD cipher
/// 
/// WARNING: Software AES is vulnerable to timing attacks!
/// Only use this on systems with AES-NI or in non-security-critical contexts.
pub struct Aes256Gcm {
    key: [u8; 32],
    // Precomputed round keys
    round_keys: [[u8; 16]; 15],
}

impl Aes256Gcm {
    // AES S-box
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

    // Round constants
    const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

    pub fn new(key: &[u8; 32]) -> Self {
        let round_keys = Self::key_expansion(key);
        Aes256Gcm {
            key: *key,
            round_keys,
        }
    }

    fn key_expansion(key: &[u8; 32]) -> [[u8; 16]; 15] {
        let mut round_keys = [[0u8; 16]; 15];
        let mut w = [0u8; 240]; // 60 words * 4 bytes

        // Copy key
        w[..32].copy_from_slice(key);

        // Expand
        for i in 8..60 {
            let mut temp = [w[i*4-4], w[i*4-3], w[i*4-2], w[i*4-1]];
            
            if i % 8 == 0 {
                // RotWord + SubWord + Rcon
                temp = [
                    Self::SBOX[temp[1] as usize] ^ Self::RCON[i/8 - 1],
                    Self::SBOX[temp[2] as usize],
                    Self::SBOX[temp[3] as usize],
                    Self::SBOX[temp[0] as usize],
                ];
            } else if i % 8 == 4 {
                // SubWord only
                temp = [
                    Self::SBOX[temp[0] as usize],
                    Self::SBOX[temp[1] as usize],
                    Self::SBOX[temp[2] as usize],
                    Self::SBOX[temp[3] as usize],
                ];
            }

            for j in 0..4 {
                w[i*4 + j] = w[(i-8)*4 + j] ^ temp[j];
            }
        }

        // Convert to round keys
        for i in 0..15 {
            round_keys[i].copy_from_slice(&w[i*16..(i+1)*16]);
        }

        round_keys
    }

    fn sub_bytes(state: &mut [u8; 16]) {
        for byte in state.iter_mut() {
            *byte = Self::SBOX[*byte as usize];
        }
    }

    fn shift_rows(state: &mut [u8; 16]) {
        let tmp = *state;
        // Row 0: no shift
        // Row 1: shift left 1
        state[1] = tmp[5];
        state[5] = tmp[9];
        state[9] = tmp[13];
        state[13] = tmp[1];
        // Row 2: shift left 2
        state[2] = tmp[10];
        state[6] = tmp[14];
        state[10] = tmp[2];
        state[14] = tmp[6];
        // Row 3: shift left 3
        state[3] = tmp[15];
        state[7] = tmp[3];
        state[11] = tmp[7];
        state[15] = tmp[11];
    }

    fn xtime(x: u8) -> u8 {
        if x & 0x80 != 0 {
            (x << 1) ^ 0x1b
        } else {
            x << 1
        }
    }

    fn mix_columns(state: &mut [u8; 16]) {
        for i in 0..4 {
            let col = i * 4;
            let a = state[col];
            let b = state[col + 1];
            let c = state[col + 2];
            let d = state[col + 3];
            
            let t = a ^ b ^ c ^ d;
            
            state[col] = a ^ t ^ Self::xtime(a ^ b);
            state[col + 1] = b ^ t ^ Self::xtime(b ^ c);
            state[col + 2] = c ^ t ^ Self::xtime(c ^ d);
            state[col + 3] = d ^ t ^ Self::xtime(d ^ a);
        }
    }

    fn add_round_key(state: &mut [u8; 16], round_key: &[u8; 16]) {
        for i in 0..16 {
            state[i] ^= round_key[i];
        }
    }

    fn aes_encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut state = *block;

        // Initial round
        Self::add_round_key(&mut state, &self.round_keys[0]);

        // Main rounds
        for round in 1..14 {
            Self::sub_bytes(&mut state);
            Self::shift_rows(&mut state);
            Self::mix_columns(&mut state);
            Self::add_round_key(&mut state, &self.round_keys[round]);
        }

        // Final round (no MixColumns)
        Self::sub_bytes(&mut state);
        Self::shift_rows(&mut state);
        Self::add_round_key(&mut state, &self.round_keys[14]);

        state
    }

    // GCM multiplication in GF(2^128)
    fn gcm_mult(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
        let mut z = [0u8; 16];
        let mut v = *y;

        for i in 0..128 {
            if (x[i / 8] >> (7 - (i % 8))) & 1 == 1 {
                for j in 0..16 {
                    z[j] ^= v[j];
                }
            }

            let lsb = v[15] & 1;
            for j in (1..16).rev() {
                v[j] = (v[j] >> 1) | ((v[j-1] & 1) << 7);
            }
            v[0] >>= 1;

            if lsb == 1 {
                v[0] ^= 0xe1; // R = 11100001 || 0^120
            }
        }

        z
    }

    fn ghash(&self, h: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
        let mut y = [0u8; 16];

        // Process AAD
        let aad_blocks = (aad.len() + 15) / 16;
        for i in 0..aad_blocks {
            let start = i * 16;
            let end = (start + 16).min(aad.len());
            let mut block = [0u8; 16];
            block[..end-start].copy_from_slice(&aad[start..end]);
            for j in 0..16 { y[j] ^= block[j]; }
            y = Self::gcm_mult(&y, h);
        }

        // Process ciphertext
        let ct_blocks = (ciphertext.len() + 15) / 16;
        for i in 0..ct_blocks {
            let start = i * 16;
            let end = (start + 16).min(ciphertext.len());
            let mut block = [0u8; 16];
            block[..end-start].copy_from_slice(&ciphertext[start..end]);
            for j in 0..16 { y[j] ^= block[j]; }
            y = Self::gcm_mult(&y, h);
        }

        // Length block
        let mut len_block = [0u8; 16];
        let aad_bits = (aad.len() as u64) * 8;
        let ct_bits = (ciphertext.len() as u64) * 8;
        len_block[..8].copy_from_slice(&aad_bits.to_be_bytes());
        len_block[8..].copy_from_slice(&ct_bits.to_be_bytes());
        for j in 0..16 { y[j] ^= len_block[j]; }
        y = Self::gcm_mult(&y, h);

        y
    }

    pub fn encrypt(&self, nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        // H = AES(K, 0^128)
        let h = self.aes_encrypt_block(&[0u8; 16]);

        // J0 = nonce || 0^31 || 1
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;

        // Encrypt plaintext with counter mode starting at J0 + 1
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut counter = j0;
        
        for i in 0..((plaintext.len() + 15) / 16) {
            // Increment counter
            let mut carry = 1u16;
            for j in (12..16).rev() {
                let sum = counter[j] as u16 + carry;
                counter[j] = sum as u8;
                carry = sum >> 8;
            }

            let keystream = self.aes_encrypt_block(&counter);
            let start = i * 16;
            let end = (start + 16).min(plaintext.len());
            for j in start..end {
                ciphertext[j] = plaintext[j] ^ keystream[j - start];
            }
        }

        // Compute GHASH
        let s = self.ghash(&h, aad, &ciphertext);

        // Tag = GHASH ^ AES(K, J0)
        let j0_enc = self.aes_encrypt_block(&j0);
        let mut tag = [0u8; 16];
        for i in 0..16 {
            tag[i] = s[i] ^ j0_enc[i];
        }

        // Append tag
        ciphertext.extend_from_slice(&tag);
        Ok(ciphertext)
    }

    pub fn decrypt(&self, nonce: &[u8; 12], ciphertext_with_tag: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if ciphertext_with_tag.len() < 16 {
            return Err(crate::error::CryptoError::AuthenticationFailed.into());
        }

        let tag_start = ciphertext_with_tag.len() - 16;
        let ciphertext = &ciphertext_with_tag[..tag_start];
        let tag = &ciphertext_with_tag[tag_start..];

        // H = AES(K, 0^128)
        let h = self.aes_encrypt_block(&[0u8; 16]);

        // Verify tag first
        let s = self.ghash(&h, aad, ciphertext);
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;
        let j0_enc = self.aes_encrypt_block(&j0);
        
        let mut expected_tag = [0u8; 16];
        for i in 0..16 {
            expected_tag[i] = s[i] ^ j0_enc[i];
        }

        if !constant_time_compare(tag, &expected_tag) {
            return Err(crate::error::CryptoError::AuthenticationFailed.into());
        }

        // Decrypt
        let mut plaintext = vec![0u8; ciphertext.len()];
        let mut counter = j0;
        
        for i in 0..((ciphertext.len() + 15) / 16) {
            let mut carry = 1u16;
            for j in (12..16).rev() {
                let sum = counter[j] as u16 + carry;
                counter[j] = sum as u8;
                carry = sum >> 8;
            }

            let keystream = self.aes_encrypt_block(&counter);
            let start = i * 16;
            let end = (start + 16).min(ciphertext.len());
            for j in start..end {
                plaintext[j] = ciphertext[j] ^ keystream[j - start];
            }
        }

        Ok(plaintext)
    }
}

impl Cipher for Aes256Gcm {
    fn encrypt(&self, nonce: &[u8; CHACHA20_NONCE_SIZE], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        Aes256Gcm::encrypt(self, nonce, plaintext, aad)
    }
    
    fn decrypt(&self, nonce: &[u8; CHACHA20_NONCE_SIZE], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        Aes256Gcm::decrypt(self, nonce, ciphertext, aad)
    }
    
    fn name(&self) -> &'static str { "AES-256-GCM" }
}

impl Drop for Aes256Gcm {
    fn drop(&mut self) {
        secure_zero(&mut self.key);
        for rk in &mut self.round_keys {
            secure_zero(rk);
        }
    }
}

/// Create cipher from config
pub fn create_cipher(cipher_type: crate::config::CipherSuite, key: &[u8; 32]) -> Box<dyn Cipher> {
    match cipher_type {
        crate::config::CipherSuite::ChaCha20Poly1305 => Box::new(ChaCha20Poly1305::new(key)),
        crate::config::CipherSuite::Aes256Gcm => Box::new(Aes256Gcm::new(key)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let chacha = ChaCha20::new(&key, &nonce);
        let plaintext = b"Hello!";
        let ct = chacha.encrypt(plaintext);
        let pt = chacha.decrypt(&ct);
        assert_eq!(plaintext, &pt[..]);
    }

    #[test]
    fn test_aead() {
        let key = [42u8; 32];
        let nonce = [1u8; 12];
        let aead = ChaCha20Poly1305::new(&key);
        let pt = b"Secret";
        let aad = b"header";
        let ct = aead.encrypt(&nonce, pt, aad).unwrap();
        let decrypted = aead.decrypt(&nonce, &ct, aad).unwrap();
        assert_eq!(pt, &decrypted[..]);
    }

    #[test]
    fn test_aes_gcm() {
        let key = [42u8; 32];
        let nonce = [1u8; 12];
        let aead = Aes256Gcm::new(&key);
        let pt = b"Secret message for AES-GCM test";
        let aad = b"header";
        let ct = aead.encrypt(&nonce, pt, aad).unwrap();
        let decrypted = aead.decrypt(&nonce, &ct, aad).unwrap();
        assert_eq!(pt, &decrypted[..]);
    }

    #[test]
    fn test_aes_gcm_tamper() {
        let key = [42u8; 32];
        let nonce = [1u8; 12];
        let aead = Aes256Gcm::new(&key);
        let pt = b"Secret";
        let aad = b"header";
        let mut ct = aead.encrypt(&nonce, pt, aad).unwrap();
        ct[0] ^= 1; // Tamper
        assert!(aead.decrypt(&nonce, &ct, aad).is_err());
    }
}
