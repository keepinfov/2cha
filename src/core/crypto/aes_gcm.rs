//! # AES-256-GCM AEAD
//!
//! Software implementation of AES-256-GCM.

use super::util::*;
use crate::core::error::{CryptoError, Result};

/// AES-256-GCM AEAD cipher
pub struct Aes256Gcm {
    key: [u8; 32],
    round_keys: [[u8; 16]; 15],
}

impl Aes256Gcm {
    const SBOX: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
        0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
        0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
        0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
        0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
        0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
        0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
        0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
        0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
        0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
        0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
        0x16,
    ];

    const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

    /// Create new AES-256-GCM instance
    pub fn new(key: &[u8; 32]) -> Self {
        let round_keys = Self::key_expansion(key);
        Aes256Gcm {
            key: *key,
            round_keys,
        }
    }

    fn key_expansion(key: &[u8; 32]) -> [[u8; 16]; 15] {
        let mut round_keys = [[0u8; 16]; 15];
        let mut w = [0u8; 240];
        w[..32].copy_from_slice(key);

        for i in 8..60 {
            let mut temp = [w[i * 4 - 4], w[i * 4 - 3], w[i * 4 - 2], w[i * 4 - 1]];

            if i % 8 == 0 {
                temp = [
                    Self::SBOX[temp[1] as usize] ^ Self::RCON[i / 8 - 1],
                    Self::SBOX[temp[2] as usize],
                    Self::SBOX[temp[3] as usize],
                    Self::SBOX[temp[0] as usize],
                ];
            } else if i % 8 == 4 {
                temp = [
                    Self::SBOX[temp[0] as usize],
                    Self::SBOX[temp[1] as usize],
                    Self::SBOX[temp[2] as usize],
                    Self::SBOX[temp[3] as usize],
                ];
            }

            for j in 0..4 {
                w[i * 4 + j] = w[(i - 8) * 4 + j] ^ temp[j];
            }
        }

        for i in 0..15 {
            round_keys[i].copy_from_slice(&w[i * 16..(i + 1) * 16]);
        }

        round_keys
    }

    #[inline]
    fn sub_bytes(state: &mut [u8; 16]) {
        for byte in state.iter_mut() {
            *byte = Self::SBOX[*byte as usize];
        }
    }

    #[inline]
    fn shift_rows(state: &mut [u8; 16]) {
        let tmp = *state;
        state[1] = tmp[5];
        state[5] = tmp[9];
        state[9] = tmp[13];
        state[13] = tmp[1];
        state[2] = tmp[10];
        state[6] = tmp[14];
        state[10] = tmp[2];
        state[14] = tmp[6];
        state[3] = tmp[15];
        state[7] = tmp[3];
        state[11] = tmp[7];
        state[15] = tmp[11];
    }

    #[inline]
    fn xtime(x: u8) -> u8 {
        if x & 0x80 != 0 {
            (x << 1) ^ 0x1b
        } else {
            x << 1
        }
    }

    #[inline]
    fn mix_columns(state: &mut [u8; 16]) {
        for i in 0..4 {
            let col = i * 4;
            let (a, b, c, d) = (state[col], state[col + 1], state[col + 2], state[col + 3]);
            let t = a ^ b ^ c ^ d;
            state[col] = a ^ t ^ Self::xtime(a ^ b);
            state[col + 1] = b ^ t ^ Self::xtime(b ^ c);
            state[col + 2] = c ^ t ^ Self::xtime(c ^ d);
            state[col + 3] = d ^ t ^ Self::xtime(d ^ a);
        }
    }

    #[inline]
    fn add_round_key(state: &mut [u8; 16], round_key: &[u8; 16]) {
        for i in 0..16 {
            state[i] ^= round_key[i];
        }
    }

    fn aes_encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut state = *block;
        Self::add_round_key(&mut state, &self.round_keys[0]);

        for round in 1..14 {
            Self::sub_bytes(&mut state);
            Self::shift_rows(&mut state);
            Self::mix_columns(&mut state);
            Self::add_round_key(&mut state, &self.round_keys[round]);
        }

        Self::sub_bytes(&mut state);
        Self::shift_rows(&mut state);
        Self::add_round_key(&mut state, &self.round_keys[14]);
        state
    }

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
                v[j] = (v[j] >> 1) | ((v[j - 1] & 1) << 7);
            }
            v[0] >>= 1;
            if lsb == 1 {
                v[0] ^= 0xe1;
            }
        }
        z
    }

    fn ghash(&self, h: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
        let mut y = [0u8; 16];

        for chunk in aad.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            for j in 0..16 {
                y[j] ^= block[j];
            }
            y = Self::gcm_mult(&y, h);
        }

        for chunk in ciphertext.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            for j in 0..16 {
                y[j] ^= block[j];
            }
            y = Self::gcm_mult(&y, h);
        }

        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
        len_block[8..].copy_from_slice(&((ciphertext.len() as u64) * 8).to_be_bytes());
        for j in 0..16 {
            y[j] ^= len_block[j];
        }
        Self::gcm_mult(&y, h)
    }

    /// Encrypt with authentication
    pub fn encrypt(&self, nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let h = self.aes_encrypt_block(&[0u8; 16]);

        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;

        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut counter = j0;

        for (i, chunk) in plaintext.chunks(16).enumerate() {
            // Increment counter
            for j in (12..16).rev() {
                let (new_val, overflow) = counter[j].overflowing_add(1);
                counter[j] = new_val;
                if !overflow {
                    break;
                }
            }

            let keystream = self.aes_encrypt_block(&counter);
            let start = i * 16;
            for (j, &byte) in chunk.iter().enumerate() {
                ciphertext[start + j] = byte ^ keystream[j];
            }
        }

        let s = self.ghash(&h, aad, &ciphertext);
        let j0_enc = self.aes_encrypt_block(&j0);
        let mut tag = [0u8; 16];
        for i in 0..16 {
            tag[i] = s[i] ^ j0_enc[i];
        }

        ciphertext.extend_from_slice(&tag);
        Ok(ciphertext)
    }

    /// Decrypt and verify
    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        ciphertext_with_tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        if ciphertext_with_tag.len() < 16 {
            return Err(CryptoError::AuthenticationFailed.into());
        }

        let (ciphertext, tag) = ciphertext_with_tag.split_at(ciphertext_with_tag.len() - 16);
        let h = self.aes_encrypt_block(&[0u8; 16]);

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
            return Err(CryptoError::AuthenticationFailed.into());
        }

        let mut plaintext = vec![0u8; ciphertext.len()];
        let mut counter = j0;

        for (i, chunk) in ciphertext.chunks(16).enumerate() {
            for j in (12..16).rev() {
                let (new_val, overflow) = counter[j].overflowing_add(1);
                counter[j] = new_val;
                if !overflow {
                    break;
                }
            }

            let keystream = self.aes_encrypt_block(&counter);
            let start = i * 16;
            for (j, &byte) in chunk.iter().enumerate() {
                plaintext[start + j] = byte ^ keystream[j];
            }
        }

        Ok(plaintext)
    }
}

impl Drop for Aes256Gcm {
    fn drop(&mut self) {
        secure_zero(&mut self.key);
        for rk in &mut self.round_keys {
            secure_zero(rk);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = [42u8; 32];
        let nonce = [1u8; 12];
        let aead = Aes256Gcm::new(&key);
        let plaintext = b"Hello, World!";
        let aad = b"additional data";

        let ciphertext = aead.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = aead.decrypt(&nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }
}
