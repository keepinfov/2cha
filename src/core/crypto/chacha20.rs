//! # ChaCha20 Stream Cipher
//!
//! High-performance ChaCha20 implementation optimized for throughput.

use crate::constants::{CHACHA20_KEY_SIZE, CHACHA20_NONCE_SIZE};

/// ChaCha20 stream cipher (optimized)
pub struct ChaCha20 {
    state: [u32; 16],
}

impl ChaCha20 {
    /// ChaCha20 constants ("expand 32-byte k")
    pub const CONSTANTS: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

    /// Create new ChaCha20 instance with key and nonce
    pub fn new(key: &[u8; CHACHA20_KEY_SIZE], nonce: &[u8; CHACHA20_NONCE_SIZE]) -> Self {
        let mut state = [0u32; 16];

        // Constants
        state[0] = Self::CONSTANTS[0];
        state[1] = Self::CONSTANTS[1];
        state[2] = Self::CONSTANTS[2];
        state[3] = Self::CONSTANTS[3];

        // Key (8 words)
        for i in 0..8 {
            state[4 + i] =
                u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
        }

        // Counter (starts at 0)
        state[12] = 0;

        // Nonce (3 words)
        for i in 0..3 {
            state[13 + i] = u32::from_le_bytes([
                nonce[i * 4],
                nonce[i * 4 + 1],
                nonce[i * 4 + 2],
                nonce[i * 4 + 3],
            ]);
        }

        ChaCha20 { state }
    }

    /// Quarter round function (inlined for performance)
    #[inline(always)]
    fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(16);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(12);

        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(8);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(7);
    }

    /// Generate a single keystream block
    #[inline]
    pub fn generate_block(&self, counter: u32) -> [u8; 64] {
        let mut working = self.state;
        working[12] = counter;

        // 20 rounds = 10 double rounds
        for _ in 0..10 {
            // Column rounds
            Self::quarter_round(&mut working, 0, 4, 8, 12);
            Self::quarter_round(&mut working, 1, 5, 9, 13);
            Self::quarter_round(&mut working, 2, 6, 10, 14);
            Self::quarter_round(&mut working, 3, 7, 11, 15);
            // Diagonal rounds
            Self::quarter_round(&mut working, 0, 5, 10, 15);
            Self::quarter_round(&mut working, 1, 6, 11, 12);
            Self::quarter_round(&mut working, 2, 7, 8, 13);
            Self::quarter_round(&mut working, 3, 4, 9, 14);
        }

        // Add original state
        let mut initial = self.state;
        initial[12] = counter;
        for i in 0..16 {
            working[i] = working[i].wrapping_add(initial[i]);
        }

        // Serialize to bytes
        let mut output = [0u8; 64];
        for i in 0..16 {
            output[i * 4..i * 4 + 4].copy_from_slice(&working[i].to_le_bytes());
        }
        output
    }

    /// Apply keystream to data (encrypt/decrypt)
    #[inline]
    pub fn apply_keystream(&self, data: &mut [u8]) {
        let mut counter = 0u32;
        let mut offset = 0;

        while offset < data.len() {
            let keystream = self.generate_block(counter);
            let remaining = data.len() - offset;
            let block_size = remaining.min(64);

            // XOR with keystream (unrolled for small blocks)
            for i in 0..block_size {
                data[offset + i] ^= keystream[i];
            }

            offset += block_size;
            counter = counter.wrapping_add(1);
        }
    }

    /// Apply keystream starting from a specific counter
    #[inline]
    pub fn apply_keystream_at(&self, data: &mut [u8], start_counter: u32) {
        let mut counter = start_counter;
        let mut offset = 0;

        while offset < data.len() {
            let keystream = self.generate_block(counter);
            let remaining = data.len() - offset;
            let block_size = remaining.min(64);

            for i in 0..block_size {
                data[offset + i] ^= keystream[i];
            }

            offset += block_size;
            counter = counter.wrapping_add(1);
        }
    }

    /// Encrypt plaintext
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut ciphertext = plaintext.to_vec();
        self.apply_keystream(&mut ciphertext);
        ciphertext
    }

    /// Decrypt ciphertext (same as encrypt for stream cipher)
    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        self.encrypt(ciphertext)
    }
}
