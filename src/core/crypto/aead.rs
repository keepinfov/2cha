//! # AEAD Ciphers
//!
//! ChaCha20-Poly1305 AEAD implementation.

use super::chacha20::ChaCha20;
use super::poly1305::Poly1305;
use super::util::*;
use crate::constants::{CHACHA20_KEY_SIZE, CHACHA20_NONCE_SIZE, POLY1305_TAG_SIZE};
use crate::core::error::{CryptoError, Result};

/// ChaCha20-Poly1305 AEAD cipher
pub struct ChaCha20Poly1305 {
    key: [u8; CHACHA20_KEY_SIZE],
}

#[allow(clippy::manual_is_multiple_of)]
impl ChaCha20Poly1305 {
    /// Create new ChaCha20-Poly1305 instance
    pub fn new(key: &[u8; CHACHA20_KEY_SIZE]) -> Self {
        ChaCha20Poly1305 { key: *key }
    }

    /// Encrypt with authentication
    pub fn encrypt(
        &self,
        nonce: &[u8; CHACHA20_NONCE_SIZE],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        let chacha = ChaCha20::new(&self.key, nonce);

        // Generate Poly1305 key from first block
        let mut poly_key = [0u8; 32];
        let first_block = chacha.generate_block(0);
        poly_key.copy_from_slice(&first_block[..32]);

        // Encrypt plaintext starting from counter 1
        let mut ciphertext = plaintext.to_vec();
        chacha.apply_keystream_at(&mut ciphertext, 1);

        // Compute tag
        let mut poly = Poly1305::new(&poly_key);
        poly.update(aad);
        if aad.len() % 16 != 0 {
            poly.update(&[0u8; 16][..16 - (aad.len() % 16)]);
        }
        poly.update(&ciphertext);
        if ciphertext.len() % 16 != 0 {
            poly.update(&[0u8; 16][..16 - (ciphertext.len() % 16)]);
        }
        poly.update(&(aad.len() as u64).to_le_bytes());
        poly.update(&(ciphertext.len() as u64).to_le_bytes());
        let tag = poly.finalize();

        ciphertext.extend_from_slice(&tag);
        secure_zero(&mut poly_key);
        Ok(ciphertext)
    }

    /// Decrypt and verify
    pub fn decrypt(
        &self,
        nonce: &[u8; CHACHA20_NONCE_SIZE],
        ciphertext_with_tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        if ciphertext_with_tag.len() < POLY1305_TAG_SIZE {
            return Err(CryptoError::AuthenticationFailed.into());
        }

        let (ciphertext, tag) =
            ciphertext_with_tag.split_at(ciphertext_with_tag.len() - POLY1305_TAG_SIZE);
        let chacha = ChaCha20::new(&self.key, nonce);

        // Generate Poly1305 key
        let mut poly_key = [0u8; 32];
        let first_block = chacha.generate_block(0);
        poly_key.copy_from_slice(&first_block[..32]);

        // Verify tag
        let mut poly = Poly1305::new(&poly_key);
        poly.update(aad);
        if aad.len() % 16 != 0 {
            poly.update(&[0u8; 16][..16 - (aad.len() % 16)]);
        }
        poly.update(ciphertext);
        if ciphertext.len() % 16 != 0 {
            poly.update(&[0u8; 16][..16 - (ciphertext.len() % 16)]);
        }
        poly.update(&(aad.len() as u64).to_le_bytes());
        poly.update(&(ciphertext.len() as u64).to_le_bytes());
        let expected_tag = poly.finalize();

        if !constant_time_compare(&expected_tag, tag) {
            secure_zero(&mut poly_key);
            return Err(CryptoError::AuthenticationFailed.into());
        }

        // Decrypt
        let mut plaintext = ciphertext.to_vec();
        chacha.apply_keystream_at(&mut plaintext, 1);

        secure_zero(&mut poly_key);
        Ok(plaintext)
    }
}

impl Drop for ChaCha20Poly1305 {
    fn drop(&mut self) {
        secure_zero(&mut self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_poly1305_roundtrip() {
        let key = [42u8; 32];
        let nonce = [1u8; 12];
        let aead = ChaCha20Poly1305::new(&key);
        let plaintext = b"Hello, World!";
        let aad = b"additional data";

        let ciphertext = aead.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = aead.decrypt(&nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_tamper_detection() {
        let key = [42u8; 32];
        let nonce = [1u8; 12];
        let aead = ChaCha20Poly1305::new(&key);

        let mut ct = aead.encrypt(&nonce, b"secret", b"").unwrap();
        ct[0] ^= 1; // Tamper

        assert!(aead.decrypt(&nonce, &ct, b"").is_err());
    }
}
