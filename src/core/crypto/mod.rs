//! # Cryptographic Module
//!
//! High-performance AEAD implementations.
//!
//! NOTE: This is an educational implementation.
//! For production, consider using ring or RustCrypto.

mod aead;
mod aes_gcm;
mod chacha20;
mod poly1305;
mod util;

pub use aead::ChaCha20Poly1305;
pub use aes_gcm::Aes256Gcm;
pub use chacha20::ChaCha20;
pub use poly1305::Poly1305;
pub use util::{constant_time_compare, secure_zero};

use crate::constants::CHACHA20_NONCE_SIZE;
use crate::core::error::Result;

/// Unified AEAD cipher interface
pub trait Cipher: Send + Sync {
    fn encrypt(
        &self,
        nonce: &[u8; CHACHA20_NONCE_SIZE],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>>;
    fn decrypt(
        &self,
        nonce: &[u8; CHACHA20_NONCE_SIZE],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>>;
    fn name(&self) -> &'static str;
}

impl Cipher for ChaCha20Poly1305 {
    fn encrypt(
        &self,
        nonce: &[u8; CHACHA20_NONCE_SIZE],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        ChaCha20Poly1305::encrypt(self, nonce, plaintext, aad)
    }
    fn decrypt(
        &self,
        nonce: &[u8; CHACHA20_NONCE_SIZE],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        ChaCha20Poly1305::decrypt(self, nonce, ciphertext, aad)
    }
    fn name(&self) -> &'static str {
        "ChaCha20-Poly1305"
    }
}

impl Cipher for Aes256Gcm {
    fn encrypt(
        &self,
        nonce: &[u8; CHACHA20_NONCE_SIZE],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        Aes256Gcm::encrypt(self, nonce, plaintext, aad)
    }
    fn decrypt(
        &self,
        nonce: &[u8; CHACHA20_NONCE_SIZE],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        Aes256Gcm::decrypt(self, nonce, ciphertext, aad)
    }
    fn name(&self) -> &'static str {
        "AES-256-GCM"
    }
}

/// Create cipher from config
#[allow(dead_code)]
pub fn create_cipher(
    cipher_type: crate::core::config::CipherSuite,
    key: &[u8; 32],
) -> Box<dyn Cipher> {
    match cipher_type {
        crate::core::config::CipherSuite::ChaCha20Poly1305 => Box::new(ChaCha20Poly1305::new(key)),
        crate::core::config::CipherSuite::Aes256Gcm => Box::new(Aes256Gcm::new(key)),
    }
}
