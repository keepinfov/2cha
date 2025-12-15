//! # Cryptographic Module
//!
//! Production-ready cryptographic implementations using RustCrypto.
//!
//! This module provides secure, audited cryptographic primitives:
//!
//! ## Symmetric Encryption (v3/v4)
//! - ChaCha20-Poly1305 (RFC 8439)
//! - AES-256-GCM (NIST SP 800-38D)
//!
//! ## Asymmetric Cryptography (v4)
//! - Ed25519 for identity and signing
//! - X25519 for Diffie-Hellman key exchange
//!
//! ## Key Derivation (v4)
//! - HKDF-SHA256
//! - HKDF-BLAKE2s (for Noise protocol)

mod aead;
mod aes_gcm;
mod util;

// Protocol v4 cryptographic primitives
pub mod identity;
pub mod key_exchange;
pub mod kdf;
pub mod keyfile;

pub use aead::ChaCha20Poly1305;
pub use aes_gcm::Aes256Gcm;
pub use util::{constant_time_compare, secure_zero};

// Re-export commonly used types from v4 modules
pub use identity::{Ed25519KeyPair, Ed25519PublicKey, IdentityError};
pub use key_exchange::{
    X25519StaticKeyPair, X25519EphemeralKeyPair, X25519PublicKey, KeyExchangeError,
};
pub use kdf::{HkdfSha256, HkdfBlake2s, ChainingKey, KdfError};
pub use keyfile::{KeyFile, KeyFileInfo, KeyType, KeyFileError};

use crate::config::CipherSuite;
use twocha_protocol::{Result, CHACHA20_NONCE_SIZE};

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
pub fn create_cipher(cipher_type: CipherSuite, key: &[u8; 32]) -> Box<dyn Cipher> {
    match cipher_type {
        CipherSuite::ChaCha20Poly1305 => Box::new(ChaCha20Poly1305::new(key)),
        CipherSuite::Aes256Gcm => Box::new(Aes256Gcm::new(key)),
    }
}
