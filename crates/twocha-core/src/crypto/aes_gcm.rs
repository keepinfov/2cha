//! # AES-256-GCM AEAD
//!
//! Production-ready AES-256-GCM implementation using RustCrypto.
//! NIST SP 800-38D compliant.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm as AesGcmCipher, Nonce,
};
use zeroize::ZeroizeOnDrop;

use twocha_protocol::{CryptoError, Result, CHACHA20_NONCE_SIZE}; // 12 bytes, same for GCM

const AES_GCM_TAG_SIZE: usize = 16;
const AES_256_KEY_SIZE: usize = 32;

/// AES-256-GCM AEAD cipher (RustCrypto implementation)
#[derive(ZeroizeOnDrop)]
pub struct Aes256Gcm {
    #[zeroize(skip)]
    cipher: AesGcmCipher,
    key: [u8; AES_256_KEY_SIZE],
}

impl Aes256Gcm {
    /// Create new AES-256-GCM instance
    pub fn new(key: &[u8; AES_256_KEY_SIZE]) -> Self {
        let cipher = AesGcmCipher::new_from_slice(key).expect("valid key size");
        Aes256Gcm { cipher, key: *key }
    }

    /// Encrypt with authentication
    pub fn encrypt(
        &self,
        nonce: &[u8; CHACHA20_NONCE_SIZE],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);
        let payload = Payload {
            msg: plaintext,
            aad,
        };

        self.cipher
            .encrypt(nonce, payload)
            .map_err(|_| CryptoError::EncryptionFailed.into())
    }

    /// Decrypt and verify
    pub fn decrypt(
        &self,
        nonce: &[u8; CHACHA20_NONCE_SIZE],
        ciphertext_with_tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        if ciphertext_with_tag.len() < AES_GCM_TAG_SIZE {
            return Err(CryptoError::AuthenticationFailed.into());
        }

        let nonce = Nonce::from_slice(nonce);
        let payload = Payload {
            msg: ciphertext_with_tag,
            aad,
        };

        self.cipher
            .decrypt(nonce, payload)
            .map_err(|_| CryptoError::AuthenticationFailed.into())
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

    #[test]
    fn test_aes_gcm_tamper_detection() {
        let key = [42u8; 32];
        let nonce = [1u8; 12];
        let aead = Aes256Gcm::new(&key);

        let mut ct = aead.encrypt(&nonce, b"secret", b"").unwrap();
        ct[0] ^= 1; // Tamper

        assert!(aead.decrypt(&nonce, &ct, b"").is_err());
    }

    #[test]
    fn test_aes_gcm_wrong_aad_fails() {
        let key = [42u8; 32];
        let nonce = [1u8; 12];
        let aead = Aes256Gcm::new(&key);

        let ct = aead.encrypt(&nonce, b"secret", b"correct aad").unwrap();
        assert!(aead.decrypt(&nonce, &ct, b"wrong aad").is_err());
    }

    #[test]
    fn test_aes_gcm_empty_plaintext() {
        let key = [42u8; 32];
        let nonce = [1u8; 12];
        let aead = Aes256Gcm::new(&key);

        let ct = aead.encrypt(&nonce, b"", b"aad").unwrap();
        let decrypted = aead.decrypt(&nonce, &ct, b"aad").unwrap();
        assert!(decrypted.is_empty());
    }
}
