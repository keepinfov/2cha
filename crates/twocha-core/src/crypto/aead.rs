//! # ChaCha20-Poly1305 AEAD
//!
//! Production-ready ChaCha20-Poly1305 implementation using RustCrypto.
//! RFC 8439 compliant.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305 as ChaChaCipher, Nonce,
};

use twocha_protocol::{
    CryptoError, Result, CHACHA20_KEY_SIZE, CHACHA20_NONCE_SIZE, POLY1305_TAG_SIZE,
};

/// ChaCha20-Poly1305 AEAD cipher (RustCrypto implementation)
pub struct ChaCha20Poly1305 {
    cipher: ChaChaCipher,
}

impl ChaCha20Poly1305 {
    /// Create new ChaCha20-Poly1305 instance
    pub fn new(key: &[u8; CHACHA20_KEY_SIZE]) -> Self {
        let cipher = ChaChaCipher::new_from_slice(key).expect("valid key size");
        ChaCha20Poly1305 { cipher }
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
        if ciphertext_with_tag.len() < POLY1305_TAG_SIZE {
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

    #[test]
    fn test_wrong_aad_fails() {
        let key = [42u8; 32];
        let nonce = [1u8; 12];
        let aead = ChaCha20Poly1305::new(&key);

        let ct = aead.encrypt(&nonce, b"secret", b"correct aad").unwrap();
        assert!(aead.decrypt(&nonce, &ct, b"wrong aad").is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [42u8; 32];
        let nonce = [1u8; 12];
        let aead = ChaCha20Poly1305::new(&key);

        let ct = aead.encrypt(&nonce, b"", b"aad").unwrap();
        let decrypted = aead.decrypt(&nonce, &ct, b"aad").unwrap();
        assert!(decrypted.is_empty());
    }
}
