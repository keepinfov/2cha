//! # X25519 Key Exchange Module
//!
//! Provides X25519 Diffie-Hellman key exchange for protocol v4.
//!
//! X25519 keys are used for:
//! - Ephemeral key exchange during handshake
//! - Session key derivation
//! - Perfect Forward Secrecy (PFS)

use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use rand_core::OsRng;
use zeroize::{Zeroize, Zeroizing};
use std::fmt;

/// Size of X25519 private key in bytes
pub const X25519_PRIVATE_KEY_SIZE: usize = 32;

/// Size of X25519 public key in bytes
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;

/// Size of X25519 shared secret in bytes
pub const X25519_SHARED_SECRET_SIZE: usize = 32;

/// Error type for key exchange operations
#[derive(Debug, Clone)]
pub enum KeyExchangeError {
    /// Invalid key length
    InvalidKeyLength { expected: usize, got: usize },
    /// Invalid key format
    InvalidKeyFormat(String),
    /// Key exchange computation failed
    ComputationFailed(String),
    /// Zero shared secret (indicates invalid public key)
    ZeroSharedSecret,
}

impl fmt::Display for KeyExchangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyExchangeError::InvalidKeyLength { expected, got } => {
                write!(f, "Invalid key length: expected {}, got {}", expected, got)
            }
            KeyExchangeError::InvalidKeyFormat(msg) => {
                write!(f, "Invalid key format: {}", msg)
            }
            KeyExchangeError::ComputationFailed(msg) => {
                write!(f, "Key exchange computation failed: {}", msg)
            }
            KeyExchangeError::ZeroSharedSecret => {
                write!(f, "Zero shared secret - invalid peer public key")
            }
        }
    }
}

impl std::error::Error for KeyExchangeError {}

/// X25519 static key pair for long-term key exchange
///
/// Used for `ss` (static-static) DH in Noise protocol.
pub struct X25519StaticKeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl X25519StaticKeyPair {
    /// Generate a new random X25519 static key pair
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Create key pair from private key bytes
    pub fn from_private_key(private_key: &[u8]) -> Result<Self, KeyExchangeError> {
        if private_key.len() != X25519_PRIVATE_KEY_SIZE {
            return Err(KeyExchangeError::InvalidKeyLength {
                expected: X25519_PRIVATE_KEY_SIZE,
                got: private_key.len(),
            });
        }

        let mut key_bytes = [0u8; X25519_PRIVATE_KEY_SIZE];
        key_bytes.copy_from_slice(private_key);

        let secret = StaticSecret::from(key_bytes);
        let public = PublicKey::from(&secret);

        // Zeroize the temporary copy
        key_bytes.zeroize();

        Ok(Self { secret, public })
    }

    /// Get the private key bytes (securely zeroized on drop)
    pub fn private_key(&self) -> Zeroizing<[u8; X25519_PRIVATE_KEY_SIZE]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    /// Get the public key bytes
    pub fn public_key(&self) -> [u8; X25519_PUBLIC_KEY_SIZE] {
        self.public.to_bytes()
    }

    /// Get the public key wrapper
    pub fn public(&self) -> X25519PublicKey {
        X25519PublicKey { key: self.public }
    }

    /// Perform Diffie-Hellman with another public key
    ///
    /// Returns the shared secret. The result should be passed through
    /// a KDF before use as an encryption key.
    pub fn diffie_hellman(&self, their_public: &X25519PublicKey) -> Result<Zeroizing<[u8; X25519_SHARED_SECRET_SIZE]>, KeyExchangeError> {
        let shared = self.secret.diffie_hellman(&their_public.key);

        // Check for zero shared secret (indicates invalid peer key)
        if shared.as_bytes().iter().all(|&b| b == 0) {
            return Err(KeyExchangeError::ZeroSharedSecret);
        }

        Ok(Zeroizing::new(*shared.as_bytes()))
    }
}

impl fmt::Debug for X25519StaticKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X25519StaticKeyPair")
            .field("public_key", &hex::encode(&self.public_key()))
            .finish_non_exhaustive()
    }
}

/// X25519 ephemeral key pair for one-time key exchange
///
/// Used for `e` (ephemeral) keys in Noise protocol.
/// Cannot be serialized or reused.
pub struct X25519EphemeralKeyPair {
    secret: Option<EphemeralSecret>,
    public: PublicKey,
}

impl X25519EphemeralKeyPair {
    /// Generate a new random X25519 ephemeral key pair
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self {
            secret: Some(secret),
            public,
        }
    }

    /// Get the public key bytes
    pub fn public_key(&self) -> [u8; X25519_PUBLIC_KEY_SIZE] {
        self.public.to_bytes()
    }

    /// Get the public key wrapper
    pub fn public(&self) -> X25519PublicKey {
        X25519PublicKey { key: self.public }
    }

    /// Perform Diffie-Hellman with another public key (consumes the ephemeral secret)
    ///
    /// This method can only be called once. After the DH is performed,
    /// the ephemeral secret is consumed and cannot be reused.
    pub fn diffie_hellman(mut self, their_public: &X25519PublicKey) -> Result<Zeroizing<[u8; X25519_SHARED_SECRET_SIZE]>, KeyExchangeError> {
        let secret = self.secret.take().ok_or_else(|| {
            KeyExchangeError::ComputationFailed("Ephemeral secret already consumed".to_string())
        })?;

        let shared = secret.diffie_hellman(&their_public.key);

        // Check for zero shared secret (indicates invalid peer key)
        if shared.as_bytes().iter().all(|&b| b == 0) {
            return Err(KeyExchangeError::ZeroSharedSecret);
        }

        Ok(Zeroizing::new(*shared.as_bytes()))
    }
}

impl fmt::Debug for X25519EphemeralKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X25519EphemeralKeyPair")
            .field("public_key", &hex::encode(&self.public_key()))
            .field("consumed", &self.secret.is_none())
            .finish()
    }
}

/// X25519 public key for Diffie-Hellman
#[derive(Clone, Copy)]
pub struct X25519PublicKey {
    key: PublicKey,
}

impl X25519PublicKey {
    /// Create public key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyExchangeError> {
        if bytes.len() != X25519_PUBLIC_KEY_SIZE {
            return Err(KeyExchangeError::InvalidKeyLength {
                expected: X25519_PUBLIC_KEY_SIZE,
                got: bytes.len(),
            });
        }

        let mut key_bytes = [0u8; X25519_PUBLIC_KEY_SIZE];
        key_bytes.copy_from_slice(bytes);

        Ok(Self {
            key: PublicKey::from(key_bytes),
        })
    }

    /// Get the public key bytes
    pub fn to_bytes(&self) -> [u8; X25519_PUBLIC_KEY_SIZE] {
        self.key.to_bytes()
    }

    /// Get reference to internal public key
    pub fn as_bytes(&self) -> &[u8; X25519_PUBLIC_KEY_SIZE] {
        self.key.as_bytes()
    }
}

impl fmt::Debug for X25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X25519PublicKey")
            .field("key", &hex::encode(&self.to_bytes()))
            .finish()
    }
}

impl PartialEq for X25519PublicKey {
    fn eq(&self, other: &Self) -> bool {
        crate::crypto::constant_time_compare(&self.to_bytes(), &other.to_bytes())
    }
}

impl Eq for X25519PublicKey {}

impl From<[u8; X25519_PUBLIC_KEY_SIZE]> for X25519PublicKey {
    fn from(bytes: [u8; X25519_PUBLIC_KEY_SIZE]) -> Self {
        Self {
            key: PublicKey::from(bytes),
        }
    }
}

/// Simple hex encoding (no external dependency)
mod hex {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    pub fn encode(data: &[u8]) -> String {
        let mut hex = String::with_capacity(data.len() * 2);
        for byte in data {
            hex.push(HEX_CHARS[(byte >> 4) as usize] as char);
            hex.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
        }
        hex
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_key_generation() {
        let keypair = X25519StaticKeyPair::generate();
        assert_eq!(keypair.private_key().len(), X25519_PRIVATE_KEY_SIZE);
        assert_eq!(keypair.public_key().len(), X25519_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_static_key_from_private() {
        let keypair1 = X25519StaticKeyPair::generate();
        let private_key = keypair1.private_key();

        let keypair2 = X25519StaticKeyPair::from_private_key(&private_key[..]).unwrap();
        assert_eq!(keypair1.public_key(), keypair2.public_key());
    }

    #[test]
    fn test_ephemeral_key_generation() {
        let keypair = X25519EphemeralKeyPair::generate();
        assert_eq!(keypair.public_key().len(), X25519_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_static_diffie_hellman() {
        let alice = X25519StaticKeyPair::generate();
        let bob = X25519StaticKeyPair::generate();

        let alice_shared = alice.diffie_hellman(&bob.public()).unwrap();
        let bob_shared = bob.diffie_hellman(&alice.public()).unwrap();

        assert_eq!(&*alice_shared, &*bob_shared);
    }

    #[test]
    fn test_ephemeral_diffie_hellman() {
        let alice = X25519EphemeralKeyPair::generate();
        let bob = X25519StaticKeyPair::generate();

        let alice_public = alice.public();
        let alice_shared = alice.diffie_hellman(&bob.public()).unwrap();
        let bob_shared = bob.diffie_hellman(&alice_public).unwrap();

        assert_eq!(&*alice_shared, &*bob_shared);
    }

    #[test]
    fn test_mixed_static_ephemeral_dh() {
        // Simulate Noise pattern: initiator has ephemeral, responder has static
        let initiator_ephemeral = X25519EphemeralKeyPair::generate();
        let responder_static = X25519StaticKeyPair::generate();

        let initiator_public = initiator_ephemeral.public();
        let shared_initiator = initiator_ephemeral.diffie_hellman(&responder_static.public()).unwrap();
        let shared_responder = responder_static.diffie_hellman(&initiator_public).unwrap();

        assert_eq!(&*shared_initiator, &*shared_responder);
    }

    #[test]
    fn test_public_key_from_bytes() {
        let keypair = X25519StaticKeyPair::generate();
        let public_bytes = keypair.public_key();

        let public_key = X25519PublicKey::from_bytes(&public_bytes).unwrap();
        assert_eq!(public_key.to_bytes(), public_bytes);
    }

    #[test]
    fn test_invalid_key_length() {
        let result = X25519StaticKeyPair::from_private_key(&[0u8; 16]);
        assert!(matches!(result, Err(KeyExchangeError::InvalidKeyLength { .. })));

        let result = X25519PublicKey::from_bytes(&[0u8; 16]);
        assert!(matches!(result, Err(KeyExchangeError::InvalidKeyLength { .. })));
    }

    #[test]
    fn test_public_key_equality() {
        let keypair1 = X25519StaticKeyPair::generate();
        let keypair2 = X25519StaticKeyPair::generate();

        let pk1a = keypair1.public();
        let pk1b = X25519PublicKey::from_bytes(&keypair1.public_key()).unwrap();
        let pk2 = keypair2.public();

        assert_eq!(pk1a, pk1b);
        assert_ne!(pk1a, pk2);
    }

    #[test]
    fn test_public_key_from_array() {
        let keypair = X25519StaticKeyPair::generate();
        let public_bytes = keypair.public_key();

        let public_key: X25519PublicKey = public_bytes.into();
        assert_eq!(public_key.to_bytes(), public_bytes);
    }

    #[test]
    fn test_different_keys_produce_different_secrets() {
        let alice = X25519StaticKeyPair::generate();
        let bob1 = X25519StaticKeyPair::generate();
        let bob2 = X25519StaticKeyPair::generate();

        let shared1 = alice.diffie_hellman(&bob1.public()).unwrap();
        let shared2 = alice.diffie_hellman(&bob2.public()).unwrap();

        assert_ne!(&*shared1, &*shared2);
    }
}
