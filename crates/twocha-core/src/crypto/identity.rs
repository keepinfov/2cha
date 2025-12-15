//! # Ed25519 Identity Module
//!
//! Provides Ed25519 key generation, signing, and verification for protocol v4.
//!
//! Ed25519 keys are used for:
//! - Long-term identity (static keys)
//! - Digital signatures for authentication
//! - Derivation of X25519 keys for key exchange

use ed25519_dalek::{
    SecretKey, SigningKey, VerifyingKey,
    Signature, Signer, Verifier,
};
use rand_core::OsRng;
use zeroize::{Zeroize, Zeroizing};
use std::fmt;

/// Size of Ed25519 private key in bytes
pub const ED25519_PRIVATE_KEY_SIZE: usize = 32;

/// Size of Ed25519 public key in bytes
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;

/// Size of Ed25519 signature in bytes
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// Error type for identity operations
#[derive(Debug, Clone)]
pub enum IdentityError {
    /// Invalid key length
    InvalidKeyLength { expected: usize, got: usize },
    /// Invalid signature length
    InvalidSignatureLength { expected: usize, got: usize },
    /// Signature verification failed
    SignatureVerificationFailed,
    /// Key generation failed
    KeyGenerationFailed(String),
    /// Invalid key format
    InvalidKeyFormat(String),
    /// Key conversion failed
    KeyConversionFailed(String),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::InvalidKeyLength { expected, got } => {
                write!(f, "Invalid key length: expected {}, got {}", expected, got)
            }
            IdentityError::InvalidSignatureLength { expected, got } => {
                write!(f, "Invalid signature length: expected {}, got {}", expected, got)
            }
            IdentityError::SignatureVerificationFailed => {
                write!(f, "Signature verification failed")
            }
            IdentityError::KeyGenerationFailed(msg) => {
                write!(f, "Key generation failed: {}", msg)
            }
            IdentityError::InvalidKeyFormat(msg) => {
                write!(f, "Invalid key format: {}", msg)
            }
            IdentityError::KeyConversionFailed(msg) => {
                write!(f, "Key conversion failed: {}", msg)
            }
        }
    }
}

impl std::error::Error for IdentityError {}

/// Ed25519 key pair for identity and signing
pub struct Ed25519KeyPair {
    /// Signing key (contains both private and public parts)
    signing_key: SigningKey,
}

impl Ed25519KeyPair {
    /// Generate a new random Ed25519 key pair
    pub fn generate() -> Result<Self, IdentityError> {
        let signing_key = SigningKey::generate(&mut OsRng);
        Ok(Self { signing_key })
    }

    /// Create key pair from private key bytes
    pub fn from_private_key(private_key: &[u8]) -> Result<Self, IdentityError> {
        if private_key.len() != ED25519_PRIVATE_KEY_SIZE {
            return Err(IdentityError::InvalidKeyLength {
                expected: ED25519_PRIVATE_KEY_SIZE,
                got: private_key.len(),
            });
        }

        let secret_key: SecretKey = private_key
            .try_into()
            .map_err(|_| IdentityError::InvalidKeyFormat("Invalid private key bytes".to_string()))?;

        let signing_key = SigningKey::from_bytes(&secret_key);
        Ok(Self { signing_key })
    }

    /// Get the private key bytes (securely zeroized on drop)
    pub fn private_key(&self) -> Zeroizing<[u8; ED25519_PRIVATE_KEY_SIZE]> {
        Zeroizing::new(self.signing_key.to_bytes())
    }

    /// Get the public key bytes
    pub fn public_key(&self) -> [u8; ED25519_PUBLIC_KEY_SIZE] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Get the verifying (public) key
    pub fn verifying_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey {
            verifying_key: self.signing_key.verifying_key(),
        }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> [u8; ED25519_SIGNATURE_SIZE] {
        self.signing_key.sign(message).to_bytes()
    }

    /// Verify a signature (convenience method using own public key)
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), IdentityError> {
        self.verifying_key().verify(message, signature)
    }

    /// Convert Ed25519 private key to X25519 private key
    ///
    /// This follows the standard conversion: hash Ed25519 seed with SHA-512,
    /// take first 32 bytes and clamp for X25519.
    pub fn to_x25519_private(&self) -> Zeroizing<[u8; 32]> {
        use sha2::{Sha512, Digest};

        let mut hasher = Sha512::new();
        hasher.update(self.signing_key.to_bytes());
        let hash = hasher.finalize();

        let mut x25519_key = [0u8; 32];
        x25519_key.copy_from_slice(&hash[..32]);

        // Clamp the key for X25519
        x25519_key[0] &= 248;
        x25519_key[31] &= 127;
        x25519_key[31] |= 64;

        Zeroizing::new(x25519_key)
    }
}

impl Drop for Ed25519KeyPair {
    fn drop(&mut self) {
        // SigningKey uses zeroize internally, but we ensure it's called
        let mut bytes = self.signing_key.to_bytes();
        bytes.zeroize();
    }
}

impl fmt::Debug for Ed25519KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519KeyPair")
            .field("public_key", &hex::encode(&self.public_key()))
            .finish_non_exhaustive()
    }
}

/// Ed25519 public key for verification
#[derive(Clone)]
pub struct Ed25519PublicKey {
    verifying_key: VerifyingKey,
}

impl Ed25519PublicKey {
    /// Create public key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() != ED25519_PUBLIC_KEY_SIZE {
            return Err(IdentityError::InvalidKeyLength {
                expected: ED25519_PUBLIC_KEY_SIZE,
                got: bytes.len(),
            });
        }

        let key_bytes: [u8; ED25519_PUBLIC_KEY_SIZE] = bytes
            .try_into()
            .map_err(|_| IdentityError::InvalidKeyFormat("Invalid public key bytes".to_string()))?;

        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| IdentityError::InvalidKeyFormat(e.to_string()))?;

        Ok(Self { verifying_key })
    }

    /// Get the public key bytes
    pub fn to_bytes(&self) -> [u8; ED25519_PUBLIC_KEY_SIZE] {
        self.verifying_key.to_bytes()
    }

    /// Verify a signature on a message
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), IdentityError> {
        if signature.len() != ED25519_SIGNATURE_SIZE {
            return Err(IdentityError::InvalidSignatureLength {
                expected: ED25519_SIGNATURE_SIZE,
                got: signature.len(),
            });
        }

        let sig_bytes: [u8; ED25519_SIGNATURE_SIZE] = signature
            .try_into()
            .map_err(|_| IdentityError::InvalidKeyFormat("Invalid signature bytes".to_string()))?;

        let signature = Signature::from_bytes(&sig_bytes);

        self.verifying_key
            .verify(message, &signature)
            .map_err(|_| IdentityError::SignatureVerificationFailed)
    }

    /// Convert Ed25519 public key to X25519 public key
    ///
    /// Uses the standard Montgomery form conversion.
    pub fn to_x25519_public(&self) -> Result<[u8; 32], IdentityError> {
        use curve25519_dalek::edwards::CompressedEdwardsY;

        let compressed = CompressedEdwardsY::from_slice(&self.to_bytes())
            .map_err(|e| IdentityError::KeyConversionFailed(e.to_string()))?;

        let edwards_point = compressed
            .decompress()
            .ok_or_else(|| IdentityError::KeyConversionFailed("Invalid Edwards point".to_string()))?;

        Ok(edwards_point.to_montgomery().to_bytes())
    }
}

impl fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519PublicKey")
            .field("key", &hex::encode(&self.to_bytes()))
            .finish()
    }
}

impl PartialEq for Ed25519PublicKey {
    fn eq(&self, other: &Self) -> bool {
        crate::crypto::constant_time_compare(&self.to_bytes(), &other.to_bytes())
    }
}

impl Eq for Ed25519PublicKey {}

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
    fn test_key_generation() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        assert_eq!(keypair.private_key().len(), ED25519_PRIVATE_KEY_SIZE);
        assert_eq!(keypair.public_key().len(), ED25519_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_from_private_key() {
        let keypair1 = Ed25519KeyPair::generate().unwrap();
        let private_key = keypair1.private_key();

        let keypair2 = Ed25519KeyPair::from_private_key(&private_key[..]).unwrap();
        assert_eq!(keypair1.public_key(), keypair2.public_key());
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let message = b"Hello, 2cha protocol v4!";

        let signature = keypair.sign(message);
        assert_eq!(signature.len(), ED25519_SIGNATURE_SIZE);

        // Verify with own key
        assert!(keypair.verify(message, &signature).is_ok());

        // Verify with extracted public key
        let public_key = keypair.verifying_key();
        assert!(public_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_signature_verification_fails_for_wrong_message() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let message = b"Original message";
        let wrong_message = b"Wrong message";

        let signature = keypair.sign(message);

        let result = keypair.verify(wrong_message, &signature);
        assert!(matches!(result, Err(IdentityError::SignatureVerificationFailed)));
    }

    #[test]
    fn test_signature_verification_fails_for_wrong_key() {
        let keypair1 = Ed25519KeyPair::generate().unwrap();
        let keypair2 = Ed25519KeyPair::generate().unwrap();
        let message = b"Test message";

        let signature = keypair1.sign(message);

        let result = keypair2.verify(message, &signature);
        assert!(matches!(result, Err(IdentityError::SignatureVerificationFailed)));
    }

    #[test]
    fn test_public_key_from_bytes() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let public_bytes = keypair.public_key();

        let public_key = Ed25519PublicKey::from_bytes(&public_bytes).unwrap();
        assert_eq!(public_key.to_bytes(), public_bytes);
    }

    #[test]
    fn test_invalid_key_length() {
        let result = Ed25519KeyPair::from_private_key(&[0u8; 16]);
        assert!(matches!(result, Err(IdentityError::InvalidKeyLength { .. })));

        let result = Ed25519PublicKey::from_bytes(&[0u8; 16]);
        assert!(matches!(result, Err(IdentityError::InvalidKeyLength { .. })));
    }

    #[test]
    fn test_x25519_conversion() {
        let keypair = Ed25519KeyPair::generate().unwrap();

        // Convert to X25519 keys
        let x25519_private = keypair.to_x25519_private();
        let x25519_public = keypair.verifying_key().to_x25519_public().unwrap();

        assert_eq!(x25519_private.len(), 32);
        assert_eq!(x25519_public.len(), 32);

        // Verify the X25519 keys are related (private derives public)
        use x25519_dalek::{StaticSecret, PublicKey};
        let secret = StaticSecret::from(*x25519_private);
        let derived_public = PublicKey::from(&secret);

        assert_eq!(derived_public.as_bytes(), &x25519_public);
    }

    #[test]
    fn test_public_key_equality() {
        let keypair1 = Ed25519KeyPair::generate().unwrap();
        let keypair2 = Ed25519KeyPair::generate().unwrap();

        let pk1a = keypair1.verifying_key();
        let pk1b = Ed25519PublicKey::from_bytes(&keypair1.public_key()).unwrap();
        let pk2 = keypair2.verifying_key();

        assert_eq!(pk1a, pk1b);
        assert_ne!(pk1a, pk2);
    }
}
