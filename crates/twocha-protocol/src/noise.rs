//! # Noise_IK Handshake State Machine
//!
//! Implements the Noise_IK handshake pattern for protocol v4.
//!
//! ## Noise_IK Pattern
//!
//! The IK pattern assumes the initiator knows the responder's static public key.
//!
//! ```text
//! IK:
//!   <- s
//!   ...
//!   -> e, es, s, ss
//!   <- e, ee, se
//! ```
//!
//! Where:
//! - `e` = ephemeral key
//! - `s` = static key
//! - `es` = DH(initiator_ephemeral, responder_static)
//! - `ss` = DH(initiator_static, responder_static)
//! - `ee` = DH(initiator_ephemeral, responder_ephemeral)
//! - `se` = DH(responder_ephemeral, initiator_static)
//!
//! ## Security Properties
//!
//! - Mutual authentication
//! - Perfect Forward Secrecy (PFS)
//! - Identity hiding for initiator
//! - Resistance to replay attacks (via TAI64N timestamps)

use zeroize::Zeroizing;
use std::fmt;

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

/// Noise protocol name for 2cha v4
pub const NOISE_PROTOCOL_NAME: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

/// Construction string for hash
pub const NOISE_CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

/// Protocol identifier for additional binding
pub const NOISE_IDENTIFIER: &[u8] = b"2cha-protocol-v4";

/// Hash output size (BLAKE2s = 32 bytes)
pub const HASH_SIZE: usize = 32;

/// Key size for symmetric operations
pub const KEY_SIZE: usize = 32;

// ═══════════════════════════════════════════════════════════════════════════
// HANDSHAKE STATE
// ═══════════════════════════════════════════════════════════════════════════

/// State of the handshake process
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Initial state before any messages
    Initial,
    /// Initiator has sent init message, waiting for response
    InitSent,
    /// Responder has received init, preparing response
    InitReceived,
    /// Responder has sent response, waiting for data
    ResponseSent,
    /// Initiator has received response, handshake complete
    Complete,
    /// Handshake failed
    Failed,
}

impl HandshakeState {
    /// Check if handshake is complete
    pub fn is_complete(&self) -> bool {
        matches!(self, HandshakeState::Complete)
    }

    /// Check if handshake has failed
    pub fn is_failed(&self) -> bool {
        matches!(self, HandshakeState::Failed)
    }

    /// Check if this is an initiator state
    pub fn is_initiator(&self) -> bool {
        matches!(self, HandshakeState::Initial | HandshakeState::InitSent)
    }

    /// Check if this is a responder state
    pub fn is_responder(&self) -> bool {
        matches!(self, HandshakeState::InitReceived | HandshakeState::ResponseSent)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SYMMETRIC STATE
// ═══════════════════════════════════════════════════════════════════════════

/// Symmetric state for Noise protocol (CipherState + SymmetricState combined)
///
/// This structure holds the evolving cryptographic state during handshake.
pub struct SymmetricState {
    /// Chaining key (ck) - evolves with each MixKey operation
    chaining_key: Zeroizing<[u8; HASH_SIZE]>,
    /// Handshake hash (h) - binds all handshake data
    hash: [u8; HASH_SIZE],
    /// Current encryption key (k) - derived from chaining key
    key: Option<Zeroizing<[u8; KEY_SIZE]>>,
    /// Nonce counter for encryption (n)
    nonce: u64,
}

impl SymmetricState {
    /// Initialize symmetric state from protocol name
    ///
    /// If the protocol name is <= 32 bytes, use it directly as h.
    /// Otherwise, hash it with BLAKE2s.
    pub fn new(protocol_name: &[u8]) -> Self {
        let mut hash = [0u8; HASH_SIZE];

        if protocol_name.len() <= HASH_SIZE {
            hash[..protocol_name.len()].copy_from_slice(protocol_name);
        } else {
            hash = blake2s_hash(protocol_name);
        }

        Self {
            chaining_key: Zeroizing::new(hash),
            hash,
            key: None,
            nonce: 0,
        }
    }

    /// Mix a piece of data into the handshake hash
    ///
    /// h = HASH(h || data)
    pub fn mix_hash(&mut self, data: &[u8]) {
        self.hash = blake2s_hash_two(&self.hash, data);
    }

    /// Mix a DH output into the chaining key and derive new key
    ///
    /// (ck, k) = HKDF(ck, dh_output, 2)
    pub fn mix_key(&mut self, dh_output: &[u8]) {
        let (new_ck, new_key) = hkdf_blake2s(&*self.chaining_key, dh_output, 2);
        self.chaining_key = new_ck;
        self.key = Some(new_key);
        self.nonce = 0;
    }

    /// Mix a pre-shared key using the Noise psk modifier
    ///
    /// (ck, temp, k) = HKDF(ck, psk, 3)
    /// h = HASH(h || temp)
    pub fn mix_psk(&mut self, psk: &[u8; 32]) {
        let (new_ck, temp, new_key) = hkdf_blake2s_3(&*self.chaining_key, psk);
        self.chaining_key = new_ck;
        self.mix_hash(&temp);
        self.key = Some(new_key);
        self.nonce = 0;
    }

    /// Encrypt and authenticate data with the current key
    ///
    /// Returns ciphertext || tag
    pub fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let key = self.key.as_ref().ok_or(NoiseError::NoKey)?;

        // AEAD encrypt with h as additional data
        let ciphertext = chacha20poly1305_encrypt(key, self.nonce, &self.hash, plaintext)?;

        // Mix ciphertext into hash
        self.mix_hash(&ciphertext);

        // Increment nonce
        self.nonce = self.nonce.checked_add(1).ok_or(NoiseError::NonceOverflow)?;

        Ok(ciphertext)
    }

    /// Decrypt and verify data with the current key
    ///
    /// Returns plaintext on success
    pub fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let key = self.key.as_ref().ok_or(NoiseError::NoKey)?;

        // AEAD decrypt with h as additional data
        let plaintext = chacha20poly1305_decrypt(key, self.nonce, &self.hash, ciphertext)?;

        // Mix ciphertext into hash
        self.mix_hash(ciphertext);

        // Increment nonce
        self.nonce = self.nonce.checked_add(1).ok_or(NoiseError::NonceOverflow)?;

        Ok(plaintext)
    }

    /// Split the symmetric state into two cipher states for transport
    ///
    /// Returns (initiator_to_responder_key, responder_to_initiator_key)
    pub fn split(self) -> Result<(TransportKey, TransportKey), NoiseError> {
        let (k1, k2) = hkdf_blake2s(&*self.chaining_key, &[], 2);

        Ok((
            TransportKey::new(k1),
            TransportKey::new(k2),
        ))
    }

    /// Get current handshake hash (for channel binding)
    pub fn get_hash(&self) -> &[u8; HASH_SIZE] {
        &self.hash
    }

    /// Get current chaining key (for debugging/testing only)
    #[cfg(test)]
    pub fn get_chaining_key(&self) -> &[u8; HASH_SIZE] {
        &self.chaining_key
    }
}

impl fmt::Debug for SymmetricState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymmetricState")
            .field("hash", &hex_encode(&self.hash))
            .field("has_key", &self.key.is_some())
            .field("nonce", &self.nonce)
            .finish_non_exhaustive()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TRANSPORT KEY
// ═══════════════════════════════════════════════════════════════════════════

/// Transport key for post-handshake encryption
pub struct TransportKey {
    key: Zeroizing<[u8; KEY_SIZE]>,
    nonce: u64,
}

impl TransportKey {
    /// Create a new transport key
    fn new(key: Zeroizing<[u8; KEY_SIZE]>) -> Self {
        Self { key, nonce: 0 }
    }

    /// Encrypt data for transport
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let ciphertext = chacha20poly1305_encrypt(&self.key, self.nonce, &[], plaintext)?;
        self.nonce = self.nonce.checked_add(1).ok_or(NoiseError::NonceOverflow)?;
        Ok(ciphertext)
    }

    /// Decrypt data from transport
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let plaintext = chacha20poly1305_decrypt(&self.key, self.nonce, &[], ciphertext)?;
        self.nonce = self.nonce.checked_add(1).ok_or(NoiseError::NonceOverflow)?;
        Ok(plaintext)
    }

    /// Get current nonce value
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Check if rekey is needed
    pub fn needs_rekey(&self, max_messages: u64) -> bool {
        self.nonce >= max_messages
    }
}

impl fmt::Debug for TransportKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransportKey")
            .field("nonce", &self.nonce)
            .finish_non_exhaustive()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ERROR TYPES
// ═══════════════════════════════════════════════════════════════════════════

/// Errors during Noise protocol operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoiseError {
    /// No key available for encryption/decryption
    NoKey,
    /// Nonce counter overflow
    NonceOverflow,
    /// Encryption failed
    EncryptionFailed,
    /// Decryption/authentication failed
    DecryptionFailed,
    /// Invalid message length
    InvalidLength { expected: usize, got: usize },
    /// Invalid state for this operation
    InvalidState(HandshakeState),
    /// DH computation produced zero (invalid peer key)
    ZeroDhOutput,
    /// Handshake failed
    HandshakeFailed(String),
}

impl fmt::Display for NoiseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NoiseError::NoKey => write!(f, "No key available"),
            NoiseError::NonceOverflow => write!(f, "Nonce counter overflow"),
            NoiseError::EncryptionFailed => write!(f, "Encryption failed"),
            NoiseError::DecryptionFailed => write!(f, "Decryption failed"),
            NoiseError::InvalidLength { expected, got } => {
                write!(f, "Invalid length: expected {}, got {}", expected, got)
            }
            NoiseError::InvalidState(state) => {
                write!(f, "Invalid state for operation: {:?}", state)
            }
            NoiseError::ZeroDhOutput => write!(f, "DH produced zero output (invalid peer key)"),
            NoiseError::HandshakeFailed(msg) => write!(f, "Handshake failed: {}", msg),
        }
    }
}

impl std::error::Error for NoiseError {}

// ═══════════════════════════════════════════════════════════════════════════
// CRYPTOGRAPHIC PRIMITIVES
// ═══════════════════════════════════════════════════════════════════════════

/// BLAKE2s hash of single input
fn blake2s_hash(data: &[u8]) -> [u8; HASH_SIZE] {
    use blake2::{Blake2s256, Digest};
    let mut hasher = Blake2s256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; HASH_SIZE];
    output.copy_from_slice(&result);
    output
}

/// BLAKE2s hash of two concatenated inputs
fn blake2s_hash_two(a: &[u8], b: &[u8]) -> [u8; HASH_SIZE] {
    use blake2::{Blake2s256, Digest};
    let mut hasher = Blake2s256::new();
    hasher.update(a);
    hasher.update(b);
    let result = hasher.finalize();
    let mut output = [0u8; HASH_SIZE];
    output.copy_from_slice(&result);
    output
}

/// HKDF-BLAKE2s to derive 2 keys
fn hkdf_blake2s(
    chaining_key: &[u8],
    input: &[u8],
    _outputs: usize,
) -> (Zeroizing<[u8; KEY_SIZE]>, Zeroizing<[u8; KEY_SIZE]>) {
    // HKDF-Extract
    let temp_key = hmac_blake2s(chaining_key, input);

    // HKDF-Expand
    let output1 = hmac_blake2s(&temp_key, &[0x01]);

    let mut input2 = Vec::with_capacity(KEY_SIZE + 1);
    input2.extend_from_slice(&output1);
    input2.push(0x02);
    let output2 = hmac_blake2s(&temp_key, &input2);

    (Zeroizing::new(output1), Zeroizing::new(output2))
}

/// HKDF-BLAKE2s to derive 3 keys
fn hkdf_blake2s_3(
    chaining_key: &[u8],
    input: &[u8],
) -> (Zeroizing<[u8; KEY_SIZE]>, [u8; KEY_SIZE], Zeroizing<[u8; KEY_SIZE]>) {
    // HKDF-Extract
    let temp_key = hmac_blake2s(chaining_key, input);

    // HKDF-Expand for 3 outputs
    let output1 = hmac_blake2s(&temp_key, &[0x01]);

    let mut input2 = Vec::with_capacity(KEY_SIZE + 1);
    input2.extend_from_slice(&output1);
    input2.push(0x02);
    let output2 = hmac_blake2s(&temp_key, &input2);

    let mut input3 = Vec::with_capacity(KEY_SIZE + 1);
    input3.extend_from_slice(&output2);
    input3.push(0x03);
    let output3 = hmac_blake2s(&temp_key, &input3);

    (Zeroizing::new(output1), output2, Zeroizing::new(output3))
}

/// HMAC-BLAKE2s (using keyed BLAKE2s which is equivalent for our purposes)
fn hmac_blake2s(key: &[u8], data: &[u8]) -> [u8; KEY_SIZE] {
    use blake2::{Blake2sMac, digest::{KeyInit, FixedOutput, Update}};
    use blake2::digest::consts::U32;

    // BLAKE2s key must be <= 32 bytes, hash if longer
    let mac_key: [u8; 32] = if key.len() <= 32 {
        let mut k = [0u8; 32];
        k[..key.len()].copy_from_slice(key);
        k
    } else {
        blake2s_hash(key)
    };

    let mut mac = Blake2sMac::<U32>::new_from_slice(&mac_key)
        .expect("Blake2sMac accepts any key size up to 32 bytes");
    mac.update(data);
    let result = mac.finalize_fixed();

    let mut output = [0u8; KEY_SIZE];
    output.copy_from_slice(&result);
    output
}

/// ChaCha20-Poly1305 AEAD encryption
fn chacha20poly1305_encrypt(
    key: &[u8; KEY_SIZE],
    nonce: u64,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, NoiseError> {
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::{Aead, Payload}};

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| NoiseError::EncryptionFailed)?;

    // Noise uses 8-byte nonce with 4 leading zero bytes
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..].copy_from_slice(&nonce.to_le_bytes());

    cipher
        .encrypt(
            &nonce_bytes.into(),
            Payload { msg: plaintext, aad },
        )
        .map_err(|_| NoiseError::EncryptionFailed)
}

/// ChaCha20-Poly1305 AEAD decryption
fn chacha20poly1305_decrypt(
    key: &[u8; KEY_SIZE],
    nonce: u64,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, NoiseError> {
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::{Aead, Payload}};

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| NoiseError::DecryptionFailed)?;

    // Noise uses 8-byte nonce with 4 leading zero bytes
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..].copy_from_slice(&nonce.to_le_bytes());

    cipher
        .decrypt(
            &nonce_bytes.into(),
            Payload { msg: ciphertext, aad },
        )
        .map_err(|_| NoiseError::DecryptionFailed)
}

// ═══════════════════════════════════════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

/// Simple hex encoding helper
fn hex_encode(data: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(data.len() * 2);
    for byte in data {
        hex.push(HEX_CHARS[(byte >> 4) as usize] as char);
        hex.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
    }
    hex
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_state_checks() {
        assert!(HandshakeState::Complete.is_complete());
        assert!(!HandshakeState::Initial.is_complete());

        assert!(HandshakeState::Failed.is_failed());
        assert!(!HandshakeState::Complete.is_failed());

        assert!(HandshakeState::Initial.is_initiator());
        assert!(HandshakeState::InitSent.is_initiator());
        assert!(!HandshakeState::InitReceived.is_initiator());

        assert!(HandshakeState::InitReceived.is_responder());
        assert!(HandshakeState::ResponseSent.is_responder());
        assert!(!HandshakeState::InitSent.is_responder());
    }

    #[test]
    fn test_symmetric_state_initialization() {
        let state = SymmetricState::new(NOISE_CONSTRUCTION);

        // Hash should be initialized from construction
        assert_ne!(state.hash, [0u8; 32]);
    }

    #[test]
    fn test_symmetric_state_mix_hash() {
        let mut state = SymmetricState::new(NOISE_CONSTRUCTION);
        let initial_hash = state.hash;

        state.mix_hash(b"test data");

        // Hash should change
        assert_ne!(state.hash, initial_hash);
    }

    #[test]
    fn test_symmetric_state_mix_key() {
        let mut state = SymmetricState::new(NOISE_CONSTRUCTION);

        // Initially no key
        assert!(state.key.is_none());

        // Mix in a DH output
        state.mix_key(&[0x42u8; 32]);

        // Now should have a key
        assert!(state.key.is_some());
        assert_eq!(state.nonce, 0);
    }

    #[test]
    fn test_symmetric_state_encrypt_decrypt() {
        let mut state1 = SymmetricState::new(NOISE_CONSTRUCTION);
        let mut state2 = SymmetricState::new(NOISE_CONSTRUCTION);

        // Both mix the same key
        let dh_output = [0x42u8; 32];
        state1.mix_key(&dh_output);
        state2.mix_key(&dh_output);

        // Encrypt with state1
        let plaintext = b"Hello, Noise!";
        let ciphertext = state1.encrypt_and_hash(plaintext).unwrap();

        // Decrypt with state2
        let decrypted = state2.decrypt_and_hash(&ciphertext).unwrap();

        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_symmetric_state_hash_evolves() {
        let mut state1 = SymmetricState::new(NOISE_CONSTRUCTION);
        let mut state2 = SymmetricState::new(NOISE_CONSTRUCTION);

        state1.mix_key(&[0x42u8; 32]);
        state2.mix_key(&[0x42u8; 32]);

        let plaintext = b"test";
        let ciphertext = state1.encrypt_and_hash(plaintext).unwrap();
        let _ = state2.decrypt_and_hash(&ciphertext).unwrap();

        // Hashes should be the same after corresponding operations
        assert_eq!(state1.hash, state2.hash);
    }

    #[test]
    fn test_transport_key_encrypt_decrypt() {
        let key = Zeroizing::new([0x42u8; 32]);
        let mut tx = TransportKey::new(key.clone());
        let mut rx = TransportKey::new(key);

        let plaintext = b"Transport layer message";
        let ciphertext = tx.encrypt(plaintext).unwrap();
        let decrypted = rx.decrypt(&ciphertext).unwrap();

        assert_eq!(&decrypted[..], plaintext);
        assert_eq!(tx.nonce(), 1);
        assert_eq!(rx.nonce(), 1);
    }

    #[test]
    fn test_transport_key_needs_rekey() {
        let key = Zeroizing::new([0x42u8; 32]);
        let mut tx = TransportKey::new(key);

        assert!(!tx.needs_rekey(100));

        // Encrypt many messages
        for _ in 0..50 {
            tx.encrypt(b"test").unwrap();
        }

        assert!(!tx.needs_rekey(100));

        for _ in 0..50 {
            tx.encrypt(b"test").unwrap();
        }

        assert!(tx.needs_rekey(100));
    }

    #[test]
    fn test_symmetric_state_split() {
        let mut state = SymmetricState::new(NOISE_CONSTRUCTION);
        state.mix_key(&[0x42u8; 32]);
        state.mix_key(&[0x43u8; 32]);

        let (mut i2r, mut r2i) = state.split().unwrap();

        // Test bidirectional communication
        let msg1 = b"From initiator";
        let enc1 = i2r.encrypt(msg1).unwrap();

        let msg2 = b"From responder";
        let enc2 = r2i.encrypt(msg2).unwrap();

        // Create matching key pairs for receiving
        let mut state2 = SymmetricState::new(NOISE_CONSTRUCTION);
        state2.mix_key(&[0x42u8; 32]);
        state2.mix_key(&[0x43u8; 32]);
        let (mut r_i2r, mut r_r2i) = state2.split().unwrap();

        let dec1 = r_i2r.decrypt(&enc1).unwrap();
        let dec2 = r_r2i.decrypt(&enc2).unwrap();

        assert_eq!(&dec1[..], msg1);
        assert_eq!(&dec2[..], msg2);
    }

    #[test]
    fn test_blake2s_hash() {
        let hash1 = blake2s_hash(b"test");
        let hash2 = blake2s_hash(b"test");
        let hash3 = blake2s_hash(b"different");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn test_hkdf_blake2s() {
        let (k1, k2) = hkdf_blake2s(&[0x42u8; 32], &[0x43u8; 32], 2);

        assert_ne!(&*k1, &*k2);
        assert_eq!(k1.len(), 32);
        assert_eq!(k2.len(), 32);
    }

    #[test]
    fn test_chacha20poly1305_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"Secret message";
        let aad = b"Additional data";

        let ciphertext = chacha20poly1305_encrypt(&key, 0, aad, plaintext).unwrap();
        let decrypted = chacha20poly1305_decrypt(&key, 0, aad, &ciphertext).unwrap();

        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_chacha20poly1305_authentication_fails() {
        let key = [0x42u8; 32];
        let plaintext = b"Secret message";

        let mut ciphertext = chacha20poly1305_encrypt(&key, 0, &[], plaintext).unwrap();

        // Tamper with ciphertext
        ciphertext[0] ^= 1;

        let result = chacha20poly1305_decrypt(&key, 0, &[], &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_chacha20poly1305_wrong_aad_fails() {
        let key = [0x42u8; 32];
        let plaintext = b"Secret message";

        let ciphertext = chacha20poly1305_encrypt(&key, 0, b"correct", plaintext).unwrap();
        let result = chacha20poly1305_decrypt(&key, 0, b"wrong", &ciphertext);

        assert!(result.is_err());
    }

    #[test]
    fn test_noise_error_display() {
        assert_eq!(format!("{}", NoiseError::NoKey), "No key available");
        assert_eq!(format!("{}", NoiseError::NonceOverflow), "Nonce counter overflow");
        assert_eq!(
            format!("{}", NoiseError::InvalidLength { expected: 32, got: 16 }),
            "Invalid length: expected 32, got 16"
        );
    }
}
