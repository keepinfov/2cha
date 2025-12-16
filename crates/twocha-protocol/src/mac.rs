//! # MAC1/MAC2 DoS Protection
//!
//! Provides Message Authentication Codes for handshake DoS protection.
//!
//! ## MAC1 - Basic Authentication
//!
//! MAC1 authenticates handshake messages using a key derived from the
//! responder's static public key. This prevents blind injection attacks.
//!
//! ```text
//! mac1_key = HASH(LABEL_MAC1 || responder_static_public)
//! MAC1 = KEYED_HASH(mac1_key, msg_bytes[..len-32])
//! ```
//!
//! ## MAC2 - Cookie-based Rate Limiting
//!
//! MAC2 provides additional DoS protection using cookies. When a server
//! is under load, it can require valid MAC2 before processing handshakes.
//!
//! ```text
//! cookie = KEYED_HASH(cookie_secret, initiator_ip || current_time)
//! MAC2 = KEYED_HASH(cookie, msg_bytes[..len-16])
//! ```
//!
//! ## Cookie Reply Message
//!
//! When MAC2 is required but invalid/missing, the server sends a cookie
//! reply that the client must use to compute a valid MAC2.

use crate::constants::HANDSHAKE_MAC_SIZE;

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

/// Label for MAC1 key derivation
pub const LABEL_MAC1: &[u8] = b"mac1----";

/// Label for cookie key derivation
pub const LABEL_COOKIE: &[u8] = b"cookie--";

/// Cookie size in bytes
pub const COOKIE_SIZE: usize = 16;

/// Cookie secret size in bytes
pub const COOKIE_SECRET_SIZE: usize = 32;

/// Cookie validity window in seconds
pub const COOKIE_VALIDITY_SECS: u64 = 120;

/// Cookie reply message size
pub const COOKIE_REPLY_SIZE: usize = 64;

// ═══════════════════════════════════════════════════════════════════════════
// MAC CALCULATOR
// ═══════════════════════════════════════════════════════════════════════════

/// MAC1/MAC2 calculator for handshake messages
pub struct MacCalculator {
    /// MAC1 key derived from responder's static public key
    mac1_key: [u8; 32],
}

impl MacCalculator {
    /// Create a new MAC calculator for a given responder static public key
    ///
    /// The MAC1 key is derived as: HASH(LABEL_MAC1 || responder_static)
    pub fn new(responder_static_public: &[u8; 32]) -> Self {
        let mac1_key = blake2s_hash_two(LABEL_MAC1, responder_static_public);
        Self { mac1_key }
    }

    /// Compute MAC1 for a handshake message
    ///
    /// MAC1 = KEYED_HASH(mac1_key, msg[..msg.len() - 32])
    /// (32 bytes = MAC1 (16) + MAC2 (16))
    pub fn compute_mac1(&self, message: &[u8]) -> [u8; HANDSHAKE_MAC_SIZE] {
        let data = if message.len() >= 32 {
            &message[..message.len() - 32]
        } else {
            message
        };

        let full_mac = keyed_blake2s(&self.mac1_key, data);
        let mut mac1 = [0u8; HANDSHAKE_MAC_SIZE];
        mac1.copy_from_slice(&full_mac[..HANDSHAKE_MAC_SIZE]);
        mac1
    }

    /// Verify MAC1 for a received handshake message
    ///
    /// Returns true if MAC1 is valid
    pub fn verify_mac1(&self, message: &[u8], expected_mac1: &[u8; HANDSHAKE_MAC_SIZE]) -> bool {
        let computed = self.compute_mac1(message);
        constant_time_compare(&computed, expected_mac1)
    }

    /// Compute MAC2 for a handshake message using a cookie
    ///
    /// MAC2 = KEYED_HASH(cookie, msg[..msg.len() - 16])
    /// (16 bytes = MAC2 only)
    pub fn compute_mac2(cookie: &[u8; COOKIE_SIZE], message: &[u8]) -> [u8; HANDSHAKE_MAC_SIZE] {
        // Pad cookie to 32 bytes for keyed hash
        let mut cookie_key = [0u8; 32];
        cookie_key[..COOKIE_SIZE].copy_from_slice(cookie);

        let data = if message.len() >= 16 {
            &message[..message.len() - 16]
        } else {
            message
        };

        let full_mac = keyed_blake2s(&cookie_key, data);
        let mut mac2 = [0u8; HANDSHAKE_MAC_SIZE];
        mac2.copy_from_slice(&full_mac[..HANDSHAKE_MAC_SIZE]);
        mac2
    }

    /// Verify MAC2 for a received handshake message
    pub fn verify_mac2(
        cookie: &[u8; COOKIE_SIZE],
        message: &[u8],
        expected_mac2: &[u8; HANDSHAKE_MAC_SIZE],
    ) -> bool {
        let computed = Self::compute_mac2(cookie, message);
        constant_time_compare(&computed, expected_mac2)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// COOKIE GENERATOR
// ═══════════════════════════════════════════════════════════════════════════

/// Cookie generator for DoS protection
///
/// Generates and verifies cookies based on client IP and current time.
pub struct CookieGenerator {
    /// Random secret for cookie generation (rotated periodically)
    secret: [u8; COOKIE_SECRET_SIZE],
    /// Timestamp when secret was created
    secret_time: u64,
}

impl CookieGenerator {
    /// Create a new cookie generator with a random secret
    pub fn new() -> Self {
        let mut secret = [0u8; COOKIE_SECRET_SIZE];
        fill_random(&mut secret);

        Self {
            secret,
            secret_time: current_timestamp(),
        }
    }

    /// Create a cookie generator with a specific secret (for testing)
    pub fn with_secret(secret: [u8; COOKIE_SECRET_SIZE]) -> Self {
        Self {
            secret,
            secret_time: current_timestamp(),
        }
    }

    /// Generate a cookie for a client
    ///
    /// cookie = HASH(secret || client_id || timestamp_bucket)
    pub fn generate(&self, client_id: &[u8]) -> [u8; COOKIE_SIZE] {
        let timestamp_bucket = current_timestamp() / COOKIE_VALIDITY_SECS;
        self.generate_for_bucket(client_id, timestamp_bucket)
    }

    /// Generate a cookie for a specific time bucket (internal use)
    fn generate_for_bucket(&self, client_id: &[u8], bucket: u64) -> [u8; COOKIE_SIZE] {
        use blake2::{Blake2s256, Digest};

        let mut hasher = Blake2s256::new();
        hasher.update(&self.secret);
        hasher.update(client_id);
        hasher.update(&bucket.to_le_bytes());
        let hash = hasher.finalize();

        let mut cookie = [0u8; COOKIE_SIZE];
        cookie.copy_from_slice(&hash[..COOKIE_SIZE]);
        cookie
    }

    /// Verify a cookie from a client
    ///
    /// Checks both current and previous time buckets for clock skew tolerance
    pub fn verify(&self, client_id: &[u8], cookie: &[u8; COOKIE_SIZE]) -> bool {
        let current_bucket = current_timestamp() / COOKIE_VALIDITY_SECS;

        // Check current bucket
        let expected = self.generate_for_bucket(client_id, current_bucket);
        if constant_time_compare(&expected, cookie) {
            return true;
        }

        // Check previous bucket (for clock skew)
        if current_bucket > 0 {
            let expected_prev = self.generate_for_bucket(client_id, current_bucket - 1);
            if constant_time_compare(&expected_prev, cookie) {
                return true;
            }
        }

        false
    }

    /// Rotate the secret (should be called periodically)
    pub fn rotate_secret(&mut self) {
        fill_random(&mut self.secret);
        self.secret_time = current_timestamp();
    }

    /// Check if secret should be rotated
    pub fn needs_rotation(&self) -> bool {
        current_timestamp() - self.secret_time > COOKIE_VALIDITY_SECS * 2
    }
}

impl Default for CookieGenerator {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// COOKIE REPLY MESSAGE
// ═══════════════════════════════════════════════════════════════════════════

/// Cookie reply message (64 bytes)
///
/// Sent when a handshake is rejected due to missing/invalid MAC2
/// under DoS protection mode.
///
/// ```text
/// ┌─────────────────────────────────────────────────────────────┐
/// │ Version (1)        │ Type (3)           │ Reserved (2)     │
/// ├─────────────────────────────────────────────────────────────┤
/// │ Receiver Index (4) (from init message)                     │
/// ├─────────────────────────────────────────────────────────────┤
/// │ Nonce (24) (for XChaCha20-Poly1305)                        │
/// ├─────────────────────────────────────────────────────────────┤
/// │ Encrypted Cookie (32 = 16 cookie + 16 tag)                 │
/// └─────────────────────────────────────────────────────────────┘
/// ```
#[derive(Clone)]
pub struct CookieReply {
    /// Receiver index from the rejected init message
    pub receiver_index: u32,
    /// Random nonce for encryption
    pub nonce: [u8; 24],
    /// Encrypted cookie (cookie + poly1305 tag)
    pub encrypted_cookie: [u8; 32],
}

impl CookieReply {
    /// Create a new cookie reply
    pub fn new(
        receiver_index: u32,
        nonce: [u8; 24],
        encrypted_cookie: [u8; 32],
    ) -> Self {
        Self {
            receiver_index,
            nonce,
            encrypted_cookie,
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; COOKIE_REPLY_SIZE] {
        let mut buf = [0u8; COOKIE_REPLY_SIZE];

        buf[0] = crate::constants::PROTOCOL_VERSION_V4;
        buf[1] = 3; // CookieReply type
        // Reserved bytes [2..4]
        buf[4..8].copy_from_slice(&self.receiver_index.to_le_bytes());
        buf[8..32].copy_from_slice(&self.nonce);
        buf[32..64].copy_from_slice(&self.encrypted_cookie);

        buf
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < COOKIE_REPLY_SIZE {
            return None;
        }

        // Version check
        if data[0] != crate::constants::PROTOCOL_VERSION_V4 {
            return None;
        }

        // Type check
        if data[1] != 3 {
            return None;
        }

        let receiver_index = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&data[8..32]);

        let mut encrypted_cookie = [0u8; 32];
        encrypted_cookie.copy_from_slice(&data[32..64]);

        Some(Self {
            receiver_index,
            nonce,
            encrypted_cookie,
        })
    }
}

impl std::fmt::Debug for CookieReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CookieReply")
            .field("receiver_index", &self.receiver_index)
            .finish_non_exhaustive()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════

/// BLAKE2s hash of two inputs concatenated
fn blake2s_hash_two(a: &[u8], b: &[u8]) -> [u8; 32] {
    use blake2::{Blake2s256, Digest};
    let mut hasher = Blake2s256::new();
    hasher.update(a);
    hasher.update(b);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Keyed BLAKE2s (using keyed mode)
fn keyed_blake2s(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    use blake2::{Blake2sMac, digest::{KeyInit, FixedOutput, Update}};
    use blake2::digest::consts::U32;

    let mut mac = Blake2sMac::<U32>::new_from_slice(key)
        .expect("Blake2sMac accepts 32-byte keys");
    mac.update(data);
    let result = mac.finalize_fixed();

    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Constant-time comparison
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Get current unix timestamp
fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Fill buffer with random bytes
fn fill_random(buf: &mut [u8]) {
    if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = file.read_exact(buf);
    } else {
        // Fallback: use timestamp-based pseudo-randomness
        let ts = current_timestamp();
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = ((ts >> (i % 8 * 8)) ^ (i as u64)) as u8;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_calculator_mac1() {
        let responder_public = [0x42u8; 32];
        let calc = MacCalculator::new(&responder_public);

        // Create a fake message
        let message = [0xABu8; 148]; // HandshakeInit size
        let mac1 = calc.compute_mac1(&message);

        assert_eq!(mac1.len(), HANDSHAKE_MAC_SIZE);

        // Verify MAC1
        assert!(calc.verify_mac1(&message, &mac1));
    }

    #[test]
    fn test_mac_calculator_mac1_different_keys() {
        let calc1 = MacCalculator::new(&[0x42u8; 32]);
        let calc2 = MacCalculator::new(&[0x43u8; 32]);

        let message = [0xABu8; 148];
        let mac1_a = calc1.compute_mac1(&message);
        let mac1_b = calc2.compute_mac1(&message);

        // Different keys should produce different MACs
        assert_ne!(mac1_a, mac1_b);
    }

    #[test]
    fn test_mac_calculator_mac1_verification_fails_for_tampered() {
        let calc = MacCalculator::new(&[0x42u8; 32]);

        let message = [0xABu8; 148];
        let mac1 = calc.compute_mac1(&message);

        // Tamper with message
        let mut tampered = message;
        tampered[0] ^= 1;

        assert!(!calc.verify_mac1(&tampered, &mac1));
    }

    #[test]
    fn test_mac_calculator_mac2() {
        let cookie = [0x42u8; COOKIE_SIZE];
        let message = [0xABu8; 148];

        let mac2 = MacCalculator::compute_mac2(&cookie, &message);
        assert_eq!(mac2.len(), HANDSHAKE_MAC_SIZE);

        // Verify
        assert!(MacCalculator::verify_mac2(&cookie, &message, &mac2));
    }

    #[test]
    fn test_mac_calculator_mac2_different_cookies() {
        let cookie1 = [0x42u8; COOKIE_SIZE];
        let cookie2 = [0x43u8; COOKIE_SIZE];
        let message = [0xABu8; 148];

        let mac2_a = MacCalculator::compute_mac2(&cookie1, &message);
        let mac2_b = MacCalculator::compute_mac2(&cookie2, &message);

        assert_ne!(mac2_a, mac2_b);
    }

    #[test]
    fn test_cookie_generator() {
        let gen = CookieGenerator::new();
        let client_id = b"192.168.1.100:12345";

        let cookie = gen.generate(client_id);
        assert_eq!(cookie.len(), COOKIE_SIZE);

        // Should verify immediately
        assert!(gen.verify(client_id, &cookie));
    }

    #[test]
    fn test_cookie_generator_different_clients() {
        let gen = CookieGenerator::new();

        let cookie_a = gen.generate(b"client_a");
        let cookie_b = gen.generate(b"client_b");

        // Different clients get different cookies
        assert_ne!(cookie_a, cookie_b);

        // Each can only verify their own
        assert!(gen.verify(b"client_a", &cookie_a));
        assert!(gen.verify(b"client_b", &cookie_b));
        assert!(!gen.verify(b"client_a", &cookie_b));
        assert!(!gen.verify(b"client_b", &cookie_a));
    }

    #[test]
    fn test_cookie_generator_deterministic_for_same_bucket() {
        let secret = [0x42u8; COOKIE_SECRET_SIZE];
        let gen = CookieGenerator::with_secret(secret);

        let cookie1 = gen.generate(b"client");
        let cookie2 = gen.generate(b"client");

        // Same client in same time bucket should get same cookie
        assert_eq!(cookie1, cookie2);
    }

    #[test]
    fn test_cookie_reply_roundtrip() {
        let reply = CookieReply::new(
            0x12345678,
            [0xAAu8; 24],
            [0xBBu8; 32],
        );

        let bytes = reply.to_bytes();
        assert_eq!(bytes.len(), COOKIE_REPLY_SIZE);

        let restored = CookieReply::from_bytes(&bytes).unwrap();
        assert_eq!(restored.receiver_index, reply.receiver_index);
        assert_eq!(restored.nonce, reply.nonce);
        assert_eq!(restored.encrypted_cookie, reply.encrypted_cookie);
    }

    #[test]
    fn test_cookie_reply_version_check() {
        let mut bytes = [0u8; COOKIE_REPLY_SIZE];
        bytes[0] = 3; // Wrong version
        bytes[1] = 3; // CookieReply type

        assert!(CookieReply::from_bytes(&bytes).is_none());
    }

    #[test]
    fn test_cookie_reply_type_check() {
        let mut bytes = [0u8; COOKIE_REPLY_SIZE];
        bytes[0] = crate::constants::PROTOCOL_VERSION_V4;
        bytes[1] = 1; // Wrong type (HandshakeInit)

        assert!(CookieReply::from_bytes(&bytes).is_none());
    }

    #[test]
    fn test_constant_time_compare() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5];
        let d = [1, 2, 3];

        assert!(constant_time_compare(&a, &b));
        assert!(!constant_time_compare(&a, &c));
        assert!(!constant_time_compare(&a, &d));
    }

    #[test]
    fn test_blake2s_hash_two() {
        let h1 = blake2s_hash_two(b"hello", b"world");
        let h2 = blake2s_hash_two(b"hello", b"world");
        let h3 = blake2s_hash_two(b"hello", b"universe");

        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn test_keyed_blake2s() {
        let key = [0x42u8; 32];
        let h1 = keyed_blake2s(&key, b"data");
        let h2 = keyed_blake2s(&key, b"data");
        let h3 = keyed_blake2s(&key, b"different");

        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }
}
