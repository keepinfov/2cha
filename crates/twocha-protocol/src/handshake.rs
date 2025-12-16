//! # Handshake Message Structures (Protocol v4)
//!
//! Provides Noise_IK handshake message types for protocol v4.
//!
//! ## Handshake Pattern: Noise_IK
//!
//! The IK pattern provides:
//! - Initiator identity hidden from passive observers
//! - Responder identity authenticated by initiator
//! - Perfect Forward Secrecy (PFS)
//!
//! Message flow:
//! ```text
//! -> e, es, s, ss    (HandshakeInit)
//! <- e, ee, se       (HandshakeResponse)
//! ```
//!
//! ## Packet Structures
//!
//! ### HandshakeInit (148 bytes)
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │ Version (1)        │ Type (1)           │ Reserved (2)     │
//! ├─────────────────────────────────────────────────────────────┤
//! │ Sender Index (4)                                           │
//! ├─────────────────────────────────────────────────────────────┤
//! │ Ephemeral Public Key (32)                                  │
//! ├─────────────────────────────────────────────────────────────┤
//! │ Encrypted Static Key (48 = 32 key + 16 tag)                │
//! ├─────────────────────────────────────────────────────────────┤
//! │ Encrypted Timestamp (28 = 12 data + 16 tag)                │
//! ├─────────────────────────────────────────────────────────────┤
//! │ MAC1 (16)                                                  │
//! ├─────────────────────────────────────────────────────────────┤
//! │ MAC2 (16)                                                  │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ### HandshakeResponse (92 bytes)
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │ Version (1)        │ Type (1)           │ Reserved (2)     │
//! ├─────────────────────────────────────────────────────────────┤
//! │ Sender Index (4)                                           │
//! ├─────────────────────────────────────────────────────────────┤
//! │ Receiver Index (4)                                         │
//! ├─────────────────────────────────────────────────────────────┤
//! │ Ephemeral Public Key (32)                                  │
//! ├─────────────────────────────────────────────────────────────┤
//! │ Encrypted Empty (16)                                       │
//! ├─────────────────────────────────────────────────────────────┤
//! │ MAC1 (16)                                                  │
//! ├─────────────────────────────────────────────────────────────┤
//! │ MAC2 (16)                                                  │
//! └─────────────────────────────────────────────────────────────┘
//! ```

use crate::constants::{
    HANDSHAKE_INIT_SIZE, HANDSHAKE_RESPONSE_SIZE, HANDSHAKE_MAC_SIZE,
    PROTOCOL_VERSION_V4, X25519_PUBLIC_KEY_SIZE,
};
use crate::error::{ProtocolError, Result};

// ═══════════════════════════════════════════════════════════════════════════
// SIZE CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

/// Encrypted static key size (32-byte key + 16-byte Poly1305 tag)
pub const ENCRYPTED_STATIC_SIZE: usize = 48;

/// Encrypted timestamp size (12-byte TAI64N + 16-byte Poly1305 tag)
pub const ENCRYPTED_TIMESTAMP_SIZE: usize = 28;

/// Encrypted empty message size (0-byte message + 16-byte Poly1305 tag)
pub const ENCRYPTED_EMPTY_SIZE: usize = 16;

/// TAI64N timestamp size in bytes
pub const TAI64N_SIZE: usize = 12;

// ═══════════════════════════════════════════════════════════════════════════
// MESSAGE TYPE IDENTIFIERS
// ═══════════════════════════════════════════════════════════════════════════

/// Handshake message type identifiers for v4 protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeType {
    /// Handshake initiation message
    Init = 1,
    /// Handshake response message
    Response = 2,
    /// Cookie reply (for DoS protection)
    CookieReply = 3,
}

impl HandshakeType {
    /// Parse from byte value
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(HandshakeType::Init),
            2 => Some(HandshakeType::Response),
            3 => Some(HandshakeType::CookieReply),
            _ => None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// HANDSHAKE INIT MESSAGE
// ═══════════════════════════════════════════════════════════════════════════

/// Handshake initiation message (148 bytes)
///
/// Sent by the initiator to begin the Noise_IK handshake.
/// Contains:
/// - Initiator's ephemeral public key
/// - Encrypted initiator static public key
/// - Encrypted TAI64N timestamp (for replay protection)
/// - MAC1/MAC2 for DoS protection
#[derive(Clone)]
pub struct HandshakeInit {
    /// Sender's session index (for demultiplexing)
    pub sender_index: u32,
    /// Initiator's ephemeral X25519 public key
    pub ephemeral_public: [u8; X25519_PUBLIC_KEY_SIZE],
    /// Encrypted initiator static public key (32 bytes + 16 byte tag)
    pub encrypted_static: [u8; ENCRYPTED_STATIC_SIZE],
    /// Encrypted TAI64N timestamp (12 bytes + 16 byte tag)
    pub encrypted_timestamp: [u8; ENCRYPTED_TIMESTAMP_SIZE],
    /// First MAC for verification
    pub mac1: [u8; HANDSHAKE_MAC_SIZE],
    /// Second MAC for cookie verification (zeros if no cookie)
    pub mac2: [u8; HANDSHAKE_MAC_SIZE],
}

impl HandshakeInit {
    /// Create a new handshake init message
    pub fn new(
        sender_index: u32,
        ephemeral_public: [u8; X25519_PUBLIC_KEY_SIZE],
        encrypted_static: [u8; ENCRYPTED_STATIC_SIZE],
        encrypted_timestamp: [u8; ENCRYPTED_TIMESTAMP_SIZE],
    ) -> Self {
        Self {
            sender_index,
            ephemeral_public,
            encrypted_static,
            encrypted_timestamp,
            mac1: [0u8; HANDSHAKE_MAC_SIZE],
            mac2: [0u8; HANDSHAKE_MAC_SIZE],
        }
    }

    /// Serialize to bytes (148 bytes)
    pub fn to_bytes(&self) -> [u8; HANDSHAKE_INIT_SIZE] {
        let mut buf = [0u8; HANDSHAKE_INIT_SIZE];
        let mut offset = 0;

        // Version (1 byte)
        buf[offset] = PROTOCOL_VERSION_V4;
        offset += 1;

        // Type (1 byte)
        buf[offset] = HandshakeType::Init as u8;
        offset += 1;

        // Reserved (2 bytes)
        offset += 2;

        // Sender index (4 bytes, little-endian)
        buf[offset..offset + 4].copy_from_slice(&self.sender_index.to_le_bytes());
        offset += 4;

        // Ephemeral public key (32 bytes)
        buf[offset..offset + X25519_PUBLIC_KEY_SIZE].copy_from_slice(&self.ephemeral_public);
        offset += X25519_PUBLIC_KEY_SIZE;

        // Encrypted static (48 bytes)
        buf[offset..offset + ENCRYPTED_STATIC_SIZE].copy_from_slice(&self.encrypted_static);
        offset += ENCRYPTED_STATIC_SIZE;

        // Encrypted timestamp (28 bytes)
        buf[offset..offset + ENCRYPTED_TIMESTAMP_SIZE].copy_from_slice(&self.encrypted_timestamp);
        offset += ENCRYPTED_TIMESTAMP_SIZE;

        // MAC1 (16 bytes)
        buf[offset..offset + HANDSHAKE_MAC_SIZE].copy_from_slice(&self.mac1);
        offset += HANDSHAKE_MAC_SIZE;

        // MAC2 (16 bytes)
        buf[offset..offset + HANDSHAKE_MAC_SIZE].copy_from_slice(&self.mac2);

        buf
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < HANDSHAKE_INIT_SIZE {
            return Err(ProtocolError::PacketTooSmall {
                min: HANDSHAKE_INIT_SIZE,
                got: data.len(),
            }.into());
        }

        let mut offset = 0;

        // Version check
        let version = data[offset];
        if version != PROTOCOL_VERSION_V4 {
            return Err(ProtocolError::InvalidVersion {
                expected: PROTOCOL_VERSION_V4,
                got: version,
            }.into());
        }
        offset += 1;

        // Type check
        let msg_type = data[offset];
        if msg_type != HandshakeType::Init as u8 {
            return Err(ProtocolError::UnexpectedPacket(
                format!("Expected HandshakeInit (1), got {}", msg_type)
            ).into());
        }
        offset += 1;

        // Skip reserved
        offset += 2;

        // Sender index
        let sender_index = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]);
        offset += 4;

        // Ephemeral public key
        let mut ephemeral_public = [0u8; X25519_PUBLIC_KEY_SIZE];
        ephemeral_public.copy_from_slice(&data[offset..offset + X25519_PUBLIC_KEY_SIZE]);
        offset += X25519_PUBLIC_KEY_SIZE;

        // Encrypted static
        let mut encrypted_static = [0u8; ENCRYPTED_STATIC_SIZE];
        encrypted_static.copy_from_slice(&data[offset..offset + ENCRYPTED_STATIC_SIZE]);
        offset += ENCRYPTED_STATIC_SIZE;

        // Encrypted timestamp
        let mut encrypted_timestamp = [0u8; ENCRYPTED_TIMESTAMP_SIZE];
        encrypted_timestamp.copy_from_slice(&data[offset..offset + ENCRYPTED_TIMESTAMP_SIZE]);
        offset += ENCRYPTED_TIMESTAMP_SIZE;

        // MAC1
        let mut mac1 = [0u8; HANDSHAKE_MAC_SIZE];
        mac1.copy_from_slice(&data[offset..offset + HANDSHAKE_MAC_SIZE]);
        offset += HANDSHAKE_MAC_SIZE;

        // MAC2
        let mut mac2 = [0u8; HANDSHAKE_MAC_SIZE];
        mac2.copy_from_slice(&data[offset..offset + HANDSHAKE_MAC_SIZE]);

        Ok(Self {
            sender_index,
            ephemeral_public,
            encrypted_static,
            encrypted_timestamp,
            mac1,
            mac2,
        })
    }

    /// Get the bytes that MAC1 covers (everything except MAC1 and MAC2)
    pub fn mac1_input(&self) -> Vec<u8> {
        let bytes = self.to_bytes();
        bytes[..HANDSHAKE_INIT_SIZE - 2 * HANDSHAKE_MAC_SIZE].to_vec()
    }

    /// Get the bytes that MAC2 covers (everything except MAC2)
    pub fn mac2_input(&self) -> Vec<u8> {
        let bytes = self.to_bytes();
        bytes[..HANDSHAKE_INIT_SIZE - HANDSHAKE_MAC_SIZE].to_vec()
    }
}

impl std::fmt::Debug for HandshakeInit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeInit")
            .field("sender_index", &self.sender_index)
            .field("ephemeral_public", &hex_encode(&self.ephemeral_public))
            .finish_non_exhaustive()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// HANDSHAKE RESPONSE MESSAGE
// ═══════════════════════════════════════════════════════════════════════════

/// Handshake response message (92 bytes)
///
/// Sent by the responder to complete the Noise_IK handshake.
/// Contains:
/// - Responder's ephemeral public key
/// - Encrypted empty payload (for key confirmation)
/// - MAC1/MAC2 for DoS protection
#[derive(Clone)]
pub struct HandshakeResponse {
    /// Responder's session index
    pub sender_index: u32,
    /// Initiator's session index (from init message)
    pub receiver_index: u32,
    /// Responder's ephemeral X25519 public key
    pub ephemeral_public: [u8; X25519_PUBLIC_KEY_SIZE],
    /// Encrypted empty payload (for key confirmation)
    pub encrypted_empty: [u8; ENCRYPTED_EMPTY_SIZE],
    /// First MAC for verification
    pub mac1: [u8; HANDSHAKE_MAC_SIZE],
    /// Second MAC for cookie verification
    pub mac2: [u8; HANDSHAKE_MAC_SIZE],
}

impl HandshakeResponse {
    /// Create a new handshake response message
    pub fn new(
        sender_index: u32,
        receiver_index: u32,
        ephemeral_public: [u8; X25519_PUBLIC_KEY_SIZE],
        encrypted_empty: [u8; ENCRYPTED_EMPTY_SIZE],
    ) -> Self {
        Self {
            sender_index,
            receiver_index,
            ephemeral_public,
            encrypted_empty,
            mac1: [0u8; HANDSHAKE_MAC_SIZE],
            mac2: [0u8; HANDSHAKE_MAC_SIZE],
        }
    }

    /// Serialize to bytes (92 bytes)
    pub fn to_bytes(&self) -> [u8; HANDSHAKE_RESPONSE_SIZE] {
        let mut buf = [0u8; HANDSHAKE_RESPONSE_SIZE];
        let mut offset = 0;

        // Version (1 byte)
        buf[offset] = PROTOCOL_VERSION_V4;
        offset += 1;

        // Type (1 byte)
        buf[offset] = HandshakeType::Response as u8;
        offset += 1;

        // Reserved (2 bytes)
        offset += 2;

        // Sender index (4 bytes)
        buf[offset..offset + 4].copy_from_slice(&self.sender_index.to_le_bytes());
        offset += 4;

        // Receiver index (4 bytes)
        buf[offset..offset + 4].copy_from_slice(&self.receiver_index.to_le_bytes());
        offset += 4;

        // Ephemeral public key (32 bytes)
        buf[offset..offset + X25519_PUBLIC_KEY_SIZE].copy_from_slice(&self.ephemeral_public);
        offset += X25519_PUBLIC_KEY_SIZE;

        // Encrypted empty (16 bytes)
        buf[offset..offset + ENCRYPTED_EMPTY_SIZE].copy_from_slice(&self.encrypted_empty);
        offset += ENCRYPTED_EMPTY_SIZE;

        // MAC1 (16 bytes)
        buf[offset..offset + HANDSHAKE_MAC_SIZE].copy_from_slice(&self.mac1);
        offset += HANDSHAKE_MAC_SIZE;

        // MAC2 (16 bytes)
        buf[offset..offset + HANDSHAKE_MAC_SIZE].copy_from_slice(&self.mac2);

        buf
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < HANDSHAKE_RESPONSE_SIZE {
            return Err(ProtocolError::PacketTooSmall {
                min: HANDSHAKE_RESPONSE_SIZE,
                got: data.len(),
            }.into());
        }

        let mut offset = 0;

        // Version check
        let version = data[offset];
        if version != PROTOCOL_VERSION_V4 {
            return Err(ProtocolError::InvalidVersion {
                expected: PROTOCOL_VERSION_V4,
                got: version,
            }.into());
        }
        offset += 1;

        // Type check
        let msg_type = data[offset];
        if msg_type != HandshakeType::Response as u8 {
            return Err(ProtocolError::UnexpectedPacket(
                format!("Expected HandshakeResponse (2), got {}", msg_type)
            ).into());
        }
        offset += 1;

        // Skip reserved
        offset += 2;

        // Sender index
        let sender_index = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]);
        offset += 4;

        // Receiver index
        let receiver_index = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]);
        offset += 4;

        // Ephemeral public key
        let mut ephemeral_public = [0u8; X25519_PUBLIC_KEY_SIZE];
        ephemeral_public.copy_from_slice(&data[offset..offset + X25519_PUBLIC_KEY_SIZE]);
        offset += X25519_PUBLIC_KEY_SIZE;

        // Encrypted empty
        let mut encrypted_empty = [0u8; ENCRYPTED_EMPTY_SIZE];
        encrypted_empty.copy_from_slice(&data[offset..offset + ENCRYPTED_EMPTY_SIZE]);
        offset += ENCRYPTED_EMPTY_SIZE;

        // MAC1
        let mut mac1 = [0u8; HANDSHAKE_MAC_SIZE];
        mac1.copy_from_slice(&data[offset..offset + HANDSHAKE_MAC_SIZE]);
        offset += HANDSHAKE_MAC_SIZE;

        // MAC2
        let mut mac2 = [0u8; HANDSHAKE_MAC_SIZE];
        mac2.copy_from_slice(&data[offset..offset + HANDSHAKE_MAC_SIZE]);

        Ok(Self {
            sender_index,
            receiver_index,
            ephemeral_public,
            encrypted_empty,
            mac1,
            mac2,
        })
    }

    /// Get the bytes that MAC1 covers (everything except MAC1 and MAC2)
    pub fn mac1_input(&self) -> Vec<u8> {
        let bytes = self.to_bytes();
        bytes[..HANDSHAKE_RESPONSE_SIZE - 2 * HANDSHAKE_MAC_SIZE].to_vec()
    }

    /// Get the bytes that MAC2 covers (everything except MAC2)
    pub fn mac2_input(&self) -> Vec<u8> {
        let bytes = self.to_bytes();
        bytes[..HANDSHAKE_RESPONSE_SIZE - HANDSHAKE_MAC_SIZE].to_vec()
    }
}

impl std::fmt::Debug for HandshakeResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeResponse")
            .field("sender_index", &self.sender_index)
            .field("receiver_index", &self.receiver_index)
            .field("ephemeral_public", &hex_encode(&self.ephemeral_public))
            .finish_non_exhaustive()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TAI64N TIMESTAMP
// ═══════════════════════════════════════════════════════════════════════════

/// TAI64N timestamp for replay protection
///
/// TAI64N is a 12-byte timestamp format:
/// - 8 bytes: TAI64 (seconds since 1970-01-01 00:00:00 TAI + 2^62)
/// - 4 bytes: Nanoseconds
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Tai64n([u8; TAI64N_SIZE]);

impl Tai64n {
    /// TAI64 epoch offset (2^62)
    const TAI64_EPOCH: u64 = 1u64 << 62;

    /// Create a new TAI64N timestamp from the current time
    pub fn now() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();

        let seconds = duration.as_secs() + Self::TAI64_EPOCH;
        let nanos = duration.subsec_nanos();

        let mut bytes = [0u8; TAI64N_SIZE];
        bytes[0..8].copy_from_slice(&seconds.to_be_bytes());
        bytes[8..12].copy_from_slice(&nanos.to_be_bytes());

        Self(bytes)
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != TAI64N_SIZE {
            return None;
        }
        let mut arr = [0u8; TAI64N_SIZE];
        arr.copy_from_slice(bytes);
        Some(Self(arr))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; TAI64N_SIZE] {
        &self.0
    }

    /// Convert to bytes array
    pub fn to_bytes(self) -> [u8; TAI64N_SIZE] {
        self.0
    }

    /// Check if this timestamp is newer than another
    pub fn is_newer_than(&self, other: &Self) -> bool {
        self.0 > other.0
    }
}

impl std::fmt::Debug for Tai64n {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Tai64n({})", hex_encode(&self.0))
    }
}

impl Default for Tai64n {
    fn default() -> Self {
        Self::now()
    }
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
    fn test_handshake_init_size() {
        let init = HandshakeInit::new(
            12345,
            [1u8; 32],
            [2u8; 48],
            [3u8; 28],
        );
        let bytes = init.to_bytes();
        assert_eq!(bytes.len(), HANDSHAKE_INIT_SIZE);
    }

    #[test]
    fn test_handshake_init_roundtrip() {
        let init = HandshakeInit {
            sender_index: 0x12345678,
            ephemeral_public: [0xAA; 32],
            encrypted_static: [0xBB; 48],
            encrypted_timestamp: [0xCC; 28],
            mac1: [0xDD; 16],
            mac2: [0xEE; 16],
        };

        let bytes = init.to_bytes();
        let restored = HandshakeInit::from_bytes(&bytes).unwrap();

        assert_eq!(restored.sender_index, init.sender_index);
        assert_eq!(restored.ephemeral_public, init.ephemeral_public);
        assert_eq!(restored.encrypted_static, init.encrypted_static);
        assert_eq!(restored.encrypted_timestamp, init.encrypted_timestamp);
        assert_eq!(restored.mac1, init.mac1);
        assert_eq!(restored.mac2, init.mac2);
    }

    #[test]
    fn test_handshake_response_size() {
        let response = HandshakeResponse::new(
            12345,
            67890,
            [1u8; 32],
            [2u8; 16],
        );
        let bytes = response.to_bytes();
        assert_eq!(bytes.len(), HANDSHAKE_RESPONSE_SIZE);
    }

    #[test]
    fn test_handshake_response_roundtrip() {
        let response = HandshakeResponse {
            sender_index: 0x12345678,
            receiver_index: 0x87654321,
            ephemeral_public: [0xAA; 32],
            encrypted_empty: [0xBB; 16],
            mac1: [0xCC; 16],
            mac2: [0xDD; 16],
        };

        let bytes = response.to_bytes();
        let restored = HandshakeResponse::from_bytes(&bytes).unwrap();

        assert_eq!(restored.sender_index, response.sender_index);
        assert_eq!(restored.receiver_index, response.receiver_index);
        assert_eq!(restored.ephemeral_public, response.ephemeral_public);
        assert_eq!(restored.encrypted_empty, response.encrypted_empty);
        assert_eq!(restored.mac1, response.mac1);
        assert_eq!(restored.mac2, response.mac2);
    }

    #[test]
    fn test_handshake_init_version_check() {
        let mut bytes = [0u8; HANDSHAKE_INIT_SIZE];
        bytes[0] = 3; // Wrong version
        bytes[1] = HandshakeType::Init as u8;

        let result = HandshakeInit::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_handshake_init_type_check() {
        let mut bytes = [0u8; HANDSHAKE_INIT_SIZE];
        bytes[0] = PROTOCOL_VERSION_V4;
        bytes[1] = HandshakeType::Response as u8; // Wrong type

        let result = HandshakeInit::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_handshake_init_too_small() {
        let bytes = [0u8; 10];
        let result = HandshakeInit::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_tai64n_now() {
        let ts1 = Tai64n::now();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let ts2 = Tai64n::now();

        assert!(ts2.is_newer_than(&ts1));
    }

    #[test]
    fn test_tai64n_roundtrip() {
        let ts = Tai64n::now();
        let bytes = ts.to_bytes();
        let restored = Tai64n::from_bytes(&bytes).unwrap();
        assert_eq!(ts, restored);
    }

    #[test]
    fn test_tai64n_from_bytes_wrong_size() {
        let bytes = [0u8; 8];
        assert!(Tai64n::from_bytes(&bytes).is_none());
    }

    #[test]
    fn test_mac1_input() {
        let init = HandshakeInit::new(
            12345,
            [1u8; 32],
            [2u8; 48],
            [3u8; 28],
        );
        let mac1_input = init.mac1_input();
        // MAC1 input should be everything except MAC1 (16) and MAC2 (16)
        assert_eq!(mac1_input.len(), HANDSHAKE_INIT_SIZE - 32);
    }

    #[test]
    fn test_mac2_input() {
        let init = HandshakeInit::new(
            12345,
            [1u8; 32],
            [2u8; 48],
            [3u8; 28],
        );
        let mac2_input = init.mac2_input();
        // MAC2 input should be everything except MAC2 (16)
        assert_eq!(mac2_input.len(), HANDSHAKE_INIT_SIZE - 16);
    }

    #[test]
    fn test_handshake_type_from_u8() {
        assert_eq!(HandshakeType::from_u8(1), Some(HandshakeType::Init));
        assert_eq!(HandshakeType::from_u8(2), Some(HandshakeType::Response));
        assert_eq!(HandshakeType::from_u8(3), Some(HandshakeType::CookieReply));
        assert_eq!(HandshakeType::from_u8(4), None);
    }
}
