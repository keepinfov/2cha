//! # Protocol v4 Packet Types
//!
//! Data packet format for protocol v4 post-handshake communication.
//!
//! ## Data Packet Structure (variable size)
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │ Type (1) = 4                                                │
//! ├─────────────────────────────────────────────────────────────┤
//! │ Receiver Index (4)                                          │
//! ├─────────────────────────────────────────────────────────────┤
//! │ Counter (8)                                                 │
//! ├─────────────────────────────────────────────────────────────┤
//! │ Encrypted Payload (variable) + Poly1305 Tag (16)            │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! The counter serves as the nonce for ChaCha20-Poly1305 AEAD.
//! This eliminates the need for random nonce generation and enables
//! replay detection.

use crate::constants::{PROTOCOL_V4_DATA_HEADER_SIZE, POLY1305_TAG_SIZE, PROTOCOL_VERSION_V4};
use crate::error::{ProtocolError, Result};

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

/// Packet type for v4 data packets
pub const PACKET_TYPE_DATA: u8 = 4;

/// Packet type for v4 keepalive (empty data packet)
pub const PACKET_TYPE_KEEPALIVE: u8 = 4; // Same as data, just empty payload

/// Minimum v4 data packet size (header + tag, no payload)
pub const MIN_DATA_PACKET_SIZE: usize = PROTOCOL_V4_DATA_HEADER_SIZE + POLY1305_TAG_SIZE;

/// Maximum payload size (MTU - header - tag)
pub const MAX_PAYLOAD_SIZE: usize = 1500 - PROTOCOL_V4_DATA_HEADER_SIZE - POLY1305_TAG_SIZE;

// ═══════════════════════════════════════════════════════════════════════════
// DATA PACKET
// ═══════════════════════════════════════════════════════════════════════════

/// Protocol v4 data packet header
///
/// Used for encrypted payload transport after handshake completes.
#[derive(Debug, Clone, Copy)]
pub struct DataPacketHeader {
    /// Receiver's session index
    pub receiver_index: u32,
    /// Packet counter (used as nonce)
    pub counter: u64,
}

impl DataPacketHeader {
    /// Create a new data packet header
    pub fn new(receiver_index: u32, counter: u64) -> Self {
        Self {
            receiver_index,
            counter,
        }
    }

    /// Serialize header to bytes (13 bytes)
    pub fn to_bytes(&self) -> [u8; PROTOCOL_V4_DATA_HEADER_SIZE] {
        let mut buf = [0u8; PROTOCOL_V4_DATA_HEADER_SIZE];

        buf[0] = PACKET_TYPE_DATA;
        buf[1..5].copy_from_slice(&self.receiver_index.to_le_bytes());
        buf[5..13].copy_from_slice(&self.counter.to_le_bytes());

        buf
    }

    /// Deserialize header from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < PROTOCOL_V4_DATA_HEADER_SIZE {
            return Err(ProtocolError::PacketTooSmall {
                min: PROTOCOL_V4_DATA_HEADER_SIZE,
                got: data.len(),
            }.into());
        }

        // Type check
        if data[0] != PACKET_TYPE_DATA {
            return Err(ProtocolError::InvalidPacketType(data[0]).into());
        }

        let receiver_index = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
        let counter = u64::from_le_bytes([
            data[5], data[6], data[7], data[8],
            data[9], data[10], data[11], data[12],
        ]);

        Ok(Self {
            receiver_index,
            counter,
        })
    }

    /// Get the nonce for AEAD encryption (counter padded to 12 bytes)
    pub fn to_nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        // Put counter in the last 8 bytes, first 4 bytes are zero
        nonce[4..12].copy_from_slice(&self.counter.to_le_bytes());
        nonce
    }
}

/// Complete v4 data packet
#[derive(Debug, Clone)]
pub struct DataPacket {
    /// Packet header
    pub header: DataPacketHeader,
    /// Encrypted payload + authentication tag
    pub encrypted_payload: Vec<u8>,
}

impl DataPacket {
    /// Create a new data packet (payload should already be encrypted)
    pub fn new(receiver_index: u32, counter: u64, encrypted_payload: Vec<u8>) -> Self {
        Self {
            header: DataPacketHeader::new(receiver_index, counter),
            encrypted_payload,
        }
    }

    /// Create a keepalive packet (empty payload, still has auth tag)
    pub fn new_keepalive(receiver_index: u32, counter: u64, auth_tag: [u8; POLY1305_TAG_SIZE]) -> Self {
        Self {
            header: DataPacketHeader::new(receiver_index, counter),
            encrypted_payload: auth_tag.to_vec(),
        }
    }

    /// Serialize packet to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(PROTOCOL_V4_DATA_HEADER_SIZE + self.encrypted_payload.len());
        buf.extend_from_slice(&self.header.to_bytes());
        buf.extend_from_slice(&self.encrypted_payload);
        buf
    }

    /// Deserialize packet from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < MIN_DATA_PACKET_SIZE {
            return Err(ProtocolError::PacketTooSmall {
                min: MIN_DATA_PACKET_SIZE,
                got: data.len(),
            }.into());
        }

        let header = DataPacketHeader::from_bytes(data)?;
        let encrypted_payload = data[PROTOCOL_V4_DATA_HEADER_SIZE..].to_vec();

        Ok(Self {
            header,
            encrypted_payload,
        })
    }

    /// Check if this is a keepalive (empty payload after decryption)
    pub fn is_keepalive(&self) -> bool {
        self.encrypted_payload.len() == POLY1305_TAG_SIZE
    }

    /// Total packet size
    pub fn size(&self) -> usize {
        PROTOCOL_V4_DATA_HEADER_SIZE + self.encrypted_payload.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// V4 PACKET TYPE ENUM
// ═══════════════════════════════════════════════════════════════════════════

/// Protocol v4 packet types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketTypeV4 {
    /// Handshake initiation
    HandshakeInit = 1,
    /// Handshake response
    HandshakeResponse = 2,
    /// Cookie reply (DoS protection)
    CookieReply = 3,
    /// Data packet (includes keepalive)
    Data = 4,
}

impl PacketTypeV4 {
    /// Parse packet type from first byte
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(PacketTypeV4::HandshakeInit),
            2 => Some(PacketTypeV4::HandshakeResponse),
            3 => Some(PacketTypeV4::CookieReply),
            4 => Some(PacketTypeV4::Data),
            _ => None,
        }
    }

    /// Check if this is a handshake packet
    pub fn is_handshake(&self) -> bool {
        matches!(self, PacketTypeV4::HandshakeInit | PacketTypeV4::HandshakeResponse)
    }

    /// Get expected minimum packet size for this type
    pub fn min_size(&self) -> usize {
        match self {
            PacketTypeV4::HandshakeInit => crate::constants::HANDSHAKE_INIT_SIZE,
            PacketTypeV4::HandshakeResponse => crate::constants::HANDSHAKE_RESPONSE_SIZE,
            PacketTypeV4::CookieReply => crate::mac::COOKIE_REPLY_SIZE,
            PacketTypeV4::Data => MIN_DATA_PACKET_SIZE,
        }
    }
}

/// Identify packet type from raw bytes
///
/// Protocol v4 has two packet formats:
/// - Handshake packets: Version(4) + Type(1/2/3) + ...
/// - Data packets: Type(4) + ReceiverIndex(4) + ...
///
/// Since PROTOCOL_VERSION_V4 == 4 and PACKET_TYPE_DATA == 4,
/// we distinguish them by the second byte:
/// - If second byte is 1, 2, or 3: it's a handshake/cookie packet
/// - Otherwise: it's a data packet (second byte is part of receiver_index)
pub fn identify_packet_type(data: &[u8]) -> Option<PacketTypeV4> {
    if data.len() < 2 {
        return None;
    }

    // First byte is either version (for handshake) or type (for data)
    // Both are value 4 for v4 protocol

    if data[0] == PROTOCOL_VERSION_V4 {
        // Could be handshake (version=4, type=1/2/3) or data (type=4, receiver_index...)
        // Check if second byte is a valid handshake type
        match data[1] {
            1 => Some(PacketTypeV4::HandshakeInit),
            2 => Some(PacketTypeV4::HandshakeResponse),
            3 => Some(PacketTypeV4::CookieReply),
            _ => Some(PacketTypeV4::Data), // Second byte is part of receiver_index
        }
    } else {
        // Unknown packet format
        None
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_packet_header_roundtrip() {
        let header = DataPacketHeader::new(0x12345678, 0xAABBCCDDEEFF0011);
        let bytes = header.to_bytes();

        assert_eq!(bytes.len(), PROTOCOL_V4_DATA_HEADER_SIZE);
        assert_eq!(bytes[0], PACKET_TYPE_DATA);

        let restored = DataPacketHeader::from_bytes(&bytes).unwrap();
        assert_eq!(restored.receiver_index, header.receiver_index);
        assert_eq!(restored.counter, header.counter);
    }

    #[test]
    fn test_data_packet_header_nonce() {
        let header = DataPacketHeader::new(0, 0x0102030405060708);
        let nonce = header.to_nonce();

        // First 4 bytes should be zero
        assert_eq!(&nonce[0..4], &[0, 0, 0, 0]);
        // Last 8 bytes should be counter in little-endian
        assert_eq!(&nonce[4..12], &0x0102030405060708u64.to_le_bytes());
    }

    #[test]
    fn test_data_packet_roundtrip() {
        let payload = vec![0xAA; 100]; // Simulated encrypted payload
        let packet = DataPacket::new(0x12345678, 42, payload.clone());

        let bytes = packet.to_bytes();
        let restored = DataPacket::from_bytes(&bytes).unwrap();

        assert_eq!(restored.header.receiver_index, 0x12345678);
        assert_eq!(restored.header.counter, 42);
        assert_eq!(restored.encrypted_payload, payload);
    }

    #[test]
    fn test_data_packet_keepalive() {
        let tag = [0xBB; POLY1305_TAG_SIZE];
        let packet = DataPacket::new_keepalive(0x12345678, 1, tag);

        assert!(packet.is_keepalive());
        assert_eq!(packet.encrypted_payload.len(), POLY1305_TAG_SIZE);
    }

    #[test]
    fn test_data_packet_not_keepalive() {
        let payload = vec![0xAA; 50];
        let packet = DataPacket::new(0x12345678, 1, payload);

        assert!(!packet.is_keepalive());
    }

    #[test]
    fn test_data_packet_too_small() {
        let bytes = [0u8; 10];
        let result = DataPacket::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_packet_type_v4_from_u8() {
        assert_eq!(PacketTypeV4::from_u8(1), Some(PacketTypeV4::HandshakeInit));
        assert_eq!(PacketTypeV4::from_u8(2), Some(PacketTypeV4::HandshakeResponse));
        assert_eq!(PacketTypeV4::from_u8(3), Some(PacketTypeV4::CookieReply));
        assert_eq!(PacketTypeV4::from_u8(4), Some(PacketTypeV4::Data));
        assert_eq!(PacketTypeV4::from_u8(5), None);
    }

    #[test]
    fn test_packet_type_is_handshake() {
        assert!(PacketTypeV4::HandshakeInit.is_handshake());
        assert!(PacketTypeV4::HandshakeResponse.is_handshake());
        assert!(!PacketTypeV4::CookieReply.is_handshake());
        assert!(!PacketTypeV4::Data.is_handshake());
    }

    #[test]
    fn test_identify_packet_type_data() {
        // Data packet: Type(4) + ReceiverIndex(4) + Counter(8) + payload
        // Second byte is NOT 1, 2, or 3, so it's identified as data
        let mut packet = vec![PACKET_TYPE_DATA, 0x12]; // type + first byte of receiver_index
        packet.extend_from_slice(&[0u8; 27]); // Rest of min data packet

        assert_eq!(identify_packet_type(&packet), Some(PacketTypeV4::Data));
    }

    #[test]
    fn test_identify_packet_type_handshake() {
        let mut packet = vec![PROTOCOL_VERSION_V4, 1]; // Version + HandshakeInit type
        packet.extend_from_slice(&[0u8; 146]); // Rest of handshake

        assert_eq!(identify_packet_type(&packet), Some(PacketTypeV4::HandshakeInit));
    }

    #[test]
    fn test_identify_packet_type_too_small() {
        // Need at least 2 bytes
        assert_eq!(identify_packet_type(&[]), None);
        assert_eq!(identify_packet_type(&[4]), None);
    }

    #[test]
    fn test_identify_packet_type_unknown() {
        // First byte is not PROTOCOL_VERSION_V4 (4)
        assert_eq!(identify_packet_type(&[3, 1]), None);
        assert_eq!(identify_packet_type(&[5, 1]), None);
    }

    #[test]
    fn test_packet_size() {
        let payload = vec![0xAA; 100];
        let packet = DataPacket::new(0, 0, payload);

        assert_eq!(packet.size(), PROTOCOL_V4_DATA_HEADER_SIZE + 100);
    }
}
