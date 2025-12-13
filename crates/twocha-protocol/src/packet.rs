//! # Packet Types
//!
//! VPN protocol packet structures and serialization.

use crate::constants::{CHACHA20_NONCE_SIZE, PROTOCOL_HEADER_SIZE, PROTOCOL_VERSION};
use crate::error::{ProtocolError, Result};

/// Packet types for the VPN protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    HandshakeInit = 1,
    HandshakeResponse = 2,
    Data = 3,
    Keepalive = 4,
    Disconnect = 5,
}

impl PacketType {
    /// Parse packet type from byte value
    #[inline]
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(PacketType::HandshakeInit),
            2 => Ok(PacketType::HandshakeResponse),
            3 => Ok(PacketType::Data),
            4 => Ok(PacketType::Keepalive),
            5 => Ok(PacketType::Disconnect),
            _ => Err(ProtocolError::InvalidPacketType(value).into()),
        }
    }
}

/// Packet header (24 bytes)
///
/// ```text
/// ┌────────┬────────┬────────────┬──────────────────────────┐
/// │ Version│  Type  │  Counter   │         Nonce            │
/// │ (1)    │  (1)   │   (4)      │         (12)             │
/// └────────┴────────┴────────────┴──────────────────────────┘
/// │ Reserved (6)                                            │
/// └─────────────────────────────────────────────────────────┘
/// ```
#[derive(Debug, Clone)]
pub struct PacketHeader {
    pub version: u8,
    pub packet_type: PacketType,
    pub counter: u32,
    pub nonce: [u8; CHACHA20_NONCE_SIZE],
}

impl PacketHeader {
    /// Create new header with random nonce
    pub fn new(packet_type: PacketType, counter: u32) -> Self {
        let mut nonce = [0u8; CHACHA20_NONCE_SIZE];

        // Nonce = counter (4 bytes) + random (8 bytes)
        nonce[0..4].copy_from_slice(&counter.to_le_bytes());

        // Get randomness from /dev/urandom or fallback to timestamp
        if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
            use std::io::Read;
            let _ = file.read_exact(&mut nonce[4..12]);
        } else {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64;
            nonce[4..12].copy_from_slice(&timestamp.to_le_bytes());
        }

        PacketHeader {
            version: PROTOCOL_VERSION,
            packet_type,
            counter,
            nonce,
        }
    }

    /// Create header with specific nonce
    #[inline]
    pub fn with_nonce(
        packet_type: PacketType,
        counter: u32,
        nonce: [u8; CHACHA20_NONCE_SIZE],
    ) -> Self {
        PacketHeader {
            version: PROTOCOL_VERSION,
            packet_type,
            counter,
            nonce,
        }
    }

    /// Serialize to bytes
    #[inline]
    pub fn serialize(&self) -> [u8; PROTOCOL_HEADER_SIZE] {
        let mut buf = [0u8; PROTOCOL_HEADER_SIZE];
        buf[0] = self.version;
        buf[1] = self.packet_type as u8;
        buf[2..6].copy_from_slice(&self.counter.to_le_bytes());
        buf[6..18].copy_from_slice(&self.nonce);
        buf
    }

    /// Serialize into existing buffer (zero-copy)
    #[inline]
    pub fn serialize_into(&self, buf: &mut [u8]) {
        debug_assert!(buf.len() >= PROTOCOL_HEADER_SIZE);
        buf[0] = self.version;
        buf[1] = self.packet_type as u8;
        buf[2..6].copy_from_slice(&self.counter.to_le_bytes());
        buf[6..18].copy_from_slice(&self.nonce);
    }

    /// Deserialize from bytes
    #[inline]
    pub fn deserialize(buf: &[u8]) -> Result<Self> {
        if buf.len() < PROTOCOL_HEADER_SIZE {
            return Err(ProtocolError::PacketTooSmall {
                min: PROTOCOL_HEADER_SIZE,
                got: buf.len(),
            }
            .into());
        }

        let version = buf[0];
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::InvalidVersion {
                expected: PROTOCOL_VERSION,
                got: version,
            }
            .into());
        }

        let packet_type = PacketType::from_u8(buf[1])?;
        let counter = u32::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]);
        let mut nonce = [0u8; CHACHA20_NONCE_SIZE];
        nonce.copy_from_slice(&buf[6..18]);

        Ok(PacketHeader {
            version,
            packet_type,
            counter,
            nonce,
        })
    }
}

/// Complete VPN packet
#[derive(Debug)]
pub struct Packet {
    pub header: PacketHeader,
    pub payload: Vec<u8>,
}

impl Packet {
    /// Create data packet
    pub fn new_data(counter: u32, payload: Vec<u8>) -> Self {
        Packet {
            header: PacketHeader::new(PacketType::Data, counter),
            payload,
        }
    }

    /// Create keepalive packet
    pub fn new_keepalive(counter: u32) -> Self {
        Packet {
            header: PacketHeader::new(PacketType::Keepalive, counter),
            payload: Vec::new(),
        }
    }

    /// Create handshake init packet
    pub fn new_handshake_init(counter: u32, client_info: Vec<u8>) -> Self {
        Packet {
            header: PacketHeader::new(PacketType::HandshakeInit, counter),
            payload: client_info,
        }
    }

    /// Serialize packet
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(PROTOCOL_HEADER_SIZE + self.payload.len());
        buf.extend_from_slice(&self.header.serialize());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Deserialize packet
    pub fn deserialize(buf: &[u8]) -> Result<Self> {
        let header = PacketHeader::deserialize(buf)?;
        let payload = buf[PROTOCOL_HEADER_SIZE..].to_vec();
        Ok(Packet { header, payload })
    }

    /// Total packet size
    #[inline]
    pub fn size(&self) -> usize {
        PROTOCOL_HEADER_SIZE + self.payload.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_roundtrip() {
        let packet = Packet::new_data(42, b"Hello VPN!".to_vec());
        let serialized = packet.serialize();
        let deserialized = Packet::deserialize(&serialized).unwrap();

        assert_eq!(packet.header.counter, deserialized.header.counter);
        assert_eq!(packet.payload, deserialized.payload);
    }
}
