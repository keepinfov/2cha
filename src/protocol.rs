//! # VPN Protocol Module
//!
//! Type-safe protocol with efficient serialization.

use crate::error::{ProtocolError, Result};
use crate::{PROTOCOL_VERSION, PROTOCOL_HEADER_SIZE, CHACHA20_NONCE_SIZE};

/// Packet types
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
    pub fn with_nonce(packet_type: PacketType, counter: u32, nonce: [u8; CHACHA20_NONCE_SIZE]) -> Self {
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
            }.into());
        }

        let version = buf[0];
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::InvalidVersion {
                expected: PROTOCOL_VERSION,
                got: version,
            }.into());
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

// ═══════════════════════════════════════════════════════════════════════════
// ANTI-REPLAY PROTECTION
// ═══════════════════════════════════════════════════════════════════════════

/// Sliding window for replay attack protection
#[derive(Debug)]
pub struct ReplayWindow {
    last_counter: u64,
    bitmap: u64,
    window_size: u64,
}

impl ReplayWindow {
    pub fn new() -> Self {
        ReplayWindow {
            last_counter: 0,
            bitmap: 0,
            window_size: 64,
        }
    }

    /// Check if packet is valid (not a replay)
    /// Returns true if packet should be accepted
    #[inline]
    pub fn check_and_update(&mut self, counter: u64) -> bool {
        if counter == 0 {
            return false;
        }

        if counter > self.last_counter {
            // New packet ahead of window
            let diff = counter - self.last_counter;
            if diff >= self.window_size {
                self.bitmap = 1;
            } else {
                self.bitmap <<= diff;
                self.bitmap |= 1;
            }
            self.last_counter = counter;
            return true;
        }

        // Packet within or before window
        let diff = self.last_counter - counter;
        if diff >= self.window_size {
            return false; // Too old
        }

        // Check if already seen
        let bit = 1u64 << diff;
        if self.bitmap & bit != 0 {
            return false; // Replay
        }

        // Mark as seen
        self.bitmap |= bit;
        true
    }

    /// Reset window
    pub fn reset(&mut self) {
        self.last_counter = 0;
        self.bitmap = 0;
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
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

    #[test]
    fn test_replay_window() {
        let mut window = ReplayWindow::new();
        
        // Sequential packets
        assert!(window.check_and_update(1));
        assert!(window.check_and_update(2));
        assert!(window.check_and_update(3));
        
        // Replay should fail
        assert!(!window.check_and_update(2));
        
        // Out of order but within window
        assert!(window.check_and_update(5));
        assert!(window.check_and_update(4));
        
        // Replay again
        assert!(!window.check_and_update(4));
    }

    #[test]
    fn test_replay_window_jump() {
        let mut window = ReplayWindow::new();
        
        assert!(window.check_and_update(1));
        assert!(window.check_and_update(100)); // Big jump
        assert!(!window.check_and_update(1)); // Old packet
        assert!(window.check_and_update(99)); // Just within window
    }
}
