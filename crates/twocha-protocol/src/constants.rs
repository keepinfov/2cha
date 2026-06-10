//! # Constants
//!
//! Shared constants for the VPN protocol.

/// Protocol version
/// Version 4: Noise_IK handshake, per-session keys, QUIC-mimicking wire format
pub const PROTOCOL_VERSION: u8 = 4;

/// ChaCha20 key size in bytes
pub const CHACHA20_KEY_SIZE: usize = 32;

/// ChaCha20 nonce size in bytes (same for AES-256-GCM)
pub const CHACHA20_NONCE_SIZE: usize = 12;

/// Poly1305 authentication tag size in bytes
pub const POLY1305_TAG_SIZE: usize = 16;

/// Maximum packet size (MTU)
pub const MAX_PACKET_SIZE: usize = 1500;
