//! # Constants
//!
//! Shared constants for the VPN protocol.

/// Protocol version
pub const PROTOCOL_VERSION: u8 = 2;

/// ChaCha20 key size in bytes
pub const CHACHA20_KEY_SIZE: usize = 32;

/// ChaCha20 nonce size in bytes
pub const CHACHA20_NONCE_SIZE: usize = 12;

/// Poly1305 authentication tag size in bytes
pub const POLY1305_TAG_SIZE: usize = 16;

/// Protocol header size in bytes
pub const PROTOCOL_HEADER_SIZE: usize = 24;

/// Maximum packet size (MTU)
pub const MAX_PACKET_SIZE: usize = 1500;
