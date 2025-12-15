//! # Constants
//!
//! Shared constants for the VPN protocol.

// ═══════════════════════════════════════════════════════════════════════════
// PROTOCOL VERSIONS
// ═══════════════════════════════════════════════════════════════════════════

/// Protocol version 3: Symmetric key encryption (legacy)
///
/// Features:
/// - Shared symmetric key (32 bytes)
/// - ChaCha20-Poly1305 / AES-256-GCM encryption
/// - Random nonce per packet
/// - Simple replay protection (64-bit sliding window)
pub const PROTOCOL_VERSION_V3: u8 = 3;

/// Protocol version 4: Asymmetric key exchange (current)
///
/// Features:
/// - Ed25519 identity keys
/// - X25519 ephemeral key exchange
/// - Noise_IK handshake pattern
/// - Perfect Forward Secrecy (PFS)
/// - Per-session keys derived via HKDF
/// - Deterministic nonces (counter-based)
/// - Per-peer access control
pub const PROTOCOL_VERSION_V4: u8 = 4;

/// Current protocol version (for new connections)
/// Version 3: Legacy symmetric key (backward compatibility)
/// Version 4: Asymmetric keys with Noise_IK handshake
pub const PROTOCOL_VERSION: u8 = PROTOCOL_VERSION_V3;

/// Minimum supported protocol version
pub const PROTOCOL_VERSION_MIN: u8 = PROTOCOL_VERSION_V3;

/// Maximum supported protocol version
pub const PROTOCOL_VERSION_MAX: u8 = PROTOCOL_VERSION_V4;

// ═══════════════════════════════════════════════════════════════════════════
// SYMMETRIC ENCRYPTION CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

/// ChaCha20 key size in bytes
pub const CHACHA20_KEY_SIZE: usize = 32;

/// ChaCha20 nonce size in bytes
pub const CHACHA20_NONCE_SIZE: usize = 12;

/// Poly1305 authentication tag size in bytes
pub const POLY1305_TAG_SIZE: usize = 16;

// ═══════════════════════════════════════════════════════════════════════════
// ASYMMETRIC KEY CONSTANTS (Protocol v4)
// ═══════════════════════════════════════════════════════════════════════════

/// Ed25519 private key size in bytes
pub const ED25519_PRIVATE_KEY_SIZE: usize = 32;

/// Ed25519 public key size in bytes
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;

/// Ed25519 signature size in bytes
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// X25519 private key size in bytes
pub const X25519_PRIVATE_KEY_SIZE: usize = 32;

/// X25519 public key size in bytes
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;

/// X25519 shared secret size in bytes
pub const X25519_SHARED_SECRET_SIZE: usize = 32;

// ═══════════════════════════════════════════════════════════════════════════
// PACKET CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

/// Protocol header size in bytes (v3)
/// Version(1) + Type(1) + Counter(4) + Nonce(12) + Reserved(6)
pub const PROTOCOL_HEADER_SIZE: usize = 24;

/// Protocol header size for v4 data packets
/// Type(1) + ReceiverIndex(4) + Counter(8)
pub const PROTOCOL_V4_DATA_HEADER_SIZE: usize = 13;

/// Maximum packet size (MTU)
pub const MAX_PACKET_SIZE: usize = 1500;

// ═══════════════════════════════════════════════════════════════════════════
// HANDSHAKE CONSTANTS (Protocol v4)
// ═══════════════════════════════════════════════════════════════════════════

/// Handshake init packet size (v4)
/// Version(1) + Type(1) + SenderIndex(4) + EphemeralPublic(32) +
/// EncryptedStatic(48) + EncryptedTimestamp(28) + MAC1(16) + MAC2(16)
pub const HANDSHAKE_INIT_SIZE: usize = 148;

/// Handshake response packet size (v4)
/// Version(1) + Type(1) + SenderIndex(4) + ReceiverIndex(4) +
/// EphemeralPublic(32) + EncryptedEmpty(16) + MAC1(16) + MAC2(16)
pub const HANDSHAKE_RESPONSE_SIZE: usize = 92;

/// MAC size for handshake packets
pub const HANDSHAKE_MAC_SIZE: usize = 16;

// ═══════════════════════════════════════════════════════════════════════════
// TIMING CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

/// Rekey after this many seconds (v4)
pub const REKEY_AFTER_TIME_SECS: u64 = 120;

/// Rekey after this many messages (v4)
/// Using u64::MAX - 2^16 to leave headroom
pub const REKEY_AFTER_MESSAGES: u64 = u64::MAX - (1 << 16);

/// Rekey timeout in seconds
pub const REKEY_TIMEOUT_SECS: u64 = 15;

/// Keepalive interval in seconds
pub const KEEPALIVE_INTERVAL_SECS: u64 = 25;

/// Session timeout in seconds (no traffic)
pub const SESSION_TIMEOUT_SECS: u64 = 180;
