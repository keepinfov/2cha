//! # Common Configuration Types
//!
//! Shared configuration types and utilities.

use serde::Deserialize;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Supported cipher suites
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CipherSuite {
    #[default]
    #[serde(rename = "chacha20-poly1305")]
    ChaCha20Poly1305,
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
}

impl std::fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CipherSuite::ChaCha20Poly1305 => write!(f, "ChaCha20-Poly1305"),
            CipherSuite::Aes256Gcm => write!(f, "AES-256-GCM"),
        }
    }
}

/// Obfuscation transport carrying the v4 protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    /// UDP with QUIC-mimicry framing (backwards compatible default).
    #[default]
    Quic,
    /// Real TLS 1.3 over TCP with Noise riding inside.
    Tls,
}

impl std::fmt::Display for TransportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportKind::Quic => write!(f, "quic"),
            TransportKind::Tls => write!(f, "tls"),
        }
    }
}

/// TLS transport configuration. Only consulted when `transport = "tls"`.
#[derive(Debug, Clone, Deserialize)]
pub struct TlsSection {
    /// SNI the client presents / the server expects. Choose a plausible host
    /// to blend in. On the server a self-signed cert is generated for it when
    /// no cert/key files are supplied.
    #[serde(default = "default_tls_sni")]
    pub sni: String,
    /// PEM certificate chain path (server only; optional — self-signed if absent).
    #[serde(default)]
    pub cert_file: Option<String>,
    /// PEM PKCS#8 private key path (server only; required if `cert_file` is set).
    #[serde(default)]
    pub key_file: Option<String>,
}

impl Default for TlsSection {
    fn default() -> Self {
        // Keep this consistent with the per-field serde defaults so an omitted
        // `[tls]` table and a present-but-empty one resolve to the same SNI.
        TlsSection {
            sni: default_tls_sni(),
            cert_file: None,
            key_file: None,
        }
    }
}

/// TUN device configuration
#[derive(Debug, Deserialize)]
pub struct TunSection {
    #[serde(default = "default_tun_name")]
    pub name: String,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    #[serde(default = "default_queue_len")]
    pub queue_len: u32,
}

/// Cryptographic configuration
#[derive(Debug, Deserialize)]
pub struct CryptoSection {
    #[serde(default)]
    pub cipher: CipherSuite,
    /// Path to the X25519 private key file (raw 32 bytes, mode 0600)
    pub private_key_file: String,
    /// Base64 public key of the server (client configs only)
    #[serde(default)]
    pub server_public_key: Option<String>,
}

impl CryptoSection {
    /// Load the local identity from `private_key_file`, enforcing 0600 perms
    pub fn identity(&self) -> Result<crate::crypto::Identity, ConfigError> {
        crate::crypto::Identity::load(std::path::Path::new(&self.private_key_file))
            .map_err(|e| ConfigError::InvalidKey(format!("{}: {}", self.private_key_file, e)))
    }
}

/// Decode a base64 X25519 public key from a config value
pub fn decode_config_public_key(value: &str) -> Result<[u8; 32], ConfigError> {
    crate::crypto::decode_public_key(value.trim())
        .map_err(|e| ConfigError::InvalidKey(format!("bad public key: {}", e)))
}

/// Performance configuration
#[derive(Debug, Deserialize)]
pub struct PerformanceSection {
    #[serde(default = "default_socket_buffer")]
    pub socket_recv_buffer: usize,
    #[serde(default = "default_socket_buffer")]
    pub socket_send_buffer: usize,
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    #[serde(default)]
    pub multi_queue: bool,
    #[serde(default)]
    pub cpu_affinity: Vec<usize>,
}

impl Default for PerformanceSection {
    fn default() -> Self {
        PerformanceSection {
            socket_recv_buffer: 2 * 1024 * 1024,
            socket_send_buffer: 2 * 1024 * 1024,
            batch_size: 32,
            multi_queue: false,
            cpu_affinity: Vec::new(),
        }
    }
}

/// Timeout configuration
#[derive(Debug, Deserialize)]
pub struct TimeoutsSection {
    /// Drop a session after this many seconds without authenticated traffic
    #[serde(default = "default_session_timeout")]
    pub session: u64,
}

impl Default for TimeoutsSection {
    fn default() -> Self {
        TimeoutsSection { session: 180 }
    }
}

/// Logging configuration
#[derive(Debug, Deserialize)]
pub struct LoggingSection {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub file: Option<String>,
}

impl Default for LoggingSection {
    fn default() -> Self {
        LoggingSection {
            level: "info".to_string(),
            file: None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// DEFAULT VALUES
// ═══════════════════════════════════════════════════════════════════════════

pub fn default_tun_name() -> String {
    "tun0".to_string()
}
pub fn default_mtu() -> u16 {
    1420
}
pub fn default_queue_len() -> u32 {
    500
}
pub fn default_prefix_v4() -> u8 {
    24
}
pub fn default_prefix_v6() -> u8 {
    64
}
pub fn default_session_timeout() -> u64 {
    180
}
pub fn default_log_level() -> String {
    "info".to_string()
}
pub fn default_tls_sni() -> String {
    "www.cloudflare.com".to_string()
}
pub fn default_max_clients() -> usize {
    256
}
pub fn default_socket_buffer() -> usize {
    2 * 1024 * 1024
}
pub fn default_batch_size() -> usize {
    32
}
pub fn default_true() -> bool {
    true
}

// ═══════════════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug)]
pub enum ConfigError {
    IoError(String),
    ParseError(String),
    InvalidAddress(String),
    InvalidKey(String),
    MissingKey,
    Invalid(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::IoError(e) => write!(f, "I/O error: {}", e),
            ConfigError::ParseError(e) => write!(f, "Parse error: {}", e),
            ConfigError::InvalidAddress(a) => write!(f, "Invalid address: {}", a),
            ConfigError::InvalidKey(e) => write!(f, "Invalid key: {}", e),
            ConfigError::MissingKey => {
                write!(f, "No private key configured (set crypto.private_key_file)")
            }
            ConfigError::Invalid(e) => write!(f, "Invalid config: {}", e),
        }
    }
}

impl std::error::Error for ConfigError {}

// ═══════════════════════════════════════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

#[allow(dead_code)]
pub fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let addr: Ipv4Addr = s.parse().ok()?;
    Some(addr.octets())
}

#[allow(dead_code)]
pub fn parse_ipv6(s: &str) -> Option<[u8; 16]> {
    let addr: Ipv6Addr = s.parse().ok()?;
    Some(addr.octets())
}

pub fn prefix_to_netmask_v4(prefix: u8) -> [u8; 4] {
    let mask = if prefix == 0 {
        0u32
    } else if prefix >= 32 {
        0xFFFFFFFFu32
    } else {
        !((1u32 << (32 - prefix)) - 1)
    };
    mask.to_be_bytes()
}

#[allow(dead_code)]
pub fn prefix_to_netmask_v6(prefix: u8) -> [u8; 16] {
    let mut mask = [0u8; 16];
    let full_bytes = (prefix / 8) as usize;
    let remaining_bits = prefix % 8;

    for byte in mask.iter_mut().take(full_bytes.min(16)) {
        *byte = 0xFF;
    }
    if full_bytes < 16 && remaining_bits > 0 {
        mask[full_bytes] = !((1u8 << (8 - remaining_bits)) - 1);
    }
    mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_to_netmask_v4() {
        assert_eq!(prefix_to_netmask_v4(0), [0, 0, 0, 0]);
        assert_eq!(prefix_to_netmask_v4(32), [255, 255, 255, 255]);
        assert_eq!(prefix_to_netmask_v4(24), [255, 255, 255, 0]);
        assert_eq!(prefix_to_netmask_v4(8), [255, 0, 0, 0]);
    }
}
