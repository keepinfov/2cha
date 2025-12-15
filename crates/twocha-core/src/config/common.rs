//! # Common Configuration Types
//!
//! Shared configuration types and utilities.

use serde::Deserialize;
use std::fs;
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
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub key_file: Option<String>,
}

impl CryptoSection {
    pub fn get_key(&self) -> Result<[u8; 32], ConfigError> {
        if let Some(ref path) = self.key_file {
            let content = fs::read_to_string(path)
                .map_err(|e| ConfigError::IoError(format!("Cannot read key file: {}", e)))?;
            return hex_to_key(content.trim());
        }
        if let Some(ref hex) = self.key {
            return hex_to_key(hex);
        }
        if let Ok(hex) = std::env::var("VPN_KEY") {
            return hex_to_key(&hex);
        }
        Err(ConfigError::MissingKey)
    }
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
    #[serde(default = "default_keepalive")]
    pub keepalive: u64,
    #[serde(default = "default_session_timeout")]
    pub session: u64,
    #[serde(default = "default_handshake_timeout")]
    pub handshake: u64,
}

impl Default for TimeoutsSection {
    fn default() -> Self {
        TimeoutsSection {
            keepalive: 25,
            session: 180,
            handshake: 10,
        }
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
pub fn default_keepalive() -> u64 {
    25
}
pub fn default_session_timeout() -> u64 {
    180
}
pub fn default_handshake_timeout() -> u64 {
    10
}
pub fn default_log_level() -> String {
    "info".to_string()
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
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::IoError(e) => write!(f, "I/O error: {}", e),
            ConfigError::ParseError(e) => write!(f, "Parse error: {}", e),
            ConfigError::InvalidAddress(a) => write!(f, "Invalid address: {}", a),
            ConfigError::InvalidKey(e) => write!(f, "Invalid key: {}", e),
            ConfigError::MissingKey => {
                write!(f, "No key provided (use key, key_file, or VPN_KEY env)")
            }
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

pub fn hex_to_key(hex: &str) -> Result<[u8; 32], ConfigError> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return Err(ConfigError::InvalidKey(format!(
            "Key must be 64 hex chars, got {}",
            hex.len()
        )));
    }
    let mut key = [0u8; 32];
    for i in 0..32 {
        key[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| ConfigError::InvalidKey("Invalid hex character".to_string()))?;
    }
    Ok(key)
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

    #[test]
    fn test_hex_to_key() {
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let key = hex_to_key(hex).unwrap();
        assert_eq!(key[0], 0x01);
        assert_eq!(key[1], 0x23);
        assert_eq!(key[31], 0xef);
    }
}
