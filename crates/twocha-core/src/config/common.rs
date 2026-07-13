//! # Common Configuration Types
//!
//! Shared configuration types and utilities.

use serde::Deserialize;
use std::net::{Ipv4Addr, Ipv6Addr};
use twocha_protocol::obfs::{AwgParams, HeaderRange};

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
    /// UDP with AmneziaWG-2.0-style randomized framing: per-packet magic
    /// headers, configurable padding, junk + signature packets before the
    /// handshake. See [`AwgSection`].
    Awg,
}

impl std::fmt::Display for TransportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportKind::Quic => write!(f, "quic"),
            TransportKind::Tls => write!(f, "tls"),
            TransportKind::Awg => write!(f, "awg"),
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

/// AmneziaWG-2.0-style obfuscation. Only consulted when `transport = "awg"`.
///
/// All fields except the junk counts (`jc`/`jmin`/`jmax`, which are client-only)
/// **must be identical on both ends** — the magic-header ranges and padding are
/// part of the wire format. Generate a matched pair with the `2cha init` wizard.
#[derive(Debug, Clone, Deserialize)]
pub struct AwgSection {
    /// Junk packets sent before each handshake (client-only). 0 disables.
    #[serde(default = "default_awg_jc")]
    pub jc: u8,
    /// Minimum junk-packet size in bytes.
    #[serde(default = "default_awg_jmin")]
    pub jmin: u16,
    /// Maximum junk-packet size in bytes.
    #[serde(default = "default_awg_jmax")]
    pub jmax: u16,
    /// S1–S4: max extra padding for init / resp / cookie / data packets.
    #[serde(default = "default_awg_s1")]
    pub s1: u16,
    #[serde(default = "default_awg_s2")]
    pub s2: u16,
    #[serde(default = "default_awg_s3")]
    pub s3: u16,
    #[serde(default = "default_awg_s4")]
    pub s4: u16,
    /// H1–H4: magic-header base values for init / resp / cookie / data. Each
    /// packet's header is a random value in `[hN, hN + header_span]`.
    #[serde(default = "default_awg_h1")]
    pub h1: u32,
    #[serde(default = "default_awg_h2")]
    pub h2: u32,
    #[serde(default = "default_awg_h3")]
    pub h3: u32,
    #[serde(default = "default_awg_h4")]
    pub h4: u32,
    /// Width of each magic-header range (0 = static headers, AmneziaWG 1.x
    /// style; non-zero = dynamic per-packet headers, 2.0 style). The four
    /// resulting ranges must not overlap.
    #[serde(default = "default_awg_header_span")]
    pub header_span: u32,
    /// I1–I5: optional CPS signature-packet templates sent before the handshake
    /// (client-only). See `docs/transports.md` for the tag syntax.
    #[serde(default)]
    pub i1: Option<String>,
    #[serde(default)]
    pub i2: Option<String>,
    #[serde(default)]
    pub i3: Option<String>,
    #[serde(default)]
    pub i4: Option<String>,
    #[serde(default)]
    pub i5: Option<String>,
}

fn default_awg_jc() -> u8 {
    4
}
fn default_awg_jmin() -> u16 {
    64
}
fn default_awg_jmax() -> u16 {
    1024
}
fn default_awg_s1() -> u16 {
    24
}
fn default_awg_s2() -> u16 {
    40
}
fn default_awg_s3() -> u16 {
    24
}
fn default_awg_s4() -> u16 {
    16
}
fn default_awg_h1() -> u32 {
    0x1000_0000
}
fn default_awg_h2() -> u32 {
    0x2000_0000
}
fn default_awg_h3() -> u32 {
    0x3000_0000
}
fn default_awg_h4() -> u32 {
    0x4000_0000
}
fn default_awg_header_span() -> u32 {
    0x00ff_ffff
}

impl Default for AwgSection {
    fn default() -> Self {
        AwgSection {
            jc: default_awg_jc(),
            jmin: default_awg_jmin(),
            jmax: default_awg_jmax(),
            s1: default_awg_s1(),
            s2: default_awg_s2(),
            s3: default_awg_s3(),
            s4: default_awg_s4(),
            h1: default_awg_h1(),
            h2: default_awg_h2(),
            h3: default_awg_h3(),
            h4: default_awg_h4(),
            header_span: default_awg_header_span(),
            i1: None,
            i2: None,
            i3: None,
            i4: None,
            i5: None,
        }
    }
}

impl AwgSection {
    /// The shared magic-header ranges + padding, as consumed by the wire codec.
    pub fn to_params(&self) -> AwgParams {
        let range = |h: u32| HeaderRange::new(h, h.saturating_add(self.header_span));
        AwgParams {
            headers: [
                range(self.h1),
                range(self.h2),
                range(self.h3),
                range(self.h4),
            ],
            padding: [self.s1, self.s2, self.s3, self.s4],
        }
    }

    /// The configured I1–I5 CPS templates, in order, skipping unset ones.
    pub fn signature_templates(&self) -> Vec<&str> {
        [&self.i1, &self.i2, &self.i3, &self.i4, &self.i5]
            .into_iter()
            .filter_map(|o| o.as_deref())
            .collect()
    }

    /// Validate internal consistency (called from client/server `validate`).
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.jmin > self.jmax {
            return Err(ConfigError::Invalid(
                "awg.jmin must be <= awg.jmax".into(),
            ));
        }
        if self.jc > 0 && self.jmax == 0 {
            return Err(ConfigError::Invalid(
                "awg.jmax must be > 0 when awg.jc > 0".into(),
            ));
        }
        if self.to_params().has_overlap() {
            return Err(ConfigError::Invalid(
                "awg H1–H4 ranges (hN..hN+header_span) must not overlap".into(),
            ));
        }
        Ok(())
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

/// Validate `tun.mtu` against the wire format: a full-MTU packet plus the
/// 35-byte data-datagram overhead must fit in a 1500-byte wire datagram
/// ([`crate::v4::session::MAX_TUN_MTU`] = 1465), and IPv4 requires >= 576.
pub fn validate_tun_mtu(mtu: u16) -> Result<(), ConfigError> {
    let max = crate::v4::session::MAX_TUN_MTU;
    if !(576..=max).contains(&mtu) {
        return Err(ConfigError::Invalid(format!(
            "tun.mtu must be 576..={} (got {}): each packet gains 35 bytes of \
             tunnel overhead and must fit in a 1500-byte datagram",
            max, mtu
        )));
    }
    Ok(())
}

/// AmneziaWG's 4-byte magic header is 3 bytes wider than the QUIC short header,
/// so its data overhead is 38 bytes and a full-MTU packet needs a slightly
/// lower cap than [`validate_tun_mtu`].
pub fn validate_awg_mtu(mtu: u16) -> Result<(), ConfigError> {
    const AWG_DATA_OVERHEAD: usize =
        twocha_protocol::wire::AWG_DATA_HEADER_LEN + 2 + twocha_protocol::POLY1305_TAG_SIZE;
    let max = (twocha_protocol::MAX_PACKET_SIZE - AWG_DATA_OVERHEAD) as u16;
    if mtu > max {
        return Err(ConfigError::Invalid(format!(
            "tun.mtu must be <= {} for transport = \"awg\" (got {}): AWG's magic \
             header adds 3 bytes over quic, so each packet gains 38 bytes of overhead",
            max, mtu
        )));
    }
    Ok(())
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
    /// Data-plane threads. `0` = auto (client: 2-thread split on the QUIC
    /// transport; server: single-threaded). `1` forces the single-threaded
    /// loop. On the server, values >= 2 enable the opt-in multi-worker QUIC
    /// data plane (Linux only; requires `multi_queue = true`).
    #[serde(default)]
    pub worker_threads: usize,
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
            worker_threads: 0,
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
    fn test_validate_tun_mtu() {
        assert!(validate_tun_mtu(576).is_ok());
        assert!(validate_tun_mtu(1420).is_ok());
        assert!(validate_tun_mtu(1465).is_ok());
        assert!(validate_tun_mtu(575).is_err());
        assert!(validate_tun_mtu(1466).is_err());
        assert!(validate_tun_mtu(1500).is_err());
    }

    #[test]
    fn test_awg_defaults_validate() {
        let awg = AwgSection::default();
        assert!(awg.validate().is_ok());
        // The four default header ranges are disjoint quadrant bases.
        assert!(!awg.to_params().has_overlap());
    }

    #[test]
    fn test_awg_rejects_overlapping_headers() {
        let mut awg = AwgSection::default();
        // Push H2's base inside H1's span so the two ranges collide.
        awg.h2 = awg.h1 + 1;
        assert!(awg.validate().is_err());
    }

    #[test]
    fn test_awg_rejects_inverted_junk_range() {
        let mut awg = AwgSection {
            jmin: 100,
            jmax: 50,
            ..Default::default()
        };
        assert!(awg.validate().is_err());
        awg.jmin = 50;
        awg.jmax = 50;
        assert!(awg.validate().is_ok());
    }

    #[test]
    fn test_awg_static_headers_allowed() {
        // header_span = 0 (AmneziaWG 1.x static headers): distinct bases stay
        // disjoint single-value ranges.
        let awg = AwgSection {
            header_span: 0,
            ..Default::default()
        };
        assert!(awg.validate().is_ok());
    }

    #[test]
    fn test_awg_mtu_bounds() {
        // AWG data overhead is 38 bytes, capping the MTU 3 below the QUIC max.
        assert!(validate_awg_mtu(1420).is_ok());
        assert!(validate_awg_mtu(1462).is_ok());
        assert!(validate_awg_mtu(1463).is_err());
    }

    #[test]
    fn test_prefix_to_netmask_v4() {
        assert_eq!(prefix_to_netmask_v4(0), [0, 0, 0, 0]);
        assert_eq!(prefix_to_netmask_v4(32), [255, 255, 255, 255]);
        assert_eq!(prefix_to_netmask_v4(24), [255, 255, 255, 0]);
        assert_eq!(prefix_to_netmask_v4(8), [255, 0, 0, 0]);
    }
}
