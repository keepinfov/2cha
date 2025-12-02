//! # Configuration Module
//!
//! Improved TOML configuration with IPv4/IPv6 support.
//! Designed for flexibility and security.

use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};

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

// ═══════════════════════════════════════════════════════════════════════════
// SERVER CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub server: ServerSection,
    pub tun: TunSection,
    pub crypto: CryptoSection,
    #[serde(default)]
    pub ipv4: Ipv4Section,
    #[serde(default)]
    pub ipv6: Ipv6Section,
    #[serde(default)]
    pub gateway: GatewaySection,
    #[serde(default)]
    pub performance: PerformanceSection,
    #[serde(default)]
    pub timeouts: TimeoutsSection,
    #[serde(default)]
    pub logging: LoggingSection,
}

#[derive(Debug, Deserialize)]
pub struct ServerSection {
    /// Listen address (e.g., "0.0.0.0:51820" or "[::]:51820")
    pub listen: String,
    /// Optional listen address for IPv6 if different
    #[serde(default)]
    pub listen_v6: Option<String>,
    /// Maximum number of clients
    #[serde(default = "default_max_clients")]
    pub max_clients: usize,
}

// ═══════════════════════════════════════════════════════════════════════════
// CLIENT CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
pub struct ClientConfig {
    pub client: ClientSection,
    pub tun: TunSection,
    pub crypto: CryptoSection,
    #[serde(default)]
    pub ipv4: Ipv4ClientSection,
    #[serde(default)]
    pub ipv6: Ipv6ClientSection,
    #[serde(default)]
    pub dns: DnsSection,
    #[serde(default)]
    pub performance: PerformanceSection,
    #[serde(default)]
    pub timeouts: TimeoutsSection,
    #[serde(default)]
    pub logging: LoggingSection,
}

#[derive(Debug, Deserialize)]
pub struct ClientSection {
    /// Server address (hostname:port or IP:port)
    pub server: String,
    /// Prefer IPv6 connection to server
    #[serde(default)]
    pub prefer_ipv6: bool,
}

// ═══════════════════════════════════════════════════════════════════════════
// SHARED SECTIONS
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
pub struct TunSection {
    #[serde(default = "default_tun_name")]
    pub name: String,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Queue length for TUN device
    #[serde(default = "default_queue_len")]
    pub queue_len: u32,
}

#[derive(Debug, Deserialize)]
pub struct CryptoSection {
    #[serde(default)]
    pub cipher: CipherSuite,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub key_file: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// IPv4 CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
pub struct Ipv4Section {
    /// Enable IPv4 support
    #[serde(default = "default_true")]
    pub enable: bool,
    /// TUN device IPv4 address
    pub address: Option<String>,
    /// Network prefix length (e.g., 24 for /24)
    #[serde(default = "default_prefix_v4")]
    pub prefix: u8,
    /// Allowed source IPs (empty = allow all)
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    /// Blocked source IPs
    #[serde(default)]
    pub blocked_ips: Vec<String>,
    /// Routes to push to clients (server only)
    #[serde(default)]
    pub push_routes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Ipv4ClientSection {
    /// Enable IPv4
    #[serde(default = "default_true")]
    pub enable: bool,
    /// TUN device IPv4 address
    pub address: Option<String>,
    /// Network prefix length
    #[serde(default = "default_prefix_v4")]
    pub prefix: u8,
    /// Route all IPv4 traffic through VPN
    #[serde(default)]
    pub route_all: bool,
    /// Specific routes to add
    #[serde(default)]
    pub routes: Vec<String>,
    /// IPs to exclude from VPN (even with route_all)
    #[serde(default)]
    pub exclude_ips: Vec<String>,
}

impl Default for Ipv4Section {
    fn default() -> Self {
        Ipv4Section {
            enable: true,
            address: Some("10.0.0.1".to_string()),
            prefix: 24,
            allowed_ips: Vec::new(),
            blocked_ips: Vec::new(),
            push_routes: Vec::new(),
        }
    }
}

impl Default for Ipv4ClientSection {
    fn default() -> Self {
        Ipv4ClientSection {
            enable: true,
            address: Some("10.0.0.2".to_string()),
            prefix: 24,
            route_all: false,
            routes: Vec::new(),
            exclude_ips: Vec::new(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// IPv6 CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
pub struct Ipv6Section {
    /// Enable IPv6 support
    #[serde(default)]
    pub enable: bool,
    /// TUN device IPv6 address (e.g., "fd00::1")
    pub address: Option<String>,
    /// Network prefix length (e.g., 64 for /64)
    #[serde(default = "default_prefix_v6")]
    pub prefix: u8,
    /// Allowed source IPs (empty = allow all)
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    /// Blocked source IPs  
    #[serde(default)]
    pub blocked_ips: Vec<String>,
    /// Routes to push to clients
    #[serde(default)]
    pub push_routes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Ipv6ClientSection {
    /// Enable IPv6
    #[serde(default)]
    pub enable: bool,
    /// TUN device IPv6 address
    pub address: Option<String>,
    /// Network prefix length
    #[serde(default = "default_prefix_v6")]
    pub prefix: u8,
    /// Route all IPv6 traffic through VPN
    #[serde(default)]
    pub route_all: bool,
    /// Specific routes to add
    #[serde(default)]
    pub routes: Vec<String>,
    /// IPs to exclude from VPN
    #[serde(default)]
    pub exclude_ips: Vec<String>,
}

impl Default for Ipv6Section {
    fn default() -> Self {
        Ipv6Section {
            enable: false,
            address: None,
            prefix: 64,
            allowed_ips: Vec::new(),
            blocked_ips: Vec::new(),
            push_routes: Vec::new(),
        }
    }
}

impl Default for Ipv6ClientSection {
    fn default() -> Self {
        Ipv6ClientSection {
            enable: false,
            address: None,
            prefix: 64,
            route_all: false,
            routes: Vec::new(),
            exclude_ips: Vec::new(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// DNS CONFIGURATION (Client only)
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize, Default)]
pub struct DnsSection {
    /// IPv4 DNS servers
    #[serde(default)]
    pub servers_v4: Vec<String>,
    /// IPv6 DNS servers
    #[serde(default)]
    pub servers_v6: Vec<String>,
    /// Search domains
    #[serde(default)]
    pub search: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// GATEWAY CONFIGURATION (Server only)
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize, Default)]
pub struct GatewaySection {
    /// Enable IP forwarding
    #[serde(default)]
    pub ip_forward: bool,
    /// Enable IPv6 forwarding
    #[serde(default)]
    pub ip6_forward: bool,
    /// Enable NAT/masquerading for IPv4
    #[serde(default)]
    pub masquerade_v4: bool,
    /// Enable NAT/masquerading for IPv6
    #[serde(default)]
    pub masquerade_v6: bool,
    /// External interface for NAT
    #[serde(default)]
    pub external_interface: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// PERFORMANCE CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
pub struct PerformanceSection {
    /// Socket receive buffer size (bytes)
    #[serde(default = "default_socket_buffer")]
    pub socket_recv_buffer: usize,
    /// Socket send buffer size (bytes)
    #[serde(default = "default_socket_buffer")]
    pub socket_send_buffer: usize,
    /// Number of packets to batch read
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    /// Use multi-queue TUN (if available)
    #[serde(default)]
    pub multi_queue: bool,
    /// Pin to specific CPU cores (empty = no pinning)
    #[serde(default)]
    pub cpu_affinity: Vec<usize>,
}

impl Default for PerformanceSection {
    fn default() -> Self {
        PerformanceSection {
            socket_recv_buffer: 2 * 1024 * 1024, // 2MB
            socket_send_buffer: 2 * 1024 * 1024, // 2MB
            batch_size: 32,
            multi_queue: false,
            cpu_affinity: Vec::new(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TIMEOUTS
// ═══════════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════════
// LOGGING
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
pub struct LoggingSection {
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Log to file instead of stderr
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

fn default_tun_name() -> String { "tun0".to_string() }
fn default_mtu() -> u16 { 1420 } // Optimized for most networks
fn default_queue_len() -> u32 { 500 }
fn default_prefix_v4() -> u8 { 24 }
fn default_prefix_v6() -> u8 { 64 }
fn default_keepalive() -> u64 { 25 }
fn default_session_timeout() -> u64 { 180 }
fn default_handshake_timeout() -> u64 { 10 }
fn default_log_level() -> String { "info".to_string() }
fn default_max_clients() -> usize { 256 }
fn default_socket_buffer() -> usize { 2 * 1024 * 1024 }
fn default_batch_size() -> usize { 32 }
fn default_true() -> bool { true }

// ═══════════════════════════════════════════════════════════════════════════
// IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════

impl ServerConfig {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path)
            .map_err(|e| ConfigError::IoError(e.to_string()))?;
        Self::from_str(&content)
    }

    pub fn from_str(content: &str) -> Result<Self, ConfigError> {
        toml::from_str(content)
            .map_err(|e| ConfigError::ParseError(e.to_string()))
    }

    pub fn listen_addr(&self) -> Result<SocketAddr, ConfigError> {
        self.server.listen.parse()
            .map_err(|_| ConfigError::InvalidAddress(self.server.listen.clone()))
    }

    pub fn listen_addr_v6(&self) -> Result<Option<SocketAddr>, ConfigError> {
        match &self.server.listen_v6 {
            Some(addr) => addr.parse()
                .map(Some)
                .map_err(|_| ConfigError::InvalidAddress(addr.clone())),
            None => Ok(None),
        }
    }

    pub fn tun_ipv4(&self) -> Result<Option<Ipv4Addr>, ConfigError> {
        match &self.ipv4.address {
            Some(addr) if self.ipv4.enable => {
                addr.parse()
                    .map(Some)
                    .map_err(|_| ConfigError::InvalidAddress(addr.clone()))
            }
            _ => Ok(None),
        }
    }

    pub fn tun_ipv6(&self) -> Result<Option<Ipv6Addr>, ConfigError> {
        match &self.ipv6.address {
            Some(addr) if self.ipv6.enable => {
                addr.parse()
                    .map(Some)
                    .map_err(|_| ConfigError::InvalidAddress(addr.clone()))
            }
            _ => Ok(None),
        }
    }

    pub fn key(&self) -> Result<[u8; 32], ConfigError> {
        self.crypto.get_key()
    }
}

impl ClientConfig {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path)
            .map_err(|e| ConfigError::IoError(e.to_string()))?;
        Self::from_str(&content)
    }

    pub fn from_str(content: &str) -> Result<Self, ConfigError> {
        toml::from_str(content)
            .map_err(|e| ConfigError::ParseError(e.to_string()))
    }

    pub fn server_addr(&self) -> Result<SocketAddr, ConfigError> {
        self.client.server.parse()
            .map_err(|_| ConfigError::InvalidAddress(self.client.server.clone()))
    }

    pub fn tun_ipv4(&self) -> Result<Option<Ipv4Addr>, ConfigError> {
        match &self.ipv4.address {
            Some(addr) if self.ipv4.enable => {
                addr.parse()
                    .map(Some)
                    .map_err(|_| ConfigError::InvalidAddress(addr.clone()))
            }
            _ => Ok(None),
        }
    }

    pub fn tun_ipv6(&self) -> Result<Option<Ipv6Addr>, ConfigError> {
        match &self.ipv6.address {
            Some(addr) if self.ipv6.enable => {
                addr.parse()
                    .map(Some)
                    .map_err(|_| ConfigError::InvalidAddress(addr.clone()))
            }
            _ => Ok(None),
        }
    }

    pub fn key(&self) -> Result<[u8; 32], ConfigError> {
        self.crypto.get_key()
    }

    /// Get all DNS servers (both v4 and v6)
    pub fn dns_servers(&self) -> Vec<String> {
        let mut servers = self.dns.servers_v4.clone();
        servers.extend(self.dns.servers_v6.clone());
        servers
    }
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
            ConfigError::MissingKey => write!(f, "No key provided (use key, key_file, or VPN_KEY env)"),
        }
    }
}

impl std::error::Error for ConfigError {}

// ═══════════════════════════════════════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

pub fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let addr: Ipv4Addr = s.parse().ok()?;
    Some(addr.octets())
}

pub fn parse_ipv6(s: &str) -> Option<[u8; 16]> {
    let addr: Ipv6Addr = s.parse().ok()?;
    Some(addr.octets())
}

pub fn hex_to_key(hex: &str) -> Result<[u8; 32], ConfigError> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return Err(ConfigError::InvalidKey(
            format!("Key must be 64 hex chars, got {}", hex.len())
        ));
    }
    let mut key = [0u8; 32];
    for i in 0..32 {
        key[i] = u8::from_str_radix(&hex[i*2..i*2+2], 16)
            .map_err(|_| ConfigError::InvalidKey("Invalid hex character".to_string()))?;
    }
    Ok(key)
}

pub fn prefix_to_netmask_v4(prefix: u8) -> [u8; 4] {
    let mask = if prefix >= 32 {
        0xFFFFFFFFu32
    } else {
        !((1u32 << (32 - prefix)) - 1)
    };
    mask.to_be_bytes()
}

pub fn prefix_to_netmask_v6(prefix: u8) -> [u8; 16] {
    let mut mask = [0u8; 16];
    let full_bytes = (prefix / 8) as usize;
    let remaining_bits = prefix % 8;
    
    for i in 0..full_bytes.min(16) {
        mask[i] = 0xFF;
    }
    if full_bytes < 16 && remaining_bits > 0 {
        mask[full_bytes] = !((1u8 << (8 - remaining_bits)) - 1);
    }
    mask
}

// ═══════════════════════════════════════════════════════════════════════════
// EXAMPLE CONFIGS
// ═══════════════════════════════════════════════════════════════════════════

pub fn example_server_config() -> &'static str {
    r#"# 2cha VPN Server Configuration v0.3
# Usage: sudo 2cha server -c server.toml

[server]
listen = "0.0.0.0:51820"      # IPv4 + IPv6 dual-stack
# listen_v6 = "[::]:51820"    # Separate IPv6 socket (optional)
max_clients = 256

[tun]
name = "tun0"
mtu = 1420
queue_len = 500

[crypto]
cipher = "chacha20-poly1305"  # or "aes-256-gcm"
# key = "YOUR_64_HEX_CHAR_KEY"
# key_file = "/etc/2cha/server.key"
# Or use VPN_KEY environment variable

# ─────────────────────────────────────────────────────────────────────────────
# IPv4 Configuration
# ─────────────────────────────────────────────────────────────────────────────
[ipv4]
enable = true
address = "10.0.0.1"
prefix = 24                   # /24 = 255.255.255.0
allowed_ips = []              # Empty = allow all; e.g., ["192.168.0.0/16"]
blocked_ips = []              # Block specific IPs/ranges
push_routes = []              # Routes to advertise to clients

# ─────────────────────────────────────────────────────────────────────────────
# IPv6 Configuration
# ─────────────────────────────────────────────────────────────────────────────
[ipv6]
enable = false                # Set to true to enable IPv6
address = "fd00:2cha::1"      # ULA address recommended
prefix = 64
allowed_ips = []
blocked_ips = []
push_routes = []

# ─────────────────────────────────────────────────────────────────────────────
# Gateway Mode (for routing client internet traffic)
# ─────────────────────────────────────────────────────────────────────────────
[gateway]
ip_forward = false            # Enable IPv4 forwarding
ip6_forward = false           # Enable IPv6 forwarding
masquerade_v4 = false         # Enable NAT for IPv4
masquerade_v6 = false         # Enable NAT for IPv6
external_interface = "eth0"   # Internet-facing interface

# ─────────────────────────────────────────────────────────────────────────────
# Performance Tuning
# ─────────────────────────────────────────────────────────────────────────────
[performance]
socket_recv_buffer = 2097152  # 2MB
socket_send_buffer = 2097152  # 2MB
batch_size = 32               # Packets per batch
multi_queue = false           # Multi-queue TUN (Linux 3.8+)
cpu_affinity = []             # Pin to CPUs, e.g., [0, 1]

[timeouts]
keepalive = 25                # Seconds between keepalives
session = 180                 # Session timeout (seconds)
handshake = 10                # Handshake timeout (seconds)

[logging]
level = "info"                # trace, debug, info, warn, error
# file = "/var/log/2cha.log"  # Log to file
"#
}

pub fn example_client_config() -> &'static str {
    r#"# 2cha VPN Client Configuration v0.3
# Usage: sudo 2cha up -c client.toml

[client]
server = "vpn.example.com:51820"
prefer_ipv6 = false           # Prefer IPv6 connection to server

[tun]
name = "tun0"
mtu = 1420
queue_len = 500

[crypto]
cipher = "chacha20-poly1305"  # Must match server!
# key = "SAME_KEY_AS_SERVER"
# key_file = "/etc/2cha/client.key"

# ─────────────────────────────────────────────────────────────────────────────
# IPv4 Configuration
# ─────────────────────────────────────────────────────────────────────────────
[ipv4]
enable = true
address = "10.0.0.2"
prefix = 24
route_all = false             # Route ALL IPv4 traffic through VPN
routes = []                   # Specific routes, e.g., ["10.0.0.0/24", "192.168.100.0/24"]
exclude_ips = []              # Always bypass VPN, e.g., ["192.168.1.0/24"]

# ─────────────────────────────────────────────────────────────────────────────
# IPv6 Configuration
# ─────────────────────────────────────────────────────────────────────────────
[ipv6]
enable = false
address = "fd00:2cha::2"
prefix = 64
route_all = false             # Route ALL IPv6 traffic through VPN
routes = []                   # Specific IPv6 routes
exclude_ips = []              # Always bypass VPN

# ─────────────────────────────────────────────────────────────────────────────
# DNS Configuration
# ─────────────────────────────────────────────────────────────────────────────
[dns]
servers_v4 = []               # e.g., ["1.1.1.1", "8.8.8.8"]
servers_v6 = []               # e.g., ["2606:4700:4700::1111"]
search = []                   # Search domains

# ─────────────────────────────────────────────────────────────────────────────
# Performance Tuning
# ─────────────────────────────────────────────────────────────────────────────
[performance]
socket_recv_buffer = 2097152
socket_send_buffer = 2097152
batch_size = 32
multi_queue = false
cpu_affinity = []

[timeouts]
keepalive = 25

[logging]
level = "info"
"#
}
