//! # Server Configuration
//!
//! VPN server configuration structures.

use super::common::*;
use serde::Deserialize;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

/// Server configuration
#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub server: ServerSection,
    pub tun: TunSection,
    pub crypto: CryptoSection,
    #[serde(default)]
    pub ipv4: Ipv4ServerSection,
    #[serde(default)]
    pub ipv6: Ipv6ServerSection,
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
    pub listen: String,
    #[serde(default)]
    pub listen_v6: Option<String>,
    #[serde(default = "default_max_clients")]
    pub max_clients: usize,
}

#[derive(Debug, Deserialize)]
pub struct Ipv4ServerSection {
    #[serde(default = "default_true")]
    pub enable: bool,
    pub address: Option<String>,
    #[serde(default = "default_prefix_v4")]
    pub prefix: u8,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub blocked_ips: Vec<String>,
    #[serde(default)]
    pub push_routes: Vec<String>,
}

impl Default for Ipv4ServerSection {
    fn default() -> Self {
        Ipv4ServerSection {
            enable: true,
            address: Some("10.0.0.1".to_string()),
            prefix: 24,
            allowed_ips: Vec::new(),
            blocked_ips: Vec::new(),
            push_routes: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Ipv6ServerSection {
    #[serde(default)]
    pub enable: bool,
    pub address: Option<String>,
    #[serde(default = "default_prefix_v6")]
    pub prefix: u8,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub blocked_ips: Vec<String>,
    #[serde(default)]
    pub push_routes: Vec<String>,
}

impl Default for Ipv6ServerSection {
    fn default() -> Self {
        Ipv6ServerSection {
            enable: false,
            address: None,
            prefix: 64,
            allowed_ips: Vec::new(),
            blocked_ips: Vec::new(),
            push_routes: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct GatewaySection {
    #[serde(default)]
    pub ip_forward: bool,
    #[serde(default)]
    pub ip6_forward: bool,
    #[serde(default)]
    pub masquerade_v4: bool,
    #[serde(default)]
    pub masquerade_v6: bool,
    #[serde(default)]
    pub external_interface: Option<String>,
}

impl ServerConfig {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path).map_err(|e| ConfigError::IoError(e.to_string()))?;
        Self::parse(&content)
    }

    pub fn parse(content: &str) -> Result<Self, ConfigError> {
        toml::from_str(content).map_err(|e| ConfigError::ParseError(e.to_string()))
    }

    pub fn listen_addr(&self) -> Result<SocketAddr, ConfigError> {
        self.server
            .listen
            .parse()
            .map_err(|_| ConfigError::InvalidAddress(self.server.listen.clone()))
    }

    pub fn listen_addr_v6(&self) -> Result<Option<SocketAddr>, ConfigError> {
        match &self.server.listen_v6 {
            Some(addr) => addr
                .parse()
                .map(Some)
                .map_err(|_| ConfigError::InvalidAddress(addr.clone())),
            None => Ok(None),
        }
    }

    pub fn tun_ipv4(&self) -> Result<Option<Ipv4Addr>, ConfigError> {
        match &self.ipv4.address {
            Some(addr) if self.ipv4.enable => addr
                .parse()
                .map(Some)
                .map_err(|_| ConfigError::InvalidAddress(addr.clone())),
            _ => Ok(None),
        }
    }

    pub fn tun_ipv6(&self) -> Result<Option<Ipv6Addr>, ConfigError> {
        match &self.ipv6.address {
            Some(addr) if self.ipv6.enable => addr
                .parse()
                .map(Some)
                .map_err(|_| ConfigError::InvalidAddress(addr.clone())),
            _ => Ok(None),
        }
    }

    pub fn key(&self) -> Result<[u8; 32], ConfigError> {
        self.crypto.get_key()
    }
}

/// Generate example server config
pub fn example_server_config() -> &'static str {
    r#"# 2cha VPN Server Configuration v0.6
# Usage: sudo 2cha server -c server.toml

[server]
listen = "0.0.0.0:51820"
# listen_v6 = "[::]:51820"
max_clients = 256

[tun]
name = "tun0"
mtu = 1420
queue_len = 500

[crypto]
cipher = "chacha20-poly1305"
# key = "YOUR_64_HEX_CHAR_KEY"
# key_file = "/etc/2cha/server.key"

# ─────────────────────────────────────────────────────────────────────────────
# IPv4 Configuration
# ─────────────────────────────────────────────────────────────────────────────
[ipv4]
enable = true
address = "10.0.0.1"
prefix = 24
allowed_ips = []
blocked_ips = []
push_routes = []

# ─────────────────────────────────────────────────────────────────────────────
# IPv6 Configuration
# ─────────────────────────────────────────────────────────────────────────────
[ipv6]
enable = false
address = "fd00:2cha::1"
prefix = 64
allowed_ips = []
blocked_ips = []
push_routes = []

# ─────────────────────────────────────────────────────────────────────────────
# Gateway Mode
# ─────────────────────────────────────────────────────────────────────────────
[gateway]
ip_forward = false
ip6_forward = false
masquerade_v4 = false
masquerade_v6 = false
external_interface = "eth0"

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
session = 180
handshake = 10

[logging]
level = "info"
# file = "/var/log/2cha.log"
"#
}
