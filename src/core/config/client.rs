//! # Client Configuration
//!
//! VPN client configuration structures.

use super::common::*;
use serde::Deserialize;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

/// Client configuration
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
    pub server: String,
    #[serde(default)]
    pub prefer_ipv6: bool,
    #[serde(default = "default_true")]
    pub dns_lookup: bool,
}

#[derive(Debug, Deserialize)]
pub struct Ipv4ClientSection {
    #[serde(default = "default_true")]
    pub enable: bool,
    pub address: Option<String>,
    #[serde(default = "default_prefix_v4")]
    pub prefix: u8,
    #[serde(default)]
    pub route_all: bool,
    #[serde(default)]
    pub routes: Vec<String>,
    #[serde(default)]
    pub exclude_ips: Vec<String>,
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

#[derive(Debug, Deserialize)]
pub struct Ipv6ClientSection {
    #[serde(default)]
    pub enable: bool,
    pub address: Option<String>,
    #[serde(default = "default_prefix_v6")]
    pub prefix: u8,
    #[serde(default)]
    pub route_all: bool,
    #[serde(default)]
    pub routes: Vec<String>,
    #[serde(default)]
    pub exclude_ips: Vec<String>,
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

#[derive(Debug, Deserialize, Default)]
pub struct DnsSection {
    #[serde(default)]
    pub servers_v4: Vec<String>,
    #[serde(default)]
    pub servers_v6: Vec<String>,
    #[serde(default)]
    pub search: Vec<String>,
}

impl ClientConfig {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path).map_err(|e| ConfigError::IoError(e.to_string()))?;
        Self::parse(&content)
    }

    pub fn parse(content: &str) -> Result<Self, ConfigError> {
        toml::from_str(content).map_err(|e| ConfigError::ParseError(e.to_string()))
    }

    pub fn server_addr(&self) -> Result<SocketAddr, ConfigError> {
        self.client
            .server
            .parse()
            .map_err(|_| ConfigError::InvalidAddress(self.client.server.clone()))
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

    pub fn dns_servers(&self) -> Vec<String> {
        let mut servers = self.dns.servers_v4.clone();
        servers.extend(self.dns.servers_v6.clone());
        servers
    }
}

/// Generate example client config
pub fn example_client_config() -> &'static str {
    r#"# 2cha VPN Client Configuration v0.6
# Usage: sudo 2cha up -c client.toml

[client]
server = "vpn.example.com:51820"
prefer_ipv6 = false
dns_lookup = true

[tun]
name = "tun0"
mtu = 1420
queue_len = 500

[crypto]
cipher = "chacha20-poly1305"
# key = "SAME_KEY_AS_SERVER"
# key_file = "/etc/2cha/client.key"

# ─────────────────────────────────────────────────────────────────────────────
# IPv4 Configuration
# ─────────────────────────────────────────────────────────────────────────────
[ipv4]
enable = true
address = "10.0.0.2"
prefix = 24
route_all = false
routes = []
exclude_ips = []

# ─────────────────────────────────────────────────────────────────────────────
# IPv6 Configuration
# ─────────────────────────────────────────────────────────────────────────────
[ipv6]
enable = false
address = "fd00:2cha::2"
prefix = 64
route_all = false
routes = []
exclude_ips = []

# ─────────────────────────────────────────────────────────────────────────────
# DNS Configuration
# ─────────────────────────────────────────────────────────────────────────────
[dns]
servers_v4 = []
servers_v6 = []
search = []

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
