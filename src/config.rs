//! # Configuration Module
//!
//! TOML configuration support for VPN server and client.

use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::net::SocketAddr;

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

/// Server configuration
#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub server: ServerSection,
    pub tun: TunSection,
    pub crypto: CryptoSection,
    #[serde(default)]
    pub routing: RoutingSection,
    #[serde(default)]
    pub timeouts: TimeoutsSection,
    #[serde(default)]
    pub logging: LoggingSection,
}

/// Client configuration
#[derive(Debug, Deserialize)]
pub struct ClientConfig {
    pub client: ClientSection,
    pub tun: TunSection,
    pub crypto: CryptoSection,
    #[serde(default)]
    pub routing: ClientRoutingSection,
    #[serde(default)]
    pub timeouts: TimeoutsSection,
    #[serde(default)]
    pub logging: LoggingSection,
}

#[derive(Debug, Deserialize)]
pub struct ServerSection {
    pub listen: String,
}

#[derive(Debug, Deserialize)]
pub struct ClientSection {
    pub server: String,
}

#[derive(Debug, Deserialize)]
pub struct TunSection {
    #[serde(default = "default_tun_name")]
    pub name: String,
    pub address: String,
    #[serde(default = "default_netmask")]
    pub netmask: String,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
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

#[derive(Debug, Deserialize, Default)]
pub struct RoutingSection {
    /// Enable IP forwarding (act as gateway)
    #[serde(default)]
    pub ip_forward: bool,
    /// Enable NAT/masquerading
    #[serde(default)]
    pub masquerade: bool,
    /// External interface for NAT
    #[serde(default)]
    pub external_interface: Option<String>,
    /// Allowed client subnets
    #[serde(default)]
    pub allowed_ips: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ClientRoutingSection {
    /// Route all traffic through VPN
    #[serde(default)]
    pub route_all_traffic: bool,
    /// Specific routes
    #[serde(default)]
    pub routes: Vec<String>,
    /// DNS servers
    #[serde(default)]
    pub dns: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct TimeoutsSection {
    #[serde(default = "default_keepalive")]
    pub keepalive: u64,
    #[serde(default = "default_session_timeout")]
    pub session: u64,
}

#[derive(Debug, Deserialize)]
pub struct LoggingSection {
    #[serde(default = "default_log_level")]
    pub level: String,
}

fn default_tun_name() -> String { "tun0".to_string() }
fn default_netmask() -> String { "255.255.255.0".to_string() }
fn default_mtu() -> u16 { 1400 }
fn default_keepalive() -> u64 { 25 }
fn default_session_timeout() -> u64 { 180 }
fn default_log_level() -> String { "info".to_string() }

impl Default for TimeoutsSection {
    fn default() -> Self {
        TimeoutsSection {
            keepalive: default_keepalive(),
            session: default_session_timeout(),
        }
    }
}

impl Default for LoggingSection {
    fn default() -> Self {
        LoggingSection { level: default_log_level() }
    }
}

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

    pub fn tun_ip(&self) -> Result<[u8; 4], ConfigError> {
        parse_ip(&self.tun.address)
            .ok_or_else(|| ConfigError::InvalidAddress(self.tun.address.clone()))
    }

    pub fn netmask(&self) -> Result<[u8; 4], ConfigError> {
        parse_ip(&self.tun.netmask)
            .ok_or_else(|| ConfigError::InvalidAddress(self.tun.netmask.clone()))
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

    pub fn tun_ip(&self) -> Result<[u8; 4], ConfigError> {
        parse_ip(&self.tun.address)
            .ok_or_else(|| ConfigError::InvalidAddress(self.tun.address.clone()))
    }

    pub fn netmask(&self) -> Result<[u8; 4], ConfigError> {
        parse_ip(&self.tun.netmask)
            .ok_or_else(|| ConfigError::InvalidAddress(self.tun.netmask.clone()))
    }

    pub fn key(&self) -> Result<[u8; 32], ConfigError> {
        self.crypto.get_key()
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
            ConfigError::MissingKey => write!(f, "No key provided"),
        }
    }
}

impl std::error::Error for ConfigError {}

pub fn parse_ip(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 { return None; }
    Some([
        parts[0].parse().ok()?,
        parts[1].parse().ok()?,
        parts[2].parse().ok()?,
        parts[3].parse().ok()?,
    ])
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
            .map_err(|_| ConfigError::InvalidKey("Invalid hex".to_string()))?;
    }
    Ok(key)
}

pub fn example_server_config() -> &'static str {
    r#"# VPN Server Configuration

[server]
listen = "0.0.0.0:51820"

[tun]
name = "tun0"
address = "10.0.0.1"
netmask = "255.255.255.0"
mtu = 1400

[crypto]
# Cipher: "chacha20-poly1305" (default, recommended) or "aes-256-gcm"
cipher = "chacha20-poly1305"
# Key: 64 hex chars. Generate with: openssl rand -hex 32
# key = "YOUR_KEY_HERE"
# Or use key_file or VPN_KEY env variable

[routing]
# Enable to act as internet gateway for clients
ip_forward = false
# Enable NAT/masquerading (requires ip_forward)
masquerade = false
# External interface for NAT (e.g., "eth0")
# external_interface = "eth0"

[timeouts]
keepalive = 25
session = 180

[logging]
level = "info"
"#
}

pub fn example_client_config() -> &'static str {
    r#"# VPN Client Configuration

[client]
server = "vpn.example.com:51820"

[tun]
name = "tun0"
address = "10.0.0.2"
netmask = "255.255.255.0"
mtu = 1400

[crypto]
# Must match server!
cipher = "chacha20-poly1305"
# key = "SAME_AS_SERVER"

[routing]
# Route ALL traffic through VPN (default gateway)
route_all_traffic = false
# Or specific routes only:
# routes = ["10.0.0.0/24", "192.168.100.0/24"]
# DNS when connected:
# dns = ["10.0.0.1", "1.1.1.1"]

[timeouts]
keepalive = 25

[logging]
level = "info"
"#
}
