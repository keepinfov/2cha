//! # Server Configuration
//!
//! VPN server configuration structures.

use super::common::*;
use super::edit::edit_config;
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
    /// Authorized peers (whitelist). Handshakes from unknown keys are dropped.
    #[serde(default)]
    pub peers: Vec<PeerSection>,
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
    #[serde(default)]
    pub tls: TlsSection,
}

/// An authorized peer entry
#[derive(Debug, Deserialize)]
pub struct PeerSection {
    /// Base64-encoded X25519 public key
    pub public_key: String,
    /// Optional human-readable label for logs
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ServerSection {
    pub listen: String,
    #[serde(default)]
    pub listen_v6: Option<String>,
    #[serde(default = "default_max_clients")]
    pub max_clients: usize,
    /// Obfuscation transport. Must match the clients' `transport`.
    #[serde(default)]
    pub transport: TransportKind,
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
        let path = path.as_ref();
        let content = fs::read_to_string(path).map_err(|e| ConfigError::IoError(e.to_string()))?;
        let mut config = Self::parse(&content)?;
        resolve_paths(&mut config.crypto, &mut config.tls, path);
        config.validate()?;
        Ok(config)
    }

    /// Early validation: fail at load time, not deep in the runtime
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.listen_addr()?;
        self.listen_addr_v6()?;
        self.tun_ipv4()?;
        self.tun_ipv6()?;
        validate_tun_mtu(self.tun.mtu)?;
        if self.server.max_clients == 0 {
            return Err(ConfigError::Invalid("max_clients must be > 0".into()));
        }
        if self.ipv4.prefix > 32 {
            return Err(ConfigError::Invalid("ipv4.prefix must be 0..=32".into()));
        }
        if self.ipv6.prefix > 128 {
            return Err(ConfigError::Invalid("ipv6.prefix must be 0..=128".into()));
        }
        if self.peers.is_empty() {
            return Err(ConfigError::Invalid(
                "no [[peers]] configured; add at least one client public_key".into(),
            ));
        }
        self.peer_keys()?;
        Ok(())
    }

    /// Decoded whitelist of authorized peer public keys
    pub fn peer_keys(&self) -> Result<Vec<[u8; 32]>, ConfigError> {
        self.peers
            .iter()
            .map(|p| decode_config_public_key(&p.public_key))
            .collect()
    }

    /// Load the server identity key
    pub fn identity(&self) -> Result<crate::crypto::Identity, ConfigError> {
        self.crypto.identity()
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
}

/// Add or update a `[[peers]]` entry in a config file, preserving
/// comments and formatting. Written atomically (tmp file + rename).
pub fn upsert_peer_in_file(
    path: &Path,
    public_key: &str,
    name: Option<&str>,
) -> Result<(), ConfigError> {
    decode_config_public_key(public_key)?;
    edit_config(path, |doc| {
        let peers = peers_array(doc)?;
        for peer in peers.iter_mut() {
            if peer.get("public_key").and_then(|v| v.as_str()) == Some(public_key) {
                if let Some(name) = name {
                    peer["name"] = toml_edit::value(name);
                }
                return Ok(());
            }
        }
        let mut table = toml_edit::Table::new();
        table["public_key"] = toml_edit::value(public_key);
        if let Some(name) = name {
            table["name"] = toml_edit::value(name);
        }
        peers.push(table);
        Ok(())
    })
}

/// Remove a `[[peers]]` entry from a config file.
/// Returns whether the key was present.
pub fn remove_peer_from_file(path: &Path, public_key: &str) -> Result<bool, ConfigError> {
    let mut removed = false;
    edit_config(path, |doc| {
        let peers = peers_array(doc)?;
        let before = peers.len();
        peers.retain(|peer| peer.get("public_key").and_then(|v| v.as_str()) != Some(public_key));
        removed = peers.len() != before;
        Ok(())
    })?;
    Ok(removed)
}

fn peers_array(
    doc: &mut toml_edit::DocumentMut,
) -> Result<&mut toml_edit::ArrayOfTables, ConfigError> {
    doc.entry("peers")
        .or_insert(toml_edit::Item::ArrayOfTables(
            toml_edit::ArrayOfTables::new(),
        ))
        .as_array_of_tables_mut()
        .ok_or_else(|| ConfigError::Invalid("'peers' is not an array of tables".into()))
}

/// Resolve a relative path against the config file's directory, in place.
/// Absolute paths are left untouched.
pub(super) fn resolve_relative_path(path_str: &mut String, config_path: &Path) {
    let p = Path::new(path_str.as_str());
    if p.is_relative() {
        if let Some(config_dir) = config_path.parent() {
            let absolute = config_dir.join(p);
            let resolved = fs::canonicalize(&absolute).unwrap_or(absolute);
            *path_str = resolved.to_string_lossy().to_string();
        }
    }
}

/// Resolve every file-path field in `crypto`/`tls` against the config file's
/// directory, so a relative path means "next to the config" regardless of CWD.
pub(super) fn resolve_paths(
    crypto: &mut super::common::CryptoSection,
    tls: &mut super::common::TlsSection,
    config_path: &Path,
) {
    resolve_relative_path(&mut crypto.private_key_file, config_path);
    if let Some(cert) = tls.cert_file.as_mut() {
        resolve_relative_path(cert, config_path);
    }
    if let Some(key) = tls.key_file.as_mut() {
        resolve_relative_path(key, config_path);
    }
}

/// Generate example server config
pub fn example_server_config() -> &'static str {
    r#"# 2cha VPN Server Configuration v1.0
# Usage: sudo 2cha server -c server.toml

[server]
listen = "0.0.0.0:51820"
# listen_v6 = "[::]:51820"
max_clients = 256
# Obfuscation transport: "quic" (UDP, QUIC-mimicry) or "tls" (real TLS 1.3 over TCP).
# Must match the clients' transport setting.
transport = "quic"

[tun]
name = "tun0"
mtu = 1420
queue_len = 500

[crypto]
cipher = "chacha20-poly1305"
# Generate with: 2cha genkey /etc/2cha/server.key
private_key_file = "/etc/2cha/server.key"

# Authorized clients. Get a client's key with: 2cha pubkey client.key
[[peers]]
public_key = "CLIENT_PUBLIC_KEY_BASE64"
name = "laptop"

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
# Data-plane threads: 0/1 = single-threaded loop (default);
# >= 2 = opt-in multi-worker pool (QUIC + Linux, forces multi-queue tun)
worker_threads = 0
cpu_affinity = []

[timeouts]
# Drop a client session after this many seconds without traffic
session = 180

[logging]
level = "info"
# file = "/var/log/2cha.log"

# ─────────────────────────────────────────────────────────────────────────────
# TLS Transport (only used when server.transport = "tls")
# ─────────────────────────────────────────────────────────────────────────────
[tls]
# SNI the server expects / presents. A self-signed cert is generated for it
# when no cert/key files are supplied below.
sni = "www.cloudflare.com"
# cert_file = "/etc/2cha/tls/fullchain.pem"
# key_file = "/etc/2cha/tls/privkey.pem"
"#
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";
    const KEY_B: &str = "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=";

    fn tmp_config() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "2cha-cfg-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("server.toml");
        std::fs::write(
            &path,
            "# keep this comment\n[server]\nlisten = \"0.0.0.0:51820\"\n\n[tun]\n\n[crypto]\nprivate_key_file = \"server.key\"\n",
        )
        .unwrap();
        path
    }

    #[test]
    fn test_upsert_and_remove_peer() {
        let path = tmp_config();

        upsert_peer_in_file(&path, KEY_A, Some("laptop")).unwrap();
        upsert_peer_in_file(&path, KEY_B, None).unwrap();
        // updating an existing peer must not duplicate it
        upsert_peer_in_file(&path, KEY_A, Some("renamed")).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("# keep this comment"),
            "comments preserved"
        );

        let cfg = ServerConfig::parse(&content).unwrap();
        assert_eq!(cfg.peers.len(), 2);
        assert_eq!(cfg.peers[0].name.as_deref(), Some("renamed"));

        assert!(remove_peer_from_file(&path, KEY_B).unwrap());
        assert!(!remove_peer_from_file(&path, KEY_B).unwrap());

        let cfg = ServerConfig::parse(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(cfg.peers.len(), 1);

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_upsert_rejects_bad_key() {
        let path = tmp_config();
        assert!(upsert_peer_in_file(&path, "not-base64!!", None).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn example_config_parses_with_transport_defaults() {
        let cfg = ServerConfig::parse(example_server_config()).unwrap();
        assert_eq!(cfg.server.transport, TransportKind::Quic);
        assert_eq!(cfg.tls.sni, "www.cloudflare.com");
    }

    #[test]
    fn transport_defaults_to_quic_when_absent() {
        let cfg = ServerConfig::parse(
            "[server]\nlisten = \"0.0.0.0:51820\"\n[tun]\n[crypto]\nprivate_key_file = \"k\"\n",
        )
        .unwrap();
        assert_eq!(cfg.server.transport, TransportKind::Quic);
        assert_eq!(cfg.tls.sni, "www.cloudflare.com");
    }

    #[test]
    fn from_file_resolves_relative_paths_against_config_dir() {
        let dir = std::env::temp_dir().join(format!(
            "2cha-relpath-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // Create the referenced files so canonicalize resolves cleanly.
        for f in ["server.key", "cert.pem", "tls.key"] {
            std::fs::write(dir.join(f), b"x").unwrap();
        }
        let path = dir.join("server.toml");
        std::fs::write(
            &path,
            "[server]\nlisten = \"0.0.0.0:443\"\ntransport = \"tls\"\n[tun]\n\
             [crypto]\nprivate_key_file = \"server.key\"\n\
             [tls]\ncert_file = \"cert.pem\"\nkey_file = \"tls.key\"\n\
             [[peers]]\npublic_key = \"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\"\n",
        )
        .unwrap();

        let cfg = ServerConfig::from_file(&path).unwrap();
        for resolved in [
            &cfg.crypto.private_key_file,
            cfg.tls.cert_file.as_ref().unwrap(),
            cfg.tls.key_file.as_ref().unwrap(),
        ] {
            assert!(
                Path::new(resolved).is_absolute(),
                "expected absolute path, got {resolved}"
            );
        }
        assert!(cfg.crypto.private_key_file.ends_with("server.key"));
        assert!(cfg.tls.cert_file.as_ref().unwrap().ends_with("cert.pem"));
        assert!(cfg.tls.key_file.as_ref().unwrap().ends_with("tls.key"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn transport_tls_selected() {
        let cfg = ServerConfig::parse(
            "[server]\nlisten = \"0.0.0.0:443\"\ntransport = \"tls\"\n[tun]\n[crypto]\nprivate_key_file = \"k\"\n[tls]\nsni = \"example.com\"\n",
        )
        .unwrap();
        assert_eq!(cfg.server.transport, TransportKind::Tls);
        assert_eq!(cfg.tls.sni, "example.com");
    }
}
