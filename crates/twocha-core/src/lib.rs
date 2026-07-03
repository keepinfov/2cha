//! # twocha-core
//!
//! Core functionality for the 2cha VPN.
//!
//! This crate provides:
//! - Configuration handling (TOML-based)
//! - Cryptographic primitives (ChaCha20-Poly1305, AES-256-GCM)

pub mod config;
pub mod crypto;
pub mod v4;

// Re-export commonly used types
pub use config::{
    decode_config_public_key, example_client_config, example_server_config, get_value,
    prefix_to_netmask_v4, prefix_to_netmask_v6, remove_peer_from_file, set_value,
    upsert_peer_in_file, CipherSuite, ClientConfig, ConfigError, CryptoSection, DnsSection,
    GatewaySection, Ipv4ClientSection, Ipv4ServerSection, Ipv6ClientSection, Ipv6ServerSection,
    LoggingSection, PeerSection, PerformanceSection, ServerConfig, TimeoutsSection, TlsSection,
    TransportKind, TunSection,
};
pub use crypto::{decode_public_key, encode_public_key, Identity};
