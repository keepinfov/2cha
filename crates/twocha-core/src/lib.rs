//! # twocha-core
//!
//! Core functionality for the 2cha VPN.
//!
//! This crate provides:
//! - Configuration handling (TOML-based)
//! - Cryptographic primitives (ChaCha20-Poly1305, AES-256-GCM)

pub mod config;
pub mod crypto;

// Re-export commonly used types
pub use config::{
    example_client_config, example_server_config, hex_to_key, prefix_to_netmask_v4,
    prefix_to_netmask_v6, CipherSuite, ClientConfig, ConfigError, CryptoSection, DnsSection,
    GatewaySection, Ipv4ClientSection, Ipv4ServerSection, Ipv6ClientSection, Ipv6ServerSection,
    LoggingSection, PerformanceSection, ServerConfig, TimeoutsSection, TunSection,
};
pub use crypto::{
    constant_time_compare, create_cipher, secure_zero, Aes256Gcm, ChaCha20Poly1305, Cipher,
};
