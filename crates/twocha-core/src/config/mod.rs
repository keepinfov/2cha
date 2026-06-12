//! # Configuration Module
//!
//! TOML-based configuration for client and server.

mod client;
mod common;
mod server;

pub use client::{
    example_client_config, ClientConfig, DnsSection, Ipv4ClientSection, Ipv6ClientSection,
};
pub use common::{
    decode_config_public_key, prefix_to_netmask_v4, prefix_to_netmask_v6, CipherSuite, ConfigError,
    CryptoSection, LoggingSection, PerformanceSection, TimeoutsSection, TlsSection, TransportKind,
    TunSection,
};
pub use server::{
    example_server_config, remove_peer_from_file, upsert_peer_in_file, GatewaySection,
    Ipv4ServerSection, Ipv6ServerSection, PeerSection, ServerConfig,
};
