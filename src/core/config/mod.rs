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
    hex_to_key, prefix_to_netmask_v4, prefix_to_netmask_v6, CipherSuite, ConfigError,
    CryptoSection, LoggingSection, PerformanceSection, TimeoutsSection, TunSection,
};
pub use server::{
    example_server_config, GatewaySection, Ipv4ServerSection, Ipv6ServerSection, ServerConfig,
};
