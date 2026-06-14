//! # twocha-lib
//!
//! VPN library for the 2cha VPN.
//!
//! This crate provides:
//! - Platform-specific implementations (TUN devices, networking)
//! - VPN client and server handlers driving the v4 protocol engine

pub mod platform;
#[cfg(unix)]
pub mod transport;
pub mod vpn;

// Re-export commonly used types
#[cfg(unix)]
pub use platform::unix::{
    get_routing_status, ClientRoutingContext, EventLoop, IpVersion, RoutingStatus, TunDevice,
    TunnelConfig, UdpTunnel, POLLIN,
};

#[cfg(windows)]
pub use platform::windows::{get_routing_status, IpVersion, RoutingStatus, TunDevice};

pub use vpn::{client, server};
