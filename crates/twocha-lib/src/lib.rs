//! # twocha-lib
//!
//! VPN library for the 2cha VPN.
//!
//! This crate provides:
//! - Platform-specific implementations (TUN devices, networking)
//! - VPN client and server handlers

pub mod platform;
pub mod vpn;

// Re-export commonly used types
#[cfg(unix)]
pub use platform::unix::{
    get_routing_status, ClientRoutingContext, EventLoop, IpVersion, PeerState, RoutingStatus,
    TunDevice, TunnelConfig, UdpTunnel, POLLIN,
};

#[cfg(windows)]
pub use platform::windows::{
    get_routing_status, IpVersion, PeerState, RoutingStatus, TunDevice, TunnelConfig, UdpTunnel,
};

pub use vpn::{client, server};
