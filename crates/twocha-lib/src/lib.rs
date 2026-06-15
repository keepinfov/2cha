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
pub use platform::unix::{EventLoop, IpVersion, TunDevice, TunnelConfig, UdpTunnel, POLLIN};
// Routing symbols are Linux-desktop only (no netlink on Android).
#[cfg(all(unix, not(target_os = "android")))]
pub use platform::unix::{get_routing_status, ClientRoutingContext, RoutingStatus};

#[cfg(windows)]
pub use platform::windows::{get_routing_status, IpVersion, RoutingStatus, TunDevice};

pub use vpn::client;
// The server is desktop-only; a mobile client never runs one.
#[cfg(not(target_os = "android"))]
pub use vpn::server;
