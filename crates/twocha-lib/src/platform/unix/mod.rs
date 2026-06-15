//! # Unix Platform Module
//!
//! Platform-specific implementations for Unix systems (Linux, macOS).

// Netlink/routing are Linux-desktop only — see the neli note in Cargo.toml.
// Android builds get tun + network + transport but no in-process routing.
#[cfg(not(target_os = "android"))]
pub mod netlink;
pub mod network;
#[cfg(not(target_os = "android"))]
pub mod routing;
pub mod tun;

pub use network::{is_would_block, BatchBuffer, EventLoop, TunnelConfig, UdpTunnel, POLLIN};
#[cfg(not(target_os = "android"))]
pub use routing::{get_routing_status, ClientRoutingContext, RoutingStatus};
pub use tun::{IpVersion, TunDevice};
