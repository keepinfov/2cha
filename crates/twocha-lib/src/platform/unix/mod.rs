//! # Unix Platform Module
//!
//! Platform-specific implementations for Unix systems (Linux, macOS).

pub mod network;
pub mod routing;
pub mod tun;

pub use network::{is_would_block, EventLoop, PeerState, TunnelConfig, UdpTunnel, POLLIN};
pub use routing::{get_routing_status, ClientRoutingContext, RoutingStatus};
pub use tun::{IpVersion, TunDevice};
