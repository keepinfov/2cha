//! # Windows Platform Module
//!
//! Platform-specific implementations for Windows.
//!
//! Note: Windows support requires wintun.dll and Administrator privileges.

// Re-export from original Windows-specific modules that remain in src/
// These will be moved/reorganized in a future update

pub mod network;
pub mod routing;
pub mod tun;

pub use network::{is_would_block, PeerState, TunnelConfig, UdpTunnel};
pub use routing::{get_routing_status, RoutingStatus};
pub use tun::{IpVersion, TunDevice};
