//! # VPN Module
//!
//! VPN client and server implementations.

pub mod client;
pub mod common;
// The server uses netlink routing, which doesn't build on Android; a mobile
// client never runs a server, so exclude it there.
#[cfg(not(target_os = "android"))]
pub mod server;
