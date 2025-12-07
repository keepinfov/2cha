//! # VPN Client Module
//!
//! VPN client with IPv4/IPv6 dual-stack support.

mod handler;

pub use handler::{run, stop};
