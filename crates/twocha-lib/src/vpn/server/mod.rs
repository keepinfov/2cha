//! # VPN Server Module
//!
//! VPN server with multi-client support.

#[cfg(unix)]
pub mod control;
mod handler;
#[cfg(target_os = "linux")]
mod workers;

pub use handler::{run, stop};
