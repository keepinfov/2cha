//! # VPN Server Module
//!
//! VPN server with multi-client support.

#[cfg(unix)]
pub mod control;
mod handler;

pub use handler::{run, stop};
