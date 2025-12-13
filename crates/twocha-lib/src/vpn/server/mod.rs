//! # VPN Server Module
//!
//! VPN server with multi-client support.

mod handler;

pub use handler::{run, stop};
