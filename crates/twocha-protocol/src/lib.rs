//! # twocha-protocol
//!
//! Protocol types and definitions for the 2cha VPN (protocol v4).
//!
//! This crate provides:
//! - Protocol constants
//! - Error types for all VPN operations
//! - QUIC-mimicking wire format (encode/parse, zero plaintext protocol bytes)
//! - Replay attack protection

mod constants;
mod error;
mod replay;
pub mod wire;

pub use constants::*;
pub use error::{CryptoError, NetworkError, ProtocolError, Result, TunError, VpnError};
pub use replay::ReplayWindow;
