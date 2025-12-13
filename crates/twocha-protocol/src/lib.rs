//! # twocha-protocol
//!
//! Protocol types and definitions for the 2cha VPN.
//!
//! This crate provides:
//! - Protocol constants (version, sizes, etc.)
//! - Error types for all VPN operations
//! - Packet types and serialization
//! - Replay attack protection

mod constants;
mod error;
mod packet;
mod replay;

pub use constants::*;
pub use error::{CryptoError, NetworkError, ProtocolError, Result, TunError, VpnError};
pub use packet::{Packet, PacketHeader, PacketType};
pub use replay::ReplayWindow;
