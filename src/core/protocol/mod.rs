//! # VPN Protocol Module
//!
//! Type-safe protocol with efficient serialization.

mod packet;
mod replay;

pub use packet::{Packet, PacketHeader, PacketType};
pub use replay::ReplayWindow;
