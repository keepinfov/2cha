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
pub mod handshake;
pub mod noise;
pub mod mac;
pub mod packet_v4;

pub use constants::*;
pub use error::{CryptoError, NetworkError, ProtocolError, Result, TunError, VpnError};
pub use packet::{Packet, PacketHeader, PacketType};
pub use replay::ReplayWindow;
pub use handshake::{
    HandshakeInit, HandshakeResponse, HandshakeType, Tai64n,
    ENCRYPTED_STATIC_SIZE, ENCRYPTED_TIMESTAMP_SIZE, ENCRYPTED_EMPTY_SIZE, TAI64N_SIZE,
};
pub use noise::{
    HandshakeState, SymmetricState, TransportKey, NoiseError,
    NOISE_PROTOCOL_NAME, NOISE_CONSTRUCTION, NOISE_IDENTIFIER, HASH_SIZE, KEY_SIZE,
};
pub use mac::{
    MacCalculator, CookieGenerator, CookieReply,
    LABEL_MAC1, LABEL_COOKIE, COOKIE_SIZE, COOKIE_SECRET_SIZE,
    COOKIE_VALIDITY_SECS, COOKIE_REPLY_SIZE,
};
pub use packet_v4::{
    DataPacket, DataPacketHeader, PacketTypeV4, identify_packet_type,
    PACKET_TYPE_DATA, MIN_DATA_PACKET_SIZE, MAX_PAYLOAD_SIZE,
};
