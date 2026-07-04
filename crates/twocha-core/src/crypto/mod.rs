//! # Cryptographic Module
//!
//! The data path's AEAD runs inside snow's Noise transport ([`noise`]);
//! [`mac`] implements the wire-format MAC/cookie/counter-mask primitives and
//! [`identity`] the static X25519 keys. (The old standalone `Cipher` trait
//! and its ChaCha20-Poly1305/AES-256-GCM wrappers had no callers and were
//! removed; cipher choice is expressed through the Noise pattern instead.)

pub mod identity;
pub mod mac;
pub mod noise;
pub mod reality;

pub use identity::{decode_public_key, encode_public_key, Identity};
pub use noise::{Handshake, SessionCrypto};
