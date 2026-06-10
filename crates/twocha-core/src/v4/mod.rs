//! # Protocol v4 Engine (sans-IO)
//!
//! State machines for the v4 protocol: Noise_IK handshake orchestration,
//! established sessions, and handshake rate limiting. This module never
//! touches sockets or timers — twocha-lib drives it with real I/O, which
//! keeps the whole protocol unit-testable in memory.

pub mod handshake;
pub mod ratelimit;
pub mod session;

pub use handshake::{ClientHandshake, InitOutcome, ServerHandshakeEngine};
pub use ratelimit::RateLimiter;
pub use session::Session;
