//! # Pluggable Transport
//!
//! The VPN's obfuscation layer is selectable. Every transport is a duplex
//! carrier of *complete v4 wire datagrams* (the same bytes `twocha_protocol::wire`
//! produces) — so the entire crypto/handshake/session engine in `twocha-core`
//! is transport-agnostic and unchanged.
//!
//! - **QUIC mimicry** (`quic`): each v4 datagram is one UDP packet, framed to
//!   look like QUIC on the wire. Backwards compatible with existing deployments.
//! - **TLS** (`tls`): each v4 datagram is length-prefixed and tunnelled inside a
//!   *real* TLS 1.3 session over TCP. A passive or active observer sees genuine
//!   TLS; the Noise_IK handshake (and thus all authentication) rides inside.
//!   See [`tls`] for the REALITY-readiness seam.
//!
//! The redundant QUIC framing carried inside TLS is wasted bytes but keeps the
//! crypto core untouched; it can be stripped later as an optimisation.

use std::io;
use std::os::unix::io::RawFd;

pub mod tls;
pub mod udp_quic;

/// Largest v4 wire datagram we will frame. Matches the UDP receive buffer.
pub use twocha_protocol::MAX_PACKET_SIZE;

/// Length-prefix framing used by stream transports (TLS): `u16` big-endian
/// length followed by exactly that many datagram bytes.
pub const FRAME_HEADER_LEN: usize = 2;

/// Client-side carrier: a single logical connection to one server, moving
/// complete v4 wire datagrams in both directions.
pub trait ClientTransport {
    /// Send one complete v4 datagram.
    fn send(&mut self, datagram: &[u8]) -> io::Result<()>;

    /// Pull the next fully-received datagram into `out`. Returns `Ok(true)` if
    /// one was produced, `Ok(false)` if the transport would block (no datagram
    /// available right now).
    fn recv(&mut self, out: &mut Vec<u8>) -> io::Result<bool>;

    /// File descriptors to register for readability in the poll loop.
    fn pollfds(&self) -> Vec<RawFd>;

    /// Switch the underlying socket(s) between blocking and non-blocking.
    fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()>;
}

/// Append a length-prefixed frame for `datagram` to `buf`.
pub fn push_frame(buf: &mut Vec<u8>, datagram: &[u8]) -> io::Result<()> {
    if datagram.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "datagram exceeds u16 frame length",
        ));
    }
    buf.extend_from_slice(&(datagram.len() as u16).to_be_bytes());
    buf.extend_from_slice(datagram);
    Ok(())
}

/// Try to split one complete frame off the front of `buf`. On success returns
/// the datagram bytes and drains them (plus the header) from `buf`. Returns
/// `None` when `buf` does not yet hold a full frame.
pub fn take_frame(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buf.len() < FRAME_HEADER_LEN {
        return None;
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    let total = FRAME_HEADER_LEN + len;
    if buf.len() < total {
        return None;
    }
    let datagram = buf[FRAME_HEADER_LEN..total].to_vec();
    buf.drain(..total);
    Some(datagram)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let mut buf = Vec::new();
        push_frame(&mut buf, b"hello").unwrap();
        push_frame(&mut buf, b"world!!").unwrap();
        assert_eq!(take_frame(&mut buf).unwrap(), b"hello");
        assert_eq!(take_frame(&mut buf).unwrap(), b"world!!");
        assert!(take_frame(&mut buf).is_none());
    }

    #[test]
    fn partial_frame_not_taken() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&5u16.to_be_bytes());
        buf.extend_from_slice(b"abc"); // only 3 of 5 bytes
        assert!(take_frame(&mut buf).is_none());
        buf.extend_from_slice(b"de");
        assert_eq!(take_frame(&mut buf).unwrap(), b"abcde");
    }

    #[test]
    fn oversize_rejected() {
        let mut buf = Vec::new();
        let big = vec![0u8; u16::MAX as usize + 1];
        assert!(push_frame(&mut buf, &big).is_err());
    }
}
