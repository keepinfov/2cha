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
//!
//! The redundant QUIC framing carried inside TLS is wasted bytes but keeps the
//! crypto core untouched; it can be stripped later as an optimisation.

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::io::RawFd;

pub mod tls;
pub mod udp_quic;

pub use crate::platform::unix::BatchBuffer;

/// Largest v4 wire datagram we will frame. Matches the UDP receive buffer.
pub use twocha_protocol::MAX_PACKET_SIZE;

/// Length-prefix framing used by stream transports (TLS): `u16` big-endian
/// length followed by exactly that many datagram bytes.
pub const FRAME_HEADER_LEN: usize = 2;

/// Placeholder source tag for batch slots filled by stream transports, where
/// the peer address is fixed by the connection and irrelevant to the caller.
const STREAM_SRC: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

/// Client-side carrier: a single logical connection to one server, moving
/// complete v4 wire datagrams in both directions.
pub trait ClientTransport {
    /// Send one complete v4 datagram.
    fn send(&mut self, datagram: &[u8]) -> io::Result<()>;

    /// Pull the next fully-received datagram into `out`. Returns `Ok(true)` if
    /// one was produced, `Ok(false)` if the transport would block (no datagram
    /// available right now).
    fn recv(&mut self, out: &mut Vec<u8>) -> io::Result<bool>;

    /// Send a burst of complete v4 datagrams in as few syscalls as the
    /// carrier allows. Default: loop the single-shot [`ClientTransport::send`].
    fn send_many(&mut self, datagrams: &[Vec<u8>]) -> io::Result<()> {
        for datagram in datagrams {
            self.send(datagram)?;
        }
        Ok(())
    }

    /// Receive up to `batch.capacity()` datagrams into `batch`, reusing its
    /// buffers. Returns the number of filled slots (0 = would block); slots
    /// where `batch.get(i)` yields `None` must be skipped. Default: loop the
    /// single-shot [`ClientTransport::recv`]; datagram carriers override this
    /// with real syscall batching.
    fn recv_batch(&mut self, batch: &mut BatchBuffer) -> io::Result<usize> {
        batch.clear();
        let mut tmp = Vec::new();
        while batch.len() < batch.capacity() {
            match self.recv(&mut tmp) {
                // The loop guard guarantees a free slot, so a failed push
                // means an oversized datagram: drop it and keep draining
                // (same policy as MSG_TRUNC on the datagram path).
                Ok(true) => {
                    let _ = batch.push(STREAM_SRC, &tmp);
                }
                Ok(false) => break,
                // Surface an error only when nothing was batched; already
                // buffered datagrams are delivered first and the error (e.g.
                // EOF) re-appears on the next call.
                Err(e) if batch.is_empty() => return Err(e),
                Err(_) => break,
            }
        }
        Ok(batch.len())
    }

    /// File descriptors to register for readability in the poll loop.
    fn pollfds(&self) -> Vec<RawFd>;

    /// Switch the underlying socket(s) between blocking and non-blocking.
    fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()>;
}

/// One accepted, transport-handshaked server connection (TLS): exactly the
/// per-connection surface the server's poll loop needs.
pub trait StreamServerConn: Send + 'static {
    fn send(&mut self, datagram: &[u8]) -> io::Result<()>;
    fn recv(&mut self, out: &mut Vec<u8>) -> io::Result<bool>;
    fn pollfd(&self) -> RawFd;
    fn peer_addr(&self) -> SocketAddr;
    fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()>;
}

/// A stream-oriented server transport listener (TLS): one accepted TCP
/// connection per client, camouflaged by a transport-specific handshake.
///
/// Accept is split from handshake so callers can run the handshake off the
/// reactor thread: a TLS handshake is an attacker-paced network round trip, and
/// running it inline on the single-threaded reactor would stall every other
/// connection for as long as it takes.
pub trait StreamServerListener: Send + Sync + 'static {
    type Conn: StreamServerConn;

    /// Accept one pending raw TCP connection without blocking. `Ok(None)`
    /// means nothing is waiting.
    fn accept_raw(&self) -> io::Result<Option<(TcpStream, SocketAddr)>>;

    /// Run the (possibly slow) transport handshake on an accepted stream.
    /// `Ok(None)` means the peer was rejected and already handled — there is
    /// nothing to register.
    fn handshake(&self, stream: TcpStream, peer: SocketAddr) -> io::Result<Option<Self::Conn>>;

    fn pollfd(&self) -> RawFd;
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()>;
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

/// Once the dead prefix of a [`FrameBuf`] exceeds this, compact even if the
/// buffer still holds a partial frame.
const FRAMEBUF_COMPACT_AT: usize = 64 * 1024;

/// Reassembly buffer for length-prefixed frames with O(1) consumption.
///
/// [`take_frame`] pays an O(n) `Vec::drain` memmove per frame; under load a
/// stream transport reassembles thousands of frames per second, so this
/// tracks a consumed offset instead and compacts only when fully drained (a
/// free `clear`) or when the dead prefix passes [`FRAMEBUF_COMPACT_AT`].
#[derive(Default)]
pub struct FrameBuf {
    buf: Vec<u8>,
    consumed: usize,
}

impl FrameBuf {
    pub fn new() -> Self {
        FrameBuf::default()
    }

    /// Grow the buffer by `additional` bytes and return the new tail for the
    /// caller to fill (e.g. `read_exact` of decrypted plaintext).
    pub fn make_room(&mut self, additional: usize) -> &mut [u8] {
        self.maybe_compact();
        let start = self.buf.len();
        self.buf.resize(start + additional, 0);
        &mut self.buf[start..]
    }

    /// Copy the next complete frame into `out` (reusing its allocation) and
    /// consume it. Returns false when no full frame is buffered yet.
    pub fn pop_frame_into(&mut self, out: &mut Vec<u8>) -> bool {
        let avail = &self.buf[self.consumed..];
        if avail.len() < FRAME_HEADER_LEN {
            self.maybe_compact();
            return false;
        }
        let len = u16::from_be_bytes([avail[0], avail[1]]) as usize;
        if avail.len() < FRAME_HEADER_LEN + len {
            self.maybe_compact();
            return false;
        }
        out.clear();
        out.extend_from_slice(&avail[FRAME_HEADER_LEN..FRAME_HEADER_LEN + len]);
        self.consumed += FRAME_HEADER_LEN + len;
        true
    }

    fn maybe_compact(&mut self) {
        if self.consumed == self.buf.len() {
            self.buf.clear();
            self.consumed = 0;
        } else if self.consumed > FRAMEBUF_COMPACT_AT {
            self.buf.copy_within(self.consumed.., 0);
            self.buf.truncate(self.buf.len() - self.consumed);
            self.consumed = 0;
        }
    }
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

    #[test]
    fn framebuf_roundtrip_with_partial_appends() {
        let mut fb = FrameBuf::new();
        let mut framed = Vec::new();
        push_frame(&mut framed, b"hello").unwrap();
        push_frame(&mut framed, b"world!!").unwrap();

        // Feed in two arbitrary chunks that split the second frame
        let split = framed.len() - 3;
        fb.make_room(split).copy_from_slice(&framed[..split]);

        let mut out = Vec::new();
        assert!(fb.pop_frame_into(&mut out));
        assert_eq!(out, b"hello");
        assert!(!fb.pop_frame_into(&mut out), "partial frame not yielded");

        fb.make_room(3).copy_from_slice(&framed[split..]);
        assert!(fb.pop_frame_into(&mut out));
        assert_eq!(out, b"world!!");
        assert!(!fb.pop_frame_into(&mut out));
    }

    #[test]
    fn framebuf_compacts_dead_prefix() {
        let mut fb = FrameBuf::new();
        let payload = vec![0xAAu8; 1024];
        let mut framed = Vec::new();
        push_frame(&mut framed, &payload).unwrap();

        let mut out = Vec::new();
        // Push/pop far past the compaction threshold; the buffer must not
        // grow without bound and every frame must round-trip.
        for _ in 0..500 {
            fb.make_room(framed.len()).copy_from_slice(&framed);
            assert!(fb.pop_frame_into(&mut out));
            assert_eq!(out, payload);
        }
        assert!(
            fb.buf.capacity() < 4 * FRAMEBUF_COMPACT_AT,
            "dead prefix not compacted: capacity {}",
            fb.buf.capacity()
        );
    }
}
