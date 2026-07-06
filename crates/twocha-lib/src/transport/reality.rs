//! # REALITY carrier (Go `xtls/reality` via FFI)
//!
//! The Go core (`native/goreality`, linked as `libgoreality.a`) owns the whole
//! TLS+REALITY connection and hands us one end of a socketpair carrying the
//! *decrypted* application stream. This module frames v4 datagrams over that
//! plaintext fd exactly like [`super::tls`] does inside TLS — but with no rustls
//! on the Rust side. Noise_IK inside the tunnel remains the trust anchor.
//!
//! Enabled by the `reality` cargo feature (which also links the archive via
//! `build.rs`). See `docs/reality-go-design.md`.

use std::ffi::CString;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::raw::c_char;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;

use super::{push_frame, ClientTransport, FrameBuf};

const GOR_FALLBACK: i64 = -1;

extern "C" {
    fn gor_server_new(
        private_key: *const u8,
        dest: *const c_char,
        server_names_csv: *const c_char,
        short_ids_csv: *const c_char,
        max_time_diff_ms: i64,
        err: *mut c_char,
        errlen: i32,
    ) -> i64;
    fn gor_server_handshake(
        server_handle: i64,
        tcp_fd: i32,
        out_fd: *mut i32,
        err: *mut c_char,
        errlen: i32,
    ) -> i64;
    fn gor_client_handshake(
        tcp_fd: i32,
        server_name: *const c_char,
        public_key: *const u8,
        short_id: *const u8,
        fingerprint: *const c_char,
        out_fd: *mut i32,
        err: *mut c_char,
        errlen: i32,
    ) -> i64;
    fn gor_close(handle: i64);
}

fn take_err(buf: &[c_char]) -> String {
    let bytes: Vec<u8> = buf
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Plaintext framing over the Go socketpair fd. Owns the Go handle and tears the
/// connection down (closing both socketpair ends) on drop.
struct Carrier {
    sock: UnixStream,
    handle: i64,
    inbuf: FrameBuf,
}

impl Carrier {
    /// Adopt the decrypted-stream fd returned by a handshake.
    fn new(out_fd: i32, handle: i64) -> Self {
        let sock = unsafe { UnixStream::from_raw_fd(out_fd as RawFd) };
        Carrier {
            sock,
            handle,
            inbuf: FrameBuf::new(),
        }
    }

    fn send(&mut self, datagram: &[u8]) -> io::Result<()> {
        let mut frame = Vec::with_capacity(super::FRAME_HEADER_LEN + datagram.len());
        push_frame(&mut frame, datagram)?;
        self.sock.write_all(&frame)
    }

    fn recv(&mut self, out: &mut Vec<u8>) -> io::Result<bool> {
        if self.inbuf.pop_frame_into(out) {
            return Ok(true);
        }
        let mut tmp = [0u8; 8192];
        loop {
            match self.sock.read(&mut tmp) {
                Ok(0) => {
                    if self.inbuf.pop_frame_into(out) {
                        return Ok(true);
                    }
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                }
                Ok(n) => {
                    self.inbuf.make_room(n).copy_from_slice(&tmp[..n]);
                    if self.inbuf.pop_frame_into(out) {
                        return Ok(true);
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        Ok(false)
    }

    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.sock.set_nonblocking(nonblocking)
    }

    fn pollfd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }
}

impl Drop for Carrier {
    fn drop(&mut self) {
        unsafe { gor_close(self.handle) };
    }
}

/// Client-side REALITY carrier to one server.
pub struct RealityClientTransport {
    carrier: Carrier,
}

impl RealityClientTransport {
    /// Connect to `addr`, run the REALITY client handshake mimicking `server_name`
    /// and authenticating with the server's public key + short id, and return a
    /// carrier ready for the poll loop.
    pub fn connect<A: ToSocketAddrs>(
        addr: A,
        server_name: &str,
        public_key: &[u8; 32],
        short_id: &[u8; 8],
        fingerprint: &str,
    ) -> io::Result<Self> {
        let tcp = TcpStream::connect(addr)?;
        tcp.set_nodelay(true)?;
        let fd = tcp.into_raw_fd(); // ownership passes to Go
        let name = CString::new(server_name).map_err(io::Error::other)?;
        let fp = CString::new(fingerprint).map_err(io::Error::other)?;
        let (mut out_fd, mut err) = (0i32, [0 as c_char; 256]);
        let handle = unsafe {
            gor_client_handshake(
                fd,
                name.as_ptr(),
                public_key.as_ptr(),
                short_id.as_ptr(),
                fp.as_ptr(),
                &mut out_fd,
                err.as_mut_ptr(),
                256,
            )
        };
        if handle < 0 {
            return Err(io::Error::other(format!(
                "reality client handshake failed: {}",
                take_err(&err)
            )));
        }
        Ok(RealityClientTransport {
            carrier: Carrier::new(out_fd, handle),
        })
    }
}

impl ClientTransport for RealityClientTransport {
    fn send(&mut self, datagram: &[u8]) -> io::Result<()> {
        self.carrier.send(datagram)
    }
    fn recv(&mut self, out: &mut Vec<u8>) -> io::Result<bool> {
        self.carrier.recv(out)
    }
    fn pollfds(&self) -> Vec<RawFd> {
        vec![self.carrier.pollfd()]
    }
    fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        self.carrier.set_nonblocking(nonblocking)
    }
}

/// One accepted + REALITY-handshaked server-side connection.
pub struct RealityServerConn {
    carrier: Carrier,
    peer: SocketAddr,
}

impl RealityServerConn {
    pub fn send(&mut self, datagram: &[u8]) -> io::Result<()> {
        self.carrier.send(datagram)
    }
    pub fn recv(&mut self, out: &mut Vec<u8>) -> io::Result<bool> {
        self.carrier.recv(out)
    }
    pub fn pollfd(&self) -> RawFd {
        self.carrier.pollfd()
    }
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        self.carrier.set_nonblocking(nonblocking)
    }
}

/// Server-side REALITY listener: a TCP listener plus the shared Go server config.
pub struct RealityServerListener {
    listener: TcpListener,
    server_handle: i64,
}

impl RealityServerListener {
    /// Bind and build the Go REALITY server config from raw settings.
    pub fn bind<A: ToSocketAddrs>(
        addr: A,
        private_key: &[u8; 32],
        dest: &str,
        server_names: &[String],
        short_ids: &[String],
        max_time_diff_ms: u64,
    ) -> io::Result<Self> {
        let dest_c = CString::new(dest).map_err(io::Error::other)?;
        let names_c = CString::new(server_names.join(",")).map_err(io::Error::other)?;
        let ids_c = CString::new(short_ids.join(",")).map_err(io::Error::other)?;
        // The Go side takes a signed 64-bit millisecond duration; reject values
        // that would silently wrap negative and disable the freshness check
        // instead of passing them through.
        let max_time_diff_ms = i64::try_from(max_time_diff_ms).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "reality.max_time_diff_ms is too large",
            )
        })?;
        let mut err = [0 as c_char; 256];
        let handle = unsafe {
            gor_server_new(
                private_key.as_ptr(),
                dest_c.as_ptr(),
                names_c.as_ptr(),
                ids_c.as_ptr(),
                max_time_diff_ms,
                err.as_mut_ptr(),
                256,
            )
        };
        if handle < 0 {
            return Err(io::Error::other(format!(
                "reality server config failed: {}",
                take_err(&err)
            )));
        }
        let listener = TcpListener::bind(addr)?;
        Ok(RealityServerListener {
            listener,
            server_handle: handle,
        })
    }

    pub fn pollfd(&self) -> RawFd {
        self.listener.as_raw_fd()
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.listener.set_nonblocking(nonblocking)
    }

}

impl super::StreamServerConn for RealityServerConn {
    fn send(&mut self, datagram: &[u8]) -> io::Result<()> {
        self.send(datagram)
    }
    fn recv(&mut self, out: &mut Vec<u8>) -> io::Result<bool> {
        self.recv(out)
    }
    fn pollfd(&self) -> RawFd {
        self.pollfd()
    }
    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr()
    }
    fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        self.set_nonblocking(nonblocking)
    }
}

impl super::StreamServerListener for RealityServerListener {
    type Conn = RealityServerConn;

    /// Accept one pending raw TCP connection. `Ok(None)` if none is waiting
    /// (non-blocking listener).
    fn accept_raw(&self) -> io::Result<Option<(TcpStream, SocketAddr)>> {
        let (sock, peer) = match self.listener.accept() {
            Ok(pair) => pair,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) => return Err(e),
        };
        sock.set_nodelay(true)?;
        Ok(Some((sock, peer)))
    }

    /// Run the REALITY server handshake on an accepted stream. `Ok(None)`
    /// means the peer was an unauthenticated probe, already relayed to `dest`
    /// inside Go — there is nothing for us to carry. This call can block for
    /// as long as that relay stays open (an attacker-controlled duration), so
    /// callers must run it off the reactor thread.
    fn handshake(&self, stream: TcpStream, peer: SocketAddr) -> io::Result<Option<RealityServerConn>> {
        let fd = stream.into_raw_fd(); // ownership passes to Go
        let (mut out_fd, mut err) = (0i32, [0 as c_char; 256]);
        let handle = unsafe {
            gor_server_handshake(self.server_handle, fd, &mut out_fd, err.as_mut_ptr(), 256)
        };
        if handle == GOR_FALLBACK {
            return Ok(None); // probe: Go handled it (relayed to dest)
        }
        if handle < 0 {
            return Err(io::Error::other(format!(
                "reality server handshake failed: {}",
                take_err(&err)
            )));
        }
        Ok(Some(RealityServerConn {
            carrier: Carrier::new(out_fd, handle),
            peer,
        }))
    }

    fn pollfd(&self) -> RawFd {
        self.pollfd()
    }

    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.set_nonblocking(nonblocking)
    }
}

impl Drop for RealityServerListener {
    fn drop(&mut self) {
        // Unlike Carrier's handle (a live connection), server_handle only owns
        // a Go-side *reality.Config (private key + server names) — but it still
        // occupies an entry in the Go handles map until released, so every
        // bind() without this leaks that entry (and the private key bytes) for
        // the life of the process.
        unsafe { gor_close(self.server_handle) };
    }
}

// Needs `gor_test_start_tls_dest`, which only exists in the archive when
// built with `--features reality-test-support` (see native/goreality/testdest.go
// and build.rs) — plain `cargo test --features reality` skips this module.
#[cfg(all(test, feature = "reality-test-support"))]
mod tests {
    use super::*;
    use crate::transport::StreamServerListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    extern "C" {
        fn gor_test_start_tls_dest() -> i32;
    }

    // Drives a real REALITY tunnel through the FFI carrier: a Go TLS server as
    // Dest, the Go server (RealityServerListener) and the ported Go client
    // (RealityClientTransport) authenticate, and a framed datagram crosses.
    fn drive_tunnel(server_priv: &[u8; 32], client_pub: &[u8; 32]) {
        // Dest: throwaway Go TLS server (accepts the mirrored uTLS ClientHello).
        let dest_port = unsafe { gor_test_start_tls_dest() };
        assert!(dest_port > 0, "failed to start test TLS dest");
        let dest_addr = format!("127.0.0.1:{dest_port}");

        let short_hex = "0123456789abcdef";
        let short_id = twocha_core::crypto::reality::parse_short_id(short_hex).unwrap();

        let server = RealityServerListener::bind(
            "127.0.0.1:0",
            server_priv,
            &dest_addr,
            &["example.com".to_string()],
            &[short_hex.to_string()],
            0,
        )
        .unwrap();
        let server_addr = server.local_addr().unwrap();

        let (tx, rx) = mpsc::channel();
        let srv = thread::spawn(move || {
            let mut conn = loop {
                if let Some((stream, peer)) = server.accept_raw().unwrap() {
                    if let Some(c) = server.handshake(stream, peer).unwrap() {
                        break c;
                    }
                }
            };
            let mut out = Vec::new();
            while !conn.recv(&mut out).unwrap() {}
            tx.send(out).unwrap();
        });

        let mut client = RealityClientTransport::connect(
            server_addr,
            "example.com",
            client_pub,
            &short_id,
            "chrome",
        )
        .unwrap();
        client.send(b"reality-carrier-payload").unwrap();

        let got = rx
            .recv_timeout(Duration::from_secs(20))
            .expect("server recv timed out");
        assert_eq!(got, b"reality-carrier-payload");
        srv.join().unwrap();
    }

    #[test]
    fn reality_tunnel_roundtrip() {
        // Keypair from twocha-core's X25519 `Identity` — the exact path `2cha
        // reality-keygen` and the config use (private_key_file + base64 public_key).
        // Proves x25519-dalek keys interoperate with the Go REALITY ECDH.
        let identity = twocha_core::Identity::generate();
        let priv_k: [u8; 32] = *identity.private_bytes();
        let pub_k = twocha_core::decode_public_key(&identity.public_base64()).unwrap();

        // Retry a bounded number of times: there is a rare (~1 in 10), known
        // upstream race where reality.Server() completes the handshake
        // cleanly (traced identically on pass and fail via reality.Config.Show)
        // but the very first post-handshake relay read/write then fails with
        // UnexpectedEof/BrokenPipe. It reproduces inside the vendored
        // xtls/reality/uTLS TLS 1.3 internals immediately after handshake, not
        // in this crate's own code — see docs/reality-go-design.md's risk
        // register. Real deployments have natural client/server timing gaps
        // this synthetic zero-latency test doesn't, so retrying here trades a
        // CI-only flake for a real (if rare) upstream timing artifact rather
        // than papering over an actual bug in code we own.
        const ATTEMPTS: u32 = 3;
        let mut last_err = None;
        for attempt in 1..=ATTEMPTS {
            match std::panic::catch_unwind(|| drive_tunnel(&priv_k, &pub_k)) {
                Ok(()) => return,
                Err(e) => {
                    eprintln!(
                        "reality_tunnel_roundtrip: attempt {attempt}/{ATTEMPTS} failed, retrying"
                    );
                    last_err = Some(e);
                }
            }
        }
        std::panic::resume_unwind(last_err.unwrap());
    }
}
