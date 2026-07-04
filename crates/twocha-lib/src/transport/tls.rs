//! # TLS-over-TCP carrier
//!
//! Tunnels complete v4 wire datagrams length-prefixed inside a *real* TLS 1.3
//! session over TCP. A passive or active observer sees a genuine TLS handshake
//! (ServerHello, certificate, Finished); the Noise_IK handshake and every byte
//! of authentication ride *inside* the TLS app-data stream.
//!
//! ## Why we accept any server certificate
//!
//! The client uses a certificate verifier that accepts any presented chain
//! ([`AcceptAnyServerCert`]). This is **intentional and safe in this design**:
//! TLS here is purely an obfuscation envelope to defeat DPI, not the trust
//! anchor. All peer authentication is performed by the Noise_IK handshake that
//! runs *inside* the tunnel using pre-shared static public keys. A
//! man-in-the-middle who terminates TLS still cannot complete Noise_IK without
//! the server's static private key, so the tunnel fails closed. Pinning the
//! TLS cert would add nothing and would leak a stable fingerprint.
//!
//! ## REALITY-readiness seam
//!
//! The server path is structured so a future REALITY-style gate can slot in
//! between `accept()` and the Noise handshake: inspect the ClientHello, and for
//! unauthenticated probes transparently proxy to a real backend while borrowing
//! its certificate. See [`TlsServerListener::accept`] for the hook point. The
//! actual REALITY/uTLS work is deferred (tracked as future work) pending a
//! mature uTLS-equivalent in Rust.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, Connection, ServerConfig, ServerConnection};

use super::{ClientTransport, FrameBuf};

/// Certificate verifier that accepts any server certificate. See the module
/// docs for why this is safe here: Noise_IK inside the tunnel is the real trust
/// anchor; TLS is only a DPI-evasion envelope.
#[derive(Debug)]
struct AcceptAnyServerCert {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Shared TLS app-data carrier: drives a rustls connection over a TcpStream and
/// frames v4 datagrams (`u16`-BE length prefix) inside the encrypted stream.
struct TlsCarrier {
    sock: TcpStream,
    conn: Connection,
    /// Decrypted plaintext awaiting reassembly into complete frames.
    inbuf: FrameBuf,
}

impl TlsCarrier {
    /// Run the TLS handshake to completion in blocking mode, then return a
    /// carrier ready to be switched to non-blocking for the poll loop.
    fn handshake(mut sock: TcpStream, mut conn: Connection) -> io::Result<Self> {
        sock.set_nonblocking(false)?;
        while conn.is_handshaking() {
            conn.complete_io(&mut sock).map_err(io::Error::other)?;
        }
        Ok(TlsCarrier {
            sock,
            conn,
            inbuf: FrameBuf::new(),
        })
    }

    /// Push whatever TLS records rustls has queued out to the socket. In
    /// non-blocking mode a partial write is fine: rustls retains the unsent
    /// bytes and we flush again on the next call.
    fn flush(&mut self) -> io::Result<()> {
        while self.conn.wants_write() {
            match self.conn.write_tls(&mut self.sock) {
                Ok(0) => break,
                Ok(_) => continue,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn send(&mut self, datagram: &[u8]) -> io::Result<()> {
        if datagram.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "datagram exceeds u16 frame length",
            ));
        }
        // rustls' writer buffers plaintext internally, so writing the header
        // and body separately costs no extra copy of the datagram.
        let header = (datagram.len() as u16).to_be_bytes();
        let mut writer = self.conn.writer();
        writer.write_all(&header)?;
        writer.write_all(datagram)?;
        self.flush()
    }

    /// Move any plaintext rustls has already decrypted into the reassembly
    /// buffer, and push out any records the TLS layer owes the peer (session
    /// tickets, key updates) so the connection stays healthy.
    fn drain_plaintext(&mut self) -> io::Result<()> {
        let state = self
            .conn
            .process_new_packets()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let pending = state.plaintext_bytes_to_read();
        if pending > 0 {
            self.conn
                .reader()
                .read_exact(self.inbuf.make_room(pending))?;
        }
        if self.conn.wants_write() {
            self.flush()?;
        }
        Ok(())
    }

    fn recv(&mut self, out: &mut Vec<u8>) -> io::Result<bool> {
        if self.inbuf.pop_frame_into(out) {
            return Ok(true);
        }
        // Drain plaintext already buffered inside rustls BEFORE polling the
        // socket: the blocking handshake's `complete_io` can pull the peer's
        // first app-data records in the same TCP segment as its final
        // handshake flight, and a socket-first loop would strand that data
        // (invisible to poll) until the peer happens to send more.
        self.drain_plaintext()?;
        // In non-blocking mode `read_tls` returns WouldBlock when the socket is
        // merely drained, so `Ok(0)` genuinely means the peer closed the TCP
        // connection (EOF). We surface that as an error so the poll loop can
        // reap the dead connection instead of spinning on a readable-at-EOF fd.
        let mut eof = false;
        loop {
            match self.conn.read_tls(&mut self.sock) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(_) => {}
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
            self.drain_plaintext()?;
        }
        // Drain any frame we did manage to reassemble before reporting EOF, so
        // the last bytes before a close are never lost.
        if self.inbuf.pop_frame_into(out) {
            return Ok(true);
        }
        if eof {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        Ok(false)
    }
}

/// Client-side TLS carrier to one server.
pub struct TlsClientTransport {
    carrier: TlsCarrier,
}

impl TlsClientTransport {
    /// Connect to `addr`, perform a real TLS 1.3 handshake presenting `sni` as
    /// the server name, and return a carrier ready for the poll loop. The TCP
    /// connect and TLS handshake are blocking; the caller switches to
    /// non-blocking via [`ClientTransport::set_nonblocking`].
    pub fn connect<A: ToSocketAddrs>(addr: A, sni: &str) -> io::Result<Self> {
        let provider = Arc::new(ring::default_provider());
        let config = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert { provider }))
            .with_no_client_auth();

        let server_name = ServerName::try_from(sni.to_owned())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let conn =
            ClientConnection::new(Arc::new(config), server_name).map_err(io::Error::other)?;

        let sock = TcpStream::connect(addr)?;
        sock.set_nodelay(true)?;
        let carrier = TlsCarrier::handshake(sock, Connection::Client(conn))?;
        Ok(TlsClientTransport { carrier })
    }
}

impl ClientTransport for TlsClientTransport {
    fn send(&mut self, datagram: &[u8]) -> io::Result<()> {
        self.carrier.send(datagram)
    }

    fn recv(&mut self, out: &mut Vec<u8>) -> io::Result<bool> {
        self.carrier.recv(out)
    }

    fn pollfds(&self) -> Vec<RawFd> {
        vec![self.carrier.sock.as_raw_fd()]
    }

    fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        self.carrier.sock.set_nonblocking(nonblocking)
    }
}

/// One accepted + TLS-handshaked server-side connection. Carries v4 datagrams
/// to/from a single client. The server handler owns one of these per client and
/// registers [`TlsServerConn::pollfd`] in the event loop.
pub struct TlsServerConn {
    carrier: TlsCarrier,
    peer: std::net::SocketAddr,
}

impl TlsServerConn {
    pub fn send(&mut self, datagram: &[u8]) -> io::Result<()> {
        self.carrier.send(datagram)
    }

    pub fn recv(&mut self, out: &mut Vec<u8>) -> io::Result<bool> {
        self.carrier.recv(out)
    }

    pub fn pollfd(&self) -> RawFd {
        self.carrier.sock.as_raw_fd()
    }

    pub fn peer_addr(&self) -> std::net::SocketAddr {
        self.peer
    }

    pub fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        self.carrier.sock.set_nonblocking(nonblocking)
    }
}

/// Server-side TLS listener. Accepts TCP connections and performs a real TLS
/// handshake on each before handing back a per-client carrier.
pub struct TlsServerListener {
    listener: TcpListener,
    config: Arc<ServerConfig>,
}

impl TlsServerListener {
    /// Bind a listening TCP socket and build a TLS server config from a
    /// PEM-encoded certificate chain and PKCS#8 private key.
    pub fn bind<A: ToSocketAddrs>(addr: A, cert_pem: &[u8], key_pem: &[u8]) -> io::Result<Self> {
        let certs =
            rustls_pemfile::certs(&mut io::Cursor::new(cert_pem)).collect::<Result<Vec<_>, _>>()?;
        if certs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no certificates in PEM",
            ));
        }
        let key = rustls_pemfile::private_key(&mut io::Cursor::new(key_pem))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no private key in PEM"))?;
        Self::with_der(addr, certs, key)
    }

    /// Bind using a freshly generated in-memory self-signed certificate for
    /// `sni`. Convenient for deployments that do not supply their own cert; the
    /// cert is never trusted by the client anyway (Noise authenticates).
    pub fn bind_self_signed<A: ToSocketAddrs>(addr: A, sni: &str) -> io::Result<Self> {
        let key =
            rcgen::generate_simple_self_signed(vec![sni.to_owned()]).map_err(io::Error::other)?;
        let cert_der = key.cert.der().clone();
        let key_der = PrivatePkcs8KeyDer::from(key.key_pair.serialize_der());
        Self::with_der(addr, vec![cert_der], key_der.into())
    }

    fn with_der<A: ToSocketAddrs>(
        addr: A,
        certs: Vec<CertificateDer<'static>>,
        key: rustls::pki_types::PrivateKeyDer<'static>,
    ) -> io::Result<Self> {
        let provider = Arc::new(ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let listener = TcpListener::bind(addr)?;
        Ok(TlsServerListener {
            listener,
            config: Arc::new(config),
        })
    }

    /// File descriptor of the listening socket, for the poll loop.
    pub fn pollfd(&self) -> RawFd {
        self.listener.as_raw_fd()
    }

    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.listener.set_nonblocking(nonblocking)
    }

    /// Accept one pending connection and complete its TLS handshake. Returns
    /// `Ok(None)` if no connection is waiting (non-blocking listener).
    ///
    /// REALITY seam: this is where a future gate inspects the ClientHello and,
    /// for unauthenticated probes, proxies to a real backend instead of
    /// proceeding to Noise. Today every accepted TLS session proceeds.
    pub fn accept(&self) -> io::Result<Option<TlsServerConn>> {
        let (sock, peer) = match self.listener.accept() {
            Ok(pair) => pair,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) => return Err(e),
        };
        sock.set_nodelay(true)?;
        let conn = ServerConnection::new(self.config.clone()).map_err(io::Error::other)?;
        let carrier = TlsCarrier::handshake(sock, Connection::Server(conn))?;
        Ok(Some(TlsServerConn { carrier, peer }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::{Duration, Instant};

    /// Poll `f` until it yields a frame, yielding the CPU between attempts and
    /// giving up after `TEST_DEADLINE`. The busy-spin without a yield/timeout is
    /// what let this test wedge a (single-core) sandbox builder forever; bounding
    /// it turns a hang into a clear failure.
    fn poll_frame(label: &str, mut f: impl FnMut() -> io::Result<bool>) {
        const TEST_DEADLINE: Duration = Duration::from_secs(10);
        let start = Instant::now();
        loop {
            if f().unwrap() {
                return;
            }
            assert!(
                start.elapsed() < TEST_DEADLINE,
                "timed out waiting for {label}"
            );
            thread::yield_now();
        }
    }

    #[test]
    fn tls_loopback_roundtrip() {
        let listener = TlsServerListener::bind_self_signed("127.0.0.1:0", "example.com").unwrap();
        let addr = listener.listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            // Blocking accept + handshake, then drive non-blocking like the
            // real poll loop (recv() is designed to be polled, not blocked on).
            let mut conn = loop {
                if let Some(c) = listener.accept().unwrap() {
                    break c;
                }
            };
            conn.set_nonblocking(true).unwrap();
            // Echo two datagrams back.
            let mut out = Vec::new();
            for _ in 0..2 {
                poll_frame("server recv", || conn.recv(&mut out));
                conn.send(&out).unwrap();
            }
        });

        let mut client = TlsClientTransport::connect(addr, "example.com").unwrap();
        client.set_nonblocking(true).unwrap();

        let mut got = Vec::new();
        client.send(b"hello v4 datagram").unwrap();
        poll_frame("client recv (small)", || client.recv(&mut got));
        assert_eq!(got, b"hello v4 datagram");

        let big = vec![0xABu8; 1400];
        client.send(&big).unwrap();
        poll_frame("client recv (large)", || client.recv(&mut got));
        assert_eq!(got, big);

        server.join().unwrap();
    }
}
