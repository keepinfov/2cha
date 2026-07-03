//! # Network Module (Unix)
//!
//! Plain UDP transport plus a poll-based event loop. All encryption and
//! session state lives in the v4 protocol engine (`twocha_core::v4`); this
//! layer only moves datagrams.

use std::net::{SocketAddr, UdpSocket};
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::Duration;
use twocha_protocol::{NetworkError, Result};

/// Receive buffer size per datagram. Deliberately larger than
/// `MAX_PACKET_SIZE` (1500): a datagram that fills the buffer (or carries
/// `MSG_TRUNC`) was truncated by the kernel and must be dropped, not fed to
/// the AEAD where it would fail authentication and be miscounted as an
/// attack. The headroom also tolerates pre-padding-cap peers whose datagrams
/// could reach 1519 bytes.
const RECV_BUF_LEN: usize = 2048;

/// Rate-limited (1/s) warning for truncated datagrams so a flood of
/// oversized packets cannot spam the log.
fn warn_truncated(len: usize, src: Option<SocketAddr>) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST_WARN_SECS: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let last = LAST_WARN_SECS.load(Ordering::Relaxed);
    if now != last
        && LAST_WARN_SECS
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        match src {
            Some(src) => log::warn!(
                "dropping truncated datagram (>= {} bytes) from {}",
                len,
                src
            ),
            None => log::warn!("dropping truncated datagram (>= {} bytes)", len),
        }
    }
}

/// Tunnel configuration
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub local_addr: SocketAddr,
    pub remote_addr: Option<SocketAddr>,
    pub read_timeout: Option<Duration>,
    pub write_timeout: Option<Duration>,
    pub recv_buffer_size: usize,
    pub send_buffer_size: usize,
    /// Bind with SO_REUSEPORT so several worker sockets share one listen
    /// address; the kernel then hashes each client's 4-tuple to a fixed
    /// socket, keeping a client's datagrams on one worker.
    pub reuse_port: bool,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        TunnelConfig {
            local_addr: SocketAddr::from(([0, 0, 0, 0], 51820)),
            remote_addr: None,
            read_timeout: Some(Duration::from_millis(100)),
            write_timeout: Some(Duration::from_secs(5)),
            recv_buffer_size: 2 * 1024 * 1024,
            send_buffer_size: 2 * 1024 * 1024,
            reuse_port: false,
        }
    }
}

/// UDP socket wrapper for VPN traffic
pub struct UdpTunnel {
    socket: UdpSocket,
    config: TunnelConfig,
    recv_buffer: Vec<u8>,
}

impl UdpTunnel {
    pub fn new(config: TunnelConfig) -> Result<Self> {
        log::info!("Creating UDP tunnel on {}", config.local_addr);

        let socket = if config.reuse_port {
            Self::bind_reuseport(config.local_addr)?
        } else {
            UdpSocket::bind(config.local_addr)
                .map_err(|e| NetworkError::BindFailed(e.to_string()))?
        };

        socket.set_read_timeout(config.read_timeout)?;
        socket.set_write_timeout(config.write_timeout)?;

        Self::set_socket_buffers(&socket, config.recv_buffer_size, config.send_buffer_size);

        Ok(UdpTunnel {
            socket,
            config,
            recv_buffer: vec![0u8; RECV_BUF_LEN],
        })
    }

    /// Bind with SO_REUSEPORT set before bind (requires building the socket
    /// via socket2; std's UdpSocket::bind can't set options pre-bind).
    fn bind_reuseport(addr: SocketAddr) -> Result<UdpSocket> {
        let domain = if addr.is_ipv6() {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        };
        let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
            .map_err(|e| NetworkError::BindFailed(e.to_string()))?;
        sock.set_reuse_port(true)
            .map_err(|e| NetworkError::BindFailed(format!("SO_REUSEPORT: {}", e)))?;
        sock.bind(&addr.into())
            .map_err(|e| NetworkError::BindFailed(e.to_string()))?;
        Ok(sock.into())
    }

    fn set_socket_buffers(socket: &UdpSocket, recv_size: usize, send_size: usize) {
        // socket2 borrows the std socket's fd and returns a checked Result, so
        // a failed SO_RCVBUF/SO_SNDBUF is logged instead of silently ignored.
        let sock = socket2::SockRef::from(socket);
        if let Err(e) = sock.set_recv_buffer_size(recv_size) {
            log::warn!("failed to set SO_RCVBUF to {}: {}", recv_size, e);
        }
        if let Err(e) = sock.set_send_buffer_size(send_size) {
            log::warn!("failed to set SO_SNDBUF to {}: {}", send_size, e);
        }
    }

    #[inline]
    pub fn fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }

    /// The actual local address the socket is bound to (resolves the ephemeral
    /// port when the config requested port 0).
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    /// Send a complete datagram to `addr`
    pub fn send_to(&self, datagram: &[u8], addr: SocketAddr) -> Result<usize> {
        let sent = self.socket.send_to(datagram, addr)?;
        log::trace!("Sent {} bytes to {}", sent, addr);
        Ok(sent)
    }

    /// Receive a datagram from any source into `out`, reusing its allocation.
    /// Returns the source address, or `None` when the socket would block (or
    /// the datagram was truncated and dropped).
    pub fn recv_into(&mut self, out: &mut Vec<u8>) -> Result<Option<SocketAddr>> {
        match self.socket.recv_from(&mut self.recv_buffer) {
            Ok((len, src)) => {
                // A datagram that fills the whole buffer was (very likely)
                // truncated by the kernel; decrypting it would only produce
                // an AEAD failure. Drop it here with a diagnosable warning.
                if len == self.recv_buffer.len() {
                    warn_truncated(len, Some(src));
                    return Ok(None);
                }
                log::trace!("Received {} bytes from {}", len, src);
                out.clear();
                out.extend_from_slice(&self.recv_buffer[..len]);
                Ok(Some(src))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Receive a datagram from any source (allocating convenience wrapper
    /// over [`UdpTunnel::recv_into`]).
    pub fn recv_from_any(&mut self) -> Result<Option<(SocketAddr, Vec<u8>)>> {
        let mut out = Vec::new();
        Ok(self.recv_into(&mut out)?.map(|src| (src, out)))
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        self.socket.set_nonblocking(nonblocking)?;
        Ok(())
    }

    pub fn config(&self) -> &TunnelConfig {
        &self.config
    }

    /// Receive up to `batch.capacity()` datagrams in one syscall (Linux).
    /// Returns the number received; 0 means the socket would block.
    #[cfg(target_os = "linux")]
    pub fn recv_batch(&self, batch: &mut BatchBuffer) -> Result<usize> {
        batch.count = 0;
        let n = batch.capacity();
        for i in 0..n {
            batch.iovecs[i] = libc::iovec {
                iov_base: batch.bufs[i].as_mut_ptr() as *mut libc::c_void,
                iov_len: batch.bufs[i].len(),
            };
            let hdr = &mut batch.hdrs[i];
            hdr.msg_len = 0;
            hdr.msg_hdr = unsafe { std::mem::zeroed() };
            hdr.msg_hdr.msg_name = &mut batch.addrs[i] as *mut _ as *mut libc::c_void;
            hdr.msg_hdr.msg_namelen =
                std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            hdr.msg_hdr.msg_iov = &mut batch.iovecs[i];
            hdr.msg_hdr.msg_iovlen = 1;
        }

        loop {
            let r = unsafe {
                libc::recvmmsg(
                    self.fd(),
                    batch.hdrs.as_mut_ptr(),
                    n as libc::c_uint,
                    libc::MSG_DONTWAIT as _,
                    std::ptr::null_mut(),
                )
            };
            if r < 0 {
                let err = std::io::Error::last_os_error();
                match err.kind() {
                    std::io::ErrorKind::Interrupted => continue,
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => return Ok(0),
                    _ => return Err(err.into()),
                }
            }
            let r = r as usize;
            for i in 0..r {
                batch.lens[i] = batch.hdrs[i].msg_len as usize;
                // Kernel flags a datagram larger than our buffer with
                // MSG_TRUNC: mark the slot skipped (`get` returns None)
                // instead of handing garbage to the AEAD.
                if batch.hdrs[i].msg_hdr.msg_flags & libc::MSG_TRUNC != 0 {
                    warn_truncated(batch.lens[i], decode_sockaddr(&batch.addrs[i]));
                    batch.srcs[i] = None;
                } else {
                    batch.srcs[i] = decode_sockaddr(&batch.addrs[i]);
                }
            }
            batch.count = r;
            return Ok(r);
        }
    }

    /// Fallback for non-Linux unix: drain the socket one datagram at a time.
    #[cfg(all(unix, not(target_os = "linux")))]
    pub fn recv_batch(&self, batch: &mut BatchBuffer) -> Result<usize> {
        batch.count = 0;
        while batch.count < batch.capacity() {
            let i = batch.count;
            match self.socket.recv_from(&mut batch.bufs[i]) {
                Ok((len, src)) => {
                    batch.lens[i] = len;
                    // No MSG_TRUNC via std: a datagram filling the whole
                    // buffer was (very likely) truncated — skip the slot.
                    if len == batch.bufs[i].len() {
                        warn_truncated(len, Some(src));
                        batch.srcs[i] = None;
                    } else {
                        batch.srcs[i] = Some(src);
                    }
                    batch.count += 1;
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break
                }
                Err(e) => {
                    if batch.count > 0 {
                        break;
                    }
                    return Err(e.into());
                }
            }
        }
        Ok(batch.count)
    }

    /// Send multiple datagrams in as few syscalls as possible (Linux).
    /// Returns the number actually handed to the kernel; under UDP semantics
    /// the rest are dropped (kernel send buffer full).
    #[cfg(target_os = "linux")]
    pub fn send_batch(&self, msgs: &[(Vec<u8>, SocketAddr)]) -> Result<usize> {
        if msgs.is_empty() {
            return Ok(0);
        }
        let mut addrs: Vec<(libc::sockaddr_storage, libc::socklen_t)> =
            msgs.iter().map(|(_, a)| encode_sockaddr(*a)).collect();
        let mut iovecs: Vec<libc::iovec> = msgs
            .iter()
            .map(|(data, _)| libc::iovec {
                iov_base: data.as_ptr() as *mut libc::c_void,
                iov_len: data.len(),
            })
            .collect();
        let mut hdrs: Vec<libc::mmsghdr> = Vec::with_capacity(msgs.len());
        for i in 0..msgs.len() {
            let mut hdr: libc::mmsghdr = unsafe { std::mem::zeroed() };
            hdr.msg_hdr.msg_name = &mut addrs[i].0 as *mut _ as *mut libc::c_void;
            hdr.msg_hdr.msg_namelen = addrs[i].1;
            hdr.msg_hdr.msg_iov = &mut iovecs[i];
            hdr.msg_hdr.msg_iovlen = 1;
            hdrs.push(hdr);
        }

        let mut sent = 0;
        while sent < msgs.len() {
            let r = unsafe {
                libc::sendmmsg(
                    self.fd(),
                    hdrs[sent..].as_mut_ptr(),
                    (msgs.len() - sent) as libc::c_uint,
                    0,
                )
            };
            if r < 0 {
                let err = std::io::Error::last_os_error();
                match err.kind() {
                    std::io::ErrorKind::Interrupted => continue,
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => break,
                    _ => {
                        // Unexpected error: fall back to per-datagram sends
                        for (data, addr) in &msgs[sent..] {
                            if self.socket.send_to(data, *addr).is_ok() {
                                sent += 1;
                            }
                        }
                        break;
                    }
                }
            }
            if r == 0 {
                break;
            }
            sent += r as usize;
        }
        Ok(sent)
    }

    /// Fallback for non-Linux unix: per-datagram sends.
    #[cfg(all(unix, not(target_os = "linux")))]
    pub fn send_batch(&self, msgs: &[(Vec<u8>, SocketAddr)]) -> Result<usize> {
        let mut sent = 0;
        for (data, addr) in msgs {
            if self.socket.send_to(data, *addr).is_ok() {
                sent += 1;
            }
        }
        Ok(sent)
    }

    /// Send multiple datagrams to a single fixed destination in as few
    /// syscalls as possible (client hot path: everything goes to the server).
    #[cfg(target_os = "linux")]
    pub fn send_batch_to(&self, datagrams: &[Vec<u8>], addr: SocketAddr) -> Result<usize> {
        if datagrams.is_empty() {
            return Ok(0);
        }
        let (mut storage, addr_len) = encode_sockaddr(addr);
        let mut iovecs: Vec<libc::iovec> = datagrams
            .iter()
            .map(|data| libc::iovec {
                iov_base: data.as_ptr() as *mut libc::c_void,
                iov_len: data.len(),
            })
            .collect();
        let mut hdrs: Vec<libc::mmsghdr> = Vec::with_capacity(datagrams.len());
        for iovec in iovecs.iter_mut() {
            let mut hdr: libc::mmsghdr = unsafe { std::mem::zeroed() };
            hdr.msg_hdr.msg_name = &mut storage as *mut _ as *mut libc::c_void;
            hdr.msg_hdr.msg_namelen = addr_len;
            hdr.msg_hdr.msg_iov = iovec;
            hdr.msg_hdr.msg_iovlen = 1;
            hdrs.push(hdr);
        }

        let mut sent = 0;
        while sent < datagrams.len() {
            let r = unsafe {
                libc::sendmmsg(
                    self.fd(),
                    hdrs[sent..].as_mut_ptr(),
                    (datagrams.len() - sent) as libc::c_uint,
                    0,
                )
            };
            if r < 0 {
                let err = std::io::Error::last_os_error();
                match err.kind() {
                    std::io::ErrorKind::Interrupted => continue,
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => break,
                    _ => {
                        // Unexpected error: fall back to per-datagram sends
                        for data in &datagrams[sent..] {
                            if self.socket.send_to(data, addr).is_ok() {
                                sent += 1;
                            }
                        }
                        break;
                    }
                }
            }
            if r == 0 {
                break;
            }
            sent += r as usize;
        }
        Ok(sent)
    }

    /// Fallback for non-Linux unix: per-datagram sends.
    #[cfg(all(unix, not(target_os = "linux")))]
    pub fn send_batch_to(&self, datagrams: &[Vec<u8>], addr: SocketAddr) -> Result<usize> {
        let mut sent = 0;
        for data in datagrams {
            if self.socket.send_to(data, addr).is_ok() {
                sent += 1;
            }
        }
        Ok(sent)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// BATCHED I/O
// ═══════════════════════════════════════════════════════════════════════════

/// Reusable receive buffers for batched UDP I/O — allocated once at startup.
pub struct BatchBuffer {
    bufs: Vec<Vec<u8>>,
    lens: Vec<usize>,
    srcs: Vec<Option<SocketAddr>>,
    count: usize,
    #[cfg(target_os = "linux")]
    addrs: Vec<libc::sockaddr_storage>,
    #[cfg(target_os = "linux")]
    iovecs: Vec<libc::iovec>,
    #[cfg(target_os = "linux")]
    hdrs: Vec<libc::mmsghdr>,
}

impl BatchBuffer {
    /// `batch_size` is clamped to 1..=64.
    pub fn new(batch_size: usize) -> Self {
        let n = batch_size.clamp(1, 64);
        BatchBuffer {
            bufs: vec![vec![0u8; RECV_BUF_LEN]; n],
            lens: vec![0; n],
            srcs: vec![None; n],
            count: 0,
            #[cfg(target_os = "linux")]
            addrs: vec![unsafe { std::mem::zeroed() }; n],
            #[cfg(target_os = "linux")]
            iovecs: vec![
                libc::iovec {
                    iov_base: std::ptr::null_mut(),
                    iov_len: 0,
                };
                n
            ],
            #[cfg(target_os = "linux")]
            hdrs: vec![unsafe { std::mem::zeroed() }; n],
        }
    }

    pub fn capacity(&self) -> usize {
        self.bufs.len()
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Reset for manual filling via [`BatchBuffer::push`].
    pub fn clear(&mut self) {
        self.count = 0;
    }

    /// Append a datagram copied from `data`, tagged with `src`. Returns false
    /// (without copying) when the batch is full or `data` exceeds a slot.
    /// Lets non-datagram transports satisfy batch-oriented callers.
    pub fn push(&mut self, src: SocketAddr, data: &[u8]) -> bool {
        if self.count >= self.capacity() || data.len() > self.bufs[self.count].len() {
            return false;
        }
        self.bufs[self.count][..data.len()].copy_from_slice(data);
        self.lens[self.count] = data.len();
        self.srcs[self.count] = Some(src);
        self.count += 1;
        true
    }

    /// Invalidate slot `i` so [`BatchBuffer::get`] skips it (e.g. a datagram
    /// from an unexpected source on a point-to-point path).
    pub fn skip(&mut self, i: usize) {
        if i < self.count {
            self.srcs[i] = None;
        }
    }

    /// Datagram `i` of the last `recv_batch` (None if the source address
    /// could not be decoded or the datagram was truncated and dropped).
    pub fn get(&self, i: usize) -> Option<(SocketAddr, &[u8])> {
        if i >= self.count {
            return None;
        }
        self.srcs[i].map(|src| (src, &self.bufs[i][..self.lens[i]]))
    }
}

#[cfg(target_os = "linux")]
fn decode_sockaddr(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let sin = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
            Some(SocketAddr::from((ip, u16::from_be(sin.sin_port))))
        }
        libc::AF_INET6 => {
            let sin6 = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            Some(
                std::net::SocketAddrV6::new(
                    ip,
                    u16::from_be(sin6.sin6_port),
                    sin6.sin6_flowinfo,
                    sin6.sin6_scope_id,
                )
                .into(),
            )
        }
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn encode_sockaddr(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        SocketAddr::V4(v4) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                std::ptr::write(&mut storage as *mut _ as *mut libc::sockaddr_in, sin);
            }
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(v6) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            unsafe {
                std::ptr::write(&mut storage as *mut _ as *mut libc::sockaddr_in6, sin6);
            }
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// EVENT LOOP
// ═══════════════════════════════════════════════════════════════════════════

/// Simple event loop using poll
pub struct EventLoop {
    poll_fds: Vec<libc::pollfd>,
}

impl EventLoop {
    pub fn new() -> Self {
        EventLoop {
            poll_fds: Vec::new(),
        }
    }

    pub fn add_fd(&mut self, fd: RawFd, events: i16) {
        self.poll_fds.push(libc::pollfd {
            fd,
            events,
            revents: 0,
        });
    }

    #[allow(dead_code)]
    pub fn remove_fd(&mut self, fd: RawFd) {
        self.poll_fds.retain(|pfd| pfd.fd != fd);
    }

    pub fn poll(&mut self, timeout_ms: i32) -> Result<Vec<(RawFd, i16)>> {
        let result = unsafe {
            libc::poll(
                self.poll_fds.as_mut_ptr(),
                self.poll_fds.len() as libc::nfds_t,
                timeout_ms,
            )
        };

        if result < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        let mut events = Vec::new();
        for pfd in &self.poll_fds {
            if pfd.revents != 0 {
                events.push((pfd.fd, pfd.revents));
            }
        }

        for pfd in &mut self.poll_fds {
            pfd.revents = 0;
        }

        Ok(events)
    }
}

impl Default for EventLoop {
    fn default() -> Self {
        Self::new()
    }
}

// Poll constants
pub const POLLIN: i16 = libc::POLLIN;
#[allow(dead_code)]
pub const POLLOUT: i16 = libc::POLLOUT;
#[allow(dead_code)]
pub const POLLERR: i16 = libc::POLLERR;
#[allow(dead_code)]
pub const POLLHUP: i16 = libc::POLLHUP;

/// Check if an error means "no data right now" (the socket/fd would block or a
/// read timeout elapsed). Matches on the error's structured kind rather than
/// its display text, which is both faster and robust to locale/format changes.
#[inline]
pub fn is_would_block(e: &twocha_protocol::VpnError) -> bool {
    use twocha_protocol::{NetworkError, VpnError};
    match e {
        VpnError::Io(io_err) => matches!(
            io_err.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
        VpnError::Network(NetworkError::WouldBlock) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tunnel_on_loopback() -> UdpTunnel {
        UdpTunnel::new(TunnelConfig {
            local_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            read_timeout: Some(Duration::from_millis(200)),
            ..Default::default()
        })
        .unwrap()
    }

    fn local_addr(t: &UdpTunnel) -> SocketAddr {
        t.socket.local_addr().unwrap()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_sockaddr_roundtrip() {
        for addr in [
            "127.0.0.1:51820".parse::<SocketAddr>().unwrap(),
            "[::1]:443".parse().unwrap(),
            "10.8.0.1:1".parse().unwrap(),
        ] {
            let (storage, _) = encode_sockaddr(addr);
            assert_eq!(decode_sockaddr(&storage), Some(addr));
        }
    }

    #[test]
    fn test_is_would_block() {
        use std::io;
        use twocha_protocol::{NetworkError, VpnError};

        assert!(is_would_block(&VpnError::Io(io::Error::from(
            io::ErrorKind::WouldBlock
        ))));
        assert!(is_would_block(&VpnError::Io(io::Error::from(
            io::ErrorKind::TimedOut
        ))));
        assert!(is_would_block(&VpnError::Network(NetworkError::WouldBlock)));
        // Unrelated errors must not be misclassified — the old string match
        // treated anything containing "os error 11" as would-block.
        assert!(!is_would_block(&VpnError::Io(io::Error::from(
            io::ErrorKind::ConnectionReset
        ))));
        assert!(!is_would_block(&VpnError::Config("os error 11".into())));
        assert!(!is_would_block(&VpnError::Network(NetworkError::Timeout)));
    }

    #[test]
    fn test_batch_buffer_clamp() {
        assert_eq!(BatchBuffer::new(0).capacity(), 1);
        assert_eq!(BatchBuffer::new(32).capacity(), 32);
        assert_eq!(BatchBuffer::new(1000).capacity(), 64);
    }

    #[test]
    fn test_recv_batch_roundtrip() {
        let sender = tunnel_on_loopback();
        let receiver = tunnel_on_loopback();
        receiver.set_nonblocking(true).unwrap();
        let dst = local_addr(&receiver);

        for payload in [b"one".as_slice(), b"two", b"three"] {
            sender.send_to(payload, dst).unwrap();
        }
        // Give the loopback a moment to deliver
        std::thread::sleep(Duration::from_millis(50));

        let mut batch = BatchBuffer::new(8);
        let n = receiver.recv_batch(&mut batch).unwrap();
        assert_eq!(n, 3);
        let (src, data) = batch.get(0).unwrap();
        assert_eq!(src, local_addr(&sender));
        assert_eq!(data, b"one");
        assert_eq!(batch.get(2).unwrap().1, b"three");
        assert!(batch.get(3).is_none());

        // Drained socket: next call reports 0, not an error
        assert_eq!(receiver.recv_batch(&mut batch).unwrap(), 0);
    }

    #[test]
    fn test_recv_batch_skips_truncated_datagram() {
        let sender = tunnel_on_loopback();
        let receiver = tunnel_on_loopback();
        receiver.set_nonblocking(true).unwrap();
        let dst = local_addr(&receiver);

        sender.send_to(b"before", dst).unwrap();
        // Larger than RECV_BUF_LEN: the kernel truncates it on delivery
        sender
            .send_to(&vec![0xEEu8; RECV_BUF_LEN + 500], dst)
            .unwrap();
        sender.send_to(b"after", dst).unwrap();
        std::thread::sleep(Duration::from_millis(50));

        let mut batch = BatchBuffer::new(8);
        let n = receiver.recv_batch(&mut batch).unwrap();
        assert_eq!(n, 3);
        assert_eq!(batch.get(0).unwrap().1, b"before");
        assert!(batch.get(1).is_none(), "truncated slot must be skipped");
        assert_eq!(batch.get(2).unwrap().1, b"after");
    }

    #[test]
    fn test_recv_from_any_drops_truncated_datagram() {
        let sender = tunnel_on_loopback();
        let mut receiver = tunnel_on_loopback();
        let dst = local_addr(&receiver);

        sender
            .send_to(&vec![0xEEu8; RECV_BUF_LEN + 500], dst)
            .unwrap();
        sender.send_to(b"ok", dst).unwrap();
        std::thread::sleep(Duration::from_millis(50));

        // Truncated datagram is swallowed (reported as no-data), the intact
        // one arrives next.
        assert!(receiver.recv_from_any().unwrap().is_none());
        let (_, data) = receiver.recv_from_any().unwrap().unwrap();
        assert_eq!(data, b"ok");
    }

    #[test]
    fn test_send_batch_roundtrip() {
        let sender = tunnel_on_loopback();
        let receiver = tunnel_on_loopback();
        receiver.set_nonblocking(true).unwrap();
        let dst = local_addr(&receiver);

        let msgs: Vec<(Vec<u8>, SocketAddr)> = (0..5u8)
            .map(|i| (vec![i; (i as usize + 1) * 10], dst))
            .collect();
        assert_eq!(sender.send_batch(&msgs).unwrap(), 5);
        std::thread::sleep(Duration::from_millis(50));

        let mut batch = BatchBuffer::new(16);
        let n = receiver.recv_batch(&mut batch).unwrap();
        assert_eq!(n, 5);
        for i in 0..5usize {
            let (_, data) = batch.get(i).unwrap();
            assert_eq!(data, &vec![i as u8; (i + 1) * 10][..]);
        }
    }
}
