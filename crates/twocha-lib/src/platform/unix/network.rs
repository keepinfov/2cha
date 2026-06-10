//! # Network Module (Unix)
//!
//! Plain UDP transport plus a poll-based event loop. All encryption and
//! session state lives in the v4 protocol engine (`twocha_core::v4`); this
//! layer only moves datagrams.

use std::net::{SocketAddr, UdpSocket};
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::Duration;
use twocha_protocol::{NetworkError, Result, MAX_PACKET_SIZE};

/// Tunnel configuration
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub local_addr: SocketAddr,
    pub remote_addr: Option<SocketAddr>,
    pub read_timeout: Option<Duration>,
    pub write_timeout: Option<Duration>,
    pub recv_buffer_size: usize,
    pub send_buffer_size: usize,
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

        let socket = UdpSocket::bind(config.local_addr)
            .map_err(|e| NetworkError::BindFailed(e.to_string()))?;

        socket.set_read_timeout(config.read_timeout)?;
        socket.set_write_timeout(config.write_timeout)?;

        Self::set_socket_buffers(&socket, config.recv_buffer_size, config.send_buffer_size);

        Ok(UdpTunnel {
            socket,
            config,
            recv_buffer: vec![0u8; MAX_PACKET_SIZE],
        })
    }

    fn set_socket_buffers(socket: &UdpSocket, recv_size: usize, send_size: usize) {
        let fd = socket.as_raw_fd();

        unsafe {
            let recv_size = recv_size as libc::c_int;
            let send_size = send_size as libc::c_int;

            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &recv_size as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );

            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &send_size as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    #[inline]
    pub fn fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }

    /// Send a complete datagram to `addr`
    pub fn send_to(&self, datagram: &[u8], addr: SocketAddr) -> Result<usize> {
        let sent = self.socket.send_to(datagram, addr)?;
        log::trace!("Sent {} bytes to {}", sent, addr);
        Ok(sent)
    }

    /// Receive a datagram from any source
    pub fn recv_from_any(&mut self) -> Result<Option<(SocketAddr, Vec<u8>)>> {
        match self.socket.recv_from(&mut self.recv_buffer) {
            Ok((len, src)) => {
                log::trace!("Received {} bytes from {}", len, src);
                Ok(Some((src, self.recv_buffer[..len].to_vec())))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Ok(None),
            Err(e) => Err(e.into()),
        }
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
                    libc::MSG_DONTWAIT,
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
                batch.srcs[i] = decode_sockaddr(&batch.addrs[i]);
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
                    batch.srcs[i] = Some(src);
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
            bufs: vec![vec![0u8; MAX_PACKET_SIZE]; n],
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

    /// Datagram `i` of the last `recv_batch` (None if the source address
    /// could not be decoded).
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

/// Check if error is "would block"
#[inline]
pub fn is_would_block(e: &twocha_protocol::VpnError) -> bool {
    let s = e.to_string();
    s.contains("WouldBlock")
        || s.contains("temporarily unavailable")
        || s.contains("os error 11")
        || s.contains("Resource temporarily unavailable")
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
