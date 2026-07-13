//! # Network Module (Unix)
//!
//! Plain UDP transport plus a poll-based event loop. All encryption and
//! session state lives in the v4 protocol engine (`twocha_core::v4`); this
//! layer only moves datagrams.

use std::net::{SocketAddr, UdpSocket};
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::Duration;
use twocha_protocol::{NetworkError, Result};

// UDP GSO/GRO socket options. glibc's headers define these but the `libc` crate
// only exposes them for uclibc/android/l4re, so mirror the kernel values here
// (stable UAPI). `SOL_UDP` and the `CMSG_*` helpers come from `libc`. UDP GSO
// needs kernel >= 4.18, GRO >= 5.0; older kernels reject the cmsg/setsockopt and
// we fall back to the per-datagram path.
#[cfg(target_os = "linux")]
const UDP_SEGMENT: libc::c_int = 103;
#[cfg(target_os = "linux")]
const UDP_GRO: libc::c_int = 104;

/// Read the `UDP_GRO` receive control message from a `msghdr`: the segment size
/// the kernel used when coalescing a run of same-flow, same-size datagrams into
/// this buffer. Returns `None` when the message carries no such cmsg (i.e. the
/// buffer holds a single, non-coalesced datagram).
#[cfg(target_os = "linux")]
fn parse_gro_segment(msg: &libc::msghdr) -> Option<usize> {
    // SAFETY: `msg` is a fully-initialised msghdr whose control buffer (if any)
    // was filled by the kernel; the CMSG_* macros walk it within bounds.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_UDP && (*cmsg).cmsg_type == UDP_GRO {
                let mut seg: libc::c_int = 0;
                std::ptr::copy_nonoverlapping(
                    libc::CMSG_DATA(cmsg),
                    &mut seg as *mut _ as *mut u8,
                    std::mem::size_of::<libc::c_int>(),
                );
                return if seg > 0 { Some(seg as usize) } else { None };
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }
    None
}

/// Cap on datagrams coalesced into one GSO `sendmsg`. The kernel historically
/// limits a GSO super-buffer to 64 segments (`UDP_MAX_SEGMENTS`); staying at or
/// below that keeps a single `sendmsg` valid across kernels.
#[cfg(target_os = "linux")]
const MAX_GSO_SEGMENTS: usize = 64;

/// Maximal run of datagrams starting at `i` that can share one GSO `sendmsg`:
/// consecutive datagrams of exactly `seg` bytes, plus an optional single
/// shorter trailing datagram (the last GSO segment may be short). Bounded by
/// [`MAX_GSO_SEGMENTS`] and a 64 KiB aggregate. Returns `(end, total_bytes)`.
#[cfg(target_os = "linux")]
fn gso_run(payloads: &[&[u8]], i: usize, seg: usize) -> (usize, usize) {
    const GSO_MAX_BYTES: usize = 65535;
    let mut j = i;
    let mut total = 0usize;
    while j < payloads.len()
        && payloads[j].len() == seg
        && (j - i) < MAX_GSO_SEGMENTS
        && total + seg <= GSO_MAX_BYTES
    {
        total += seg;
        j += 1;
    }
    if j < payloads.len()
        && !payloads[j].is_empty()
        && payloads[j].len() < seg
        && (j - i) < MAX_GSO_SEGMENTS
        && total + payloads[j].len() <= GSO_MAX_BYTES
    {
        total += payloads[j].len();
        j += 1;
    }
    (j, total)
}

/// Invoke `f(start, len)` for each wire datagram inside a GRO-coalesced buffer
/// of `total` bytes whose segment size is `seg`: consecutive `seg`-byte chunks
/// with a possibly-shorter final chunk. A `seg` of 0 or `>= total` (i.e. not
/// actually coalesced) yields the whole buffer as one chunk; `total == 0`
/// yields nothing.
#[cfg(target_os = "linux")]
fn each_gro_segment(total: usize, seg: usize, mut f: impl FnMut(usize, usize)) {
    if total == 0 {
        return;
    }
    if seg == 0 || seg >= total {
        f(0, total);
        return;
    }
    let mut start = 0;
    while start < total {
        let len = seg.min(total - start);
        f(start, len);
        start += len;
    }
}

/// A GSO `sendmsg` failure meaning the kernel doesn't support UDP segmentation
/// (too old): disable GSO permanently and fall back to `sendmmsg`.
#[cfg(target_os = "linux")]
fn gso_unsupported(e: &std::io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::ENOPROTOOPT) | Some(libc::EOPNOTSUPP) | Some(libc::EIO) | Some(libc::EINVAL)
    )
}

/// Whether a raw I/O error is a transient "try again later".
#[cfg(target_os = "linux")]
fn is_wouldblock_io(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// Receive buffer size per datagram. Deliberately larger than
/// `MAX_PACKET_SIZE` (1500): a datagram that fills the buffer (or carries
/// `MSG_TRUNC`) was truncated by the kernel and must be dropped, not fed to
/// the AEAD where it would fail authentication and be miscounted as an
/// attack. The headroom also tolerates pre-padding-cap peers whose datagrams
/// could reach 1519 bytes.
const RECV_BUF_LEN: usize = 2048;

/// Upper bound on [`BatchBuffer`] capacity. Raised from the old hard cap of 64
/// so a throughput-tuned deployment can set a larger `performance.batch_size`
/// and amortize the batched-I/O syscall over more datagrams. At 1024 slots the
/// per-batch receive memory is 1024 * 2048 = 2 MiB.
const MAX_BATCH: usize = 1024;

/// Physical receive-slot size once a [`BatchBuffer`] is switched to GRO mode: a
/// `UDP_GRO`-coalesced super-datagram can be up to 64 KiB, which one `recvmmsg`
/// slot must hold before we split it into wire datagrams.
#[cfg(target_os = "linux")]
const GRO_BUF_LEN: usize = 65535;

/// Cap on physical GRO receive slots, bounding a GRO-mode [`BatchBuffer`] to
/// `GRO_MAX_SLOTS * GRO_BUF_LEN` (~4 MiB). Coalescing means far fewer slots are
/// needed than the logical datagram count, so this rarely binds throughput.
#[cfg(target_os = "linux")]
const GRO_MAX_SLOTS: usize = 64;

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
    /// GSO send (UDP_SEGMENT) is probed lazily: it starts enabled on Linux and
    /// is disabled permanently the first time a GSO `sendmsg` reports the option
    /// is unsupported (old kernel), after which every send uses `sendmmsg`.
    #[cfg(target_os = "linux")]
    gso: std::sync::atomic::AtomicBool,
    /// Whether `UDP_GRO` was accepted on this socket (kernel >= 5.0). When true,
    /// receives read a per-message segment-size cmsg and split coalesced
    /// super-datagrams into individual wire datagrams.
    #[cfg(target_os = "linux")]
    gro: bool,
    /// Overflow from a GRO-coalesced [`UdpTunnel::recv_into`]: a single `recvmsg`
    /// can return several datagrams, so the extras are queued here and dispensed
    /// one per subsequent call. Only touched by `recv_into` (`&mut self`).
    #[cfg(target_os = "linux")]
    gro_pending: std::collections::VecDeque<(SocketAddr, Vec<u8>)>,
}

impl UdpTunnel {
    pub fn new(config: TunnelConfig) -> Result<Self> {
        Self::new_inner(config, true)
    }

    /// Construct a tunnel with kernel offload (GSO/GRO) forced off. Used by
    /// tests that must exercise the portable small-buffer path deterministically
    /// (GRO's 64 KiB buffers otherwise make single-datagram truncation
    /// impossible).
    #[cfg(test)]
    fn new_no_offload(config: TunnelConfig) -> Result<Self> {
        Self::new_inner(config, false)
    }

    fn new_inner(config: TunnelConfig, allow_offload: bool) -> Result<Self> {
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

        // Escape hatches (ops / testing): force the portable per-packet paths,
        // matching the TUN offload override.
        #[cfg(target_os = "linux")]
        let gso_enabled = allow_offload && std::env::var_os("TWOCHA_NO_UDP_GSO").is_none();
        #[cfg(target_os = "linux")]
        if allow_offload && !gso_enabled {
            log::info!("TWOCHA_NO_UDP_GSO set; UDP GSO disabled");
        }
        #[cfg(target_os = "linux")]
        let gro = if !allow_offload {
            false
        } else if std::env::var_os("TWOCHA_NO_UDP_GRO").is_some() {
            log::info!("TWOCHA_NO_UDP_GRO set; UDP GRO disabled");
            false
        } else {
            Self::enable_gro(&socket)
        };
        #[cfg(not(target_os = "linux"))]
        let _ = allow_offload;

        Ok(UdpTunnel {
            socket,
            // GRO can hand back a 64 KiB coalesced super-datagram on the
            // single-recv path, so size that scratch buffer accordingly.
            #[cfg(target_os = "linux")]
            recv_buffer: vec![0u8; if gro { GRO_BUF_LEN } else { RECV_BUF_LEN }],
            #[cfg(not(target_os = "linux"))]
            recv_buffer: vec![0u8; RECV_BUF_LEN],
            config,
            #[cfg(target_os = "linux")]
            gso: std::sync::atomic::AtomicBool::new(gso_enabled),
            #[cfg(target_os = "linux")]
            gro,
            #[cfg(target_os = "linux")]
            gro_pending: std::collections::VecDeque::new(),
        })
    }

    /// Enable `UDP_GRO` so the kernel coalesces same-flow, same-size datagram
    /// runs into fewer `recvmmsg` reads. Returns whether the option was accepted
    /// (kernel >= 5.0); `ENOPROTOOPT` on older kernels is not an error.
    #[cfg(target_os = "linux")]
    fn enable_gro(socket: &UdpSocket) -> bool {
        let on: libc::c_int = 1;
        let r = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_UDP,
                UDP_GRO,
                &on as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if r == 0 {
            log::debug!("UDP_GRO enabled");
            true
        } else {
            log::debug!(
                "UDP_GRO unavailable ({}); using per-datagram receive",
                std::io::Error::last_os_error()
            );
            false
        }
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
        // On a GRO socket a single `recvmsg` can return a coalesced run; the
        // extras are queued and dispensed one datagram per call.
        #[cfg(target_os = "linux")]
        if self.gro {
            return self.recv_into_gro(out);
        }
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

    /// GRO-aware single-datagram receive: drains one queued segment if present,
    /// otherwise does one `recvmsg`, reads the `UDP_GRO` segment-size cmsg, and
    /// splits a coalesced buffer — the first segment into `out`, the rest queued.
    #[cfg(target_os = "linux")]
    fn recv_into_gro(&mut self, out: &mut Vec<u8>) -> Result<Option<SocketAddr>> {
        if let Some((src, seg)) = self.gro_pending.pop_front() {
            out.clear();
            out.extend_from_slice(&seg);
            return Ok(Some(src));
        }

        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: self.recv_buffer.as_mut_ptr() as *mut libc::c_void,
            iov_len: self.recv_buffer.len(),
        };
        let mut cmsg_buf = [0u64; 4]; // 8-byte-aligned control storage
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = &mut storage as *mut _ as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = std::mem::size_of_val(&cmsg_buf) as _;

        let len = loop {
            let r = unsafe { libc::recvmsg(self.fd(), &mut msg, 0) };
            if r < 0 {
                let e = std::io::Error::last_os_error();
                match e.kind() {
                    std::io::ErrorKind::Interrupted => continue,
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                        return Ok(None)
                    }
                    _ => return Err(e.into()),
                }
            }
            break r as usize;
        };

        // `recvmsg` gives an authoritative MSG_TRUNC flag (unlike `recv_from`),
        // so trust it rather than the "filled the buffer" heuristic — a full
        // 64 KiB coalesced buffer is legitimate, not truncated.
        if msg.msg_flags & libc::MSG_TRUNC != 0 {
            warn_truncated(len, decode_sockaddr(&storage));
            return Ok(None);
        }
        let Some(src) = decode_sockaddr(&storage) else {
            return Ok(None);
        };

        let seg = parse_gro_segment(&msg);
        // Collect boundaries first so the copies below don't borrow `self`
        // twice (recv_buffer shared + gro_pending mutable).
        let mut chunks: Vec<(usize, usize)> = Vec::new();
        each_gro_segment(len, seg.unwrap_or(0), |start, clen| chunks.push((start, clen)));
        let Some(&(fstart, flen)) = chunks.first() else {
            return Ok(None); // len == 0
        };
        out.clear();
        out.extend_from_slice(&self.recv_buffer[fstart..fstart + flen]);
        for &(start, clen) in &chunks[1..] {
            self.gro_pending
                .push_back((src, self.recv_buffer[start..start + clen].to_vec()));
        }
        Ok(Some(src))
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

    /// Receive up to `batch.capacity()` reads in one `recvmmsg` (Linux), each
    /// producing one wire datagram — or, when a slot is a `UDP_GRO`-coalesced
    /// super-datagram, several. Returns the logical datagram count; 0 means the
    /// socket would block.
    #[cfg(target_os = "linux")]
    pub fn recv_batch(&self, batch: &mut BatchBuffer) -> Result<usize> {
        batch.views.clear();
        if self.gro {
            batch.ensure_gro_storage();
        }
        let n = batch.bufs.len();
        for i in 0..n {
            batch.iovecs[i] = libc::iovec {
                iov_base: batch.bufs[i].as_mut_ptr() as *mut libc::c_void,
                iov_len: batch.bufs[i].len(),
            };
            let ctrl_ptr = batch.ctrls[i].as_mut_ptr() as *mut libc::c_void;
            let ctrl_len = std::mem::size_of_val(&batch.ctrls[i]);
            let addr_ptr = &mut batch.addrs[i] as *mut _ as *mut libc::c_void;
            let iov_ptr = &mut batch.iovecs[i] as *mut libc::iovec;
            let hdr = &mut batch.hdrs[i];
            hdr.msg_len = 0;
            hdr.msg_hdr = unsafe { std::mem::zeroed() };
            hdr.msg_hdr.msg_name = addr_ptr;
            hdr.msg_hdr.msg_namelen =
                std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            hdr.msg_hdr.msg_iov = iov_ptr;
            hdr.msg_hdr.msg_iovlen = 1;
            if self.gro {
                hdr.msg_hdr.msg_control = ctrl_ptr;
                hdr.msg_hdr.msg_controllen = ctrl_len as _;
            }
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
                let len = batch.hdrs[i].msg_len as usize;
                // Kernel flags a datagram larger than our buffer with
                // MSG_TRUNC: record a skipped view (`get` returns None) instead
                // of feeding the AEAD garbage. (On a GRO socket the 64 KiB slots
                // make this unreachable — no single UDP datagram truncates.)
                if batch.hdrs[i].msg_hdr.msg_flags & libc::MSG_TRUNC != 0 {
                    warn_truncated(len, decode_sockaddr(&batch.addrs[i]));
                    batch.push_view(i, 0, len, None);
                    continue;
                }
                let src = decode_sockaddr(&batch.addrs[i]);
                // A GRO cmsg means this slot coalesced a run of equal-size
                // datagrams; split it back into one view per wire datagram.
                let seg = if self.gro {
                    parse_gro_segment(&batch.hdrs[i].msg_hdr)
                } else {
                    None
                };
                match seg {
                    Some(s) => each_gro_segment(len, s, |start, clen| {
                        batch.push_view(i, start, clen, src)
                    }),
                    None => batch.push_view(i, 0, len, src),
                }
            }
            return Ok(batch.views.len());
        }
    }

    /// Fallback for non-Linux unix: drain the socket one datagram at a time.
    #[cfg(all(unix, not(target_os = "linux")))]
    pub fn recv_batch(&self, batch: &mut BatchBuffer) -> Result<usize> {
        batch.views.clear();
        while batch.views.len() < batch.bufs.len() {
            let i = batch.views.len();
            match self.socket.recv_from(&mut batch.bufs[i]) {
                Ok((len, src)) => {
                    // No MSG_TRUNC via std: a datagram filling the whole
                    // buffer was (very likely) truncated — record it as a
                    // skipped view so indices stay contiguous.
                    if len == batch.bufs[i].len() {
                        warn_truncated(len, Some(src));
                        batch.push_view(i, 0, len, None);
                    } else {
                        batch.push_view(i, 0, len, Some(src));
                    }
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
                    if !batch.views.is_empty() {
                        break;
                    }
                    return Err(e.into());
                }
            }
        }
        Ok(batch.views.len())
    }

    /// Send multiple datagrams in as few syscalls as possible (Linux).
    /// Returns the number actually handed to the kernel; under UDP semantics
    /// the rest are dropped (kernel send buffer full).
    ///
    /// When GSO is available, consecutive datagrams to the *same* destination
    /// are grouped and equal-length runs within each group are segmented by the
    /// kernel in one `sendmsg` (the server download burst to a single client is
    /// exactly this shape); everything else uses `sendmmsg`.
    #[cfg(target_os = "linux")]
    pub fn send_batch(&self, msgs: &[(Vec<u8>, SocketAddr)]) -> Result<usize> {
        use std::sync::atomic::Ordering;
        if msgs.is_empty() {
            return Ok(0);
        }
        if !self.gso.load(Ordering::Relaxed) {
            return self.send_batch_mmsg(msgs);
        }
        let mut sent = 0;
        let mut i = 0;
        while i < msgs.len() {
            let addr = msgs[i].1;
            // Group the maximal run of consecutive datagrams to this address.
            let mut k = i + 1;
            while k < msgs.len() && msgs[k].1 == addr {
                k += 1;
            }
            let payloads: Vec<&[u8]> = msgs[i..k].iter().map(|(d, _)| d.as_slice()).collect();
            sent += self.gso_send_payloads(&payloads, addr)?;
            i = k;
        }
        Ok(sent)
    }

    /// `sendmmsg` fallback used when GSO is disabled or unavailable.
    #[cfg(target_os = "linux")]
    fn send_batch_mmsg(&self, msgs: &[(Vec<u8>, SocketAddr)]) -> Result<usize> {
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
    ///
    /// When UDP GSO is available, maximal runs of equal-length datagrams (plus
    /// an optional shorter trailing datagram) are handed to the kernel as a
    /// single `sendmsg` that segments them on the wire; the throughput-dominant
    /// full-MTU bulk flow is exactly such a run. Odd-sized datagrams and the
    /// fallback path use `sendmmsg`.
    #[cfg(target_os = "linux")]
    pub fn send_batch_to(&self, datagrams: &[Vec<u8>], addr: SocketAddr) -> Result<usize> {
        use std::sync::atomic::Ordering;
        if datagrams.is_empty() {
            return Ok(0);
        }
        if !self.gso.load(Ordering::Relaxed) {
            return self.send_batch_to_mmsg(datagrams, addr);
        }
        let payloads: Vec<&[u8]> = datagrams.iter().map(|d| d.as_slice()).collect();
        self.gso_send_payloads(&payloads, addr)
    }

    /// GSO grouping engine shared by [`UdpTunnel::send_batch_to`] and
    /// [`UdpTunnel::send_batch`]: all `payloads` go to `addr`; maximal
    /// equal-length runs (plus a shorter tail) are sent as one segmenting
    /// `sendmsg`, odd sizes as plain `send_to`. Assumes GSO is currently
    /// enabled; the first unsupported error disables it permanently.
    #[cfg(target_os = "linux")]
    fn gso_send_payloads(&self, payloads: &[&[u8]], addr: SocketAddr) -> Result<usize> {
        use std::sync::atomic::Ordering;
        let (storage, addr_len) = encode_sockaddr(addr);
        let mut sent = 0;
        let mut i = 0;
        while i < payloads.len() {
            let seg = payloads[i].len();
            // A GSO run needs a non-empty, u16-bounded segment size.
            if seg == 0 || seg > u16::MAX as usize {
                if self.socket.send_to(payloads[i], addr).is_ok() {
                    sent += 1;
                }
                i += 1;
                continue;
            }
            let (j, total) = gso_run(payloads, i, seg);
            if j - i >= 2 {
                let mut iovecs: Vec<libc::iovec> = payloads[i..j]
                    .iter()
                    .map(|d| libc::iovec {
                        iov_base: d.as_ptr() as *mut libc::c_void,
                        iov_len: d.len(),
                    })
                    .collect();
                match self.sendmsg_gso(&mut iovecs, seg as u16, &storage, addr_len) {
                    Ok(_) => {
                        log::trace!("GSO sent {} datagrams ({} bytes) to {}", j - i, total, addr);
                        sent += j - i;
                        i = j;
                        continue;
                    }
                    Err(e) if gso_unsupported(&e) => {
                        // Old kernel: disable GSO for the life of this socket. The
                        // remainder of this flush goes per-datagram; every later
                        // batch takes the `sendmmsg` path via the top-level guard.
                        log::info!("UDP GSO unsupported ({e}); falling back to sendmmsg");
                        self.gso.store(false, Ordering::Relaxed);
                        for d in &payloads[i..] {
                            if self.socket.send_to(d, addr).is_ok() {
                                sent += 1;
                            }
                        }
                        return Ok(sent);
                    }
                    Err(e) if is_wouldblock_io(&e) => break,
                    Err(_) => {
                        // Transient error on this run: per-datagram best effort.
                        for d in &payloads[i..j] {
                            if self.socket.send_to(d, addr).is_ok() {
                                sent += 1;
                            }
                        }
                        i = j;
                        continue;
                    }
                }
            } else {
                if self.socket.send_to(payloads[i], addr).is_ok() {
                    sent += 1;
                }
                i += 1;
            }
        }
        Ok(sent)
    }

    /// Low-level GSO `sendmsg`: gather `iovecs` into one datagram the kernel
    /// segments every `seg` bytes (the final segment may be shorter).
    #[cfg(target_os = "linux")]
    fn sendmsg_gso(
        &self,
        iovecs: &mut [libc::iovec],
        seg: u16,
        storage: &libc::sockaddr_storage,
        addr_len: libc::socklen_t,
    ) -> std::io::Result<usize> {
        // 8-byte-aligned control buffer large enough for one UDP_SEGMENT cmsg.
        let mut cmsg_buf = [0u64; 4];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = storage as *const _ as *mut libc::c_void;
        msg.msg_namelen = addr_len;
        msg.msg_iov = iovecs.as_mut_ptr();
        msg.msg_iovlen = iovecs.len() as _;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = std::mem::size_of_val(&cmsg_buf) as _;
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_UDP;
            (*cmsg).cmsg_type = UDP_SEGMENT;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as u32) as _;
            let seg_bytes = seg.to_ne_bytes();
            std::ptr::copy_nonoverlapping(seg_bytes.as_ptr(), libc::CMSG_DATA(cmsg), seg_bytes.len());
            msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) as _;
            loop {
                let r = libc::sendmsg(self.fd(), &msg, 0);
                if r < 0 {
                    let e = std::io::Error::last_os_error();
                    if e.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(e);
                }
                return Ok(r as usize);
            }
        }
    }

    /// `sendmmsg` fallback used when GSO is disabled or unavailable.
    #[cfg(target_os = "linux")]
    fn send_batch_to_mmsg(&self, datagrams: &[Vec<u8>], addr: SocketAddr) -> Result<usize> {
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

/// One logical wire datagram produced by a receive: the slice
/// `[start, start+len)` of physical slot `buf`, tagged with its source (`None`
/// once skipped/invalid). Under GRO one physical slot yields several views.
#[derive(Clone, Copy)]
struct View {
    buf: usize,
    start: usize,
    len: usize,
    src: Option<SocketAddr>,
}

/// Reusable receive buffers for batched UDP I/O — allocated once at startup.
pub struct BatchBuffer {
    /// Physical receive slots. One `recvmmsg`/`recv_from` fills each; under GRO
    /// a slot may hold a coalesced super-datagram that splits into many views.
    bufs: Vec<Vec<u8>>,
    /// Logical datagrams from the last receive (or `push`), indexing `bufs`.
    views: Vec<View>,
    /// Whether `bufs` were switched to `GRO_BUF_LEN` slots for coalesced reads.
    #[cfg(target_os = "linux")]
    gro_sized: bool,
    #[cfg(target_os = "linux")]
    addrs: Vec<libc::sockaddr_storage>,
    #[cfg(target_os = "linux")]
    iovecs: Vec<libc::iovec>,
    #[cfg(target_os = "linux")]
    hdrs: Vec<libc::mmsghdr>,
    /// Per-slot control buffers for the `UDP_GRO` segment-size cmsg (8-aligned;
    /// `[u64; 4]` = 32 bytes, comfortably above `CMSG_SPACE(size_of::<int>())`).
    #[cfg(target_os = "linux")]
    ctrls: Vec<[u64; 4]>,
}

impl BatchBuffer {
    /// `batch_size` is clamped to `1..=MAX_BATCH`, honoring the configured
    /// `performance.batch_size` (default 32). A larger batch amortizes the
    /// `recvmmsg`/`sendmmsg` syscall over more datagrams; the ceiling bounds the
    /// per-batch memory (`MAX_BATCH * RECV_BUF_LEN`).
    pub fn new(batch_size: usize) -> Self {
        let n = batch_size.clamp(1, MAX_BATCH);
        BatchBuffer {
            bufs: vec![vec![0u8; RECV_BUF_LEN]; n],
            views: Vec::with_capacity(n),
            #[cfg(target_os = "linux")]
            gro_sized: false,
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
            #[cfg(target_os = "linux")]
            ctrls: vec![[0u64; 4]; n],
        }
    }

    /// Number of physical receive slots (the `recvmmsg` vector length).
    pub fn capacity(&self) -> usize {
        self.bufs.len()
    }

    /// Number of logical datagrams currently held.
    pub fn len(&self) -> usize {
        self.views.len()
    }

    pub fn is_empty(&self) -> bool {
        self.views.is_empty()
    }

    /// Reset for manual filling via [`BatchBuffer::push`].
    pub fn clear(&mut self) {
        self.views.clear();
    }

    /// Append a datagram copied from `data`, tagged with `src`. Returns false
    /// (without copying) when the batch is full or `data` exceeds a slot.
    /// Lets non-datagram transports satisfy batch-oriented callers. (No GRO
    /// splitting: `push` maps one datagram to one physical slot 1:1.)
    pub fn push(&mut self, src: SocketAddr, data: &[u8]) -> bool {
        let idx = self.views.len();
        if idx >= self.bufs.len() || data.len() > self.bufs[idx].len() {
            return false;
        }
        self.bufs[idx][..data.len()].copy_from_slice(data);
        self.views.push(View {
            buf: idx,
            start: 0,
            len: data.len(),
            src: Some(src),
        });
        true
    }

    /// Record one logical datagram view (used by the receive paths).
    fn push_view(&mut self, buf: usize, start: usize, len: usize, src: Option<SocketAddr>) {
        self.views.push(View {
            buf,
            start,
            len,
            src,
        });
    }

    /// Invalidate datagram `i` so [`BatchBuffer::get`] skips it (e.g. a datagram
    /// from an unexpected source on a point-to-point path).
    pub fn skip(&mut self, i: usize) {
        if let Some(v) = self.views.get_mut(i) {
            v.src = None;
        }
    }

    /// Datagram `i` of the last `recv_batch` (None if the source address
    /// could not be decoded or the datagram was truncated and dropped).
    pub fn get(&self, i: usize) -> Option<(SocketAddr, &[u8])> {
        let v = self.views.get(i)?;
        v.src
            .map(|src| (src, &self.bufs[v.buf][v.start..v.start + v.len]))
    }

    /// Switch physical slots to GRO mode: fewer (`<= GRO_MAX_SLOTS`) but
    /// `GRO_BUF_LEN`-byte buffers, so a coalesced super-datagram fits before it
    /// is split into per-segment views. Idempotent.
    #[cfg(target_os = "linux")]
    fn ensure_gro_storage(&mut self) {
        if self.gro_sized {
            return;
        }
        let n = self.bufs.len().clamp(1, GRO_MAX_SLOTS);
        self.bufs.truncate(n);
        for b in &mut self.bufs {
            b.clear();
            b.resize(GRO_BUF_LEN, 0);
        }
        self.addrs.truncate(n);
        self.iovecs.truncate(n);
        self.hdrs.truncate(n);
        self.ctrls.truncate(n);
        self.gro_sized = true;
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

    /// A loopback tunnel with kernel offload forced off. Truncation of a single
    /// UDP datagram is only observable on the small-buffer (non-GRO) path — a
    /// GRO socket's 64 KiB buffers hold any possible UDP datagram intact.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn tunnel_on_loopback_no_offload() -> UdpTunnel {
        #[cfg(target_os = "linux")]
        {
            UdpTunnel::new_no_offload(TunnelConfig {
                local_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                read_timeout: Some(Duration::from_millis(200)),
                ..Default::default()
            })
            .unwrap()
        }
        #[cfg(not(target_os = "linux"))]
        {
            tunnel_on_loopback()
        }
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

    /// The `UDP_GRO` receive control message (segment size) is parsed back out
    /// of a `msghdr`; a message with no control data reports no segmentation.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_gro_segment_reads_cmsg() {
        let mut cbuf = [0u64; 8]; // 8-byte-aligned, 64 bytes
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = std::mem::size_of_val(&cbuf) as _;
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_UDP;
            (*cmsg).cmsg_type = UDP_GRO;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
            let val: libc::c_int = 1400;
            std::ptr::copy_nonoverlapping(
                &val as *const _ as *const u8,
                libc::CMSG_DATA(cmsg),
                std::mem::size_of::<libc::c_int>(),
            );
            msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) as _;
        }
        assert_eq!(parse_gro_segment(&msg), Some(1400usize));

        // No control data at all -> not coalesced.
        let empty: libc::msghdr = unsafe { std::mem::zeroed() };
        assert_eq!(parse_gro_segment(&empty), None);
    }

    #[cfg(target_os = "linux")]
    fn collect_gro_chunks(total: usize, seg: usize) -> Vec<(usize, usize)> {
        let mut v = Vec::new();
        each_gro_segment(total, seg, |start, len| v.push((start, len)));
        v
    }

    /// A GRO-coalesced buffer splits into `seg`-sized chunks, the last possibly
    /// shorter; a non-coalesced buffer (seg 0, or seg >= total) is one chunk.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_gro_chunks_splits_evenly_and_tail() {
        assert_eq!(
            collect_gro_chunks(4200, 1000),
            vec![(0, 1000), (1000, 1000), (2000, 1000), (3000, 1000), (4000, 200)]
        );
        assert_eq!(
            collect_gro_chunks(3000, 1000),
            vec![(0, 1000), (1000, 1000), (2000, 1000)]
        );
        // segment >= total: a single whole datagram (not coalesced).
        assert_eq!(collect_gro_chunks(500, 1000), vec![(0, 500)]);
        // defensive: seg 0 must not divide-by-zero — treat as one whole chunk.
        assert_eq!(collect_gro_chunks(500, 0), vec![(0, 500)]);
        // empty buffer yields nothing.
        assert_eq!(collect_gro_chunks(0, 1000), vec![]);
    }

    /// End-to-end GRO receive: a large same-size burst (GSO-sent) reaches a
    /// GRO-enabled receiver, which — whether or not the kernel coalesced it —
    /// must yield every datagram intact and in order. Exercises the recv_batch
    /// split + view model against real kernel coalescing.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_recv_batch_gro_bulk_intact() {
        let sender = tunnel_on_loopback();
        let receiver = tunnel_on_loopback();
        receiver.set_nonblocking(true).unwrap();
        let dst = local_addr(&receiver);

        const N: usize = 40;
        // Distinct per-datagram content, all the same length so the kernel can
        // coalesce the run on receive.
        let datagrams: Vec<Vec<u8>> = (0..N)
            .map(|i| {
                let mut d = vec![0u8; 1200];
                d[0] = i as u8;
                d[1] = (i >> 8) as u8;
                d
            })
            .collect();
        assert_eq!(sender.send_batch_to(&datagrams, dst).unwrap(), N);

        // Collect across a few recv_batch calls (coalescing may pack them into
        // one call or several).
        let mut got: Vec<Vec<u8>> = Vec::new();
        let mut batch = BatchBuffer::new(32);
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while got.len() < N && std::time::Instant::now() < deadline {
            let n = receiver.recv_batch(&mut batch).unwrap();
            for i in 0..n {
                if let Some((_, data)) = batch.get(i) {
                    got.push(data.to_vec());
                }
            }
            if n == 0 {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        assert_eq!(got.len(), N, "all datagrams must arrive");
        for (i, d) in datagrams.iter().enumerate() {
            assert_eq!(&got[i], d, "datagram {i} corrupted or reordered");
        }
    }

    /// GRO-aware `recv_into` must dispense one datagram per call even when the
    /// kernel coalesced several into a single `recvmsg`.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_recv_into_gro_dispenses_each() {
        let sender = tunnel_on_loopback();
        let mut receiver = tunnel_on_loopback();
        receiver.set_nonblocking(true).unwrap();
        let dst = local_addr(&receiver);

        const N: usize = 12;
        let datagrams: Vec<Vec<u8>> = (0..N).map(|i| vec![i as u8; 900]).collect();
        assert_eq!(sender.send_batch_to(&datagrams, dst).unwrap(), N);

        let mut got: Vec<Vec<u8>> = Vec::new();
        let mut out = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while got.len() < N && std::time::Instant::now() < deadline {
            match receiver.recv_into(&mut out).unwrap() {
                Some(_) => got.push(out.clone()),
                None => std::thread::sleep(Duration::from_millis(5)),
            }
        }
        assert_eq!(got.len(), N, "recv_into must yield every datagram");
        for (i, d) in datagrams.iter().enumerate() {
            assert_eq!(&got[i], d, "datagram {i} corrupted or reordered");
        }
    }

    #[test]
    fn test_batch_buffer_clamp() {
        assert_eq!(BatchBuffer::new(0).capacity(), 1);
        assert_eq!(BatchBuffer::new(32).capacity(), 32);
        // Configured sizes up to the raised ceiling are honored verbatim.
        assert_eq!(BatchBuffer::new(256).capacity(), 256);
        assert_eq!(BatchBuffer::new(MAX_BATCH).capacity(), MAX_BATCH);
        // Anything above the ceiling clamps to it.
        assert_eq!(BatchBuffer::new(MAX_BATCH + 1).capacity(), MAX_BATCH);
        assert_eq!(BatchBuffer::new(100_000).capacity(), MAX_BATCH);
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
        // GRO's 64 KiB buffers would deliver the oversized datagram intact, so
        // this truncation-skip safety is only observable on the small-buffer
        // path.
        let receiver = tunnel_on_loopback_no_offload();
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
        // Small-buffer path: on a GRO socket the datagram would fit and deliver.
        let mut receiver = tunnel_on_loopback_no_offload();
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

    /// GSO send must place each logical datagram on the wire as its own
    /// datagram: `send_batch_to` coalesces a run of equal-size datagrams (plus a
    /// shorter tail) into one `sendmsg`, and the kernel segments it back out.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_send_batch_to_gso_segments() {
        let sender = tunnel_on_loopback();
        let receiver = tunnel_on_loopback();
        receiver.set_nonblocking(true).unwrap();
        let dst = local_addr(&receiver);

        // Four full 1000-byte segments + one shorter 400-byte tail → one GSO
        // sendmsg that the kernel splits into five datagrams.
        let mut datagrams: Vec<Vec<u8>> = (0..4u8).map(|i| vec![i; 1000]).collect();
        datagrams.push(vec![0xAA; 400]);
        assert_eq!(sender.send_batch_to(&datagrams, dst).unwrap(), 5);
        std::thread::sleep(Duration::from_millis(50));

        // The receiver has no GRO, so it observes five separate datagrams.
        let mut batch = BatchBuffer::new(16);
        let n = receiver.recv_batch(&mut batch).unwrap();
        assert_eq!(n, 5, "GSO super-datagram must arrive as 5 wire datagrams");
        for (i, d) in datagrams.iter().enumerate() {
            let (_, data) = batch.get(i).unwrap();
            assert_eq!(data, &d[..], "segment {i} mismatch");
        }
    }

    /// A run of unequal-length datagrams cannot be one GSO run; the mixed batch
    /// must still deliver every datagram intact (per-datagram / sendmmsg path).
    #[cfg(target_os = "linux")]
    #[test]
    fn test_send_batch_to_mixed_sizes() {
        let sender = tunnel_on_loopback();
        let receiver = tunnel_on_loopback();
        receiver.set_nonblocking(true).unwrap();
        let dst = local_addr(&receiver);

        let datagrams: Vec<Vec<u8>> =
            vec![vec![1u8; 300], vec![2u8; 1200], vec![3u8; 300], vec![4u8; 300]];
        assert_eq!(sender.send_batch_to(&datagrams, dst).unwrap(), 4);
        std::thread::sleep(Duration::from_millis(50));

        let mut batch = BatchBuffer::new(16);
        let n = receiver.recv_batch(&mut batch).unwrap();
        assert_eq!(n, 4);
        for (i, d) in datagrams.iter().enumerate() {
            assert_eq!(batch.get(i).unwrap().1, &d[..], "datagram {i} mismatch");
        }
    }

    /// `send_batch` GSO: a same-destination run of equal-size datagrams is
    /// segmented by the kernel and arrives as individual datagrams.
    #[cfg(target_os = "linux")]
    #[test]
    fn test_send_batch_gso_same_dst() {
        let sender = tunnel_on_loopback();
        let receiver = tunnel_on_loopback();
        receiver.set_nonblocking(true).unwrap();
        let dst = local_addr(&receiver);

        let msgs: Vec<(Vec<u8>, SocketAddr)> =
            (0..4u8).map(|i| (vec![i; 800], dst)).collect();
        assert_eq!(sender.send_batch(&msgs).unwrap(), 4);
        std::thread::sleep(Duration::from_millis(50));

        let mut batch = BatchBuffer::new(16);
        let n = receiver.recv_batch(&mut batch).unwrap();
        assert_eq!(n, 4);
        for i in 0..4usize {
            assert_eq!(batch.get(i).unwrap().1, &vec![i as u8; 800][..]);
        }
    }

    /// `send_batch` with two interleaved destinations must deliver every
    /// datagram to the correct peer (same-dst grouping must not cross peers).
    #[cfg(target_os = "linux")]
    #[test]
    fn test_send_batch_two_dsts() {
        let sender = tunnel_on_loopback();
        let rx_a = tunnel_on_loopback();
        let rx_b = tunnel_on_loopback();
        rx_a.set_nonblocking(true).unwrap();
        rx_b.set_nonblocking(true).unwrap();
        let a = local_addr(&rx_a);
        let b = local_addr(&rx_b);

        // Two equal-size runs to A, split by one datagram to B.
        let msgs: Vec<(Vec<u8>, SocketAddr)> = vec![
            (vec![1u8; 600], a),
            (vec![2u8; 600], a),
            (vec![9u8; 600], b),
            (vec![3u8; 600], a),
        ];
        assert_eq!(sender.send_batch(&msgs).unwrap(), 4);
        std::thread::sleep(Duration::from_millis(50));

        let mut ba = BatchBuffer::new(16);
        let na = rx_a.recv_batch(&mut ba).unwrap();
        assert_eq!(na, 3, "A must receive its three datagrams");
        let mut bb = BatchBuffer::new(16);
        let nb = rx_b.recv_batch(&mut bb).unwrap();
        assert_eq!(nb, 1, "B must receive its one datagram");
        assert_eq!(bb.get(0).unwrap().1, &vec![9u8; 600][..]);
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
