//! # Windows Network Module
//!
//! High-performance UDP tunnel with Windows-compatible I/O.

#![cfg(windows)]

use crate::crypto::ChaCha20Poly1305;
use crate::error::{NetworkError, Result};
use crate::protocol::{PacketHeader, PacketType, ReplayWindow};
use crate::{MAX_PACKET_SIZE, PROTOCOL_HEADER_SIZE};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Networking::WinSock::{
    select, WSACleanup, WSAStartup, FD_SET, SOCKET, TIMEVAL, WSADATA,
};

// =============================================================================
// WINSOCK INITIALIZATION
// =============================================================================

/// Initialize Winsock (called once at startup)
pub fn init_winsock() -> Result<()> {
    unsafe {
        let mut wsa_data: WSADATA = std::mem::zeroed();
        let result = WSAStartup(0x0202, &mut wsa_data);
        if result != 0 {
            return Err(NetworkError::BindFailed("WSAStartup failed".into()).into());
        }
    }
    Ok(())
}

/// Cleanup Winsock
pub fn cleanup_winsock() {
    unsafe {
        WSACleanup();
    }
}

// =============================================================================
// TUNNEL CONFIG
// =============================================================================

/// Tunnel configuration
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub local_addr: SocketAddr,
    pub remote_addr: Option<SocketAddr>,
    pub read_timeout: Option<Duration>,
    pub write_timeout: Option<Duration>,
    pub keepalive_interval: Duration,
    pub session_timeout: Duration,
    pub recv_buffer_size: usize,
    pub send_buffer_size: usize,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        TunnelConfig {
            local_addr: "0.0.0.0:51820".parse().unwrap(),
            remote_addr: None,
            read_timeout: Some(Duration::from_millis(100)),
            write_timeout: Some(Duration::from_secs(5)),
            keepalive_interval: Duration::from_secs(25),
            session_timeout: Duration::from_secs(180),
            recv_buffer_size: 2 * 1024 * 1024,
            send_buffer_size: 2 * 1024 * 1024,
        }
    }
}

// =============================================================================
// PEER STATE
// =============================================================================

/// Peer connection state
#[derive(Debug)]
pub struct PeerState {
    pub addr: SocketAddr,
    pub last_seen: Instant,
    pub tx_counter: u32,
    pub replay_window: ReplayWindow,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub packets_tx: u64,
    pub packets_rx: u64,
}

impl PeerState {
    pub fn new(addr: SocketAddr) -> Self {
        PeerState {
            addr,
            last_seen: Instant::now(),
            tx_counter: 0,
            replay_window: ReplayWindow::new(),
            bytes_tx: 0,
            bytes_rx: 0,
            packets_tx: 0,
            packets_rx: 0,
        }
    }

    #[inline]
    pub fn next_counter(&mut self) -> u32 {
        self.tx_counter = self.tx_counter.wrapping_add(1);
        self.tx_counter
    }

    #[inline]
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_seen.elapsed() > timeout
    }

    #[inline]
    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
    }
}

// =============================================================================
// UDP TUNNEL
// =============================================================================

/// UDP tunnel for VPN traffic
pub struct UdpTunnel {
    socket: UdpSocket,
    config: TunnelConfig,
    cipher: ChaCha20Poly1305,
    recv_buffer: Vec<u8>,
    send_buffer: Vec<u8>,
}

impl UdpTunnel {
    /// Create new UDP tunnel
    pub fn new(config: TunnelConfig, key: &[u8; 32]) -> Result<Self> {
        log::info!("Creating UDP tunnel on {}", config.local_addr);

        let socket = UdpSocket::bind(config.local_addr)
            .map_err(|e| NetworkError::BindFailed(e.to_string()))?;

        socket.set_read_timeout(config.read_timeout)?;
        socket.set_write_timeout(config.write_timeout)?;

        // Set socket buffer sizes using Windows setsockopt
        Self::set_socket_buffers(&socket, config.recv_buffer_size, config.send_buffer_size);

        let recv_buffer = vec![0u8; MAX_PACKET_SIZE];
        let send_buffer = vec![0u8; MAX_PACKET_SIZE];

        Ok(UdpTunnel {
            socket,
            config,
            cipher: ChaCha20Poly1305::new(key),
            recv_buffer,
            send_buffer,
        })
    }

    fn set_socket_buffers(socket: &UdpSocket, recv_size: usize, send_size: usize) {
        use std::os::windows::io::AsRawSocket;
        use windows::Win32::Networking::WinSock::{
            setsockopt, SOCKET, SOL_SOCKET, SO_RCVBUF, SO_SNDBUF,
        };

        let sock = SOCKET(socket.as_raw_socket() as usize);

        unsafe {
            let recv_size = recv_size as i32;
            let send_size = send_size as i32;

            setsockopt(
                sock,
                SOL_SOCKET as i32,
                SO_RCVBUF as i32,
                Some(&recv_size.to_ne_bytes()),
            );

            setsockopt(
                sock,
                SOL_SOCKET as i32,
                SO_SNDBUF as i32,
                Some(&send_size.to_ne_bytes()),
            );
        }
    }

    /// Get the raw socket for event waiting
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Send encrypted packet to peer
    pub fn send_encrypted(&mut self, peer: &mut PeerState, data: &[u8]) -> Result<usize> {
        let counter = peer.next_counter();
        let header = PacketHeader::new(PacketType::Data, counter);

        let header_bytes = header.serialize();
        let encrypted = self.cipher.encrypt(&header.nonce, data, &header_bytes)?;

        let total_len = PROTOCOL_HEADER_SIZE + encrypted.len();
        self.send_buffer[..PROTOCOL_HEADER_SIZE].copy_from_slice(&header_bytes);
        self.send_buffer[PROTOCOL_HEADER_SIZE..total_len].copy_from_slice(&encrypted);

        let sent = self
            .socket
            .send_to(&self.send_buffer[..total_len], peer.addr)?;
        peer.bytes_tx += sent as u64;
        peer.packets_tx += 1;

        log::trace!("Sent {} bytes to {}", sent, peer.addr);
        Ok(sent)
    }

    /// Receive packet from any source (for server)
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

    /// Send keepalive
    pub fn send_keepalive(&mut self, peer: &mut PeerState) -> Result<()> {
        let counter = peer.next_counter();
        let header = PacketHeader::new(PacketType::Keepalive, counter);
        let header_bytes = header.serialize();

        let encrypted = self.cipher.encrypt(&header.nonce, &[], &header_bytes)?;

        let total_len = PROTOCOL_HEADER_SIZE + encrypted.len();
        self.send_buffer[..PROTOCOL_HEADER_SIZE].copy_from_slice(&header_bytes);
        self.send_buffer[PROTOCOL_HEADER_SIZE..total_len].copy_from_slice(&encrypted);

        self.socket
            .send_to(&self.send_buffer[..total_len], peer.addr)?;
        log::trace!("Sent keepalive to {}", peer.addr);
        Ok(())
    }

    /// Send disconnect notification
    pub fn send_disconnect(&mut self, peer: &mut PeerState) -> Result<()> {
        let counter = peer.next_counter();
        let header = PacketHeader::new(PacketType::Disconnect, counter);
        let header_bytes = header.serialize();

        let encrypted = self.cipher.encrypt(&header.nonce, &[], &header_bytes)?;

        let total_len = PROTOCOL_HEADER_SIZE + encrypted.len();
        self.send_buffer[..PROTOCOL_HEADER_SIZE].copy_from_slice(&header_bytes);
        self.send_buffer[PROTOCOL_HEADER_SIZE..total_len].copy_from_slice(&encrypted);

        self.socket
            .send_to(&self.send_buffer[..total_len], peer.addr)?;
        Ok(())
    }

    /// Set non-blocking mode
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        self.socket.set_nonblocking(nonblocking)?;
        Ok(())
    }

    pub fn config(&self) -> &TunnelConfig {
        &self.config
    }

    pub fn cipher(&self) -> &ChaCha20Poly1305 {
        &self.cipher
    }
}

// =============================================================================
// EVENT LOOP (Windows version using select/WaitForMultipleObjects)
// =============================================================================

/// Event source types for Windows event loop
pub enum EventSource {
    Socket(std::os::windows::io::RawSocket),
    Handle(HANDLE),
}

/// Simple event loop using Windows select/WaitForMultipleObjects
pub struct EventLoop {
    sockets: Vec<std::os::windows::io::RawSocket>,
    handles: Vec<HANDLE>,
}

impl EventLoop {
    pub fn new() -> Self {
        EventLoop {
            sockets: Vec::new(),
            handles: Vec::new(),
        }
    }

    /// Add a socket for monitoring
    pub fn add_socket(&mut self, socket: std::os::windows::io::RawSocket) {
        self.sockets.push(socket);
    }

    /// Add a Windows HANDLE for monitoring (e.g., WinTun read event)
    pub fn add_handle(&mut self, handle: HANDLE) {
        self.handles.push(handle);
    }

    /// Poll for events with timeout
    pub fn poll(&mut self, timeout_ms: u32) -> Result<EventResult> {
        use windows::Win32::Foundation::WAIT_TIMEOUT;
        use windows::Win32::System::Threading::WaitForMultipleObjects;

        // If we have handles (like TUN read event), use WaitForMultipleObjects
        if !self.handles.is_empty() {
            let result = unsafe { WaitForMultipleObjects(&self.handles, false, timeout_ms) };

            if result == WAIT_TIMEOUT {
                return Ok(EventResult::Timeout);
            }

            let index = result.0 as usize;
            if index < self.handles.len() {
                return Ok(EventResult::HandleReady(index));
            }
        }

        // Use select for sockets
        if !self.sockets.is_empty() {
            let mut read_fds: FD_SET = unsafe { std::mem::zeroed() };
            read_fds.fd_count = self.sockets.len() as u32;

            for (i, &sock) in self.sockets.iter().enumerate() {
                if i < 64 {
                    read_fds.fd_array[i] = SOCKET(sock as usize);
                }
            }

            let timeout = TIMEVAL {
                tv_sec: (timeout_ms / 1000) as i32,
                tv_usec: ((timeout_ms % 1000) * 1000) as i32,
            };

            let result = unsafe { select(0, Some(&mut read_fds), None, None, Some(&timeout)) };

            if result > 0 {
                // Find which socket is ready
                for (i, &sock) in self.sockets.iter().enumerate() {
                    for j in 0..read_fds.fd_count as usize {
                        if read_fds.fd_array[j] == SOCKET(sock as usize) {
                            return Ok(EventResult::SocketReady(i));
                        }
                    }
                }
            }
        }

        Ok(EventResult::Timeout)
    }
}

impl Default for EventLoop {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of event loop poll
pub enum EventResult {
    Timeout,
    SocketReady(usize),
    HandleReady(usize),
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Check if error is "would block"
#[inline]
pub fn is_would_block(e: &crate::VpnError) -> bool {
    let s = e.to_string();
    s.contains("WouldBlock")
        || s.contains("temporarily unavailable")
        || s.contains("Resource temporarily unavailable")
        || s.contains("10035") // WSAEWOULDBLOCK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_config_default() {
        let config = TunnelConfig::default();
        assert_eq!(config.keepalive_interval, Duration::from_secs(25));
        assert_eq!(config.recv_buffer_size, 2 * 1024 * 1024);
    }

    #[test]
    fn test_peer_state() {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let mut peer = PeerState::new(addr);

        assert_eq!(peer.next_counter(), 1);
        assert_eq!(peer.next_counter(), 2);
        assert!(!peer.is_expired(Duration::from_secs(60)));
    }
}
