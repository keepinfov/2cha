//! # Windows Network Module
//!
//! UDP tunnel implementation for Windows.

#![cfg(windows)]

use twocha_core::ChaCha20Poly1305;
use twocha_protocol::{
    NetworkError, PacketHeader, PacketType, ReplayWindow, Result, MAX_PACKET_SIZE,
    PROTOCOL_HEADER_SIZE,
};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

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

/// UDP tunnel for Windows
pub struct UdpTunnel {
    socket: UdpSocket,
    config: TunnelConfig,
    cipher: ChaCha20Poly1305,
    recv_buffer: Vec<u8>,
    send_buffer: Vec<u8>,
}

impl UdpTunnel {
    pub fn new(config: TunnelConfig, key: &[u8; 32]) -> Result<Self> {
        let socket = UdpSocket::bind(config.local_addr)
            .map_err(|e| NetworkError::BindFailed(e.to_string()))?;

        socket.set_read_timeout(config.read_timeout)?;
        socket.set_write_timeout(config.write_timeout)?;

        Ok(UdpTunnel {
            socket,
            config,
            cipher: ChaCha20Poly1305::new(key),
            recv_buffer: vec![0u8; MAX_PACKET_SIZE],
            send_buffer: vec![0u8; MAX_PACKET_SIZE],
        })
    }

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
        Ok(sent)
    }

    pub fn recv_from_any(&mut self) -> Result<Option<(SocketAddr, Vec<u8>)>> {
        match self.socket.recv_from(&mut self.recv_buffer) {
            Ok((len, src)) => Ok(Some((src, self.recv_buffer[..len].to_vec()))),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

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
        Ok(())
    }

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

#[inline]
pub fn is_would_block(e: &twocha_protocol::VpnError) -> bool {
    let s = e.to_string();
    s.contains("WouldBlock") || s.contains("would block")
}
