//! # Windows Network Module
//!
//! Plain UDP transport. All encryption and session state lives in the v4
//! protocol engine (`twocha_core::v4`); this layer only moves datagrams.
//!
//! Note: the v4 client/server handlers are not implemented for Windows yet.

#![cfg(windows)]

use std::net::{SocketAddr, UdpSocket};
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
        let socket = UdpSocket::bind(config.local_addr)
            .map_err(|e| NetworkError::BindFailed(e.to_string()))?;
        socket.set_read_timeout(config.read_timeout)?;
        socket.set_write_timeout(config.write_timeout)?;
        Ok(UdpTunnel {
            socket,
            config,
            recv_buffer: vec![0u8; MAX_PACKET_SIZE],
        })
    }

    /// Send a complete datagram to `addr`
    pub fn send_to(&self, datagram: &[u8], addr: SocketAddr) -> Result<usize> {
        Ok(self.socket.send_to(datagram, addr)?)
    }

    /// Receive a datagram from any source
    pub fn recv_from_any(&mut self) -> Result<Option<(SocketAddr, Vec<u8>)>> {
        match self.socket.recv_from(&mut self.recv_buffer) {
            Ok((len, src)) => Ok(Some((src, self.recv_buffer[..len].to_vec()))),
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
}

/// Check if error is "would block"
#[inline]
pub fn is_would_block(e: &twocha_protocol::VpnError) -> bool {
    let s = e.to_string();
    s.contains("WouldBlock")
        || s.contains("temporarily unavailable")
        || s.contains("os error 10035")
}
