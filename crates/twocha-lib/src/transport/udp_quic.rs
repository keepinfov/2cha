//! # UDP / fake-QUIC carrier
//!
//! Moves complete v4 wire datagrams over a plain UDP socket — exactly the bytes
//! `twocha_protocol::wire` produces (the QUIC-mimicry framing lives in the wire
//! module, not here). UDP preserves datagram boundaries, so this carrier needs
//! no length-prefixing: one `send` is one datagram, one `recv` yields one
//! datagram. This is the backwards-compatible path: the on-wire bytes are
//! identical to the pre-transport-abstraction client.

use std::io;
use std::net::SocketAddr;
use std::os::unix::io::RawFd;

use twocha_protocol::VpnError;

use super::ClientTransport;
use crate::platform::unix::network::UdpTunnel;

fn to_io(e: VpnError) -> io::Error {
    io::Error::other(e)
}

/// Client-side UDP carrier to one server endpoint.
pub struct UdpQuicClientTransport {
    tunnel: UdpTunnel,
    remote: SocketAddr,
}

impl UdpQuicClientTransport {
    pub fn new(tunnel: UdpTunnel, remote: SocketAddr) -> Self {
        UdpQuicClientTransport { tunnel, remote }
    }
}

impl ClientTransport for UdpQuicClientTransport {
    fn send(&mut self, datagram: &[u8]) -> io::Result<()> {
        self.tunnel.send_to(datagram, self.remote).map_err(to_io)?;
        Ok(())
    }

    fn recv(&mut self, out: &mut Vec<u8>) -> io::Result<bool> {
        // Point-to-point client: only accept datagrams from our server, drop
        // (and keep draining) anything spoofed from another source — same
        // filter the pre-abstraction client applied.
        loop {
            match self.tunnel.recv_from_any().map_err(to_io)? {
                Some((src, data)) if src == self.remote => {
                    *out = data;
                    return Ok(true);
                }
                Some(_) => continue,
                None => return Ok(false),
            }
        }
    }

    fn pollfds(&self) -> Vec<RawFd> {
        vec![self.tunnel.fd()]
    }

    fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        self.tunnel.set_nonblocking(nonblocking).map_err(to_io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::unix::network::TunnelConfig;
    use std::time::Duration;

    fn loopback_tunnel() -> UdpTunnel {
        UdpTunnel::new(TunnelConfig {
            local_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            read_timeout: Some(Duration::from_millis(200)),
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn udp_carrier_roundtrip_preserves_datagrams() {
        let a_tun = loopback_tunnel();
        let b_tun = loopback_tunnel();
        let a_addr = a_tun.local_addr().unwrap();
        let b_addr = b_tun.local_addr().unwrap();

        let mut a = UdpQuicClientTransport::new(a_tun, b_addr);
        let mut b = UdpQuicClientTransport::new(b_tun, a_addr);
        a.set_nonblocking(true).unwrap();
        b.set_nonblocking(true).unwrap();

        // Send a couple of "complete v4 datagrams" of differing sizes and make
        // sure they arrive byte-identical with boundaries preserved.
        a.send(b"first").unwrap();
        let big = vec![0x5Au8; 1300];
        a.send(&big).unwrap();

        let mut got = Vec::new();
        let mut received = Vec::new();
        for _ in 0..2 {
            loop {
                if b.recv(&mut got).unwrap() {
                    received.push(got.clone());
                    break;
                }
                std::thread::yield_now();
            }
        }
        assert_eq!(received[0], b"first");
        assert_eq!(received[1], big);
    }
}
