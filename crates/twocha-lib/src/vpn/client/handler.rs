//! # Client Handler
//!
//! Drives the v4 protocol engine from the client side: initial Noise_IK
//! handshake with retry/backoff, cookie challenges, PFS rekeying and
//! jittered keepalives.

#[cfg(unix)]
use crate::platform::unix::{
    is_would_block, routing::ClientRoutingContext, EventLoop, TunDevice, TunnelConfig, UdpTunnel,
    POLLIN,
};
#[cfg(unix)]
use crate::transport::{
    tls::TlsClientTransport, udp_quic::UdpQuicClientTransport, ClientTransport,
};

use crate::vpn::common;

#[cfg(unix)]
use std::net::SocketAddr;
#[cfg(unix)]
use std::time::{Duration, Instant};
#[cfg(unix)]
use twocha_core::v4::{session::keepalive_jitter, ClientHandshake, Session};
#[cfg(unix)]
use twocha_core::{CipherSuite, ClientConfig, Identity, TransportKind};
#[cfg(unix)]
use twocha_protocol::wire::{self, WireMsg};
use twocha_protocol::Result;
#[cfg(unix)]
use twocha_protocol::{NetworkError, VpnError};

#[cfg(unix)]
const HANDSHAKE_ATTEMPTS: u32 = 8;
#[cfg(unix)]
const HANDSHAKE_BASE_TIMEOUT: Duration = Duration::from_secs(2);
/// Recreate an unanswered rekey handshake after this long
#[cfg(unix)]
const REKEY_RETRY: Duration = Duration::from_secs(5);

/// Run the VPN client
#[cfg(unix)]
pub fn run(config_path: &str, quiet: bool) -> Result<()> {
    let cfg =
        ClientConfig::from_file(config_path).map_err(|e| VpnError::Config(format!("{}", e)))?;

    let server_addr = cfg
        .server_addr()
        .map_err(|e| VpnError::Config(format!("{}", e)))?;
    let identity = cfg
        .identity()
        .map_err(|e| VpnError::Config(format!("{}", e)))?;
    let server_public = cfg
        .server_public()
        .map_err(|e| VpnError::Config(format!("{}", e)))?;

    // Create TUN device
    let mut tun = TunDevice::create_with_options(&cfg.tun.name, cfg.performance.multi_queue)?;

    // Configure IPv4
    let ipv4_gateway = if cfg.ipv4.enable {
        if let Some(addr) = cfg
            .tun_ipv4()
            .map_err(|e| VpnError::Config(format!("{}", e)))?
        {
            tun.set_ipv4_address(addr, cfg.ipv4.prefix)?;
            let octets = addr.octets();
            Some(format!("{}.{}.{}.1", octets[0], octets[1], octets[2]))
        } else {
            None
        }
    } else {
        None
    };

    // Configure IPv6
    let ipv6_gateway = if cfg.ipv6.enable {
        if let Some(addr) = cfg
            .tun_ipv6()
            .map_err(|e| VpnError::Config(format!("{}", e)))?
        {
            tun.set_ipv6_address(addr, cfg.ipv6.prefix)?;
            let segments = addr.segments();
            Some(format!(
                "{:x}:{:x}:{:x}:{:x}::1",
                segments[0], segments[1], segments[2], segments[3]
            ))
        } else {
            None
        }
    } else {
        None
    };

    tun.set_mtu(cfg.tun.mtu)?;
    tun.bring_up()?;
    tun.set_nonblocking(true)?;

    common::reset_running();
    common::setup_signal_handler();

    // Build the selected obfuscation transport. Both carry complete v4 wire
    // datagrams; the QUIC path is byte-identical to the pre-abstraction client.
    let mut transport: Box<dyn ClientTransport> = match cfg.client.transport {
        TransportKind::Quic => {
            let local_addr: SocketAddr = if server_addr.is_ipv6() {
                SocketAddr::from(([0u16; 8], 0))
            } else {
                SocketAddr::from(([0u8; 4], 0))
            };
            let tunnel_config = TunnelConfig {
                local_addr,
                remote_addr: Some(server_addr),
                read_timeout: Some(Duration::from_millis(100)),
                recv_buffer_size: cfg.performance.socket_recv_buffer,
                send_buffer_size: cfg.performance.socket_send_buffer,
                ..Default::default()
            };
            let tunnel = UdpTunnel::new(tunnel_config)?;
            Box::new(UdpQuicClientTransport::new(tunnel, server_addr))
        }
        TransportKind::Tls => {
            // TCP connect + real TLS 1.3 handshake (blocking) happen here.
            let t = TlsClientTransport::connect(server_addr, &cfg.tls.sni).map_err(VpnError::Io)?;
            Box::new(t)
        }
    };
    log::info!("transport: {} -> {}", cfg.client.transport, server_addr);

    // Initial Noise_IK handshake, driven over the transport (retry + backoff)
    let mut session = handshake_over_transport(
        transport.as_mut(),
        cfg.crypto.cipher,
        &identity,
        server_public,
    )?;

    transport.set_nonblocking(true)?;

    // Setup routing only after the tunnel is actually up
    let mut routing_ctx = ClientRoutingContext::new();
    if let Err(e) = routing_ctx.setup(
        ipv4_gateway.as_deref(),
        ipv6_gateway.as_deref(),
        &server_addr,
        cfg.ipv4.route_all,
        cfg.ipv6.route_all,
        &cfg.ipv4.routes,
        &cfg.ipv6.routes,
        &cfg.dns.servers_v4,
        &cfg.dns.servers_v6,
        &cfg.dns.search,
    ) {
        log::error!("Failed to setup routing: {}", e);
    }

    let transport_fds = transport.pollfds();
    let tun_fd = tun.fd();
    let mut event_loop = EventLoop::new();
    event_loop.add_fd(tun_fd, POLLIN);
    for fd in &transport_fds {
        event_loop.add_fd(*fd, POLLIN);
    }

    if !quiet {
        println!();
        println!(
            "  \x1b[32m●\x1b[0m Connected to \x1b[36m{}\x1b[0m",
            server_addr
        );
        if let Some(ref gw) = ipv4_gateway {
            println!(
                "  IPv4: {} (gateway: {})",
                tun.ipv4_addr().map(|a| a.to_string()).unwrap_or_default(),
                gw
            );
        }
        if let Some(ref gw) = ipv6_gateway {
            println!(
                "  IPv6: {} (gateway: {})",
                tun.ipv6_addr().map(|a| a.to_string()).unwrap_or_default(),
                gw
            );
        }
        if cfg.ipv4.route_all || cfg.ipv6.route_all {
            println!("  Mode: \x1b[33mFull tunnel\x1b[0m");
        } else {
            println!("  Mode: Split tunnel");
        }
        println!();
    }

    let mut tun_buffer = vec![0u8; cfg.tun.mtu as usize + 100];
    let mut next_keepalive = Instant::now() + keepalive_jitter();
    let mut pending: Option<(ClientHandshake, Instant)> = None;

    while common::running() {
        let events = event_loop.poll(100)?;

        for (fd, revents) in events {
            if revents & POLLIN != 0 {
                if fd == tun_fd {
                    handle_tun_read(&mut tun, &mut tun_buffer, transport.as_mut(), &mut session)?;
                } else if transport_fds.contains(&fd) {
                    handle_transport_read(
                        transport.as_mut(),
                        &mut tun,
                        &mut session,
                        &mut pending,
                    )?;
                }
            }
        }

        let now = Instant::now();

        // PFS ratchet: initiate (or retry) a fresh handshake
        let needs_rekey = session.should_rekey() || session.expired();
        let pending_stale = matches!(&pending, Some((_, t)) if t.elapsed() > REKEY_RETRY);
        if (needs_rekey && pending.is_none()) || pending_stale {
            match ClientHandshake::new(cfg.crypto.cipher, &identity, server_public) {
                Ok(hs) => {
                    let _ = transport.send(hs.datagram());
                    pending = Some((hs, now));
                }
                Err(e) => log::error!("failed to start rekey handshake: {}", e),
            }
        }

        if now >= next_keepalive {
            if let Ok(datagram) = session.seal_data(&[]) {
                let _ = transport.send(&datagram);
            }
            next_keepalive = now + keepalive_jitter();
        }
    }

    let _ = routing_ctx.cleanup();

    if !quiet {
        println!("\n  \x1b[32m✓\x1b[0m Disconnected");
    }

    Ok(())
}

/// Initial handshake: fresh init per attempt, exponential backoff, cookie
/// challenges handled transparently. Transport-agnostic — drives the carrier
/// non-blocking and spins with a deadline (works for both UDP and TLS, where a
/// blocking recv would never see WouldBlock).
#[cfg(unix)]
fn handshake_over_transport(
    transport: &mut dyn ClientTransport,
    suite: CipherSuite,
    identity: &Identity,
    server_public: [u8; 32],
) -> Result<Session> {
    transport.set_nonblocking(true)?;
    let mut buf = Vec::new();

    for attempt in 0..HANDSHAKE_ATTEMPTS {
        if !common::running() {
            return Err(NetworkError::Timeout.into());
        }
        let timeout = HANDSHAKE_BASE_TIMEOUT * 2u32.pow(attempt.min(4));
        log::debug!(
            "handshake attempt {}/{} (timeout {:?})",
            attempt + 1,
            HANDSHAKE_ATTEMPTS,
            timeout
        );

        let mut hs = ClientHandshake::new(suite, identity, server_public)?;
        if transport.send(hs.datagram()).is_err() {
            continue;
        }

        let deadline = Instant::now() + timeout;
        let session = loop {
            if Instant::now() >= deadline || !common::running() {
                break None;
            }
            match transport.recv(&mut buf) {
                Ok(true) => {}
                Ok(false) => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(_) => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
            }
            match wire::parse(&buf) {
                Ok(WireMsg::Cookie { nonce, sealed }) => {
                    if hs.apply_cookie(nonce, sealed).is_ok() {
                        let _ = transport.send(hs.datagram());
                    }
                }
                Ok(WireMsg::Resp { .. }) => match hs.complete(&buf) {
                    Ok(session) => break Some(session),
                    Err(e) => {
                        log::debug!("handshake response rejected: {}", e);
                        break None;
                    }
                },
                _ => continue,
            }
        };

        if let Some(session) = session {
            log::info!("handshake complete");
            return Ok(session);
        }
    }

    Err(NetworkError::Timeout.into())
}

#[cfg(unix)]
fn handle_tun_read(
    tun: &mut TunDevice,
    buffer: &mut [u8],
    transport: &mut dyn ClientTransport,
    session: &mut Session,
) -> Result<()> {
    loop {
        match tun.read(buffer) {
            Ok(n) if n > 0 => {
                if let Ok(datagram) = session.seal_data(&buffer[..n]) {
                    let _ = transport.send(&datagram);
                }
            }
            Ok(_) => break,
            Err(e) if is_would_block(&e) => break,
            Err(_) => break,
        }
    }
    Ok(())
}

#[cfg(unix)]
fn handle_transport_read(
    transport: &mut dyn ClientTransport,
    tun: &mut TunDevice,
    session: &mut Session,
    pending: &mut Option<(ClientHandshake, Instant)>,
) -> Result<()> {
    let mut buf = Vec::new();
    loop {
        match transport.recv(&mut buf) {
            Ok(true) => {}
            Ok(false) => break,
            Err(_) => break,
        }
        match wire::parse(&buf) {
            Ok(WireMsg::Data {
                receiver_cid,
                masked_counter,
                ciphertext,
            }) => {
                if receiver_cid != session.local_cid {
                    continue;
                }
                match session.open_data(masked_counter, ciphertext) {
                    Ok(payload) if payload.is_empty() => {} // keepalive
                    Ok(payload) => {
                        let _ = tun.write(&payload);
                    }
                    Err(_) => {}
                }
            }
            Ok(WireMsg::Resp { .. }) => {
                if let Some((hs, _)) = pending.take() {
                    match hs.complete(&buf) {
                        Ok(new_session) => {
                            log::info!("rekey complete (session age was {:?})", session.age());
                            *session = new_session;
                        }
                        Err(e) => log::debug!("rekey response rejected: {}", e),
                    }
                }
            }
            Ok(WireMsg::Cookie { nonce, sealed }) => {
                if let Some((hs, _)) = pending.as_mut() {
                    if hs.apply_cookie(nonce, sealed).is_ok() {
                        let _ = transport.send(hs.datagram());
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Run the VPN client (Windows): not supported by protocol v4 yet
#[cfg(windows)]
pub fn run(_config_path: &str, _quiet: bool) -> Result<()> {
    Err(twocha_protocol::VpnError::Config(
        "Windows support for protocol v4 is not implemented yet".into(),
    ))
}

/// Stop the client
pub fn stop() {
    common::stop();
}
