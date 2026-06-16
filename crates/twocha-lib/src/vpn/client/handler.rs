//! # Client Handler
//!
//! Drives the v4 protocol engine from the client side: initial Noise_IK
//! handshake with retry/backoff, cookie challenges, PFS rekeying and
//! jittered keepalives.

#[cfg(unix)]
use crate::platform::unix::{
    is_would_block, EventLoop, TunDevice, TunnelConfig, UdpTunnel, POLLIN,
};
// Netlink routing is Linux-desktop only; the mobile (`run_mobile`) path lets the
// Android VpnService own routing, so this is excluded on Android.
#[cfg(all(unix, not(target_os = "android")))]
use crate::platform::unix::routing::ClientRoutingContext;
#[cfg(unix)]
use crate::transport::{
    tls::TlsClientTransport, udp_quic::UdpQuicClientTransport, ClientTransport,
};

use crate::vpn::common;

#[cfg(unix)]
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::io::RawFd;
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};
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

/// Run the VPN client (Linux desktop): owns routing via netlink.
#[cfg(all(unix, not(target_os = "android")))]
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

    let mut transport = build_transport(&cfg, server_addr)?;
    log::info!("transport: {} -> {}", cfg.client.transport, server_addr);

    // Initial Noise_IK handshake, driven over the transport (retry + backoff)
    let session = handshake_over_transport(
        transport.as_mut(),
        cfg.crypto.cipher,
        &identity,
        server_public,
        common::flag(),
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

    run_event_loop(
        &cfg,
        &identity,
        server_public,
        &mut tun,
        transport.as_mut(),
        session,
        common::flag(),
    )?;

    let _ = routing_ctx.cleanup();

    if !quiet {
        println!("\n  \x1b[32m✓\x1b[0m Disconnected");
    }

    Ok(())
}

/// Build the selected obfuscation transport. Both carry complete v4 wire
/// datagrams; the QUIC path is byte-identical to the pre-abstraction client.
#[cfg(unix)]
fn build_transport(
    cfg: &ClientConfig,
    server_addr: SocketAddr,
) -> Result<Box<dyn ClientTransport>> {
    let transport: Box<dyn ClientTransport> = match cfg.client.transport {
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
    Ok(transport)
}

/// The steady-state data plane: poll the tun fd and the transport fds, pump
/// packets both ways, ratchet PFS rekeys, and emit jittered keepalives. Shared
/// verbatim by the desktop (`run`) and mobile (`run_mobile`) entry points; it
/// returns when `common::running()` flips false.
#[cfg(unix)]
fn run_event_loop(
    cfg: &ClientConfig,
    identity: &Identity,
    server_public: [u8; 32],
    tun: &mut TunDevice,
    transport: &mut dyn ClientTransport,
    mut session: Session,
    running: &AtomicBool,
) -> Result<()> {
    let transport_fds = transport.pollfds();
    let tun_fd = tun.fd();
    let mut event_loop = EventLoop::new();
    event_loop.add_fd(tun_fd, POLLIN);
    for fd in &transport_fds {
        event_loop.add_fd(*fd, POLLIN);
    }

    let mut tun_buffer = vec![0u8; cfg.tun.mtu as usize + 100];
    let mut next_keepalive = Instant::now() + keepalive_jitter();
    let mut pending: Option<(ClientHandshake, Instant)> = None;

    while running.load(Ordering::SeqCst) {
        let events = event_loop.poll(100)?;

        for (fd, revents) in events {
            if revents & POLLIN != 0 {
                if fd == tun_fd {
                    handle_tun_read(tun, &mut tun_buffer, transport, &mut session)?;
                } else if transport_fds.contains(&fd) {
                    handle_transport_read(transport, tun, &mut session, &mut pending)?;
                }
            }
        }

        let now = Instant::now();

        // PFS ratchet: initiate (or retry) a fresh handshake
        let needs_rekey = session.should_rekey() || session.expired();
        let pending_stale = matches!(&pending, Some((_, t)) if t.elapsed() > REKEY_RETRY);
        if (needs_rekey && pending.is_none()) || pending_stale {
            match ClientHandshake::new(cfg.crypto.cipher, identity, server_public) {
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

    Ok(())
}

/// Run the VPN client on a sandboxed platform (Android `VpnService`).
///
/// Unlike [`run`], this does **not** create a TUN device, configure system
/// routing/DNS, or install a signal handler — the host app's `VpnService`
/// already owns the data plane (addresses, routes, DNS, MTU) and hands us the
/// established tun fd. We only:
///
/// 1. build the obfuscation transport and call `protect(fd)` on every socket
///    it polls **before any network I/O**, so traffic escapes the VPN routing
///    loop (Android `VpnService.protect`);
/// 2. complete the Noise_IK handshake, then invoke `on_connected` exactly once;
/// 3. wrap the external tun fd and run the shared steady-state event loop.
///
/// The lifecycle is driven by the caller-owned `running` flag (a per-tunnel
/// `AtomicBool`, not the process-global one): blocks until another thread flips
/// it false. This avoids a stop signal racing a fresh start through a shared
/// global, and lets two tunnels coexist without stomping on each other.
///
/// # Safety
/// `tun_fd` must be a valid, open TUN fd whose ownership is transferred here
/// (it is closed when the wrapped device drops). Android: pass `pfd.detachFd()`.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
pub unsafe fn run_mobile(
    cfg: ClientConfig,
    identity: Identity,
    server_public: [u8; 32],
    tun_fd: RawFd,
    protect: &dyn Fn(RawFd) -> bool,
    running: &AtomicBool,
    on_connected: &dyn Fn(),
) -> Result<()> {
    let server_addr = cfg
        .server_addr()
        .map_err(|e| VpnError::Config(format!("{}", e)))?;

    let mut transport = build_transport(&cfg, server_addr)?;
    log::info!("transport: {} -> {}", cfg.client.transport, server_addr);

    // Protect every carrier socket before it sends anything, otherwise the
    // handshake datagrams would be routed back into the tunnel we're building.
    for fd in transport.pollfds() {
        if !protect(fd) {
            log::warn!("protect(fd={}) returned false; traffic may loop", fd);
        }
    }

    let session = handshake_over_transport(
        transport.as_mut(),
        cfg.crypto.cipher,
        &identity,
        server_public,
        running,
    )?;

    // Handshake done: the tunnel is genuinely established. Tell the host so it
    // can flip its UI to "connected" (instead of guessing before this point).
    on_connected();

    transport.set_nonblocking(true)?;

    let mut tun = TunDevice::from_fd(tun_fd, cfg.tun.mtu)?;
    tun.set_nonblocking(true)?;

    run_event_loop(
        &cfg,
        &identity,
        server_public,
        &mut tun,
        transport.as_mut(),
        session,
        running,
    )
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
    running: &AtomicBool,
) -> Result<Session> {
    transport.set_nonblocking(true)?;
    let mut buf = Vec::new();

    for attempt in 0..HANDSHAKE_ATTEMPTS {
        if !running.load(Ordering::SeqCst) {
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
            if Instant::now() >= deadline || !running.load(Ordering::SeqCst) {
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

/// Run the VPN client (Windows / Android): the desktop entry point isn't
/// available. Android drives the engine through `run_mobile` instead.
#[cfg(any(windows, target_os = "android"))]
pub fn run(_config_path: &str, _quiet: bool) -> Result<()> {
    Err(twocha_protocol::VpnError::Config(
        "the desktop `run` entry point is not available on this platform".into(),
    ))
}

/// Stop the client
pub fn stop() {
    common::stop();
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::os::unix::io::IntoRawFd;
    use std::os::unix::net::UnixDatagram;
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use twocha_core::v4::{InitOutcome, ServerHandshakeEngine};
    use twocha_core::CipherSuite;

    /// Drive `run_mobile` end-to-end over real loopback sockets against a
    /// minimal in-process v4 server: assert the `protect` callback fires for
    /// the transport's pollfd(s) before the handshake, that a tun packet seals
    /// out to the server, and that a server reply round-trips back to the tun.
    ///
    /// Uses a `UnixDatagram` socketpair as the "tun fd" — `TunDevice::from_fd`
    /// only does `read`/`write` on it, so message boundaries behave like a tun.
    #[test]
    fn run_mobile_loopback_roundtrip() {
        let client_id = Identity::generate();
        let server_id = Identity::generate();
        let client_pub = client_id.public_bytes();
        let server_public = server_id.public_bytes();

        // Minimal v4 server: bind UDP, complete one handshake, echo one packet.
        let server_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        server_sock
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let mut engine = ServerHandshakeEngine::new(CipherSuite::ChaCha20Poly1305, &server_id);

        let server = thread::spawn(move || {
            let mut buf = [0u8; 2048];
            let (n, src) = server_sock.recv_from(&mut buf).expect("recv init");
            let mut session = match engine.handle_init(&buf[..n], &src, false, |k| *k == client_pub)
            {
                InitOutcome::Established {
                    datagram, session, ..
                } => {
                    server_sock.send_to(&datagram, src).unwrap();
                    session
                }
                _ => panic!("handshake not established"),
            };

            loop {
                let (n, src) = match server_sock.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(_) => return None,
                };
                if let Ok(WireMsg::Data {
                    receiver_cid,
                    masked_counter,
                    ciphertext,
                }) = wire::parse(&buf[..n])
                {
                    if receiver_cid != session.local_cid {
                        continue;
                    }
                    match session.open_data(masked_counter, ciphertext) {
                        Ok(p) if p.is_empty() => continue, // keepalive
                        Ok(p) => {
                            let pong = session.seal_data(b"pong-packet").unwrap();
                            server_sock.send_to(&pong, src).unwrap();
                            return Some(p);
                        }
                        Err(_) => continue,
                    }
                }
            }
        });

        let (test_end, client_tun) = UnixDatagram::pair().unwrap();
        test_end
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let tun_fd = client_tun.into_raw_fd();

        let cfg = ClientConfig::parse(&format!(
            "[client]\nserver = \"{server_addr}\"\ntransport = \"quic\"\n\
             [crypto]\nprivate_key_file = \"/dev/null\"\n\
             server_public_key = \"{}\"\n[tun]\nmtu = 1400\n",
            twocha_core::encode_public_key(&server_public),
        ))
        .unwrap();

        let protected: Arc<Mutex<Vec<RawFd>>> = Arc::new(Mutex::new(Vec::new()));
        let protected_in = protected.clone();

        // Per-tunnel run flag (not the process-global one) and a connected counter
        // so we can assert `on_connected` fires exactly once, after the handshake.
        let running = Arc::new(AtomicBool::new(true));
        let running_in = running.clone();
        let connected = Arc::new(AtomicUsize::new(0));
        let connected_in = connected.clone();

        let client = thread::spawn(move || {
            let protect = move |fd: RawFd| {
                protected_in.lock().unwrap().push(fd);
                true
            };
            let on_connected = || {
                connected_in.fetch_add(1, Ordering::SeqCst);
            };
            // SAFETY: tun_fd is an owned socketpair fd transferred to the engine.
            unsafe {
                run_mobile(
                    cfg,
                    client_id,
                    server_public,
                    tun_fd,
                    &protect,
                    &running_in,
                    &on_connected,
                )
            }
        });

        // Hand a "tun packet" to the client; it seals and forwards to the server
        // once the handshake completes (the datagram buffers until then).
        test_end.send(b"ping-packet").unwrap();

        let mut buf = [0u8; 2048];
        let n = test_end.recv(&mut buf).expect("reply did not round-trip");
        assert_eq!(&buf[..n], b"pong-packet");

        // Flipping the per-tunnel flag (not the global stop()) ends the loop.
        running.store(false, Ordering::SeqCst);
        let client_result = client.join().unwrap();
        let server_got = server.join().unwrap();

        assert!(
            client_result.is_ok(),
            "run_mobile errored: {client_result:?}"
        );
        assert_eq!(server_got.as_deref(), Some(&b"ping-packet"[..]));
        assert!(
            !protected.lock().unwrap().is_empty(),
            "protect() must fire for the transport pollfd before the handshake"
        );
        assert_eq!(
            connected.load(Ordering::SeqCst),
            1,
            "on_connected must fire exactly once, after the handshake completes"
        );
    }
}
