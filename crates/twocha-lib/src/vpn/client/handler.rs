//! # Client Handler
//!
//! Drives the v4 protocol engine from the client side: initial Noise_IK
//! handshake with retry/backoff, cookie challenges, PFS rekeying and
//! jittered keepalives.

#[cfg(unix)]
use crate::platform::unix::{
    is_would_block, BatchBuffer, EventLoop, TunDevice, TunnelConfig, UdpTunnel, POLLIN,
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
use twocha_core::v4::{session::keepalive_jitter, ClientHandshake, SealScratch, Session};
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
        transport.as_dyn_mut(),
        cfg.crypto.cipher,
        &identity,
        server_public,
        common::flag(),
    )?;

    transport.as_dyn_mut().set_nonblocking(true)?;

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

    run_data_plane(
        &cfg,
        &identity,
        server_public,
        tun,
        transport,
        session,
        common::flag(),
    )?;

    let _ = routing_ctx.cleanup();

    if !quiet {
        println!("\n  \x1b[32m✓\x1b[0m Disconnected");
    }

    Ok(())
}

/// A built obfuscation transport, kept concrete so the QUIC carrier can be
/// unwrapped for the threaded data plane after the handshake.
#[cfg(unix)]
enum BuiltTransport {
    Quic(UdpQuicClientTransport),
    Tls(TlsClientTransport),
}

#[cfg(unix)]
impl BuiltTransport {
    fn as_dyn_mut(&mut self) -> &mut dyn ClientTransport {
        match self {
            BuiltTransport::Quic(t) => t,
            BuiltTransport::Tls(t) => t,
        }
    }
}

/// Build the selected obfuscation transport. Both carry complete v4 wire
/// datagrams; the QUIC path is byte-identical to the pre-abstraction client.
#[cfg(unix)]
fn build_transport(cfg: &ClientConfig, server_addr: SocketAddr) -> Result<BuiltTransport> {
    let transport = match cfg.client.transport {
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
            BuiltTransport::Quic(UdpQuicClientTransport::new(tunnel, server_addr))
        }
        TransportKind::Tls => {
            // TCP connect + real TLS 1.3 handshake (blocking) happen here.
            let t = TlsClientTransport::connect(server_addr, &cfg.tls.sni).map_err(VpnError::Io)?;
            BuiltTransport::Tls(t)
        }
    };
    Ok(transport)
}

/// Post-handshake dispatch: the QUIC carrier gets the 2-thread split (uplink
/// seals on one thread, downlink + control plane on the other) unless
/// `performance.worker_threads = 1` pins the single-threaded loop. TLS always
/// keeps the single-threaded loop (a TCP stream gains nothing from the split).
#[cfg(unix)]
fn run_data_plane(
    cfg: &ClientConfig,
    identity: &Identity,
    server_public: [u8; 32],
    tun: TunDevice,
    transport: BuiltTransport,
    session: Session,
    running: &AtomicBool,
) -> Result<()> {
    // 0 = auto: the split is the default for QUIC
    let threaded = cfg.performance.worker_threads != 1;
    match transport {
        BuiltTransport::Quic(t) if threaded => {
            let (tunnel, remote) = t.into_parts();
            run_event_loop_threaded(
                cfg,
                identity,
                server_public,
                tun,
                tunnel,
                remote,
                session,
                running,
            )
        }
        mut other => run_event_loop(
            cfg,
            identity,
            server_public,
            &tun,
            other.as_dyn_mut(),
            session,
            running,
        ),
    }
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
    tun: &TunDevice,
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

    let mut bufs = IoBufs::new(cfg);
    let mut next_keepalive = Instant::now() + keepalive_jitter();
    let mut pending: Option<(ClientHandshake, Instant)> = None;

    while running.load(Ordering::SeqCst) {
        let events = event_loop.poll(100)?;

        for (fd, revents) in events {
            if revents & POLLIN != 0 {
                if fd == tun_fd {
                    handle_tun_read(tun, transport, &mut session, &mut bufs)?;
                } else if transport_fds.contains(&fd) {
                    handle_transport_read(transport, tun, &mut session, &mut pending, &mut bufs)?;
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

/// 2-thread data plane for the QUIC transport: the uplink thread owns
/// tun-read → seal → `send_batch_to`, while the calling thread owns
/// UDP-read → open → tun-write plus the whole control plane (keepalives,
/// rekey, cookies). Crypto for the two directions runs on two cores.
///
/// Sharing: `TunDevice` and `UdpTunnel` I/O take `&self` (each thread keeps
/// its own scratch/batch buffers); the session sits in an `RwLock` — read per
/// packet, write only when a rekey installs a fresh session. Scoped threads
/// guarantee the uplink joins before this returns, preserving `run_mobile`'s
/// fd-ownership contract.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn run_event_loop_threaded(
    cfg: &ClientConfig,
    identity: &Identity,
    server_public: [u8; 32],
    tun: TunDevice,
    tunnel: UdpTunnel,
    remote: SocketAddr,
    session: Session,
    running: &AtomicBool,
) -> Result<()> {
    let session = std::sync::RwLock::new(session);
    log::info!("client data plane: 2-thread split (uplink + downlink)");

    std::thread::scope(|scope| {
        let uplink = scope.spawn(|| client_uplink_loop(cfg, &tun, &tunnel, remote, &session, running));

        let downlink_result =
            client_downlink_loop(cfg, identity, server_public, &tun, &tunnel, remote, &session, running);

        // The downlink exits only when `running` flips false (or on a poll
        // error, in which case stop the uplink too instead of leaking it).
        running.store(false, Ordering::SeqCst);
        let uplink_result = uplink.join().unwrap_or_else(|_| {
            Err(VpnError::Config("client uplink thread panicked".into()))
        });
        downlink_result.and(uplink_result)
    })
}

/// Uplink half of the threaded client loop: tun → seal → UDP burst.
#[cfg(unix)]
fn client_uplink_loop(
    cfg: &ClientConfig,
    tun: &TunDevice,
    tunnel: &UdpTunnel,
    remote: SocketAddr,
    session: &std::sync::RwLock<Session>,
    running: &AtomicBool,
) -> Result<()> {
    let mut event_loop = EventLoop::new();
    event_loop.add_fd(tun.fd(), POLLIN);

    let mut tun_buffer = vec![0u8; cfg.tun.mtu as usize + 100];
    let mut scratch = SealScratch::default();
    let flush_at = cfg.performance.batch_size.max(1);
    let mut queue: Vec<Vec<u8>> = Vec::with_capacity(flush_at);
    let mut pool: Vec<Vec<u8>> = Vec::with_capacity(flush_at);

    while running.load(Ordering::SeqCst) {
        let events = event_loop.poll(100)?;
        if events.is_empty() {
            continue;
        }
        loop {
            match tun.read(&mut tun_buffer) {
                Ok(n) if n > 0 => {
                    let mut out = pool.pop().unwrap_or_default();
                    let sealed = session
                        .read()
                        .unwrap()
                        .seal_data_into(&tun_buffer[..n], &mut scratch, &mut out)
                        .is_ok();
                    if sealed {
                        queue.push(out);
                        if queue.len() >= flush_at {
                            let _ = tunnel.send_batch_to(&queue, remote);
                            pool.append(&mut queue);
                        }
                    } else {
                        // Session expired mid-rekey: drop the packet (the
                        // downlink thread is installing a fresh session).
                        pool.push(out);
                    }
                }
                Ok(_) => break,
                Err(e) if is_would_block(&e) => break,
                Err(_) => break,
            }
        }
        if !queue.is_empty() {
            let _ = tunnel.send_batch_to(&queue, remote);
            pool.append(&mut queue);
        }
    }
    Ok(())
}

/// Downlink half + control plane of the threaded client loop.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn client_downlink_loop(
    cfg: &ClientConfig,
    identity: &Identity,
    server_public: [u8; 32],
    tun: &TunDevice,
    tunnel: &UdpTunnel,
    remote: SocketAddr,
    session: &std::sync::RwLock<Session>,
    running: &AtomicBool,
) -> Result<()> {
    let mut event_loop = EventLoop::new();
    event_loop.add_fd(tunnel.fd(), POLLIN);

    let mut batch = BatchBuffer::new(cfg.performance.batch_size);
    let mut payload = Vec::new();
    let mut next_keepalive = Instant::now() + keepalive_jitter();
    let mut pending: Option<(ClientHandshake, Instant)> = None;

    while running.load(Ordering::SeqCst) {
        let events = event_loop.poll(100)?;

        if !events.is_empty() {
            loop {
                let n = match tunnel.recv_batch(&mut batch) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                for i in 0..n {
                    let Some((src, data)) = batch.get(i) else {
                        continue;
                    };
                    if src != remote {
                        continue; // point-to-point filter
                    }
                    match wire::parse(data) {
                        Ok(WireMsg::Data {
                            receiver_cid,
                            masked_counter,
                            ciphertext,
                        }) => {
                            let sess = session.read().unwrap();
                            if receiver_cid != sess.local_cid {
                                continue;
                            }
                            match sess.open_data_into(masked_counter, ciphertext, &mut payload) {
                                Ok(()) if payload.is_empty() => {} // keepalive
                                Ok(()) => {
                                    let _ = tun.write(&payload);
                                }
                                Err(_) => {}
                            }
                        }
                        Ok(WireMsg::Resp { .. }) => {
                            if let Some((hs, _)) = pending.take() {
                                match hs.complete(data) {
                                    Ok(new_session) => {
                                        let mut guard = session.write().unwrap();
                                        log::info!(
                                            "rekey complete (session age was {:?})",
                                            guard.age()
                                        );
                                        *guard = new_session;
                                    }
                                    Err(e) => log::debug!("rekey response rejected: {}", e),
                                }
                            }
                        }
                        Ok(WireMsg::Cookie { nonce, sealed }) => {
                            if let Some((hs, _)) = pending.as_mut() {
                                if hs.apply_cookie(nonce, sealed).is_ok() {
                                    let _ = tunnel.send_to(hs.datagram(), remote);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        let now = Instant::now();

        // PFS ratchet: initiate (or retry) a fresh handshake
        let needs_rekey = {
            let sess = session.read().unwrap();
            sess.should_rekey() || sess.expired()
        };
        let pending_stale = matches!(&pending, Some((_, t)) if t.elapsed() > REKEY_RETRY);
        if (needs_rekey && pending.is_none()) || pending_stale {
            match ClientHandshake::new(cfg.crypto.cipher, identity, server_public) {
                Ok(hs) => {
                    let _ = tunnel.send_to(hs.datagram(), remote);
                    pending = Some((hs, now));
                }
                Err(e) => log::error!("failed to start rekey handshake: {}", e),
            }
        }

        if now >= next_keepalive {
            if let Ok(datagram) = session.read().unwrap().seal_data(&[]) {
                let _ = tunnel.send_to(&datagram, remote);
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
    for fd in transport.as_dyn_mut().pollfds() {
        if !protect(fd) {
            log::warn!("protect(fd={}) returned false; traffic may loop", fd);
        }
    }

    let session = handshake_over_transport(
        transport.as_dyn_mut(),
        cfg.crypto.cipher,
        &identity,
        server_public,
        running,
    )?;

    // Handshake done: the tunnel is genuinely established. Tell the host so it
    // can flip its UI to "connected" (instead of guessing before this point).
    on_connected();

    transport.as_dyn_mut().set_nonblocking(true)?;

    let tun = TunDevice::from_fd(tun_fd, cfg.tun.mtu)?;
    tun.set_nonblocking(true)?;

    run_data_plane(
        &cfg,
        &identity,
        server_public,
        tun,
        transport,
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

/// Reusable data-plane buffers, allocated once per event loop: no per-packet
/// heap traffic on the TX (seal scratch + pooled datagrams) or RX
/// (recvmmsg batch + payload) paths.
#[cfg(unix)]
struct IoBufs {
    tun_buffer: Vec<u8>,
    seal_scratch: SealScratch,
    /// Sealed datagrams awaiting a send_many flush...
    send_queue: Vec<Vec<u8>>,
    /// ...and their recycled allocations after it.
    send_pool: Vec<Vec<u8>>,
    batch: BatchBuffer,
    payload: Vec<u8>,
    flush_at: usize,
}

#[cfg(unix)]
impl IoBufs {
    fn new(cfg: &ClientConfig) -> Self {
        let flush_at = cfg.performance.batch_size.max(1);
        IoBufs {
            tun_buffer: vec![0u8; cfg.tun.mtu as usize + 100],
            seal_scratch: SealScratch::default(),
            send_queue: Vec::with_capacity(flush_at),
            send_pool: Vec::with_capacity(flush_at),
            batch: BatchBuffer::new(cfg.performance.batch_size),
            payload: Vec::new(),
            flush_at,
        }
    }

    fn flush_send_queue(&mut self, transport: &mut dyn ClientTransport) {
        if self.send_queue.is_empty() {
            return;
        }
        let _ = transport.send_many(&self.send_queue);
        self.send_pool.append(&mut self.send_queue);
    }
}

#[cfg(unix)]
fn handle_tun_read(
    tun: &TunDevice,
    transport: &mut dyn ClientTransport,
    session: &mut Session,
    bufs: &mut IoBufs,
) -> Result<()> {
    loop {
        match tun.read(&mut bufs.tun_buffer) {
            Ok(n) if n > 0 => {
                let mut out = bufs.send_pool.pop().unwrap_or_default();
                match session.seal_data_into(
                    &bufs.tun_buffer[..n],
                    &mut bufs.seal_scratch,
                    &mut out,
                ) {
                    Ok(()) => {
                        bufs.send_queue.push(out);
                        if bufs.send_queue.len() >= bufs.flush_at {
                            bufs.flush_send_queue(transport);
                        }
                    }
                    Err(_) => bufs.send_pool.push(out),
                }
            }
            Ok(_) => break,
            Err(e) if is_would_block(&e) => break,
            Err(_) => break,
        }
    }
    bufs.flush_send_queue(transport);
    Ok(())
}

#[cfg(unix)]
fn handle_transport_read(
    transport: &mut dyn ClientTransport,
    tun: &TunDevice,
    session: &mut Session,
    pending: &mut Option<(ClientHandshake, Instant)>,
    bufs: &mut IoBufs,
) -> Result<()> {
    loop {
        let n = match transport.recv_batch(&mut bufs.batch) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        for i in 0..n {
            let Some((_, data)) = bufs.batch.get(i) else {
                continue; // skipped slot (truncated / spoofed source)
            };
            match wire::parse(data) {
                Ok(WireMsg::Data {
                    receiver_cid,
                    masked_counter,
                    ciphertext,
                }) => {
                    if receiver_cid != session.local_cid {
                        continue;
                    }
                    match session.open_data_into(masked_counter, ciphertext, &mut bufs.payload) {
                        Ok(()) if bufs.payload.is_empty() => {} // keepalive
                        Ok(()) => {
                            let _ = tun.write(&bufs.payload);
                        }
                        Err(_) => {}
                    }
                }
                Ok(WireMsg::Resp { .. }) => {
                    if let Some((hs, _)) = pending.take() {
                        match hs.complete(data) {
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

    /// Default config: worker_threads = 0 (auto) → 2-thread split on QUIC.
    #[test]
    fn run_mobile_loopback_roundtrip() {
        loopback_roundtrip("");
    }

    /// worker_threads = 1 pins the single-threaded event loop.
    #[test]
    fn run_mobile_loopback_roundtrip_single_thread() {
        loopback_roundtrip("[performance]\nworker_threads = 1\n");
    }

    /// Drive `run_mobile` end-to-end over real loopback sockets against a
    /// minimal in-process v4 server: assert the `protect` callback fires for
    /// the transport's pollfd(s) before the handshake, that a tun packet seals
    /// out to the server, and that a server reply round-trips back to the tun.
    ///
    /// Uses a `UnixDatagram` socketpair as the "tun fd" — `TunDevice::from_fd`
    /// only does `read`/`write` on it, so message boundaries behave like a tun.
    fn loopback_roundtrip(extra_toml: &str) {
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
             server_public_key = \"{}\"\n[tun]\nmtu = 1400\n{extra_toml}",
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
