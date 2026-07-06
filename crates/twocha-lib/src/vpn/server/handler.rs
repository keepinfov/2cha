//! # Server Handler
//!
//! Drives the v4 protocol engine with real I/O: accepts Noise_IK handshakes
//! from whitelisted peers, maintains CID-keyed sessions with roaming, and
//! never responds to unauthenticated traffic.

#[cfg(unix)]
use crate::platform::unix::{
    is_would_block, routing, BatchBuffer, EventLoop, TunDevice, TunnelConfig, UdpTunnel, POLLIN,
};
#[cfg(feature = "reality")]
use crate::transport::reality::RealityServerListener;
#[cfg(unix)]
use crate::transport::tls::TlsServerListener;
#[cfg(unix)]
use crate::transport::{StreamServerConn, StreamServerListener};

use crate::vpn::common;
#[cfg(unix)]
use crate::vpn::server::control::{ControlListener, CtlRequest};
#[cfg(unix)]
use std::path::Path;

#[cfg(unix)]
use std::collections::{HashMap, HashSet};
#[cfg(unix)]
use std::net::{IpAddr, SocketAddr};
#[cfg(unix)]
use std::os::unix::io::RawFd;
#[cfg(unix)]
use std::sync::{mpsc, Arc};
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::{Duration, Instant};
#[cfg(unix)]
use twocha_core::v4::{
    session::keepalive_jitter, InitOutcome, RateLimiter, SealScratch, ServerHandshakeEngine,
    Session,
};
#[cfg(unix)]
use twocha_core::{ServerConfig, TransportKind};
#[cfg(unix)]
use twocha_protocol::wire::{self, WireMsg, CID_LEN};
use twocha_protocol::Result;
#[cfg(unix)]
use twocha_protocol::VpnError;

/// Rotate the cookie secret this often (bounds cookie usefulness)
#[cfg(unix)]
const COOKIE_ROTATE_INTERVAL: Duration = Duration::from_secs(120);
#[cfg(unix)]
const CLEANUP_INTERVAL: Duration = Duration::from_secs(10);

/// How a session's packets reach the peer. UDP carries the peer's address
/// (which can roam); a stream transport (TLS or REALITY) pins the session to
/// a specific accepted connection, identified by its per-listener id.
#[cfg(unix)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Link {
    Udp(SocketAddr),
    Stream(u64),
}

#[cfg(unix)]
impl std::fmt::Display for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Link::Udp(addr) => write!(f, "{}", addr),
            Link::Stream(id) => write!(f, "stream#{}", id),
        }
    }
}

#[cfg(unix)]
struct SessionEntry {
    session: Session,
    peer_public: [u8; 32],
    link: Link,
    next_keepalive: Instant,
}

#[cfg(unix)]
struct ServerState {
    engine: ServerHandshakeEngine,
    limiter: RateLimiter,
    allowed: HashSet<[u8; 32]>,
    /// Optional labels for log/list output, keyed by peer public key
    peer_names: HashMap<[u8; 32], String>,
    max_clients: usize,
    /// Established sessions keyed by our receive-CID
    sessions: HashMap<[u8; CID_LEN], SessionEntry>,
    /// Current session per peer static key (new handshake replaces old)
    cid_by_peer: HashMap<[u8; 32], [u8; CID_LEN]>,
    /// Learned inner tunnel IP -> session (for TUN->UDP routing)
    cid_by_inner_ip: HashMap<IpAddr, [u8; CID_LEN]>,
    idle_timeout: Duration,
}

#[cfg(unix)]
impl ServerState {
    fn install_session(&mut self, session: Session, peer_public: [u8; 32], link: Link) {
        let cid = session.local_cid;
        if let Some(old_cid) = self.cid_by_peer.insert(peer_public, cid) {
            self.sessions.remove(&old_cid);
            self.cid_by_inner_ip.retain(|_, c| *c != old_cid);
        }
        self.sessions.insert(
            cid,
            SessionEntry {
                session,
                peer_public,
                link,
                next_keepalive: Instant::now() + keepalive_jitter(),
            },
        );
        log::info!(
            "session established with {} (peers online: {})",
            link,
            self.sessions.len()
        );
    }

    /// Drop any session bound to `link` and scrub it from the routing indices.
    /// Used by the TLS loop when a connection closes or is reaped.
    fn drop_link(&mut self, link: Link) {
        let cids: Vec<[u8; CID_LEN]> = self
            .sessions
            .iter()
            .filter(|(_, e)| e.link == link)
            .map(|(cid, _)| *cid)
            .collect();
        for cid in cids {
            if let Some(entry) = self.sessions.remove(&cid) {
                if self.cid_by_peer.get(&entry.peer_public) == Some(&cid) {
                    self.cid_by_peer.remove(&entry.peer_public);
                }
            }
            self.cid_by_inner_ip.retain(|_, c| *c != cid);
        }
    }

    fn cleanup(&mut self) {
        let idle = self.idle_timeout;
        let mut dead: Vec<[u8; CID_LEN]> = Vec::new();
        for (cid, entry) in &self.sessions {
            let expired = entry.session.expired()
                && entry.session.last_recv_elapsed() > Duration::from_secs(10);
            let idled = entry.session.last_recv_elapsed() > idle;
            if expired || idled {
                dead.push(*cid);
            }
        }
        for cid in dead {
            if let Some(entry) = self.sessions.remove(&cid) {
                log::info!("session with {} closed (expired/idle)", entry.link);
                if self.cid_by_peer.get(&entry.peer_public) == Some(&cid) {
                    self.cid_by_peer.remove(&entry.peer_public);
                }
            }
            self.cid_by_inner_ip.retain(|_, c| *c != cid);
        }
    }
}

/// Run the VPN server
#[cfg(unix)]
pub fn run(config_path: &str) -> Result<()> {
    let cfg =
        ServerConfig::from_file(config_path).map_err(|e| VpnError::Config(format!("{}", e)))?;

    let listen_addr = cfg
        .listen_addr()
        .map_err(|e| VpnError::Config(format!("{}", e)))?;
    let identity = cfg
        .identity()
        .map_err(|e| VpnError::Config(format!("{}", e)))?;
    let peer_keys = cfg
        .peer_keys()
        .map_err(|e| VpnError::Config(format!("{}", e)))?;

    log::info!("Starting 2cha server (protocol v4)...");
    log::info!("Server public key: {}", identity.public_base64());

    // Opt-in worker pool: QUIC + Linux + performance.worker_threads >= 2.
    // It needs a multi-queue TUN, so force the flag on when active.
    let workers = if cfg.server.transport == TransportKind::Quic && cfg!(target_os = "linux") {
        cfg.performance.worker_threads
    } else {
        0
    };
    let multi_queue = cfg.performance.multi_queue || workers >= 2;
    if workers >= 2 && !cfg.performance.multi_queue {
        log::info!("worker_threads = {}: enabling multi-queue tun", workers);
    }

    // Create TUN device
    let mut tun = TunDevice::create_with_options(&cfg.tun.name, multi_queue)?;

    // Configure IPv4
    if cfg.ipv4.enable {
        if let Some(addr) = cfg
            .tun_ipv4()
            .map_err(|e| VpnError::Config(format!("{}", e)))?
        {
            tun.set_ipv4_address(addr, cfg.ipv4.prefix)?;
            log::info!("IPv4: {}/{}", addr, cfg.ipv4.prefix);
        }
    }

    // Configure IPv6
    if cfg.ipv6.enable {
        if let Some(addr) = cfg
            .tun_ipv6()
            .map_err(|e| VpnError::Config(format!("{}", e)))?
        {
            tun.set_ipv6_address(addr, cfg.ipv6.prefix)?;
            log::info!("IPv6: {}/{}", addr, cfg.ipv6.prefix);
        }
    }

    tun.set_mtu(cfg.tun.mtu)?;
    tun.bring_up()?;
    tun.set_nonblocking(true)?;

    // Setup gateway/routing, tracking what we apply so it can be rolled back
    // on shutdown.
    let mut routing_ctx = routing::ServerRoutingContext::new();
    if cfg.gateway.ip_forward {
        if let Some(ref iface) = cfg.gateway.external_interface {
            if cfg.ipv4.enable {
                let subnet = format!(
                    "{}/{}",
                    cfg.ipv4.address.as_deref().unwrap_or("10.0.0.0"),
                    cfg.ipv4.prefix
                );
                if let Err(e) = routing_ctx.setup_v4(iface, &subnet, tun.name()) {
                    log::error!("Failed to setup IPv4 gateway: {}", e);
                }
            }
        }
    }

    if cfg.gateway.ip6_forward {
        if let Some(ref iface) = cfg.gateway.external_interface {
            if cfg.ipv6.enable {
                if let Some(ref addr) = cfg.ipv6.address {
                    let subnet = format!("{}/{}", addr, cfg.ipv6.prefix);
                    if let Err(e) = routing_ctx.setup_v6(iface, &subnet, tun.name()) {
                        log::error!("Failed to setup IPv6 gateway: {}", e);
                    }
                }
            }
        }
    }

    common::reset_running();
    common::setup_signal_handler();

    let mut event_loop = EventLoop::new();
    event_loop.add_fd(tun.fd(), POLLIN);

    // Runtime peer management socket (the server still runs without it)
    let control = match ControlListener::bind() {
        Ok(ctl) => {
            event_loop.add_fd(ctl.fd(), POLLIN);
            Some(ctl)
        }
        Err(e) => {
            log::warn!("peer management disabled: {}", e);
            None
        }
    };

    let peer_names: HashMap<[u8; 32], String> = peer_keys
        .iter()
        .zip(&cfg.peers)
        .filter_map(|(pk, peer)| peer.name.clone().map(|n| (*pk, n)))
        .collect();

    let mut state = ServerState {
        engine: ServerHandshakeEngine::new(cfg.crypto.cipher, &identity),
        limiter: RateLimiter::new(),
        allowed: peer_keys.into_iter().collect(),
        peer_names,
        max_clients: cfg.server.max_clients,
        sessions: HashMap::new(),
        cid_by_peer: HashMap::new(),
        cid_by_inner_ip: HashMap::new(),
        idle_timeout: Duration::from_secs(cfg.timeouts.session),
    };

    log::info!(
        "Server ready. Authorized peers: {}, max clients: {}, transport: {}",
        state.allowed.len(),
        state.max_clients,
        cfg.server.transport
    );

    #[cfg(target_os = "linux")]
    let serve_result = if workers >= 2 && cfg.server.transport == TransportKind::Quic {
        // Multi-worker pool consumes the tun (one queue per worker) and
        // builds its own shared state; `state` stays unused on this path.
        let ServerState {
            engine,
            allowed,
            peer_names,
            ..
        } = state;
        super::workers::serve_udp_workers(
            &cfg,
            config_path,
            tun,
            engine,
            allowed,
            peer_names,
            control.as_ref(),
            listen_addr,
            workers,
        )
    } else {
        serve_transport(
            &cfg,
            config_path,
            &mut tun,
            &mut state,
            &mut event_loop,
            control.as_ref(),
            listen_addr,
        )
    };
    #[cfg(not(target_os = "linux"))]
    let serve_result = serve_transport(
        &cfg,
        config_path,
        &mut tun,
        &mut state,
        &mut event_loop,
        control.as_ref(),
        listen_addr,
    );

    // Roll back NAT/forwarding regardless of how the loop exited.
    routing_ctx.cleanup();

    serve_result?;
    log::info!("Server shutdown");
    Ok(())
}

/// Single-threaded transport dispatch (the pre-worker-pool behaviour).
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn serve_transport(
    cfg: &ServerConfig,
    config_path: &str,
    tun: &mut TunDevice,
    state: &mut ServerState,
    event_loop: &mut EventLoop,
    control: Option<&ControlListener>,
    listen_addr: SocketAddr,
) -> Result<()> {
    match cfg.server.transport {
        TransportKind::Quic => serve_udp(
            cfg,
            config_path,
            tun,
            state,
            event_loop,
            control,
            listen_addr,
        ),
        TransportKind::Tls => serve_tls(
            cfg,
            config_path,
            tun,
            state,
            event_loop,
            control,
            listen_addr,
        ),
        TransportKind::Reality => serve_reality_dispatch(
            cfg,
            config_path,
            tun,
            state,
            event_loop,
            control,
            listen_addr,
        ),
    }
}

/// REALITY transport dispatch. Errors cleanly unless compiled with
/// `--features reality`.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn serve_reality_dispatch(
    cfg: &ServerConfig,
    config_path: &str,
    tun: &mut TunDevice,
    state: &mut ServerState,
    event_loop: &mut EventLoop,
    control: Option<&ControlListener>,
    listen_addr: SocketAddr,
) -> Result<()> {
    #[cfg(feature = "reality")]
    {
        serve_reality(
            cfg,
            config_path,
            tun,
            state,
            event_loop,
            control,
            listen_addr,
        )
    }
    #[cfg(not(feature = "reality"))]
    {
        let _ = (
            cfg,
            config_path,
            tun,
            state,
            event_loop,
            control,
            listen_addr,
        );
        Err(VpnError::Config(
            "reality transport requires building with --features reality".into(),
        ))
    }
}

/// Periodic maintenance shared by both transport loops: rotate the cookie
/// secret and expire idle/dead sessions.
#[cfg(unix)]
fn rotate_and_cleanup(
    state: &mut ServerState,
    last_cookie_rotate: &mut Instant,
    last_cleanup: &mut Instant,
) {
    let now = Instant::now();
    if last_cookie_rotate.elapsed() > COOKIE_ROTATE_INTERVAL {
        state.engine.rotate_cookie_secret();
        *last_cookie_rotate = now;
    }
    if last_cleanup.elapsed() > CLEANUP_INTERVAL {
        state.cleanup();
        *last_cleanup = now;
    }
}

/// UDP / QUIC-mimicry transport loop. Behaviour is identical to the
/// pre-abstraction server: one socket, demux by CID, recvmmsg batching,
/// address roaming.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn serve_udp(
    cfg: &ServerConfig,
    config_path: &str,
    tun: &mut TunDevice,
    state: &mut ServerState,
    event_loop: &mut EventLoop,
    control: Option<&ControlListener>,
    listen_addr: SocketAddr,
) -> Result<()> {
    let tunnel_config = TunnelConfig {
        local_addr: listen_addr,
        read_timeout: Some(Duration::from_millis(10)),
        recv_buffer_size: cfg.performance.socket_recv_buffer,
        send_buffer_size: cfg.performance.socket_send_buffer,
        ..Default::default()
    };

    let tunnel = UdpTunnel::new(tunnel_config)?;
    tunnel.set_nonblocking(true)?;
    event_loop.add_fd(tunnel.fd(), POLLIN);

    log::info!("Listening on {} (udp/quic)", listen_addr);

    let mut last_cleanup = Instant::now();
    let mut last_cookie_rotate = Instant::now();
    let mut tun_buffer = vec![0u8; cfg.tun.mtu as usize + 100];
    let mut udp_batch = BatchBuffer::new(cfg.performance.batch_size);
    let mut send_queue: Vec<(Vec<u8>, SocketAddr)> = Vec::with_capacity(udp_batch.capacity());
    let mut send_pool: Vec<Vec<u8>> = Vec::with_capacity(udp_batch.capacity());
    let mut seal_scratch = SealScratch::default();
    let mut payload_buf = Vec::new();

    while common::running() {
        let events = event_loop.poll(100)?;

        for (fd, revents) in events {
            if revents & POLLIN != 0 {
                if fd == tun.fd() {
                    handle_tun_read(
                        tun,
                        &mut tun_buffer,
                        &tunnel,
                        state,
                        &mut send_queue,
                        &mut send_pool,
                        &mut seal_scratch,
                    )?;
                } else if fd == tunnel.fd() {
                    handle_udp_read(&tunnel, tun, state, &mut udp_batch, &mut payload_buf)?;
                } else if let Some(ctl) = control {
                    if fd == ctl.fd() {
                        ctl.process(|req| handle_control(req, state, config_path));
                    }
                }
            }
        }

        rotate_and_cleanup(state, &mut last_cookie_rotate, &mut last_cleanup);

        // Keepalives keep NAT bindings open and break the silence pattern
        let now = Instant::now();
        for entry in state.sessions.values_mut() {
            if now >= entry.next_keepalive {
                if let Link::Udp(addr) = entry.link {
                    if let Ok(datagram) = entry.session.seal_data(&[]) {
                        let _ = tunnel.send_to(&datagram, addr);
                    }
                }
                entry.next_keepalive = now + keepalive_jitter();
            }
        }
    }

    Ok(())
}

/// Build the TLS listener from configured cert/key, or a fresh self-signed
/// certificate for the configured SNI when none is supplied.
#[cfg(unix)]
fn build_tls_listener(cfg: &ServerConfig, listen_addr: SocketAddr) -> Result<TlsServerListener> {
    match (&cfg.tls.cert_file, &cfg.tls.key_file) {
        (Some(cert), Some(key)) => {
            let cert_pem = std::fs::read(cert).map_err(VpnError::Io)?;
            let key_pem = std::fs::read(key).map_err(VpnError::Io)?;
            TlsServerListener::bind(listen_addr, &cert_pem, &key_pem).map_err(VpnError::Io)
        }
        (None, None) => {
            log::info!(
                "tls: no cert/key configured, generating self-signed cert for {}",
                cfg.tls.sni
            );
            TlsServerListener::bind_self_signed(listen_addr, &cfg.tls.sni).map_err(VpnError::Io)
        }
        _ => Err(VpnError::Config(
            "tls.cert_file and tls.key_file must both be set or both omitted".into(),
        )),
    }
}

/// Outcome of a background handshake thread, fed back to the reactor over a
/// channel so a slow or adversarial handshake never blocks it.
#[cfg(unix)]
enum HandshakeOutcome<C> {
    Established(C),
    /// Peer was rejected and already handled (e.g. a REALITY probe relayed to
    /// its decoy `dest`) — nothing to register.
    Rejected,
    Failed(SocketAddr, std::io::Error),
}

/// Drain the listener's accept backlog (cheap and non-blocking) and hand each
/// accepted TCP stream to a fresh thread to run the transport handshake.
///
/// The handshake itself can block for a long time: a REALITY probe that fails
/// auth gets relayed to a decoy `dest` inside the Go core, and the call
/// doesn't return until that connection closes — a duration an attacker
/// controls. Even a real TLS handshake is an attacker-paced network round
/// trip. Running either inline on the single-threaded reactor would stall
/// every other connection for as long as it takes.
#[cfg(unix)]
fn spawn_accepts<L: StreamServerListener>(
    listener: &Arc<L>,
    tx: &mpsc::Sender<HandshakeOutcome<L::Conn>>,
    proto: &str,
) {
    loop {
        match listener.accept_raw() {
            Ok(Some((stream, peer))) => {
                let listener = Arc::clone(listener);
                let tx = tx.clone();
                thread::spawn(move || {
                    let outcome = match listener.handshake(stream, peer) {
                        Ok(Some(conn)) => HandshakeOutcome::Established(conn),
                        Ok(None) => HandshakeOutcome::Rejected,
                        Err(e) => HandshakeOutcome::Failed(peer, e),
                    };
                    let _ = tx.send(outcome);
                });
            }
            Ok(None) => break,
            // A failed raw TCP accept is not fatal: log and keep serving.
            Err(e) => {
                log::debug!("{proto}: accept failed: {}", e);
                break;
            }
        }
    }
}

/// Stream-oriented transport loop shared by TLS and REALITY: each client is a
/// separate TCP connection with its own poll fd; sessions are pinned to a
/// connection (no address roaming).
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn serve_stream<L: StreamServerListener>(
    proto: &str,
    listener: L,
    cfg: &ServerConfig,
    config_path: &str,
    tun: &mut TunDevice,
    state: &mut ServerState,
    event_loop: &mut EventLoop,
    control: Option<&ControlListener>,
    listen_addr: SocketAddr,
) -> Result<()> {
    listener.set_nonblocking(true).map_err(VpnError::Io)?;
    let listener_fd = listener.pollfd();
    event_loop.add_fd(listener_fd, POLLIN);
    let listener = Arc::new(listener);

    log::info!("Listening on {} ({})", listen_addr, proto);

    let mut conns: HashMap<u64, L::Conn> = HashMap::new();
    let mut fd_to_conn: HashMap<RawFd, u64> = HashMap::new();
    let mut last_active: HashMap<u64, Instant> = HashMap::new();
    let mut next_conn_id: u64 = 1;

    let mut last_cleanup = Instant::now();
    let mut last_cookie_rotate = Instant::now();
    let mut tun_buffer = vec![0u8; cfg.tun.mtu as usize + 100];
    let mut seal_scratch = SealScratch::default();
    let mut seal_out = Vec::new();
    let mut payload_buf = Vec::new();
    let (handshake_tx, handshake_rx) = mpsc::channel::<HandshakeOutcome<L::Conn>>();

    while common::running() {
        let events = event_loop.poll(100)?;
        let mut to_drop: Vec<u64> = Vec::new();

        for (fd, revents) in events {
            if revents & POLLIN == 0 {
                continue;
            }
            if fd == tun.fd() {
                handle_tun_read_stream(
                    tun,
                    &mut tun_buffer,
                    state,
                    &mut conns,
                    &mut seal_scratch,
                    &mut seal_out,
                )?;
            } else if fd == listener_fd {
                spawn_accepts(&listener, &handshake_tx, proto);
            } else if let Some(&id) = fd_to_conn.get(&fd) {
                match handle_conn_read(id, tun, state, &mut conns, &mut payload_buf) {
                    Ok(true) => {
                        last_active.insert(id, Instant::now());
                    }
                    Ok(false) => {}
                    Err(_) => to_drop.push(id),
                }
            } else if let Some(ctl) = control {
                if fd == ctl.fd() {
                    ctl.process(|req| handle_control(req, state, config_path));
                }
            }
        }

        // Register connections whose handshake finished on a background
        // thread since the last iteration (bounded by the 100ms poll above).
        while let Ok(outcome) = handshake_rx.try_recv() {
            match outcome {
                HandshakeOutcome::Established(mut conn) => {
                    if let Err(e) = conn.set_nonblocking(true) {
                        log::warn!("{proto}: set_nonblocking failed: {}", e);
                        continue;
                    }
                    let id = next_conn_id;
                    next_conn_id += 1;
                    let cfd = conn.pollfd();
                    event_loop.add_fd(cfd, POLLIN);
                    fd_to_conn.insert(cfd, id);
                    last_active.insert(id, Instant::now());
                    conns.insert(id, conn);
                    log::debug!("{proto}: accepted connection {} ({} open)", id, conns.len());
                }
                HandshakeOutcome::Rejected => {}
                HandshakeOutcome::Failed(peer, e) => {
                    log::debug!("{proto}: handshake with {} failed: {}", peer, e);
                }
            }
        }

        for id in to_drop {
            log::debug!("{proto}: closing connection {}", id);
            drop_conn(
                id,
                event_loop,
                &mut conns,
                &mut fd_to_conn,
                &mut last_active,
                state,
            );
        }

        rotate_and_cleanup(state, &mut last_cookie_rotate, &mut last_cleanup);

        // Reap idle connections: never-handshaked probes and peers whose
        // session was dropped (revocation / expiry) but whose TCP stays open.
        let idle = state.idle_timeout;
        let stale: Vec<u64> = last_active
            .iter()
            .filter(|(_, t)| t.elapsed() > idle)
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            log::debug!("{proto}: reaping idle connection {}", id);
            drop_conn(
                id,
                event_loop,
                &mut conns,
                &mut fd_to_conn,
                &mut last_active,
                state,
            );
        }

        let now = Instant::now();
        for entry in state.sessions.values_mut() {
            if now >= entry.next_keepalive {
                if let Link::Stream(id) = entry.link {
                    if let Some(conn) = conns.get_mut(&id) {
                        if let Ok(datagram) = entry.session.seal_data(&[]) {
                            let _ = conn.send(&datagram);
                        }
                    }
                }
                entry.next_keepalive = now + keepalive_jitter();
            }
        }
    }

    Ok(())
}

/// TLS-over-TCP transport loop: builds the listener and hands it to the
/// stream-transport loop shared with REALITY.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn serve_tls(
    cfg: &ServerConfig,
    config_path: &str,
    tun: &mut TunDevice,
    state: &mut ServerState,
    event_loop: &mut EventLoop,
    control: Option<&ControlListener>,
    listen_addr: SocketAddr,
) -> Result<()> {
    let listener = build_tls_listener(cfg, listen_addr)?;
    let proto = format!("tls/tcp, sni={}", cfg.tls.sni);
    serve_stream(
        &proto,
        listener,
        cfg,
        config_path,
        tun,
        state,
        event_loop,
        control,
        listen_addr,
    )
}

/// Close a connection: deregister its fd, forget it, and drop any session
/// pinned to it. Idempotent.
#[cfg(unix)]
fn drop_conn<C: StreamServerConn>(
    id: u64,
    event_loop: &mut EventLoop,
    conns: &mut HashMap<u64, C>,
    fd_to_conn: &mut HashMap<RawFd, u64>,
    last_active: &mut HashMap<u64, Instant>,
    state: &mut ServerState,
) {
    if let Some(conn) = conns.remove(&id) {
        let fd = conn.pollfd();
        event_loop.remove_fd(fd);
        fd_to_conn.remove(&fd);
    }
    last_active.remove(&id);
    state.drop_link(Link::Stream(id));
}

/// Read all available datagrams off one connection. Returns whether any
/// datagram was processed; an `Err` means the connection is dead (EOF / error)
/// and should be dropped.
#[cfg(unix)]
fn handle_conn_read<C: StreamServerConn>(
    id: u64,
    tun: &mut TunDevice,
    state: &mut ServerState,
    conns: &mut HashMap<u64, C>,
    payload_buf: &mut Vec<u8>,
) -> Result<bool> {
    let mut buf = Vec::new();
    let mut got_any = false;
    while let Some(conn) = conns.get_mut(&id) {
        let peer = conn.peer_addr();
        let ready = match conn.recv(&mut buf) {
            Ok(ready) => ready,
            Err(e) => return Err(VpnError::Io(e)),
        };
        if !ready {
            break;
        }
        got_any = true;
        if let Some(reply) = handle_datagram(tun, state, peer, Link::Stream(id), &buf, payload_buf)
        {
            if let Some(conn) = conns.get_mut(&id) {
                let _ = conn.send(&reply);
            }
        }
    }
    Ok(got_any)
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn handle_tun_read(
    tun: &mut TunDevice,
    buffer: &mut [u8],
    tunnel: &UdpTunnel,
    state: &mut ServerState,
    send_queue: &mut Vec<(Vec<u8>, SocketAddr)>,
    send_pool: &mut Vec<Vec<u8>>,
    scratch: &mut SealScratch,
) -> Result<()> {
    // Datagram allocations are recycled through `send_pool` across flushes,
    // so the steady-state TX path allocates nothing.
    fn flush(
        tunnel: &UdpTunnel,
        send_queue: &mut Vec<(Vec<u8>, SocketAddr)>,
        send_pool: &mut Vec<Vec<u8>>,
    ) {
        let _ = tunnel.send_batch(send_queue);
        send_pool.extend(send_queue.drain(..).map(|(datagram, _)| datagram));
    }

    send_queue.clear();
    let flush_at = send_queue.capacity().max(1);
    loop {
        match tun.read(buffer) {
            Ok(n) if n > 0 => {
                let packet = &buffer[..n];
                let Some(dst) = common::inner_dst_ip(packet) else {
                    continue;
                };
                let Some(cid) = state.cid_by_inner_ip.get(&dst) else {
                    log::trace!("no session for inner destination {}", dst);
                    continue;
                };
                if let Some(entry) = state.sessions.get_mut(cid) {
                    if let Link::Udp(addr) = entry.link {
                        let mut datagram = send_pool.pop().unwrap_or_default();
                        match entry.session.seal_data_into(packet, scratch, &mut datagram) {
                            Ok(()) => {
                                send_queue.push((datagram, addr));
                                if send_queue.len() >= flush_at {
                                    flush(tunnel, send_queue, send_pool);
                                }
                            }
                            Err(_) => send_pool.push(datagram),
                        }
                    }
                }
            }
            Ok(_) => break,
            Err(e) if is_would_block(&e) => break,
            Err(_) => break,
        }
    }
    if !send_queue.is_empty() {
        flush(tunnel, send_queue, send_pool);
    }
    Ok(())
}

/// TUN -> stream transport: seal each inbound packet for its session and
/// write it down the pinned connection. The transport handles its own framing.
#[cfg(unix)]
fn handle_tun_read_stream<C: StreamServerConn>(
    tun: &mut TunDevice,
    buffer: &mut [u8],
    state: &mut ServerState,
    conns: &mut HashMap<u64, C>,
    scratch: &mut SealScratch,
    seal_out: &mut Vec<u8>,
) -> Result<()> {
    loop {
        match tun.read(buffer) {
            Ok(n) if n > 0 => {
                let packet = &buffer[..n];
                let Some(dst) = common::inner_dst_ip(packet) else {
                    continue;
                };
                let Some(cid) = state.cid_by_inner_ip.get(&dst).copied() else {
                    log::trace!("no session for inner destination {}", dst);
                    continue;
                };
                if let Some(entry) = state.sessions.get_mut(&cid) {
                    if let Link::Stream(id) = entry.link {
                        // seal_out is copied into the transport's internal
                        // buffer by send(), so reusing it across packets is safe.
                        if entry
                            .session
                            .seal_data_into(packet, scratch, seal_out)
                            .is_ok()
                        {
                            if let Some(conn) = conns.get_mut(&id) {
                                let _ = conn.send(seal_out);
                            }
                        }
                    }
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
fn handle_udp_read(
    tunnel: &UdpTunnel,
    tun: &mut TunDevice,
    state: &mut ServerState,
    batch: &mut BatchBuffer,
    payload_buf: &mut Vec<u8>,
) -> Result<()> {
    loop {
        match tunnel.recv_batch(batch) {
            Ok(0) => break,
            Ok(n) => {
                for i in 0..n {
                    let Some((src, data)) = batch.get(i) else {
                        continue;
                    };
                    if let Some(reply) =
                        handle_datagram(tun, state, src, Link::Udp(src), data, payload_buf)
                    {
                        let _ = tunnel.send_to(&reply, src);
                    }
                }
            }
            Err(e) if is_would_block(&e) => break,
            Err(_) => break,
        }
    }
    Ok(())
}

/// Apply a control-socket request to the live server state.
/// Changes are persisted to the config file so they survive restarts.
#[cfg(unix)]
fn handle_control(req: CtlRequest, state: &mut ServerState, config_path: &str) -> String {
    match req {
        CtlRequest::PeerAdd { key, name } => {
            let pk = match twocha_core::decode_public_key(&key) {
                Ok(pk) => pk,
                Err(e) => return format!("err {}", e),
            };
            let added = state.allowed.insert(pk);
            if let Some(ref n) = name {
                state.peer_names.insert(pk, n.clone());
            }
            let verb = if added { "added" } else { "updated" };
            log::info!(
                "control: {} peer {} ({})",
                verb,
                key,
                name.as_deref().unwrap_or("-")
            );
            match twocha_core::upsert_peer_in_file(Path::new(config_path), &key, name.as_deref()) {
                Ok(()) => format!("ok {} {}", verb, key),
                Err(e) => format!("ok {} {} (warning: not persisted: {})", verb, key, e),
            }
        }
        CtlRequest::PeerRemove { key } => {
            let pk = match twocha_core::decode_public_key(&key) {
                Ok(pk) => pk,
                Err(e) => return format!("err {}", e),
            };
            let existed = state.allowed.remove(&pk);
            state.peer_names.remove(&pk);
            // Revocation must drop the active session immediately
            if let Some(cid) = state.cid_by_peer.remove(&pk) {
                if let Some(entry) = state.sessions.remove(&cid) {
                    log::info!("session with {} closed (peer removed)", entry.link);
                }
                state.cid_by_inner_ip.retain(|_, c| *c != cid);
            }
            log::info!("control: removed peer {}", key);
            let persist = twocha_core::remove_peer_from_file(Path::new(config_path), &key);
            let mut reply = format!("ok removed {}", key);
            if !existed {
                reply.push_str(" (warning: key was not in the whitelist)");
            }
            if let Err(e) = persist {
                reply.push_str(&format!(" (warning: not persisted: {})", e));
            }
            reply
        }
        CtlRequest::PeerList => {
            let mut out = format!("ok {} peers", state.allowed.len());
            let mut keys: Vec<&[u8; 32]> = state.allowed.iter().collect();
            keys.sort();
            for pk in keys {
                let b64 = twocha_core::encode_public_key(pk);
                let name = state.peer_names.get(pk).map(String::as_str).unwrap_or("-");
                match state
                    .cid_by_peer
                    .get(pk)
                    .and_then(|cid| state.sessions.get(cid))
                {
                    Some(entry) => {
                        out.push_str(&format!(
                            "\npeer {} {} online endpoint={} last_recv_secs={}",
                            b64,
                            name,
                            entry.link,
                            entry.session.last_recv_elapsed().as_secs()
                        ));
                    }
                    None => out.push_str(&format!("\npeer {} {} offline", b64, name)),
                }
            }
            out
        }
    }
}

/// Process one inbound datagram. Transport-neutral: returns an optional reply
/// datagram for the caller to send back over the originating link (UDP socket
/// or TLS connection). All failure paths are silent drops (`None`).
/// `payload_buf` is loop-hoisted scratch for the decrypted payload.
#[cfg(unix)]
fn handle_datagram(
    tun: &mut TunDevice,
    state: &mut ServerState,
    src: SocketAddr,
    src_link: Link,
    data: &[u8],
    payload_buf: &mut Vec<u8>,
) -> Option<Vec<u8>> {
    let msg = wire::parse(data).ok()?;

    match msg {
        WireMsg::Init { .. } => {
            // Per-IP budget exceeded: drop before any crypto
            if !state.limiter.allow(src.ip()) {
                return None;
            }
            let under_load = state.limiter.under_load();
            let allowed = &state.allowed;
            let outcome = state
                .engine
                .handle_init(data, &src, under_load, |pk| allowed.contains(pk));
            match outcome {
                InitOutcome::Established {
                    datagram,
                    session,
                    peer_public,
                } => {
                    let is_new_peer = !state.cid_by_peer.contains_key(&peer_public);
                    if is_new_peer && state.cid_by_peer.len() >= state.max_clients {
                        log::warn!("max_clients reached, dropping handshake from {}", src);
                        return None;
                    }
                    state.install_session(session, peer_public, src_link);
                    Some(datagram)
                }
                InitOutcome::CookieReply(reply) => Some(reply),
                InitOutcome::Drop => None,
            }
        }
        WireMsg::Data {
            receiver_cid,
            masked_counter,
            ciphertext,
        } => {
            let entry = state.sessions.get_mut(&receiver_cid)?;
            entry
                .session
                .open_data_into(masked_counter, ciphertext, payload_buf)
                .ok()?;
            // Roaming applies only to UDP, where the peer's address can change.
            // A TLS session is pinned to its connection.
            if let Link::Udp(addr) = src_link {
                if entry.link != src_link {
                    log::info!("peer roamed {} -> {}", entry.link, addr);
                    entry.link = src_link;
                }
            }
            if payload_buf.is_empty() {
                return None; // keepalive
            }
            if let Some(inner_src) = common::inner_src_ip(payload_buf) {
                state.cid_by_inner_ip.insert(inner_src, receiver_cid);
            }
            let _ = tun.write(payload_buf);
            None
        }
        // Server never consumes handshake responses or cookies
        WireMsg::Resp { .. } | WireMsg::Cookie { .. } => None,
    }
}

/// Run the VPN server (Windows): not supported by protocol v4 yet
#[cfg(windows)]
pub fn run(_config_path: &str) -> Result<()> {
    Err(twocha_protocol::VpnError::Config(
        "Windows support for protocol v4 is not implemented yet".into(),
    ))
}

/// Stop the server
pub fn stop() {
    common::stop();
}

// ═══════════════════════════════════════════════════════════════════════════
// REALITY transport (Go xtls/reality via FFI). Shares the stream-transport
// loop with TLS (`serve_stream`, above) via the StreamServerListener /
// StreamServerConn traits — sessions are pinned via Link::Stream (only one
// stream transport runs at a time, so the id namespace can't collide).
// Unauthenticated probes never reach here — the Go core relays them to
// `dest`. Feature-gated.
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(all(unix, feature = "reality"))]
fn build_reality_listener(
    cfg: &ServerConfig,
    listen_addr: SocketAddr,
) -> Result<RealityServerListener> {
    let r = &cfg.reality.server;
    let key_file = r
        .private_key_file
        .as_deref()
        .ok_or_else(|| VpnError::Config("reality.private_key_file is required".into()))?;
    let identity = twocha_core::Identity::load(std::path::Path::new(key_file))?;
    let private = identity.private_bytes();
    let dest = r
        .dest
        .as_deref()
        .ok_or_else(|| VpnError::Config("reality.dest is required".into()))?;
    if r.server_names.is_empty() {
        return Err(VpnError::Config(
            "reality.server_names must not be empty".into(),
        ));
    }
    RealityServerListener::bind(
        listen_addr,
        &private,
        dest,
        &r.server_names,
        &r.short_ids,
        r.max_time_diff_ms,
    )
    .map_err(VpnError::Io)
}

/// REALITY transport loop: builds the listener and hands it to the
/// stream-transport loop shared with TLS.
#[cfg(all(unix, feature = "reality"))]
#[allow(clippy::too_many_arguments)]
fn serve_reality(
    cfg: &ServerConfig,
    config_path: &str,
    tun: &mut TunDevice,
    state: &mut ServerState,
    event_loop: &mut EventLoop,
    control: Option<&ControlListener>,
    listen_addr: SocketAddr,
) -> Result<()> {
    let listener = build_reality_listener(cfg, listen_addr)?;
    serve_stream(
        "reality/tcp",
        listener,
        cfg,
        config_path,
        tun,
        state,
        event_loop,
        control,
        listen_addr,
    )
}
