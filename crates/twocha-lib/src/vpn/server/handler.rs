//! # Server Handler
//!
//! Drives the v4 protocol engine with real I/O: accepts Noise_IK handshakes
//! from whitelisted peers, maintains CID-keyed sessions with roaming, and
//! never responds to unauthenticated traffic.

#[cfg(unix)]
use crate::platform::unix::{
    is_would_block, routing, BatchBuffer, EventLoop, TunDevice, TunnelConfig, UdpTunnel, POLLIN,
};

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
use std::time::{Duration, Instant};
#[cfg(unix)]
use twocha_core::v4::{
    session::keepalive_jitter, InitOutcome, RateLimiter, ServerHandshakeEngine, Session,
};
#[cfg(unix)]
use twocha_core::ServerConfig;
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

#[cfg(unix)]
struct SessionEntry {
    session: Session,
    peer_public: [u8; 32],
    endpoint: SocketAddr,
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
    fn install_session(&mut self, session: Session, peer_public: [u8; 32], endpoint: SocketAddr) {
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
                endpoint,
                next_keepalive: Instant::now() + keepalive_jitter(),
            },
        );
        log::info!(
            "session established with {} (peers online: {})",
            endpoint,
            self.sessions.len()
        );
    }

    fn cleanup(&mut self) {
        let idle = self.idle_timeout;
        let mut dead: Vec<[u8; CID_LEN]> = Vec::new();
        for (cid, entry) in &self.sessions {
            let expired = entry.session.expired()
                && entry.session.last_recv.elapsed() > Duration::from_secs(10);
            let idled = entry.session.last_recv.elapsed() > idle;
            if expired || idled {
                dead.push(*cid);
            }
        }
        for cid in dead {
            if let Some(entry) = self.sessions.remove(&cid) {
                log::info!("session with {} closed (expired/idle)", entry.endpoint);
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

    // Create TUN device
    let mut tun = TunDevice::create_with_options(&cfg.tun.name, cfg.performance.multi_queue)?;

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

    // Setup gateway/routing
    if cfg.gateway.ip_forward {
        if let Some(ref iface) = cfg.gateway.external_interface {
            if cfg.ipv4.enable {
                let subnet = format!(
                    "{}/{}",
                    cfg.ipv4.address.as_deref().unwrap_or("10.0.0.0"),
                    cfg.ipv4.prefix
                );
                if let Err(e) = routing::setup_server_gateway_v4(iface, &subnet) {
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
                    if let Err(e) = routing::setup_server_gateway_v6(iface, &subnet) {
                        log::error!("Failed to setup IPv6 gateway: {}", e);
                    }
                }
            }
        }
    }

    // Create UDP tunnel
    let tunnel_config = TunnelConfig {
        local_addr: listen_addr,
        read_timeout: Some(Duration::from_millis(10)),
        recv_buffer_size: cfg.performance.socket_recv_buffer,
        send_buffer_size: cfg.performance.socket_send_buffer,
        ..Default::default()
    };

    let tunnel = UdpTunnel::new(tunnel_config)?;
    tunnel.set_nonblocking(true)?;

    log::info!("Listening on {}", listen_addr);

    common::reset_running();
    common::setup_signal_handler();

    let mut event_loop = EventLoop::new();
    event_loop.add_fd(tun.fd(), POLLIN);
    event_loop.add_fd(tunnel.fd(), POLLIN);

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

    let mut last_cleanup = Instant::now();
    let mut last_cookie_rotate = Instant::now();
    let mut tun_buffer = vec![0u8; cfg.tun.mtu as usize + 100];
    let mut udp_batch = BatchBuffer::new(cfg.performance.batch_size);
    let mut send_queue: Vec<(Vec<u8>, SocketAddr)> = Vec::with_capacity(udp_batch.capacity());

    log::info!(
        "Server ready. Authorized peers: {}, max clients: {}",
        state.allowed.len(),
        state.max_clients
    );

    while common::running() {
        let events = event_loop.poll(100)?;

        for (fd, revents) in events {
            if revents & POLLIN != 0 {
                if fd == tun.fd() {
                    handle_tun_read(&mut tun, &mut tun_buffer, &tunnel, &mut state, &mut send_queue)?;
                } else if fd == tunnel.fd() {
                    handle_udp_read(&tunnel, &mut tun, &mut state, &mut udp_batch)?;
                } else if let Some(ref ctl) = control {
                    if fd == ctl.fd() {
                        ctl.process(|req| handle_control(req, &mut state, config_path));
                    }
                }
            }
        }

        let now = Instant::now();
        if last_cookie_rotate.elapsed() > COOKIE_ROTATE_INTERVAL {
            state.engine.rotate_cookie_secret();
            last_cookie_rotate = now;
        }
        if last_cleanup.elapsed() > CLEANUP_INTERVAL {
            state.cleanup();
            last_cleanup = now;
        }

        // Keepalives keep NAT bindings open and break the silence pattern
        for entry in state.sessions.values_mut() {
            if now >= entry.next_keepalive {
                if let Ok(datagram) = entry.session.seal_data(&[]) {
                    let _ = tunnel.send_to(&datagram, entry.endpoint);
                }
                entry.next_keepalive = now + keepalive_jitter();
            }
        }
    }

    log::info!("Server shutdown");
    Ok(())
}

#[cfg(unix)]
fn handle_tun_read(
    tun: &mut TunDevice,
    buffer: &mut [u8],
    tunnel: &UdpTunnel,
    state: &mut ServerState,
    send_queue: &mut Vec<(Vec<u8>, SocketAddr)>,
) -> Result<()> {
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
                    if let Ok(datagram) = entry.session.seal_data(packet) {
                        send_queue.push((datagram, entry.endpoint));
                        if send_queue.len() >= flush_at {
                            let _ = tunnel.send_batch(send_queue);
                            send_queue.clear();
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
        let _ = tunnel.send_batch(send_queue);
        send_queue.clear();
    }
    Ok(())
}

#[cfg(unix)]
fn handle_udp_read(
    tunnel: &UdpTunnel,
    tun: &mut TunDevice,
    state: &mut ServerState,
    batch: &mut BatchBuffer,
) -> Result<()> {
    loop {
        match tunnel.recv_batch(batch) {
            Ok(0) => break,
            Ok(n) => {
                for i in 0..n {
                    let Some((src, data)) = batch.get(i) else {
                        continue;
                    };
                    handle_datagram(tunnel, tun, state, src, data);
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
            log::info!("control: {} peer {} ({})", verb, key, name.as_deref().unwrap_or("-"));
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
                    log::info!("session with {} closed (peer removed)", entry.endpoint);
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
                            entry.endpoint,
                            entry.session.last_recv.elapsed().as_secs()
                        ));
                    }
                    None => out.push_str(&format!("\npeer {} {} offline", b64, name)),
                }
            }
            out
        }
    }
}

/// Process one inbound datagram. All failure paths are silent drops.
#[cfg(unix)]
fn handle_datagram(
    tunnel: &UdpTunnel,
    tun: &mut TunDevice,
    state: &mut ServerState,
    src: SocketAddr,
    data: &[u8],
) {
    let msg = match wire::parse(data) {
        Ok(msg) => msg,
        Err(_) => return,
    };

    match msg {
        WireMsg::Init { .. } => {
            // Per-IP budget exceeded: drop before any crypto
            if !state.limiter.allow(src.ip()) {
                return;
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
                        return;
                    }
                    let _ = tunnel.send_to(&datagram, src);
                    state.install_session(session, peer_public, src);
                }
                InitOutcome::CookieReply(reply) => {
                    let _ = tunnel.send_to(&reply, src);
                }
                InitOutcome::Drop => {}
            }
        }
        WireMsg::Data {
            receiver_cid,
            masked_counter,
            ciphertext,
        } => {
            let Some(entry) = state.sessions.get_mut(&receiver_cid) else {
                return;
            };
            let payload = match entry.session.open_data(masked_counter, ciphertext) {
                Ok(p) => p,
                Err(_) => return,
            };
            // Roaming: authenticated packet from a new address moves the peer
            if entry.endpoint != src {
                log::info!("peer roamed {} -> {}", entry.endpoint, src);
                entry.endpoint = src;
            }
            if payload.is_empty() {
                return; // keepalive
            }
            if let Some(inner_src) = common::inner_src_ip(&payload) {
                state.cid_by_inner_ip.insert(inner_src, receiver_cid);
            }
            let _ = tun.write(&payload);
        }
        // Server never consumes handshake responses or cookies
        WireMsg::Resp { .. } | WireMsg::Cookie { .. } => {}
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
