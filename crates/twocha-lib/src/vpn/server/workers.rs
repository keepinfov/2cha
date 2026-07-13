//! # Multi-worker UDP data plane (opt-in, Linux only)
//!
//! `performance.worker_threads >= 2` (with the QUIC transport) runs N
//! parallel workers instead of the single-threaded `serve_udp` loop. Each
//! worker owns one TUN queue (multi-queue clone) and one UDP socket bound
//! with SO_REUSEPORT to the same listen address:
//!
//! - UDP side: the kernel hashes each client's 4-tuple to a fixed socket, so
//!   a client's inbound datagrams stay on one worker (and roaming just moves
//!   it to another — state is shared, so this is safe).
//! - TUN side: the kernel hashes flows onto queues independently, so a
//!   session's TX may run on a different worker than its RX. Sessions are
//!   therefore shared: the map sits behind an `RwLock`, per-session crypto is
//!   `&self` (see `twocha_core::v4::Session`), and the mutable scraps
//!   (peer address, keepalive deadline) sit behind tiny per-entry mutexes.
//!
//! The cold control plane (handshake engine, rate limiter, whitelist, peer
//! index) lives behind a single mutex; lock order is always
//! `control -> sessions -> cid_by_inner_ip`. Worker 0 additionally runs
//! maintenance: cookie rotation, session cleanup, keepalives and the
//! control socket.

use crate::platform::unix::{
    is_would_block, BatchBuffer, EventLoop, TunDevice, TunnelConfig, UdpTunnel, POLLIN,
};
use crate::vpn::common;
use crate::vpn::server::control::{ControlListener, CtlRequest};

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use twocha_core::v4::{
    session::keepalive_jitter, InitOutcome, RateLimiter, SealScratch, ServerHandshakeEngine,
    Session,
};
use twocha_core::ServerConfig;
use twocha_protocol::wire::{self, WireMsg, CID_LEN};
use twocha_protocol::{ObfsProfile, Result, VpnError};

const COOKIE_ROTATE_INTERVAL: Duration = Duration::from_secs(120);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(10);

/// One shared session. Crypto is `&self`; only the roaming address and the
/// keepalive deadline need interior mutability.
struct Entry {
    session: Session,
    peer_public: [u8; 32],
    addr: Mutex<SocketAddr>,
    next_keepalive: Mutex<Instant>,
}

/// Cold-path state behind one mutex (handshakes and peer admin only).
struct ControlPlane {
    engine: ServerHandshakeEngine,
    limiter: RateLimiter,
    allowed: HashSet<[u8; 32]>,
    peer_names: HashMap<[u8; 32], String>,
    /// Current session per peer static key (new handshake replaces old)
    cid_by_peer: HashMap<[u8; 32], [u8; CID_LEN]>,
}

struct SharedState {
    control: Mutex<ControlPlane>,
    /// Wire framing used to classify inbound datagrams (QUIC-mimic or AWG).
    profile: ObfsProfile,
    /// Established sessions keyed by our receive-CID
    sessions: RwLock<HashMap<[u8; CID_LEN], Arc<Entry>>>,
    /// Learned inner tunnel IP -> session (for TUN->UDP routing)
    cid_by_inner_ip: RwLock<HashMap<IpAddr, [u8; CID_LEN]>>,
    max_clients: usize,
    idle_timeout: Duration,
}

/// Run the multi-worker UDP loop. Blocks until `common::running()` flips
/// false; all worker threads are joined before returning.
#[allow(clippy::too_many_arguments)]
pub(super) fn serve_udp_workers(
    cfg: &ServerConfig,
    config_path: &str,
    tun: TunDevice,
    engine: ServerHandshakeEngine,
    profile: ObfsProfile,
    allowed: HashSet<[u8; 32]>,
    peer_names: HashMap<[u8; 32], String>,
    control: Option<&ControlListener>,
    listen_addr: SocketAddr,
    workers: usize,
) -> Result<()> {
    let shared = SharedState {
        control: Mutex::new(ControlPlane {
            engine,
            limiter: RateLimiter::new(),
            allowed,
            peer_names,
            cid_by_peer: HashMap::new(),
        }),
        profile,
        sessions: RwLock::new(HashMap::new()),
        cid_by_inner_ip: RwLock::new(HashMap::new()),
        max_clients: cfg.server.max_clients,
        idle_timeout: Duration::from_secs(cfg.timeouts.session),
    };

    // Per-worker TUN queue (0 = the original device) + SO_REUSEPORT socket.
    let mut queues: Vec<TunDevice> = Vec::with_capacity(workers);
    let mut tunnels: Vec<UdpTunnel> = Vec::with_capacity(workers);
    for i in 0..workers {
        let queue = if i == 0 {
            None
        } else {
            Some(tun.clone_queue()?)
        };
        if let Some(ref q) = queue {
            q.set_nonblocking(true)?;
        }
        let tunnel = UdpTunnel::new(TunnelConfig {
            local_addr: listen_addr,
            read_timeout: Some(Duration::from_millis(10)),
            recv_buffer_size: cfg.performance.socket_recv_buffer,
            send_buffer_size: cfg.performance.socket_send_buffer,
            reuse_port: true,
            ..Default::default()
        })?;
        tunnel.set_nonblocking(true)?;
        tunnels.push(tunnel);
        if let Some(q) = queue {
            queues.push(q);
        }
    }

    log::info!(
        "Listening on {} (udp/{}, {} workers, multi-queue tun)",
        listen_addr,
        cfg.server.transport,
        workers
    );

    let shared = &shared;
    std::thread::scope(|scope| {
        // Workers 1..N on spawned threads; worker 0 (maintenance + control
        // socket) runs on the calling thread.
        let mut handles = Vec::with_capacity(workers - 1);
        for (i, (queue, tunnel)) in queues.drain(..).zip(tunnels.drain(1..)).enumerate() {
            handles.push(scope.spawn(move || {
                let r = worker_loop(i + 1, cfg, &queue, &tunnel, shared, None, config_path);
                if r.is_err() {
                    common::stop(); // bring the pool down instead of limping
                }
                r
            }));
        }

        let r0 = worker_loop(0, cfg, &tun, &tunnels[0], shared, control, config_path);
        common::stop();

        let mut result = r0;
        for handle in handles {
            let r = handle
                .join()
                .unwrap_or_else(|_| Err(VpnError::Config("server worker panicked".into())));
            result = result.and(r);
        }
        result
    })
}

/// One worker: poll its TUN queue + UDP socket, pump packets both ways.
/// Worker 0 also runs maintenance and the control socket.
fn worker_loop(
    idx: usize,
    cfg: &ServerConfig,
    tun: &TunDevice,
    tunnel: &UdpTunnel,
    shared: &SharedState,
    control: Option<&ControlListener>,
    config_path: &str,
) -> Result<()> {
    let mut event_loop = EventLoop::new();
    event_loop.add_fd(tun.fd(), POLLIN);
    event_loop.add_fd(tunnel.fd(), POLLIN);
    if let Some(ctl) = control {
        event_loop.add_fd(ctl.fd(), POLLIN);
    }

    let mut tun_buffer = vec![0u8; cfg.tun.mtu as usize + 100];
    let mut batch = BatchBuffer::new(cfg.performance.batch_size);
    let mut payload_buf = Vec::new();
    let mut scratch = SealScratch::default();
    let flush_at = cfg.performance.batch_size.max(1);
    let mut send_queue: Vec<(Vec<u8>, SocketAddr)> = Vec::with_capacity(flush_at);
    let mut send_pool: Vec<Vec<u8>> = Vec::with_capacity(flush_at);

    let mut last_cleanup = Instant::now();
    let mut last_cookie_rotate = Instant::now();

    log::debug!(
        "worker {} up (tun fd {}, udp fd {})",
        idx,
        tun.fd(),
        tunnel.fd()
    );

    while common::running() {
        let events = event_loop.poll(100)?;

        for (fd, revents) in events {
            if revents & POLLIN == 0 {
                continue;
            }
            if fd == tun.fd() {
                pump_tun(
                    tun,
                    tunnel,
                    shared,
                    &mut tun_buffer,
                    &mut scratch,
                    &mut send_queue,
                    &mut send_pool,
                    flush_at,
                )?;
            } else if fd == tunnel.fd() {
                pump_udp(tunnel, tun, shared, &mut batch, &mut payload_buf)?;
            } else if let Some(ctl) = control {
                if fd == ctl.fd() {
                    ctl.process(|req| handle_control(req, shared, config_path));
                }
            }
        }

        // Maintenance runs on worker 0 only
        if idx == 0 {
            let now = Instant::now();
            if last_cookie_rotate.elapsed() > COOKIE_ROTATE_INTERVAL {
                shared.control.lock().unwrap().engine.rotate_cookie_secret();
                last_cookie_rotate = now;
            }
            if last_cleanup.elapsed() > CLEANUP_INTERVAL {
                cleanup_sessions(shared);
                last_cleanup = now;
            }
            send_keepalives(tunnel, shared, now);
        }
    }

    Ok(())
}

/// TUN queue -> seal -> batched UDP send.
#[allow(clippy::too_many_arguments)]
fn pump_tun(
    tun: &TunDevice,
    tunnel: &UdpTunnel,
    shared: &SharedState,
    buffer: &mut [u8],
    scratch: &mut SealScratch,
    send_queue: &mut Vec<(Vec<u8>, SocketAddr)>,
    send_pool: &mut Vec<Vec<u8>>,
    flush_at: usize,
) -> Result<()> {
    fn flush(
        tunnel: &UdpTunnel,
        send_queue: &mut Vec<(Vec<u8>, SocketAddr)>,
        send_pool: &mut Vec<Vec<u8>>,
    ) {
        let _ = tunnel.send_batch(send_queue);
        send_pool.extend(send_queue.drain(..).map(|(datagram, _)| datagram));
    }

    loop {
        match tun.read(buffer) {
            Ok(n) if n > 0 => {
                let packet = &buffer[..n];
                let Some(dst) = common::inner_dst_ip(packet) else {
                    continue;
                };
                let Some(cid) = shared.cid_by_inner_ip.read().unwrap().get(&dst).copied() else {
                    log::trace!("no session for inner destination {}", dst);
                    continue;
                };
                let Some(entry) = shared.sessions.read().unwrap().get(&cid).cloned() else {
                    continue;
                };
                let addr = *entry.addr.lock().unwrap();
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

/// UDP -> open -> TUN queue (plus handshake handling on the cold path).
fn pump_udp(
    tunnel: &UdpTunnel,
    tun: &TunDevice,
    shared: &SharedState,
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
                    if let Some(reply) = handle_datagram(tun, shared, src, data, payload_buf) {
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

/// Worker-pool variant of the single-threaded loop's `handle_datagram`.
/// All failure paths are silent drops (`None`).
fn handle_datagram(
    tun: &TunDevice,
    shared: &SharedState,
    src: SocketAddr,
    data: &[u8],
    payload_buf: &mut Vec<u8>,
) -> Option<Vec<u8>> {
    let msg = wire::parse_profile(&shared.profile, data).ok()?;

    match msg {
        WireMsg::Init { .. } => {
            let mut cp = shared.control.lock().unwrap();
            // Per-IP budget exceeded: drop before any crypto
            if !cp.limiter.allow(src.ip()) {
                return None;
            }
            let under_load = cp.limiter.under_load();
            let ControlPlane {
                ref mut engine,
                ref allowed,
                ..
            } = *cp;
            let outcome = engine.handle_init(data, &src, under_load, |pk| allowed.contains(pk));
            match outcome {
                InitOutcome::Established {
                    datagram,
                    session,
                    peer_public,
                } => {
                    let is_new_peer = !cp.cid_by_peer.contains_key(&peer_public);
                    if is_new_peer && cp.cid_by_peer.len() >= shared.max_clients {
                        log::warn!("max_clients reached, dropping handshake from {}", src);
                        return None;
                    }
                    install_session(shared, &mut cp, session, peer_public, src);
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
            let entry = shared
                .sessions
                .read()
                .unwrap()
                .get(&receiver_cid)
                .cloned()?;
            entry
                .session
                .open_data_into(masked_counter, ciphertext, payload_buf)
                .ok()?;
            // Roaming: the peer's address can change between datagrams
            {
                let mut addr = entry.addr.lock().unwrap();
                if *addr != src {
                    log::info!("peer roamed {} -> {}", *addr, src);
                    *addr = src;
                }
            }
            if payload_buf.is_empty() {
                return None; // keepalive
            }
            if let Some(inner_src) = common::inner_src_ip(payload_buf) {
                let known = shared
                    .cid_by_inner_ip
                    .read()
                    .unwrap()
                    .get(&inner_src)
                    .copied()
                    == Some(receiver_cid);
                if !known {
                    shared
                        .cid_by_inner_ip
                        .write()
                        .unwrap()
                        .insert(inner_src, receiver_cid);
                }
            }
            let _ = tun.write(payload_buf);
            None
        }
        // Server never consumes handshake responses or cookies
        WireMsg::Resp { .. } | WireMsg::Cookie { .. } => None,
    }
}

/// Install a fresh session, replacing the peer's previous one.
/// Caller holds the control mutex (lock order: control -> sessions -> ips).
fn install_session(
    shared: &SharedState,
    cp: &mut ControlPlane,
    session: Session,
    peer_public: [u8; 32],
    addr: SocketAddr,
) {
    let cid = session.local_cid;
    let mut sessions = shared.sessions.write().unwrap();
    if let Some(old_cid) = cp.cid_by_peer.insert(peer_public, cid) {
        sessions.remove(&old_cid);
        shared
            .cid_by_inner_ip
            .write()
            .unwrap()
            .retain(|_, c| *c != old_cid);
    }
    sessions.insert(
        cid,
        Arc::new(Entry {
            session,
            peer_public,
            addr: Mutex::new(addr),
            next_keepalive: Mutex::new(Instant::now() + keepalive_jitter()),
        }),
    );
    log::info!(
        "session established with {} (peers online: {})",
        addr,
        sessions.len()
    );
}

/// Expire idle/dead sessions (worker 0 maintenance).
fn cleanup_sessions(shared: &SharedState) {
    let mut cp = shared.control.lock().unwrap();
    let mut sessions = shared.sessions.write().unwrap();
    let idle = shared.idle_timeout;
    let dead: Vec<[u8; CID_LEN]> = sessions
        .iter()
        .filter(|(_, e)| {
            let expired =
                e.session.expired() && e.session.last_recv_elapsed() > Duration::from_secs(10);
            let idled = e.session.last_recv_elapsed() > idle;
            expired || idled
        })
        .map(|(cid, _)| *cid)
        .collect();
    for cid in dead {
        if let Some(entry) = sessions.remove(&cid) {
            log::info!(
                "session with {} closed (expired/idle)",
                *entry.addr.lock().unwrap()
            );
            if cp.cid_by_peer.get(&entry.peer_public) == Some(&cid) {
                cp.cid_by_peer.remove(&entry.peer_public);
            }
        }
        shared
            .cid_by_inner_ip
            .write()
            .unwrap()
            .retain(|_, c| *c != cid);
    }
}

/// Jittered keepalives keep NAT bindings open (worker 0 maintenance).
fn send_keepalives(tunnel: &UdpTunnel, shared: &SharedState, now: Instant) {
    let entries: Vec<Arc<Entry>> = shared.sessions.read().unwrap().values().cloned().collect();
    for entry in entries {
        let mut next = entry.next_keepalive.lock().unwrap();
        if now >= *next {
            if let Ok(datagram) = entry.session.seal_data(&[]) {
                let _ = tunnel.send_to(&datagram, *entry.addr.lock().unwrap());
            }
            *next = now + keepalive_jitter();
        }
    }
}

/// Control-socket requests against the shared state (worker 0 only).
/// Mirrors the single-threaded loop's handler, including persistence.
fn handle_control(req: CtlRequest, shared: &SharedState, config_path: &str) -> String {
    match req {
        CtlRequest::PeerAdd { key, name } => {
            let pk = match twocha_core::decode_public_key(&key) {
                Ok(pk) => pk,
                Err(e) => return format!("err {}", e),
            };
            let mut cp = shared.control.lock().unwrap();
            let added = cp.allowed.insert(pk);
            if let Some(ref n) = name {
                cp.peer_names.insert(pk, n.clone());
            }
            drop(cp);
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
            let mut cp = shared.control.lock().unwrap();
            let existed = cp.allowed.remove(&pk);
            cp.peer_names.remove(&pk);
            // Revocation must drop the active session immediately
            if let Some(cid) = cp.cid_by_peer.remove(&pk) {
                if let Some(entry) = shared.sessions.write().unwrap().remove(&cid) {
                    log::info!(
                        "session with {} closed (peer removed)",
                        *entry.addr.lock().unwrap()
                    );
                }
                shared
                    .cid_by_inner_ip
                    .write()
                    .unwrap()
                    .retain(|_, c| *c != cid);
            }
            drop(cp);
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
            let cp = shared.control.lock().unwrap();
            let sessions = shared.sessions.read().unwrap();
            let mut out = format!("ok {} peers", cp.allowed.len());
            let mut keys: Vec<&[u8; 32]> = cp.allowed.iter().collect();
            keys.sort();
            for pk in keys {
                let b64 = twocha_core::encode_public_key(pk);
                let name = cp.peer_names.get(pk).map(String::as_str).unwrap_or("-");
                match cp.cid_by_peer.get(pk).and_then(|cid| sessions.get(cid)) {
                    Some(entry) => {
                        out.push_str(&format!(
                            "\npeer {} {} online endpoint={} last_recv_secs={}",
                            b64,
                            name,
                            *entry.addr.lock().unwrap(),
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
