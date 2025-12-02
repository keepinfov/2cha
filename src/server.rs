//! Server module for 2cha

use crate::{
    TunDevice, Result, ChaCha20Poly1305, ServerConfig,
    network::{UdpTunnel, TunnelConfig, PeerState, EventLoop, POLLIN},
    protocol::{PacketType, PacketHeader},
    PROTOCOL_HEADER_SIZE,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static RUNNING: AtomicBool = AtomicBool::new(true);

pub fn run(config_path: &str) -> Result<()> {
    let cfg = ServerConfig::from_file(config_path)
        .map_err(|e| crate::VpnError::Config(format!("{}", e)))?;
    
    let listen_addr = cfg.listen_addr()
        .map_err(|e| crate::VpnError::Config(format!("{}", e)))?;
    let tun_ip = cfg.tun_ip()
        .map_err(|e| crate::VpnError::Config(format!("{}", e)))?;
    let netmask = cfg.netmask()
        .map_err(|e| crate::VpnError::Config(format!("{}", e)))?;
    let key = cfg.key()
        .map_err(|e| crate::VpnError::Config(format!("{}", e)))?;

    log::info!("Starting 2cha server...");

    // Create TUN
    let mut tun = TunDevice::create(&cfg.tun.name)?;
    tun.set_address(tun_ip)?;
    tun.set_netmask(netmask)?;
    tun.set_mtu(cfg.tun.mtu)?;
    tun.bring_up()?;
    tun.set_nonblocking(true)?;
    log::info!("TUN device ready: {}.{}.{}.{}/24", tun_ip[0], tun_ip[1], tun_ip[2], tun_ip[3]);

    // Setup routing/gateway
    if cfg.routing.ip_forward {
        log::info!("Setting up gateway mode...");
        if let Err(e) = crate::routing::enable_ip_forward() {
            log::error!("Failed to enable IP forwarding: {}", e);
        } else {
            log::info!("IP forwarding enabled");
        }
        
        if cfg.routing.masquerade {
            if let Some(ref iface) = cfg.routing.external_interface {
                let vpn_subnet = format!("{}.{}.{}.0/24", tun_ip[0], tun_ip[1], tun_ip[2]);
                if let Err(e) = crate::routing::setup_masquerade(iface, &vpn_subnet) {
                    log::error!("Failed to setup NAT: {}", e);
                } else {
                    log::info!("NAT configured on {}", iface);
                }
            } else {
                log::warn!("masquerade=true but no external_interface set");
            }
        }
    }

    // Create tunnel
    let tunnel_config = TunnelConfig {
        local_addr: listen_addr,
        read_timeout: Some(Duration::from_millis(10)),
        keepalive_interval: Duration::from_secs(cfg.timeouts.keepalive),
        session_timeout: Duration::from_secs(cfg.timeouts.session),
        ..Default::default()
    };
    let mut tunnel = UdpTunnel::new(tunnel_config, &key)?;
    tunnel.set_nonblocking(true)?;
    log::info!("Listening on {}", listen_addr);

    setup_signal_handler();

    let mut event_loop = EventLoop::new();
    event_loop.add_fd(tun.fd(), POLLIN);
    event_loop.add_fd(tunnel.fd(), POLLIN);

    let mut peers: HashMap<SocketAddr, PeerState> = HashMap::new();
    let cipher = ChaCha20Poly1305::new(&key);
    let session_timeout = Duration::from_secs(cfg.timeouts.session);

    let mut last_cleanup = Instant::now();
    let cleanup_interval = Duration::from_secs(30);
    let mut tun_buffer = vec![0u8; 1500];

    log::info!("Server ready. Waiting for connections...");

    while RUNNING.load(Ordering::SeqCst) {
        let events = event_loop.poll(100)?;

        for (fd, revents) in events {
            if revents & POLLIN != 0 {
                if fd == tun.fd() {
                    handle_tun(&mut tun, &mut tun_buffer, &mut tunnel, &mut peers)?;
                } else if fd == tunnel.fd() {
                    handle_udp(&mut tunnel, &mut tun, &mut peers, &cipher)?;
                }
            }
        }

        // Cleanup expired peers
        if last_cleanup.elapsed() > cleanup_interval {
            let expired: Vec<_> = peers.iter()
                .filter(|(_, p)| p.is_expired(session_timeout))
                .map(|(a, _)| *a)
                .collect();
            
            for addr in expired {
                log::info!("Client {} timed out", addr);
                peers.remove(&addr);
            }
            last_cleanup = Instant::now();
        }
    }

    log::info!("Server shutdown");
    Ok(())
}

fn handle_tun(
    tun: &mut TunDevice,
    buffer: &mut [u8],
    tunnel: &mut UdpTunnel,
    peers: &mut HashMap<SocketAddr, PeerState>,
) -> Result<()> {
    loop {
        match tun.read(buffer) {
            Ok(n) if n > 0 => {
                for peer in peers.values_mut() {
                    let _ = tunnel.send_encrypted(peer, &buffer[..n]);
                }
            }
            Ok(_) => break,
            Err(e) if is_would_block(&e) => break,
            Err(_) => break,
        }
    }
    Ok(())
}

fn handle_udp(
    tunnel: &mut UdpTunnel,
    tun: &mut TunDevice,
    peers: &mut HashMap<SocketAddr, PeerState>,
    cipher: &ChaCha20Poly1305,
) -> Result<()> {
    loop {
        match tunnel.recv_from_any() {
            Ok(Some((src, data))) => {
                let peer = peers.entry(src).or_insert_with(|| {
                    log::info!("New client: {}", src);
                    PeerState::new(src)
                });
                peer.touch();
                peer.bytes_rx += data.len() as u64;

                if data.len() < PROTOCOL_HEADER_SIZE { continue; }

                if let Ok(header) = PacketHeader::deserialize(&data) {
                    if !peer.replay_window.check_and_update(header.counter as u64) {
                        log::warn!("Replay attack from {}", src);
                        continue;
                    }

                    let header_bytes = header.serialize();
                    let encrypted = &data[PROTOCOL_HEADER_SIZE..];

                    match header.packet_type {
                        PacketType::Data => {
                            if let Ok(decrypted) = cipher.decrypt(&header.nonce, encrypted, &header_bytes) {
                                let _ = tun.write(&decrypted);
                            }
                        }
                        PacketType::Keepalive => {
                            log::trace!("Keepalive from {}", src);
                        }
                        PacketType::Disconnect => {
                            log::info!("Client {} disconnected", src);
                            peers.remove(&src);
                        }
                        _ => {}
                    }
                }
            }
            Ok(None) => break,
            Err(e) if is_would_block(&e) => break,
            Err(_) => break,
        }
    }
    Ok(())
}

fn setup_signal_handler() {
    unsafe {
        libc::signal(libc::SIGINT, signal_handler as libc::sighandler_t);
        libc::signal(libc::SIGTERM, signal_handler as libc::sighandler_t);
    }
}

extern "C" fn signal_handler(_: libc::c_int) {
    RUNNING.store(false, Ordering::SeqCst);
}

fn is_would_block(e: &crate::VpnError) -> bool {
    let s = e.to_string();
    s.contains("WouldBlock") || s.contains("temporarily unavailable") || s.contains("os error 11")
}
