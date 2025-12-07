//! # Server Module
//!
//! VPN server with IPv4/IPv6 dual-stack support.
//!
//! Note: This module is only available on Unix platforms.

#![cfg(unix)]

use crate::{
    TunDevice, Result, ChaCha20Poly1305, ServerConfig, VpnError,
    network::{UdpTunnel, TunnelConfig, PeerState, EventLoop, POLLIN, is_would_block},
    protocol::{PacketType, PacketHeader},
    tun::IpVersion,
    PROTOCOL_HEADER_SIZE,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static RUNNING: AtomicBool = AtomicBool::new(true);

pub fn run(config_path: &str) -> Result<()> {
    let cfg = ServerConfig::from_file(config_path)
        .map_err(|e| VpnError::Config(format!("{}", e)))?;
    
    let listen_addr = cfg.listen_addr()
        .map_err(|e| VpnError::Config(format!("{}", e)))?;
    let key = cfg.key()
        .map_err(|e| VpnError::Config(format!("{}", e)))?;

    log::info!("Starting 2cha server v0.3...");

    // Create TUN device
    let mut tun = TunDevice::create_with_options(&cfg.tun.name, cfg.performance.multi_queue)?;
    
    // Configure IPv4
    if cfg.ipv4.enable {
        if let Some(addr) = cfg.tun_ipv4().map_err(|e| VpnError::Config(format!("{}", e)))? {
            tun.set_ipv4_address(addr, cfg.ipv4.prefix)?;
            log::info!("IPv4: {}/{}", addr, cfg.ipv4.prefix);
        }
    }
    
    // Configure IPv6
    if cfg.ipv6.enable {
        if let Some(addr) = cfg.tun_ipv6().map_err(|e| VpnError::Config(format!("{}", e)))? {
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
                let subnet = format!("{}/{}", 
                    cfg.ipv4.address.as_deref().unwrap_or("10.0.0.0"),
                    cfg.ipv4.prefix
                );
                if let Err(e) = crate::routing::setup_server_gateway_v4(iface, &subnet) {
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
                    if let Err(e) = crate::routing::setup_server_gateway_v6(iface, &subnet) {
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
        keepalive_interval: Duration::from_secs(cfg.timeouts.keepalive),
        session_timeout: Duration::from_secs(cfg.timeouts.session),
        recv_buffer_size: cfg.performance.socket_recv_buffer,
        send_buffer_size: cfg.performance.socket_send_buffer,
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
    let max_clients = cfg.server.max_clients;

    let mut last_cleanup = Instant::now();
    let cleanup_interval = Duration::from_secs(30);
    let mut tun_buffer = vec![0u8; cfg.tun.mtu as usize + 100];

    log::info!("Server ready. Max clients: {}", max_clients);

    while RUNNING.load(Ordering::SeqCst) {
        let events = event_loop.poll(100)?;

        for (fd, revents) in events {
            if revents & POLLIN != 0 {
                if fd == tun.fd() {
                    handle_tun_read(&mut tun, &mut tun_buffer, &mut tunnel, &mut peers)?;
                } else if fd == tunnel.fd() {
                    handle_udp_read(&mut tunnel, &mut tun, &mut peers, &cipher, max_clients)?;
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

fn handle_tun_read(
    tun: &mut TunDevice,
    buffer: &mut [u8],
    tunnel: &mut UdpTunnel,
    peers: &mut HashMap<SocketAddr, PeerState>,
) -> Result<()> {
    loop {
        match tun.read(buffer) {
            Ok(n) if n > 0 => {
                let packet = &buffer[..n];
                
                // Determine packet type and route accordingly
                let ip_version = IpVersion::from_packet(packet);
                log::trace!("TUN read: {} bytes, {:?}", n, ip_version);
                
                // Send to all peers (could optimize with routing table)
                for peer in peers.values_mut() {
                    let _ = tunnel.send_encrypted(peer, packet);
                }
            }
            Ok(_) => break,
            Err(e) if is_would_block(&e) => break,
            Err(_) => break,
        }
    }
    Ok(())
}

fn handle_udp_read(
    tunnel: &mut UdpTunnel,
    tun: &mut TunDevice,
    peers: &mut HashMap<SocketAddr, PeerState>,
    cipher: &ChaCha20Poly1305,
    max_clients: usize,
) -> Result<()> {
    loop {
        match tunnel.recv_from_any() {
            Ok(Some((src, data))) => {
                // Get or create peer
                let peer = if let Some(p) = peers.get_mut(&src) {
                    p
                } else {
                    if peers.len() >= max_clients {
                        log::warn!("Max clients reached, rejecting {}", src);
                        continue;
                    }
                    log::info!("New client: {}", src);
                    peers.entry(src).or_insert_with(|| PeerState::new(src))
                };
                
                peer.touch();
                peer.bytes_rx += data.len() as u64;
                peer.packets_rx += 1;

                if data.len() < PROTOCOL_HEADER_SIZE {
                    continue;
                }

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
