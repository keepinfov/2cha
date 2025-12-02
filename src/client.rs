//! Client module for 2cha

use crate::{
    TunDevice, Result, ChaCha20Poly1305, ClientConfig,
    network::{UdpTunnel, TunnelConfig, PeerState, EventLoop, POLLIN},
    protocol::{PacketType, PacketHeader},
    PROTOCOL_HEADER_SIZE,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static RUNNING: AtomicBool = AtomicBool::new(true);

pub fn run(config_path: &str, quiet: bool) -> Result<()> {
    let cfg = ClientConfig::from_file(config_path)
        .map_err(|e| crate::VpnError::Config(format!("{}", e)))?;
    
    let server_addr = cfg.server_addr()
        .map_err(|e| crate::VpnError::Config(format!("{}", e)))?;
    let tun_ip = cfg.tun_ip()
        .map_err(|e| crate::VpnError::Config(format!("{}", e)))?;
    let netmask = cfg.netmask()
        .map_err(|e| crate::VpnError::Config(format!("{}", e)))?;
    let key = cfg.key()
        .map_err(|e| crate::VpnError::Config(format!("{}", e)))?;

    // Create TUN
    let mut tun = TunDevice::create(&cfg.tun.name)?;
    tun.set_address(tun_ip)?;
    tun.set_netmask(netmask)?;
    tun.set_mtu(cfg.tun.mtu)?;
    tun.bring_up()?;
    tun.set_nonblocking(true)?;

    // Create tunnel
    let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let tunnel_config = TunnelConfig {
        local_addr,
        remote_addr: Some(server_addr),
        read_timeout: Some(Duration::from_millis(10)),
        keepalive_interval: Duration::from_secs(cfg.timeouts.keepalive),
        ..Default::default()
    };
    let mut tunnel = UdpTunnel::new(tunnel_config, &key)?;
    tunnel.set_nonblocking(true)?;

    let mut server_peer = PeerState::new(server_addr);
    let cipher = ChaCha20Poly1305::new(&key);

    // Setup routing
    let vpn_gateway = format!("{}.{}.{}.1", tun_ip[0], tun_ip[1], tun_ip[2]);
    let server_ip = server_addr.ip().to_string();
    let original_gateway = crate::routing::get_default_gateway().ok();

    if cfg.routing.route_all_traffic {
        if !quiet {
            println!("\x1b[36m⟳\x1b[0m Setting up full tunnel...");
        }
        if let Some(ref orig_gw) = original_gateway {
            if let Err(e) = crate::routing::set_default_gateway(&vpn_gateway, orig_gw, &server_ip) {
                log::error!("Failed to set default gateway: {}", e);
            }
        }
        if !cfg.routing.dns.is_empty() {
            let _ = crate::routing::set_dns(&cfg.routing.dns);
        }
    } else if !cfg.routing.routes.is_empty() {
        for route in &cfg.routing.routes {
            let _ = crate::routing::add_route(route, &vpn_gateway);
        }
    }

    setup_signal_handler();

    let mut event_loop = EventLoop::new();
    event_loop.add_fd(tun.fd(), POLLIN);
    event_loop.add_fd(tunnel.fd(), POLLIN);

    // Initial keepalive
    tunnel.send_keepalive(&mut server_peer)?;

    if !quiet {
        println!("\x1b[32m✓\x1b[0m Connected to \x1b[36m{}\x1b[0m", server_addr);
        println!("  VPN IP: {}.{}.{}.{}", tun_ip[0], tun_ip[1], tun_ip[2], tun_ip[3]);
        if cfg.routing.route_all_traffic {
            println!("  Mode: Full tunnel (all traffic via VPN)");
        }
        println!();
    }

    let mut tun_buffer = vec![0u8; 1500];
    let mut last_keepalive = Instant::now();
    let keepalive_interval = Duration::from_secs(cfg.timeouts.keepalive);

    while RUNNING.load(Ordering::SeqCst) {
        let events = event_loop.poll(100)?;

        for (fd, revents) in events {
            if revents & POLLIN != 0 {
                if fd == tun.fd() {
                    handle_tun(&mut tun, &mut tun_buffer, &mut tunnel, &mut server_peer)?;
                } else if fd == tunnel.fd() {
                    handle_udp(&mut tunnel, &mut tun, &mut server_peer, &cipher)?;
                }
            }
        }

        if last_keepalive.elapsed() > keepalive_interval {
            let _ = tunnel.send_keepalive(&mut server_peer);
            last_keepalive = Instant::now();
        }
    }

    // Cleanup routing
    if cfg.routing.route_all_traffic {
        if let Some(ref orig_gw) = original_gateway {
            let _ = crate::routing::restore_default_gateway(orig_gw, &server_ip);
        }
        let _ = crate::routing::restore_dns();
    } else {
        for route in &cfg.routing.routes {
            let _ = crate::routing::del_route(route);
        }
    }

    Ok(())
}

fn handle_tun(
    tun: &mut TunDevice,
    buffer: &mut [u8],
    tunnel: &mut UdpTunnel,
    peer: &mut PeerState,
) -> Result<()> {
    loop {
        match tun.read(buffer) {
            Ok(n) if n > 0 => {
                let _ = tunnel.send_encrypted(peer, &buffer[..n]);
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
    peer: &mut PeerState,
    cipher: &ChaCha20Poly1305,
) -> Result<()> {
    loop {
        match tunnel.recv_from_any() {
            Ok(Some((src, data))) => {
                if src != peer.addr { continue; }
                peer.touch();

                if data.len() < PROTOCOL_HEADER_SIZE { continue; }
                
                if let Ok(header) = PacketHeader::deserialize(&data) {
                    if !peer.replay_window.check_and_update(header.counter as u64) {
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
                        PacketType::Disconnect => {
                            RUNNING.store(false, Ordering::SeqCst);
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
