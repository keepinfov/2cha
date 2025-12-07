//! # Client Module
//!
//! VPN client with IPv4/IPv6 dual-stack support.
//!
//! Note: This module is only available on Unix platforms.

use crate::{
    network::{is_would_block, EventLoop, PeerState, TunnelConfig, UdpTunnel, POLLIN},
    protocol::{PacketHeader, PacketType},
    routing::ClientRoutingContext,
    ChaCha20Poly1305, ClientConfig, Result, TunDevice, VpnError, PROTOCOL_HEADER_SIZE,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static RUNNING: AtomicBool = AtomicBool::new(true);

pub fn run(config_path: &str, quiet: bool) -> Result<()> {
    let cfg =
        ClientConfig::from_file(config_path).map_err(|e| VpnError::Config(format!("{}", e)))?;

    let server_addr = cfg
        .server_addr()
        .map_err(|e| VpnError::Config(format!("{}", e)))?;
    let key = cfg.key().map_err(|e| VpnError::Config(format!("{}", e)))?;

    // Create TUN device
    let mut tun = TunDevice::create_with_options(&cfg.tun.name, cfg.performance.multi_queue)?;

    // Configure IPv4
    let ipv4_gateway = if cfg.ipv4.enable {
        if let Some(addr) = cfg
            .tun_ipv4()
            .map_err(|e| VpnError::Config(format!("{}", e)))?
        {
            tun.set_ipv4_address(addr, cfg.ipv4.prefix)?;
            // Gateway is typically .1 of the subnet
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
            // For IPv6, gateway is typically ::1 of the prefix
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

    // Create UDP tunnel
    let local_addr: SocketAddr = if server_addr.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };

    let tunnel_config = TunnelConfig {
        local_addr,
        remote_addr: Some(server_addr),
        read_timeout: Some(Duration::from_millis(10)),
        keepalive_interval: Duration::from_secs(cfg.timeouts.keepalive),
        recv_buffer_size: cfg.performance.socket_recv_buffer,
        send_buffer_size: cfg.performance.socket_send_buffer,
        ..Default::default()
    };

    let mut tunnel = UdpTunnel::new(tunnel_config, &key)?;
    tunnel.set_nonblocking(true)?;

    let mut server_peer = PeerState::new(server_addr);
    let cipher = ChaCha20Poly1305::new(&key);

    // Setup routing
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

    setup_signal_handler();

    let mut event_loop = EventLoop::new();
    event_loop.add_fd(tun.fd(), POLLIN);
    event_loop.add_fd(tunnel.fd(), POLLIN);

    // Initial keepalive
    tunnel.send_keepalive(&mut server_peer)?;

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
    let mut last_keepalive = Instant::now();
    let keepalive_interval = Duration::from_secs(cfg.timeouts.keepalive);

    while RUNNING.load(Ordering::SeqCst) {
        let events = event_loop.poll(100)?;

        for (fd, revents) in events {
            if revents & POLLIN != 0 {
                if fd == tun.fd() {
                    handle_tun_read(&mut tun, &mut tun_buffer, &mut tunnel, &mut server_peer)?;
                } else if fd == tunnel.fd() {
                    handle_udp_read(&mut tunnel, &mut tun, &mut server_peer, &cipher)?;
                }
            }
        }

        // Send keepalive
        if last_keepalive.elapsed() > keepalive_interval {
            let _ = tunnel.send_keepalive(&mut server_peer);
            last_keepalive = Instant::now();
        }
    }

    // Send disconnect notification
    let _ = tunnel.send_disconnect(&mut server_peer);

    // Cleanup routing
    let _ = routing_ctx.cleanup();

    if !quiet {
        println!("\n  \x1b[32m✓\x1b[0m Disconnected");
    }

    Ok(())
}

fn handle_tun_read(
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

fn handle_udp_read(
    tunnel: &mut UdpTunnel,
    tun: &mut TunDevice,
    peer: &mut PeerState,
    cipher: &ChaCha20Poly1305,
) -> Result<()> {
    loop {
        match tunnel.recv_from_any() {
            Ok(Some((src, data))) => {
                if src != peer.addr {
                    continue;
                }
                peer.touch();
                peer.bytes_rx += data.len() as u64;
                peer.packets_rx += 1;

                if data.len() < PROTOCOL_HEADER_SIZE {
                    continue;
                }

                if let Ok(header) = PacketHeader::deserialize(&data) {
                    if !peer.replay_window.check_and_update(header.counter as u64) {
                        continue;
                    }

                    let header_bytes = header.serialize();
                    let encrypted = &data[PROTOCOL_HEADER_SIZE..];

                    match header.packet_type {
                        PacketType::Data => {
                            if let Ok(decrypted) =
                                cipher.decrypt(&header.nonce, encrypted, &header_bytes)
                            {
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
