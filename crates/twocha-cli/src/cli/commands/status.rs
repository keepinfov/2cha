//! Connection status command (shared Unix/Windows logic).

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use crate::cli::output::{icon_disconnected, Icons};
use crate::cli::utils::{format_bytes, is_running};
use console::{style, Term};
use twocha_protocol::Result;

#[cfg(unix)]
use twocha_lib::platform::unix::routing;
#[cfg(windows)]
use twocha_lib::platform::windows::routing;

#[cfg(unix)]
const TUN_NAME: &str = "tun0";
#[cfg(windows)]
const TUN_NAME: &str = "2cha";

/// Refresh cadence of `--watch` (also the sysfs traffic sampling interval)
const WATCH_INTERVAL: Duration = Duration::from_secs(1);
/// Public IP re-check cadence in watch mode (it's a network round-trip)
const PUBLIC_IP_TTL: Duration = Duration::from_secs(60);

/// Show VPN status (one-shot, or a live in-place view with `--watch`)
pub fn cmd_status(watch: bool) -> Result<()> {
    if watch && Term::stdout().is_term() {
        return watch_loop();
    }
    let public_ip = if is_running() {
        fetch_public_ip()
    } else {
        None
    };
    print!("{}", render_status(public_ip.as_deref(), None));
    Ok(())
}

/// Live view: redraw the status block in place ~1/s (no alternate screen —
/// cursor-up + clear-line only, so scrollback and Ctrl-C stay well-behaved).
fn watch_loop() -> Result<()> {
    let term = Term::stdout();
    let mut public_ip: Option<String> = None;
    let mut public_ip_at: Option<Instant> = None;
    let mut drawn_lines = 0usize;

    loop {
        if is_running() && public_ip_at.is_none_or(|t| t.elapsed() > PUBLIC_IP_TTL) {
            public_ip = fetch_public_ip();
            public_ip_at = Some(Instant::now());
        }

        let peers = peers_section();
        let mut frame = render_status(public_ip.as_deref(), peers.as_deref());
        let _ = writeln!(
            frame,
            "  {}",
            style(format!(
                "watching (every {}s) — Ctrl-C to exit",
                WATCH_INTERVAL.as_secs()
            ))
            .dim()
        );

        if drawn_lines > 0 {
            term.move_cursor_up(drawn_lines)?;
        }
        let frame_lines = frame.lines().count();
        for line in frame.lines() {
            term.clear_line()?;
            term.write_line(line)?;
        }
        // A shrinking frame must blank the leftover rows from the previous
        // one (and keep the cursor at a stable height for the next pass).
        for _ in frame_lines..drawn_lines {
            term.clear_line()?;
            term.write_line("")?;
        }
        drawn_lines = frame_lines.max(drawn_lines);

        std::thread::sleep(WATCH_INTERVAL);
    }
}

/// Peer rows from the local server's control socket (server hosts only);
/// None on client hosts / when no server is running.
#[cfg(unix)]
fn peers_section() -> Option<String> {
    let peers = super::peer::fetch_peers().ok()?;
    let mut out = String::new();
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "  {} {}",
        style("◆").cyan().bold(),
        style("Peers").bold()
    );
    if peers.is_empty() {
        let _ = writeln!(out, "    {}", style("none configured").dim());
    }
    for peer in &peers {
        let _ = writeln!(out, "    {}", super::peer::render_peer_line(peer));
    }
    Some(out)
}

#[cfg(windows)]
fn peers_section() -> Option<String> {
    None
}

/// Render the full status block into a string (so the watch mode can count
/// and redraw lines).
fn render_status(public_ip: Option<&str>, peers: Option<&str>) -> String {
    let mut out = String::new();
    let o = &mut out;
    let _ = writeln!(o);

    // Header
    let _ = writeln!(
        o,
        "  {} {}",
        style("2cha").cyan().bold(),
        style("VPN Status").bold()
    );
    let _ = writeln!(o, "  {}", style("═".repeat(divider_width())).dim());

    let connected = is_running();

    // Status
    if connected {
        let _ = writeln!(
            o,
            "  {}     {} Connected",
            style("Status:").dim(),
            style(Icons::CONNECTED).green().bold()
        );
    } else {
        let _ = writeln!(
            o,
            "  {}     {} Disconnected",
            style("Status:").dim(),
            icon_disconnected()
        );
    }

    let routing_status = routing::get_routing_status(TUN_NAME);

    // Interface
    if routing_status.interface_exists {
        let _ = writeln!(
            o,
            "  {}  {} {}",
            style("Interface:").dim(),
            style(Icons::CONNECTED).green(),
            style(TUN_NAME).cyan()
        );
    } else {
        let _ = writeln!(
            o,
            "  {}  {} {}",
            style("Interface:").dim(),
            icon_disconnected(),
            TUN_NAME
        );
    }

    // IPv4
    if let Some(ref addr) = routing_status.ipv4_address {
        let _ = writeln!(o, "  {}       {}", style("IPv4:").dim(), style(addr).cyan());
    } else if connected {
        let _ = writeln!(
            o,
            "  {}       {}",
            style("IPv4:").dim(),
            style("disabled").dim()
        );
    }

    // IPv6
    if let Some(ref addr) = routing_status.ipv6_address {
        let _ = writeln!(o, "  {}       {}", style("IPv6:").dim(), style(addr).cyan());
    } else if connected {
        let _ = writeln!(
            o,
            "  {}       {}",
            style("IPv6:").dim(),
            style("disabled").dim()
        );
    }

    // Routing
    if routing_status.is_full_tunnel() {
        let mode =
            if routing_status.default_route_v4_via_tun && routing_status.default_route_v6_via_tun {
                "(v4+v6)"
            } else if routing_status.default_route_v4_via_tun {
                "(v4)"
            } else {
                "(v6)"
            };
        let _ = writeln!(
            o,
            "  {}    {} {} {}",
            style("Routing:").dim(),
            style(Icons::CONNECTED).yellow(),
            style("Full tunnel").yellow(),
            style(mode).dim()
        );
    } else if connected {
        let _ = writeln!(
            o,
            "  {}    {} {}",
            style("Routing:").dim(),
            style(Icons::CONNECTED).green(),
            style("Split tunnel").green()
        );
    } else {
        let _ = writeln!(
            o,
            "  {}    {} {}",
            style("Routing:").dim(),
            icon_disconnected(),
            style("Normal").dim()
        );
    }

    // Gateway
    if routing_status.ipv4_forwarding || routing_status.ipv6_forwarding {
        let mode = if routing_status.ipv4_forwarding && routing_status.ipv6_forwarding {
            "(v4+v6)"
        } else if routing_status.ipv4_forwarding {
            "(v4)"
        } else {
            "(v6)"
        };
        let _ = writeln!(
            o,
            "  {}    {} {} {}",
            style("Gateway:").dim(),
            style(Icons::CONNECTED).green(),
            style("Forwarding").green(),
            style(mode).dim()
        );
    }

    // Traffic stats (Linux sysfs only)
    #[cfg(unix)]
    if routing_status.interface_exists {
        if let (Ok(rx), Ok(tx)) = (
            std::fs::read_to_string(format!("/sys/class/net/{}/statistics/rx_bytes", TUN_NAME)),
            std::fs::read_to_string(format!("/sys/class/net/{}/statistics/tx_bytes", TUN_NAME)),
        ) {
            let rx: u64 = rx.trim().parse().unwrap_or(0);
            let tx: u64 = tx.trim().parse().unwrap_or(0);
            let _ = writeln!(
                o,
                "  {}    {} {} / {} {}",
                style("Traffic:").dim(),
                style("↓").cyan(),
                format_bytes(rx),
                style("↑").magenta(),
                format_bytes(tx)
            );
        }
    }

    // Public IP (pre-fetched by the caller so watch mode can cache it)
    if let Some(ip) = public_ip {
        let _ = writeln!(
            o,
            "  {}  {}",
            style("Public IP:").dim(),
            style(ip).cyan().bold()
        );
    }

    #[cfg(windows)]
    let _ = writeln!(
        o,
        "  {}   {}",
        style("Platform:").dim(),
        style("Windows").blue()
    );

    if let Some(peers) = peers {
        out.push_str(peers);
    }

    out.push('\n');
    out
}

/// Divider sized to the terminal (clamped so pipes and huge terminals both
/// stay sane; non-TTY falls back to the classic 40).
fn divider_width() -> usize {
    Term::stdout()
        .size_checked()
        .map(|(_, cols)| (cols as usize).saturating_sub(4))
        .unwrap_or(40)
        .clamp(24, 60)
}

/// Best-effort public IP: native HTTP/1.0 GET against a plain-text IP echo,
/// short timeouts, no external binary (the old `curl ifconfig.me` shell-out
/// stalled status for 3s and silently vanished on curl-less hosts).
fn fetch_public_ip() -> Option<String> {
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};

    const TIMEOUT: Duration = Duration::from_millis(1500);
    let addr = ("api.ipify.org", 80).to_socket_addrs().ok()?.next()?;
    let mut sock = TcpStream::connect_timeout(&addr, TIMEOUT).ok()?;
    sock.set_read_timeout(Some(TIMEOUT)).ok()?;
    sock.set_write_timeout(Some(TIMEOUT)).ok()?;
    sock.write_all(b"GET / HTTP/1.0\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut response = String::new();
    sock.read_to_string(&mut response).ok()?;
    let body = response.split("\r\n\r\n").nth(1)?.trim();
    // Parse-validate so an HTML error page never lands in the UI
    body.parse::<std::net::IpAddr>()
        .ok()
        .map(|ip| ip.to_string())
}
