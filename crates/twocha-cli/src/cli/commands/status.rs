//! Connection status command (shared Unix/Windows logic).

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use crate::cli::output::{icon_disconnected, Icons};
use crate::cli::utils::{format_bytes, is_running};
use console::{style, Term};
use twocha_protocol::Result;

use super::peer::PeerInfo;

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

/// This host's server facts, present only when a local server answers on the
/// control socket — that's what flips `status` from the client view to the
/// server view.
struct ServerInfo {
    peers: Vec<PeerInfo>,
    /// Address the running server listens on (best-effort, from its config)
    listen: Option<String>,
    /// Obfuscation transport (`quic`/`tls`), best-effort from its config
    transport: Option<String>,
}

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
    let server = server_info();
    print!("{}", render_status(public_ip.as_deref(), server.as_ref()));
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

        let server = server_info();
        let mut frame = render_status(public_ip.as_deref(), server.as_ref());
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

/// If a local server answers on the control socket, gather the facts that make
/// `status` a server dashboard; `None` on client hosts (and on Windows).
#[cfg(unix)]
fn server_info() -> Option<ServerInfo> {
    // A successful peer-list means the control socket is up — i.e. *this* host
    // is running a 2cha server.
    let peers = super::peer::fetch_peers().ok()?;
    let (listen, transport) = read_server_listen();
    Some(ServerInfo {
        peers,
        listen,
        transport,
    })
}

#[cfg(windows)]
fn server_info() -> Option<ServerInfo> {
    None
}

/// Best-effort listen address + transport of the running server, read from the
/// very config it was started with (`-c <path>` in `/proc/<pid>/cmdline`),
/// falling back to the documented default. Never fails the status render.
#[cfg(target_os = "linux")]
fn read_server_listen() -> (Option<String>, Option<String>) {
    let Some(path) = server_config_path() else {
        return (None, None);
    };
    match twocha_core::ServerConfig::from_file(&path) {
        Ok(cfg) => (
            cfg.listen_addr().ok().map(|a| a.to_string()),
            Some(cfg.server.transport.to_string()),
        ),
        Err(_) => (None, None),
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn read_server_listen() -> (Option<String>, Option<String>) {
    (None, None)
}

/// The config path the running server was launched with (from its cmdline),
/// else the documented default if it exists.
#[cfg(target_os = "linux")]
fn server_config_path() -> Option<std::path::PathBuf> {
    use crate::cli::utils::find_pid_file;
    use std::path::PathBuf;

    let pid = find_pid_file()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| s.trim().parse::<i32>().ok());
    if let Some(pid) = pid {
        if let Ok(raw) = std::fs::read(format!("/proc/{}/cmdline", pid)) {
            let args: Vec<String> = raw
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect();
            for (i, arg) in args.iter().enumerate() {
                if let Some(p) = arg.strip_prefix("--config=") {
                    return Some(PathBuf::from(p));
                }
                if (arg == "-c" || arg == "--config") && i + 1 < args.len() {
                    return Some(PathBuf::from(&args[i + 1]));
                }
            }
        }
    }
    let default = PathBuf::from("/etc/2cha/server.toml");
    default.exists().then_some(default)
}

/// The `◆ Peers` detail block (server view only).
fn peers_section(peers: &[PeerInfo]) -> String {
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
    for peer in peers {
        let _ = writeln!(out, "    {}", super::peer::render_peer_line(peer));
    }
    out
}

/// Render the full status block into a string (so the watch mode can count
/// and redraw lines). A `server` value switches the view to the server
/// dashboard; `None` renders the client tunnel view.
fn render_status(public_ip: Option<&str>, server: Option<&ServerInfo>) -> String {
    let is_server = server.is_some();
    let mut out = String::new();
    let o = &mut out;
    let _ = writeln!(o);

    // Header
    let _ = writeln!(
        o,
        "  {} {}",
        style("2cha").cyan().bold(),
        style(if is_server {
            "Server Status"
        } else {
            "VPN Status"
        })
        .bold()
    );
    let _ = writeln!(o, "  {}", style("═".repeat(divider_width())).dim());

    let connected = is_running();

    // Status — servers "run", clients "connect"
    if connected {
        let (label, word) = if is_server {
            (Icons::CONNECTED, "Running")
        } else {
            (Icons::CONNECTED, "Connected")
        };
        let _ = writeln!(
            o,
            "  {}     {} {}",
            style("Status:").dim(),
            style(label).green().bold(),
            word
        );
    } else {
        let word = if is_server { "Stopped" } else { "Disconnected" };
        let _ = writeln!(
            o,
            "  {}     {} {}",
            style("Status:").dim(),
            icon_disconnected(),
            word
        );
    }

    // Listening address (server view, best-effort)
    if let Some(srv) = server {
        if let Some(ref listen) = srv.listen {
            let transport = srv
                .transport
                .as_deref()
                .map(|t| format!("  {}", style(format!("({})", t)).dim()))
                .unwrap_or_default();
            let _ = writeln!(
                o,
                "  {} {}{}",
                style("Listening:").dim(),
                style(listen).cyan().bold(),
                transport
            );
        }
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

    // Routing (client-only concept — a server never tunnels its own traffic)
    if !is_server {
        if routing_status.is_full_tunnel() {
            let mode = if routing_status.default_route_v4_via_tun
                && routing_status.default_route_v6_via_tun
            {
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
    }

    // Gateway / forwarding (relevant to servers and gateway clients)
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
    } else if is_server {
        // A server that isn't forwarding usually can't route clients anywhere.
        let _ = writeln!(
            o,
            "  {}    {} {}",
            style("Gateway:").dim(),
            icon_disconnected(),
            style("not forwarding — run `2cha setup`").dim()
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

    // Peer summary + detail (server view)
    if let Some(srv) = server {
        let online = srv.peers.iter().filter(|p| p.online).count();
        let total = srv.peers.len();
        let _ = writeln!(
            o,
            "  {}     {} {} / {} total",
            style("Peers:").dim(),
            style(online).green().bold(),
            style("online").green(),
            total
        );
    }

    #[cfg(windows)]
    let _ = writeln!(
        o,
        "  {}   {}",
        style("Platform:").dim(),
        style("Windows").blue()
    );

    if let Some(srv) = server {
        out.push_str(&peers_section(&srv.peers));
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
