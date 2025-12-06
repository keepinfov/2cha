//! # 2cha - High-Performance VPN Utility
//!
//! Features:
//! - IPv4/IPv6 dual-stack support
//! - ChaCha20-Poly1305 or AES-256-GCM encryption
//! - Static binary support (musl)
//! - Full/split tunnel modes

mod config;
mod crypto;
mod error;
mod network;
mod protocol;
mod routing;
mod tun;

pub use config::{CipherSuite, ClientConfig, ConfigError, ServerConfig};
pub use crypto::{Aes256Gcm, ChaCha20, ChaCha20Poly1305, Cipher, Poly1305};
pub use error::{Result, VpnError};
pub use network::{TunnelConfig, UdpTunnel};
pub use protocol::{Packet, PacketType};
pub use tun::TunDevice;

pub const PROTOCOL_VERSION: u8 = 2;
pub const CHACHA20_KEY_SIZE: usize = 32;
pub const CHACHA20_NONCE_SIZE: usize = 12;
pub const POLY1305_TAG_SIZE: usize = 16;
pub const PROTOCOL_HEADER_SIZE: usize = 24;
pub const MAX_PACKET_SIZE: usize = 1500;

mod client;
mod server;

use std::env;
use std::process;

const VERSION: &str = "0.5.1-2";
const PID_FILE: &str = "/tmp/2cha.pid";
const DEFAULT_CONFIG: &str = "/etc/2cha/client.toml";
const DEFAULT_SERVER_CONFIG: &str = "/etc/2cha/server.toml";

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }

    let result = match args[1].as_str() {
        "up" | "connect" => cmd_up(&args[2..]),
        "down" | "disconnect" => cmd_down(),
        "status" | "s" => cmd_status(),
        "toggle" | "t" => cmd_toggle(&args[2..]),
        "server" | "serve" => cmd_server(&args[2..]),
        "genkey" | "key" => cmd_genkey(),
        "init" => cmd_init(&args[2..]),
        "-h" | "--help" | "help" => {
            print_usage();
            Ok(())
        }
        "-v" | "--version" | "version" => {
            print_version();
            Ok(())
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            print_usage();
            process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("\x1b[31m✗\x1b[0m Error: {}", e);
        process::exit(1);
    }
}

fn print_version() {
    println!("2cha v{}", VERSION);
    println!("Protocol version: {}", PROTOCOL_VERSION);

    #[cfg(target_env = "musl")]
    println!("Build: static (musl)");
    #[cfg(not(target_env = "musl"))]
    println!("Build: dynamic (glibc)");
}

fn print_usage() {
    println!(
        r#"
  ██████╗  ██████╗██╗  ██╗ █████╗ 
  ╚════██╗██╔════╝██║  ██║██╔══██╗
   █████╔╝██║     ███████║███████║
  ██╔═══╝ ██║     ██╔══██║██╔══██║
  ███████╗╚██████╗██║  ██║██║  ██║
  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝  v{}

High-performance VPN with IPv4/IPv6 support

USAGE:
    2cha <COMMAND> [OPTIONS]

COMMANDS:
    up, connect       Connect to VPN server
    down, disconnect  Disconnect from VPN
    status, s         Show connection status
    toggle, t         Toggle connection on/off
    server, serve     Run as VPN server
    genkey, key       Generate encryption key
    init              Create config template

OPTIONS:
    -c, --config <FILE>   Config file path
    -d, --daemon          Run in background
    -v, --verbose         Detailed output
    -q, --quiet           Minimal output
    -h, --help            Show help

EXAMPLES:
    sudo 2cha up -c client.toml
    sudo 2cha server -c server.toml
    2cha genkey > vpn.key
    2cha init client > client.toml
    2cha init server > server.toml
    2cha status

STATIC BUILD:
    rustup target add x86_64-unknown-linux-musl
    cargo build --release --target x86_64-unknown-linux-musl
"#,
        VERSION
    );
}

fn cmd_up(args: &[String]) -> Result<()> {
    let mut config_path = DEFAULT_CONFIG.to_string();
    let mut verbose = false;
    let mut quiet = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--config" => {
                i += 1;
                if i < args.len() {
                    config_path = args[i].to_string();
                }
            }
            "-v" | "--verbose" => verbose = true,
            "-q" | "--quiet" => quiet = true,
            _ => {}
        }
        i += 1;
    }

    if is_running() {
        if !quiet {
            println!("\x1b[33m●\x1b[0m VPN already connected");
            println!("  Use '2cha status' or '2cha down'");
        }
        return Ok(());
    }

    // Setup logging
    if verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
            .format_timestamp_millis()
            .init();
    } else if !quiet {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
            .format_target(false)
            .format_timestamp(None)
            .init();
    }

    if !quiet {
        println!("\x1b[36m⟳\x1b[0m Connecting...");
    }

    // Save PID
    std::fs::write(PID_FILE, std::process::id().to_string()).ok();

    let result = client::run(&config_path, quiet);

    std::fs::remove_file(PID_FILE).ok();
    result
}

fn cmd_down() -> Result<()> {
    if let Ok(pid_str) = std::fs::read_to_string(PID_FILE) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            println!("\x1b[36m⟳\x1b[0m Disconnecting...");
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
            std::thread::sleep(std::time::Duration::from_millis(500));

            if !is_running() {
                println!("\x1b[32m✓\x1b[0m Disconnected");
            } else {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
                std::fs::remove_file(PID_FILE).ok();
                println!("\x1b[32m✓\x1b[0m Force disconnected");
            }
            return Ok(());
        }
    }

    println!("\x1b[90m○\x1b[0m VPN not connected");
    Ok(())
}

fn cmd_status() -> Result<()> {
    println!();
    println!("  \x1b[1;36m2cha VPN Status\x1b[0m");
    println!("  ════════════════════════════════════════");

    let connected = is_running();
    let tun_name = "tun0";

    // Connection status
    if connected {
        println!("  Status:     \x1b[32m● Connected\x1b[0m");
    } else {
        println!("  Status:     \x1b[31m○ Disconnected\x1b[0m");
    }

    // Get routing status
    let routing_status = routing::get_routing_status(tun_name);

    // Interface status
    if routing_status.interface_exists {
        println!("  Interface:  \x1b[32m●\x1b[0m {}", tun_name);
    } else {
        println!("  Interface:  \x1b[90m○\x1b[0m {}", tun_name);
    }

    // IPv4 address
    if let Some(ref addr) = routing_status.ipv4_address {
        println!("  IPv4:       \x1b[36m{}\x1b[0m", addr);
    } else if connected {
        println!("  IPv4:       \x1b[90mdisabled\x1b[0m");
    }

    // IPv6 address
    if let Some(ref addr) = routing_status.ipv6_address {
        println!("  IPv6:       \x1b[36m{}\x1b[0m", addr);
    } else if connected {
        println!("  IPv6:       \x1b[90mdisabled\x1b[0m");
    }

    // Routing mode
    if routing_status.is_full_tunnel() {
        print!("  Routing:    \x1b[33m● Full tunnel\x1b[0m");
        if routing_status.default_route_v4_via_tun && routing_status.default_route_v6_via_tun {
            println!(" (v4+v6)");
        } else if routing_status.default_route_v4_via_tun {
            println!(" (v4)");
        } else {
            println!(" (v6)");
        }
    } else if connected {
        println!("  Routing:    \x1b[32m● Split tunnel\x1b[0m");
    } else {
        println!("  Routing:    \x1b[90m○ Normal\x1b[0m");
    }

    // Gateway status (for server mode)
    if routing_status.ipv4_forwarding || routing_status.ipv6_forwarding {
        print!("  Gateway:    \x1b[32m● Forwarding\x1b[0m");
        if routing_status.ipv4_forwarding && routing_status.ipv6_forwarding {
            println!(" (v4+v6)");
        } else if routing_status.ipv4_forwarding {
            println!(" (v4)");
        } else {
            println!(" (v6)");
        }
    }

    // Traffic statistics
    if routing_status.interface_exists {
        if let (Ok(rx), Ok(tx)) = (
            std::fs::read_to_string(format!("/sys/class/net/{}/statistics/rx_bytes", tun_name)),
            std::fs::read_to_string(format!("/sys/class/net/{}/statistics/tx_bytes", tun_name)),
        ) {
            let rx: u64 = rx.trim().parse().unwrap_or(0);
            let tx: u64 = tx.trim().parse().unwrap_or(0);
            println!(
                "  Traffic:    ↓ {} / ↑ {}",
                format_bytes(rx),
                format_bytes(tx)
            );
        }
    }

    // Public IP (only if connected)
    if connected {
        if let Ok(output) = std::process::Command::new("curl")
            .args(["-s", "--max-time", "3", "-4", "ifconfig.me"])
            .output()
        {
            if output.status.success() {
                let ip = String::from_utf8_lossy(&output.stdout);
                println!("  Public IP:  \x1b[36m{}\x1b[0m", ip.trim());
            }
        }
    }

    println!();
    Ok(())
}

fn cmd_toggle(args: &[String]) -> Result<()> {
    if is_running() {
        cmd_down()
    } else {
        cmd_up(args)
    }
}

fn cmd_server(args: &[String]) -> Result<()> {
    let mut config_path = DEFAULT_SERVER_CONFIG.to_string();
    let mut verbose = false;
    let mut quiet = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--config" => {
                i += 1;
                if i < args.len() {
                    config_path = args[i].to_string();
                }
            }
            "-v" | "--verbose" => verbose = true,
            "-q" | "--quiet" => quiet = true,
            _ => {}
        }
        i += 1;
    }

    let log_level = if verbose {
        "debug"
    } else if quiet {
        "error"
    } else {
        "info"
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level))
        .format_timestamp_millis()
        .init();

    server::run(&config_path)
}

fn cmd_genkey() -> Result<()> {
    let mut key = [0u8; 32];

    if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        file.read_exact(&mut key).map_err(VpnError::Io)?;
    } else {
        eprintln!("Warning: /dev/urandom unavailable");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = ((now >> (i * 2)) & 0xff) as u8;
        }
    }

    for byte in &key {
        print!("{:02x}", byte);
    }
    println!();
    Ok(())
}

fn cmd_init(args: &[String]) -> Result<()> {
    let mode = args.first().map(|s| s.as_str()).unwrap_or("client");

    match mode {
        "client" | "c" => print!("{}", config::example_client_config()),
        "server" | "s" => print!("{}", config::example_server_config()),
        _ => {
            eprintln!("Usage: 2cha init <client|server>");
            process::exit(1);
        }
    }

    Ok(())
}

fn is_running() -> bool {
    if let Ok(pid_str) = std::fs::read_to_string(PID_FILE) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            unsafe {
                return libc::kill(pid, 0) == 0;
            }
        }
    }
    false
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
