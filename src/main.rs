//! # 2cha - Simple VPN Utility
//!
//! Usage:
//!   2cha up [--config FILE] [-d]     Connect to VPN
//!   2cha down                         Disconnect
//!   2cha status                       Show connection status  
//!   2cha toggle                       Toggle connection
//!   2cha server [--config FILE]       Run as server
//!   2cha genkey                       Generate new key
//!   2cha init                         Create config template

mod tun;
mod crypto;
mod protocol;
mod network;
mod error;
mod config;
mod routing;

pub use error::{VpnError, Result};
pub use tun::TunDevice;
pub use crypto::{ChaCha20, Poly1305, ChaCha20Poly1305, Aes256Gcm, Cipher};
pub use protocol::{Packet, PacketType};
pub use network::{UdpTunnel, TunnelConfig};
pub use config::{ServerConfig, ClientConfig, ConfigError, CipherSuite};

pub const PROTOCOL_VERSION: u8 = 1;
pub const CHACHA20_KEY_SIZE: usize = 32;
pub const CHACHA20_NONCE_SIZE: usize = 12;
pub const POLY1305_TAG_SIZE: usize = 16;
pub const PROTOCOL_HEADER_SIZE: usize = 24;
pub const MAX_PACKET_SIZE: usize = 1500;

mod client;
mod server;

use std::env;
use std::process;

const VERSION: &str = "0.2.0";
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
        "-h" | "--help" | "help" => { print_usage(); Ok(()) }
        "-v" | "--version" | "version" => { println!("2cha v{}", VERSION); Ok(()) }
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

fn print_usage() {
    println!(r#"
  ██████╗  ██████╗██╗  ██╗ █████╗ 
  ╚════██╗██╔════╝██║  ██║██╔══██╗
   █████╔╝██║     ███████║███████║
  ██╔═══╝ ██║     ██╔══██║██╔══██║
  ███████╗╚██████╗██║  ██║██║  ██║
  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝  v{}

Simple VPN utility powered by ChaCha20-Poly1305

USAGE:
    2cha <COMMAND> [OPTIONS]

COMMANDS:
    up, connect       Connect to VPN server
    down, disconnect  Disconnect from VPN
    status, s         Show connection status
    toggle, t         Toggle connection on/off
    server, serve     Run as VPN server
    genkey, key       Generate a new encryption key
    init              Create config file template

OPTIONS:
    -c, --config <FILE>   Config file (default: /etc/2cha/client.toml)
    -d, --daemon          Run in background
    -v, --verbose         Show detailed output
    -q, --quiet           Minimal output
    -h, --help            Show this help

EXAMPLES:
    # Quick connect with default config
    sudo 2cha up

    # Connect with custom config
    sudo 2cha up -c ~/my-vpn.toml

    # Check status
    2cha status

    # Run server
    sudo 2cha server -c /etc/2cha/server.toml

    # Generate new key
    2cha genkey > /etc/2cha/vpn.key

    # Create config template
    2cha init client > client.toml
    2cha init server > server.toml
"#, VERSION);
}

fn cmd_up(args: &[String]) -> Result<()> {
    let mut config_path = DEFAULT_CONFIG.to_string();
    let mut daemon = false;
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
            "-d" | "--daemon" => daemon = true,
            "-v" | "--verbose" => verbose = true,
            "-q" | "--quiet" => quiet = true,
            _ => {}
        }
        i += 1;
    }
    
    let _ = daemon; // TODO: implement daemon mode

    // Check if already running
    if is_running() {
        if !quiet {
            println!("\x1b[33m●\x1b[0m VPN already connected");
            println!("  Use '\x1b[1m2cha status\x1b[0m' for details or '\x1b[1m2cha down\x1b[0m' to disconnect");
        }
        return Ok(());
    }

    // Setup logging
    if verbose {
        env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or("debug")
        ).format_timestamp_millis().init();
    } else if !quiet {
        env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or("warn")
        ).format_target(false).format_timestamp(None).init();
    }

    if !quiet {
        println!("\x1b[36m⟳\x1b[0m Connecting to VPN...");
    }

    // Save PID
    std::fs::write(PID_FILE, std::process::id().to_string()).ok();

    // Run client
    let result = client::run(&config_path, quiet);

    // Cleanup PID
    std::fs::remove_file(PID_FILE).ok();

    if !quiet && result.is_ok() {
        println!("\x1b[32m✓\x1b[0m Disconnected");
    }

    result
}

fn cmd_down() -> Result<()> {
    if let Ok(pid_str) = std::fs::read_to_string(PID_FILE) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            println!("\x1b[36m⟳\x1b[0m Disconnecting...");
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
            // Wait a bit
            std::thread::sleep(std::time::Duration::from_millis(500));
            
            if !is_running() {
                println!("\x1b[32m✓\x1b[0m Disconnected");
            } else {
                // Force kill
                unsafe { libc::kill(pid, libc::SIGKILL); }
                std::fs::remove_file(PID_FILE).ok();
                println!("\x1b[32m✓\x1b[0m Force disconnected");
            }
            return Ok(());
        }
    }
    
    println!("\x1b[33m●\x1b[0m VPN not connected");
    Ok(())
}

fn cmd_status() -> Result<()> {
    println!();
    println!("  \x1b[1m2cha VPN Status\x1b[0m");
    println!("  ─────────────────────────────────");
    
    // Check connection
    let connected = is_running();
    if connected {
        println!("  Status:    \x1b[32m● Connected\x1b[0m");
    } else {
        println!("  Status:    \x1b[31m○ Disconnected\x1b[0m");
    }

    // Check TUN interface
    if let Ok(output) = std::process::Command::new("ip")
        .args(["addr", "show", "tun0"])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(ip_line) = stdout.lines().find(|l| l.contains("inet ")) {
                let ip = ip_line.split_whitespace()
                    .nth(1)
                    .unwrap_or("unknown");
                println!("  VPN IP:    \x1b[36m{}\x1b[0m", ip);
            }
        }
    }

    // Check routing
    if let Ok(output) = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("tun0") {
            println!("  Routing:   \x1b[32m● Full tunnel\x1b[0m (all traffic via VPN)");
        } else if connected {
            println!("  Routing:   \x1b[33m● Split tunnel\x1b[0m (VPN network only)");
        } else {
            println!("  Routing:   \x1b[90m○ Normal\x1b[0m");
        }
    }

    // Get public IP
    if connected {
        if let Ok(output) = std::process::Command::new("curl")
            .args(["-s", "--max-time", "3", "ifconfig.me"])
            .output()
        {
            if output.status.success() {
                let ip = String::from_utf8_lossy(&output.stdout);
                println!("  Public IP: \x1b[36m{}\x1b[0m", ip.trim());
            }
        }
    }

    // Check IP forwarding (server mode)
    if let Ok(val) = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward") {
        if val.trim() == "1" {
            println!("  Gateway:   \x1b[32m● Enabled\x1b[0m (forwarding active)");
        }
    }

    // Stats from /sys if available
    if std::path::Path::new("/sys/class/net/tun0/statistics/rx_bytes").exists() {
        if let (Ok(rx), Ok(tx)) = (
            std::fs::read_to_string("/sys/class/net/tun0/statistics/rx_bytes"),
            std::fs::read_to_string("/sys/class/net/tun0/statistics/tx_bytes"),
        ) {
            let rx: u64 = rx.trim().parse().unwrap_or(0);
            let tx: u64 = tx.trim().parse().unwrap_or(0);
            println!("  Traffic:   ↓ {} / ↑ {}", format_bytes(rx), format_bytes(tx));
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

    // Setup logging
    let log_level = if verbose { "debug" } else if quiet { "error" } else { "info" };
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(log_level)
    ).format_timestamp_millis().init();

    server::run(&config_path)
}

fn cmd_genkey() -> Result<()> {
    let mut key = [0u8; 32];
    
    // Read from /dev/urandom
    if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        file.read_exact(&mut key).map_err(|e| VpnError::Io(e))?;
    } else {
        // Fallback to time-based (not cryptographically secure!)
        eprintln!("Warning: /dev/urandom not available, using weak randomness");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        for i in 0..32 {
            key[i] = ((now >> (i * 2)) & 0xff) as u8;
        }
    }

    // Print as hex
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
            std::process::exit(1);
        }
    }
    
    Ok(())
}

fn is_running() -> bool {
    if let Ok(pid_str) = std::fs::read_to_string(PID_FILE) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            // Check if process exists
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
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
