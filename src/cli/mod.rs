//! # CLI Module
//!
//! Command-line interface for the VPN utility.

mod commands;
mod utils;

pub use commands::{cmd_down, cmd_genkey, cmd_init, cmd_server, cmd_status, cmd_toggle, cmd_up};

use crate::constants::PROTOCOL_VERSION;

const VERSION: &str = "0.6.1";

/// Print version information
pub fn print_version() {
    println!("2cha v{}", VERSION);
    println!("Protocol version: {}", PROTOCOL_VERSION);

    #[cfg(target_env = "musl")]
    println!("Build: static (musl)");
    #[cfg(not(target_env = "musl"))]
    println!("Build: dynamic (glibc)");
}

/// Print usage information
pub fn print_usage() {
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
