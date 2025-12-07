//! # CLI Commands
//!
//! Command implementations for the VPN CLI.

use crate::cli::utils::{
    format_bytes, generate_key, is_running, setup_logging, ParsedArgs,
    DEFAULT_CONFIG, DEFAULT_SERVER_CONFIG, PID_FILE,
};
use crate::core::config::{example_client_config, example_server_config};
use crate::core::error::Result;
use crate::vpn::{client, server};

#[cfg(unix)]
use crate::platform::unix::routing;
#[cfg(windows)]
use crate::platform::windows::routing;

/// Connect to VPN server
#[cfg(unix)]
pub fn cmd_up(args: &[String]) -> Result<()> {
    let parsed = ParsedArgs::parse(args, DEFAULT_CONFIG);

    if is_running() {
        if !parsed.quiet {
            println!("\x1b[33m●\x1b[0m VPN already connected");
            println!("  Use '2cha status' or '2cha down'");
        }
        return Ok(());
    }

    if parsed.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
            .format_timestamp_millis()
            .init();
    } else if !parsed.quiet {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
            .format_target(false)
            .format_timestamp(None)
            .init();
    }

    if !parsed.quiet {
        println!("\x1b[36m⟳\x1b[0m Connecting...");
    }

    std::fs::write(PID_FILE, std::process::id().to_string()).ok();
    let result = client::run(&parsed.config_path, parsed.quiet);
    std::fs::remove_file(PID_FILE).ok();

    result
}

#[cfg(windows)]
pub fn cmd_up(args: &[String]) -> Result<()> {
    let parsed = ParsedArgs::parse(args, DEFAULT_CONFIG);

    if is_running() {
        if !parsed.quiet {
            println!("\x1b[33m*\x1b[0m VPN already connected");
            println!("  Use '2cha status' or '2cha down'");
        }
        return Ok(());
    }

    if parsed.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
            .format_timestamp_millis()
            .init();
    } else if !parsed.quiet {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
            .format_target(false)
            .format_timestamp(None)
            .init();
    }

    if !parsed.quiet {
        println!("\x1b[36m>\x1b[0m Connecting...");
        println!("  Note: Requires wintun.dll and Administrator privileges");
    }

    std::fs::write(PID_FILE, std::process::id().to_string()).ok();
    let result = client::run(&parsed.config_path, parsed.quiet);
    std::fs::remove_file(PID_FILE).ok();

    result
}

/// Disconnect from VPN
#[cfg(unix)]
pub fn cmd_down() -> Result<()> {
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

#[cfg(windows)]
pub fn cmd_down() -> Result<()> {
    if let Ok(pid_str) = std::fs::read_to_string(PID_FILE) {
        if let Ok(pid) = pid_str.trim().parse::<u32>() {
            println!("\x1b[36m⟳\x1b[0m Disconnecting...");

            let _ = std::process::Command::new("taskkill")
                .args(["/PID", &pid.to_string(), "/F"])
                .output();

            std::thread::sleep(std::time::Duration::from_millis(500));
            std::fs::remove_file(PID_FILE).ok();
            println!("\x1b[32m✓\x1b[0m Disconnected");
            return Ok(());
        }
    }

    println!("\x1b[90m○\x1b[0m VPN not connected");
    Ok(())
}

/// Show VPN status
#[cfg(unix)]
pub fn cmd_status() -> Result<()> {
    println!();
    println!("  \x1b[1;36m2cha VPN Status\x1b[0m");
    println!("  ════════════════════════════════════════");

    let connected = is_running();
    let tun_name = "tun0";

    if connected {
        println!("  Status:     \x1b[32m● Connected\x1b[0m");
    } else {
        println!("  Status:     \x1b[31m○ Disconnected\x1b[0m");
    }

    let routing_status = routing::get_routing_status(tun_name);

    if routing_status.interface_exists {
        println!("  Interface:  \x1b[32m●\x1b[0m {}", tun_name);
    } else {
        println!("  Interface:  \x1b[90m○\x1b[0m {}", tun_name);
    }

    if let Some(ref addr) = routing_status.ipv4_address {
        println!("  IPv4:       \x1b[36m{}\x1b[0m", addr);
    } else if connected {
        println!("  IPv4:       \x1b[90mdisabled\x1b[0m");
    }

    if let Some(ref addr) = routing_status.ipv6_address {
        println!("  IPv6:       \x1b[36m{}\x1b[0m", addr);
    } else if connected {
        println!("  IPv6:       \x1b[90mdisabled\x1b[0m");
    }

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

#[cfg(windows)]
pub fn cmd_status() -> Result<()> {
    println!();
    println!("  \x1b[1;36m2cha VPN Status\x1b[0m");
    println!("  ================================================");

    let connected = is_running();
    let tun_name = "2cha";

    if connected {
        println!("  Status:     \x1b[32m* Connected\x1b[0m");
    } else {
        println!("  Status:     \x1b[31mo Disconnected\x1b[0m");
    }

    let routing_status = routing::get_routing_status(tun_name);

    if routing_status.interface_exists {
        println!("  Interface:  \x1b[32m*\x1b[0m {}", tun_name);
    } else {
        println!("  Interface:  \x1b[90mo\x1b[0m {}", tun_name);
    }

    if let Some(ref addr) = routing_status.ipv4_address {
        println!("  IPv4:       \x1b[36m{}\x1b[0m", addr);
    } else if connected {
        println!("  IPv4:       \x1b[90mdisabled\x1b[0m");
    }

    if let Some(ref addr) = routing_status.ipv6_address {
        println!("  IPv6:       \x1b[36m{}\x1b[0m", addr);
    } else if connected {
        println!("  IPv6:       \x1b[90mdisabled\x1b[0m");
    }

    if routing_status.is_full_tunnel() {
        print!("  Routing:    \x1b[33m* Full tunnel\x1b[0m");
        if routing_status.default_route_v4_via_tun && routing_status.default_route_v6_via_tun {
            println!(" (v4+v6)");
        } else if routing_status.default_route_v4_via_tun {
            println!(" (v4)");
        } else {
            println!(" (v6)");
        }
    } else if connected {
        println!("  Routing:    \x1b[32m* Split tunnel\x1b[0m");
    } else {
        println!("  Routing:    \x1b[90mo Normal\x1b[0m");
    }

    if routing_status.ipv4_forwarding || routing_status.ipv6_forwarding {
        print!("  Gateway:    \x1b[32m* Forwarding\x1b[0m");
        if routing_status.ipv4_forwarding && routing_status.ipv6_forwarding {
            println!(" (v4+v6)");
        } else if routing_status.ipv4_forwarding {
            println!(" (v4)");
        } else {
            println!(" (v6)");
        }
    }

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

    println!("  Platform:   Windows");
    println!();
    Ok(())
}

/// Toggle VPN connection
pub fn cmd_toggle(args: &[String]) -> Result<()> {
    if is_running() {
        cmd_down()
    } else {
        cmd_up(args)
    }
}

/// Run VPN server
pub fn cmd_server(args: &[String]) -> Result<()> {
    let parsed = ParsedArgs::parse(args, DEFAULT_SERVER_CONFIG);
    setup_logging(parsed.verbose, parsed.quiet);

    #[cfg(windows)]
    log::info!("Note: Requires wintun.dll and Administrator privileges");

    server::run(&parsed.config_path)
}

/// Generate encryption key
pub fn cmd_genkey() -> Result<()> {
    let key = generate_key()?;

    for byte in &key {
        print!("{:02x}", byte);
    }
    println!();
    Ok(())
}

/// Create config template
pub fn cmd_init(args: &[String]) -> Result<()> {
    let mode = args.first().map(|s| s.as_str()).unwrap_or("client");

    match mode {
        "client" | "c" => print!("{}", example_client_config()),
        "server" | "s" => print!("{}", example_server_config()),
        _ => {
            eprintln!("Usage: 2cha init <client|server>");
            std::process::exit(1);
        }
    }

    Ok(())
}
