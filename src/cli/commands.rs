//! # CLI Commands
//!
//! Command implementations for the VPN CLI.

#[cfg(unix)]
use crate::cli::utils::can_signal_process;
#[cfg(unix)]
use crate::cli::utils::LOG_FILE;
use crate::cli::utils::{
    daemonize, ensure_root, format_bytes, generate_key, is_running, setup_logging, PID_FILE,
};
use crate::core::config::{example_client_config, example_server_config};
use crate::core::error::Result;
use crate::vpn::{client, server};

use super::output;
use console::{style, Term};
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

#[cfg(unix)]
use crate::platform::unix::routing;
#[cfg(windows)]
use crate::platform::windows::routing;

/// Create a spinner with consistent styling
fn create_spinner(msg: &str) -> ProgressBar {
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    spinner.set_message(msg.to_string());
    spinner.enable_steady_tick(Duration::from_millis(80));
    spinner
}

/// Connect to VPN server (Unix)
#[cfg(unix)]
pub fn cmd_up(config_path: &str, daemon: bool, verbose: bool, quiet: bool) -> Result<()> {
    if is_running() {
        if !quiet {
            output::print_connected("VPN already connected");
            println!(
                "  Use {} or {}",
                style("2cha status").cyan(),
                style("2cha down").cyan()
            );
        }
        return Ok(());
    }

    // Ensure we have root privileges (will prompt for sudo password if needed)
    ensure_root()?;

    // Convert config path to absolute before daemonizing (daemon changes cwd to /)
    let config_path = std::fs::canonicalize(config_path)
        .map_err(|e| {
            crate::core::error::VpnError::Config(format!(
                "Config file '{}' not found: {}",
                config_path, e
            ))
        })?
        .to_string_lossy()
        .to_string();

    let spinner = if !quiet {
        Some(create_spinner("Connecting..."))
    } else {
        None
    };

    // Daemonize if requested
    if daemon {
        if let Some(ref sp) = spinner {
            sp.finish_with_message(format!(
                "Connecting in background. Logs: {}",
                style(LOG_FILE).dim()
            ));
        }
        if !quiet {
            println!("  Use {} to check connection", style("2cha status").cyan());
        }
        daemonize()?;
    } else if let Some(ref sp) = spinner {
        sp.finish_and_clear();
    }

    if verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
            .format_timestamp_millis()
            .init();
    } else if !quiet && !daemon {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
            .format_target(false)
            .format_timestamp(None)
            .init();
    }

    // PID file is managed by daemonize crate in daemon mode
    if !daemon {
        std::fs::write(PID_FILE, std::process::id().to_string()).ok();
    }

    let result = client::run(&config_path, quiet || daemon);

    // Clean up PID file on exit (only in non-daemon mode, daemon crate handles it)
    if !daemon {
        std::fs::remove_file(PID_FILE).ok();
    }

    result
}

/// Connect to VPN server (Windows)
#[cfg(windows)]
pub fn cmd_up(config_path: &str, daemon: bool, verbose: bool, quiet: bool) -> Result<()> {
    if is_running() {
        if !quiet {
            output::print_connected("VPN already connected");
            println!(
                "  Use {} or {}",
                style("2cha status").cyan(),
                style("2cha down").cyan()
            );
        }
        return Ok(());
    }

    // Ensure we have Administrator privileges
    ensure_root()?;

    // Convert config path to absolute before daemonizing
    let config_path = std::fs::canonicalize(config_path)
        .map_err(|e| {
            crate::core::error::VpnError::Config(format!(
                "Config file '{}' not found: {}",
                config_path, e
            ))
        })?
        .to_string_lossy()
        .to_string();

    let spinner = if !quiet {
        Some(create_spinner("Connecting..."))
    } else {
        None
    };

    // Daemonize if requested
    if daemon {
        if let Some(ref sp) = spinner {
            sp.finish_with_message("Connecting in background...");
        }
        if !quiet {
            println!(
                "  {} Requires {} and {}",
                style("Note:").dim(),
                style("wintun.dll").yellow(),
                style("Administrator").yellow()
            );
            println!("  Use {} to check connection", style("2cha status").cyan());
        }
        daemonize()?;
    } else {
        if let Some(ref sp) = spinner {
            sp.finish_and_clear();
        }
        if !quiet {
            println!(
                "  {} Requires {} and {}",
                style("Note:").dim(),
                style("wintun.dll").yellow(),
                style("Administrator").yellow()
            );
        }
    }

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

    std::fs::write(PID_FILE, std::process::id().to_string()).ok();
    let result = client::run(&config_path, quiet || daemon);
    std::fs::remove_file(PID_FILE).ok();

    result
}

/// Disconnect from VPN (Unix)
#[cfg(unix)]
pub fn cmd_down() -> Result<()> {
    if !is_running() {
        output::print_disconnected("VPN not connected");
        return Ok(());
    }

    // Check if we have permission to stop the VPN, elevate if needed
    if !can_signal_process() {
        ensure_root()?;
    }

    if let Ok(pid_str) = std::fs::read_to_string(PID_FILE) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            let spinner = create_spinner("Disconnecting...");

            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
            std::thread::sleep(Duration::from_millis(500));

            if !is_running() {
                spinner.finish_with_message(output::format_success("Disconnected"));
            } else {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
                std::fs::remove_file(PID_FILE).ok();
                spinner.finish_with_message(output::format_success("Force disconnected"));
            }
            return Ok(());
        }
    }

    output::print_disconnected("VPN not connected");
    Ok(())
}

/// Disconnect from VPN (Windows)
#[cfg(windows)]
pub fn cmd_down() -> Result<()> {
    if let Ok(pid_str) = std::fs::read_to_string(PID_FILE) {
        if let Ok(pid) = pid_str.trim().parse::<u32>() {
            let spinner = create_spinner("Disconnecting...");

            let _ = std::process::Command::new("taskkill")
                .args(["/PID", &pid.to_string(), "/F"])
                .output();

            std::thread::sleep(Duration::from_millis(500));
            std::fs::remove_file(PID_FILE).ok();

            spinner.finish_with_message(output::format_success("Disconnected"));
            return Ok(());
        }
    }

    output::print_disconnected("VPN not connected");
    Ok(())
}

/// Show VPN status (Unix)
#[cfg(unix)]
pub fn cmd_status() -> Result<()> {
    let term = Term::stdout();
    let _ = term.write_line("");

    // Header
    println!(
        "  {} {}",
        style("2cha").cyan().bold(),
        style("VPN Status").bold()
    );
    println!("  {}", style("═".repeat(40)).dim());

    let connected = is_running();
    let tun_name = "tun0";

    // Status
    if connected {
        println!(
            "  {}     {} Connected",
            style("Status:").dim(),
            style("●").green().bold()
        );
    } else {
        println!(
            "  {}     {} Disconnected",
            style("Status:").dim(),
            style("○").red()
        );
    }

    let routing_status = routing::get_routing_status(tun_name);

    // Interface
    if routing_status.interface_exists {
        println!(
            "  {}  {} {}",
            style("Interface:").dim(),
            style("●").green(),
            style(tun_name).cyan()
        );
    } else {
        println!(
            "  {}  {} {}",
            style("Interface:").dim(),
            style("○").dim(),
            tun_name
        );
    }

    // IPv4
    if let Some(ref addr) = routing_status.ipv4_address {
        println!("  {}       {}", style("IPv4:").dim(), style(addr).cyan());
    } else if connected {
        println!(
            "  {}       {}",
            style("IPv4:").dim(),
            style("disabled").dim()
        );
    }

    // IPv6
    if let Some(ref addr) = routing_status.ipv6_address {
        println!("  {}       {}", style("IPv6:").dim(), style(addr).cyan());
    } else if connected {
        println!(
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
        println!(
            "  {}    {} {} {}",
            style("Routing:").dim(),
            style("●").yellow(),
            style("Full tunnel").yellow(),
            style(mode).dim()
        );
    } else if connected {
        println!(
            "  {}    {} {}",
            style("Routing:").dim(),
            style("●").green(),
            style("Split tunnel").green()
        );
    } else {
        println!(
            "  {}    {} {}",
            style("Routing:").dim(),
            style("○").dim(),
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
        println!(
            "  {}    {} {} {}",
            style("Gateway:").dim(),
            style("●").green(),
            style("Forwarding").green(),
            style(mode).dim()
        );
    }

    // Traffic stats
    if routing_status.interface_exists {
        if let (Ok(rx), Ok(tx)) = (
            std::fs::read_to_string(format!("/sys/class/net/{}/statistics/rx_bytes", tun_name)),
            std::fs::read_to_string(format!("/sys/class/net/{}/statistics/tx_bytes", tun_name)),
        ) {
            let rx: u64 = rx.trim().parse().unwrap_or(0);
            let tx: u64 = tx.trim().parse().unwrap_or(0);
            println!(
                "  {}    {} {} / {} {}",
                style("Traffic:").dim(),
                style("↓").cyan(),
                format_bytes(rx),
                style("↑").magenta(),
                format_bytes(tx)
            );
        }
    }

    // Public IP
    if connected {
        if let Ok(output) = std::process::Command::new("curl")
            .args(["-s", "--max-time", "3", "-4", "ifconfig.me"])
            .output()
        {
            if output.status.success() {
                let ip = String::from_utf8_lossy(&output.stdout);
                println!(
                    "  {}  {}",
                    style("Public IP:").dim(),
                    style(ip.trim()).cyan().bold()
                );
            }
        }
    }

    println!();
    Ok(())
}

/// Show VPN status (Windows)
#[cfg(windows)]
pub fn cmd_status() -> Result<()> {
    let term = Term::stdout();
    let _ = term.write_line("");

    // Header
    println!(
        "  {} {}",
        style("2cha").cyan().bold(),
        style("VPN Status").bold()
    );
    println!("  {}", style("=".repeat(48)).dim());

    let connected = is_running();
    let tun_name = "2cha";

    // Status
    if connected {
        println!(
            "  {}     {} Connected",
            style("Status:").dim(),
            style("*").green().bold()
        );
    } else {
        println!(
            "  {}     {} Disconnected",
            style("Status:").dim(),
            style("o").red()
        );
    }

    let routing_status = routing::get_routing_status(tun_name);

    // Interface
    if routing_status.interface_exists {
        println!(
            "  {}  {} {}",
            style("Interface:").dim(),
            style("*").green(),
            style(tun_name).cyan()
        );
    } else {
        println!(
            "  {}  {} {}",
            style("Interface:").dim(),
            style("o").dim(),
            tun_name
        );
    }

    // IPv4
    if let Some(ref addr) = routing_status.ipv4_address {
        println!("  {}       {}", style("IPv4:").dim(), style(addr).cyan());
    } else if connected {
        println!(
            "  {}       {}",
            style("IPv4:").dim(),
            style("disabled").dim()
        );
    }

    // IPv6
    if let Some(ref addr) = routing_status.ipv6_address {
        println!("  {}       {}", style("IPv6:").dim(), style(addr).cyan());
    } else if connected {
        println!(
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
        println!(
            "  {}    {} {} {}",
            style("Routing:").dim(),
            style("*").yellow(),
            style("Full tunnel").yellow(),
            style(mode).dim()
        );
    } else if connected {
        println!(
            "  {}    {} {}",
            style("Routing:").dim(),
            style("*").green(),
            style("Split tunnel").green()
        );
    } else {
        println!(
            "  {}    {} {}",
            style("Routing:").dim(),
            style("o").dim(),
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
        println!(
            "  {}    {} {} {}",
            style("Gateway:").dim(),
            style("*").green(),
            style("Forwarding").green(),
            style(mode).dim()
        );
    }

    // Public IP
    if connected {
        if let Ok(output) = std::process::Command::new("curl")
            .args(["-s", "--max-time", "3", "-4", "ifconfig.me"])
            .output()
        {
            if output.status.success() {
                let ip = String::from_utf8_lossy(&output.stdout);
                println!(
                    "  {}  {}",
                    style("Public IP:").dim(),
                    style(ip.trim()).cyan().bold()
                );
            }
        }
    }

    println!(
        "  {}   {}",
        style("Platform:").dim(),
        style("Windows").blue()
    );
    println!();
    Ok(())
}

/// Toggle VPN connection
pub fn cmd_toggle(config_path: &str, daemon: bool, verbose: bool, quiet: bool) -> Result<()> {
    if is_running() {
        cmd_down()
    } else {
        cmd_up(config_path, daemon, verbose, quiet)
    }
}

/// Run VPN server
pub fn cmd_server(config_path: &str, daemon: bool, verbose: bool, quiet: bool) -> Result<()> {
    // Ensure we have root privileges (will prompt for sudo password if needed)
    ensure_root()?;

    // Convert config path to absolute before daemonizing
    let config_path = std::fs::canonicalize(config_path)
        .map_err(|e| {
            crate::core::error::VpnError::Config(format!(
                "Config file '{}' not found: {}",
                config_path, e
            ))
        })?
        .to_string_lossy()
        .to_string();

    // Daemonize if requested
    if daemon {
        daemonize()?;
    }

    setup_logging(verbose, quiet);

    #[cfg(windows)]
    log::info!("Note: Requires wintun.dll and Administrator privileges");

    server::run(&config_path)
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
pub fn cmd_init(mode: &str) -> Result<()> {
    match mode {
        "client" | "c" => print!("{}", example_client_config()),
        "server" | "s" => print!("{}", example_server_config()),
        _ => {
            eprintln!(
                " {} Invalid mode: {}",
                output::icon_error(),
                style(mode).yellow()
            );
            eprintln!(
                "  Use {} or {}",
                style("client").green(),
                style("server").green()
            );
            std::process::exit(1);
        }
    }

    Ok(())
}
