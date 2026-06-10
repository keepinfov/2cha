//! Connection status command (shared Unix/Windows logic).

use crate::cli::output::Icons;
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

/// Show VPN status
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

    // Status
    if connected {
        println!(
            "  {}     {} Connected",
            style("Status:").dim(),
            style(Icons::CONNECTED).green().bold()
        );
    } else {
        println!(
            "  {}     {} Disconnected",
            style("Status:").dim(),
            style(Icons::DISCONNECTED).red()
        );
    }

    let routing_status = routing::get_routing_status(TUN_NAME);

    // Interface
    if routing_status.interface_exists {
        println!(
            "  {}  {} {}",
            style("Interface:").dim(),
            style(Icons::CONNECTED).green(),
            style(TUN_NAME).cyan()
        );
    } else {
        println!(
            "  {}  {} {}",
            style("Interface:").dim(),
            style(Icons::DISCONNECTED).dim(),
            TUN_NAME
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
            style(Icons::CONNECTED).yellow(),
            style("Full tunnel").yellow(),
            style(mode).dim()
        );
    } else if connected {
        println!(
            "  {}    {} {}",
            style("Routing:").dim(),
            style(Icons::CONNECTED).green(),
            style("Split tunnel").green()
        );
    } else {
        println!(
            "  {}    {} {}",
            style("Routing:").dim(),
            style(Icons::DISCONNECTED).dim(),
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

    #[cfg(windows)]
    println!(
        "  {}   {}",
        style("Platform:").dim(),
        style("Windows").blue()
    );

    println!();
    Ok(())
}
