//! # Routing Module
//!
//! Configure IP forwarding, NAT, and routing tables.
//! This allows the VPN server to act as a gateway for client traffic.
//!
//! ## Usage on Server (as gateway):
//! 1. Enable ip_forward in config
//! 2. Enable masquerade with external_interface
//! 3. Clients route their traffic through VPN
//!
//! ## Usage on Client (route all traffic):
//! 1. Set route_all_traffic = true
//! 2. Optionally set DNS servers

use std::process::Command;
use std::io;

/// Setup IP forwarding on Linux
pub fn enable_ip_forward() -> io::Result<()> {
    log::info!("Enabling IP forwarding...");
    
    // Using sysctl
    let output = Command::new("sysctl")
        .args(["-w", "net.ipv4.ip_forward=1"])
        .output()?;
    
    if !output.status.success() {
        // Try writing directly
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
    }
    
    log::info!("✓ IP forwarding enabled");
    Ok(())
}

/// Disable IP forwarding
pub fn disable_ip_forward() -> io::Result<()> {
    let _ = Command::new("sysctl")
        .args(["-w", "net.ipv4.ip_forward=0"])
        .output();
    Ok(())
}

/// Setup NAT/masquerading using iptables
pub fn setup_masquerade(external_iface: &str, vpn_subnet: &str) -> io::Result<()> {
    log::info!("Setting up NAT on {}...", external_iface);
    
    // Enable masquerading
    let output = Command::new("iptables")
        .args([
            "-t", "nat",
            "-A", "POSTROUTING",
            "-s", vpn_subnet,
            "-o", external_iface,
            "-j", "MASQUERADE"
        ])
        .output()?;
    
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        log::error!("iptables error: {}", err);
        return Err(io::Error::new(io::ErrorKind::Other, err.to_string()));
    }
    
    // Allow forwarding
    let _ = Command::new("iptables")
        .args([
            "-A", "FORWARD",
            "-i", "tun0",
            "-o", external_iface,
            "-j", "ACCEPT"
        ])
        .output();
    
    let _ = Command::new("iptables")
        .args([
            "-A", "FORWARD",
            "-i", external_iface,
            "-o", "tun0",
            "-m", "state",
            "--state", "RELATED,ESTABLISHED",
            "-j", "ACCEPT"
        ])
        .output();
    
    log::info!("✓ NAT/masquerading configured");
    Ok(())
}

/// Remove NAT rules
pub fn remove_masquerade(external_iface: &str, vpn_subnet: &str) -> io::Result<()> {
    let _ = Command::new("iptables")
        .args([
            "-t", "nat",
            "-D", "POSTROUTING",
            "-s", vpn_subnet,
            "-o", external_iface,
            "-j", "MASQUERADE"
        ])
        .output();
    Ok(())
}

/// Add route to routing table
pub fn add_route(destination: &str, gateway: &str) -> io::Result<()> {
    log::info!("Adding route: {} via {}", destination, gateway);
    
    let output = Command::new("ip")
        .args(["route", "add", destination, "via", gateway])
        .output()?;
    
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        // Ignore "File exists" error (route already exists)
        if !err.contains("File exists") {
            log::warn!("Route add warning: {}", err);
        }
    }
    
    Ok(())
}

/// Remove route
pub fn del_route(destination: &str) -> io::Result<()> {
    let _ = Command::new("ip")
        .args(["route", "del", destination])
        .output();
    Ok(())
}

/// Set default gateway through VPN
pub fn set_default_gateway(vpn_gateway: &str, original_gateway: &str, server_ip: &str) -> io::Result<()> {
    log::info!("Setting VPN as default gateway...");
    
    // First, add route to VPN server via original gateway
    // This ensures VPN traffic itself doesn't go through the VPN
    let _ = Command::new("ip")
        .args(["route", "add", &format!("{}/32", server_ip), "via", original_gateway])
        .output();
    
    // Replace default route
    let output = Command::new("ip")
        .args(["route", "replace", "default", "via", vpn_gateway])
        .output()?;
    
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        log::error!("Failed to set default gateway: {}", err);
        return Err(io::Error::new(io::ErrorKind::Other, err.to_string()));
    }
    
    log::info!("✓ Default gateway set to {}", vpn_gateway);
    Ok(())
}

/// Restore original default gateway
pub fn restore_default_gateway(original_gateway: &str, server_ip: &str) -> io::Result<()> {
    log::info!("Restoring original gateway...");
    
    let _ = Command::new("ip")
        .args(["route", "replace", "default", "via", original_gateway])
        .output();
    
    let _ = Command::new("ip")
        .args(["route", "del", &format!("{}/32", server_ip)])
        .output();
    
    Ok(())
}

/// Get current default gateway
pub fn get_default_gateway() -> io::Result<String> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Parse: "default via 192.168.1.1 dev eth0"
    for part in stdout.split_whitespace() {
        if let Some(prev) = stdout.split_whitespace()
            .collect::<Vec<_>>()
            .windows(2)
            .find(|w| w[0] == "via")
        {
            return Ok(prev[1].to_string());
        }
    }
    
    // Alternative parsing
    if let Some(via_idx) = stdout.find("via ") {
        let rest = &stdout[via_idx + 4..];
        if let Some(space_idx) = rest.find(' ') {
            return Ok(rest[..space_idx].to_string());
        }
    }
    
    Err(io::Error::new(io::ErrorKind::NotFound, "No default gateway found"))
}

/// Set DNS servers (modifies /etc/resolv.conf)
pub fn set_dns(servers: &[String]) -> io::Result<()> {
    if servers.is_empty() {
        return Ok(());
    }
    
    log::info!("Setting DNS servers: {:?}", servers);
    
    // Backup original resolv.conf
    let _ = std::fs::copy("/etc/resolv.conf", "/etc/resolv.conf.vpn-backup");
    
    // Write new resolv.conf
    let mut content = String::new();
    for server in servers {
        content.push_str(&format!("nameserver {}\n", server));
    }
    
    std::fs::write("/etc/resolv.conf", content)?;
    log::info!("✓ DNS configured");
    Ok(())
}

/// Restore original DNS
pub fn restore_dns() -> io::Result<()> {
    if std::path::Path::new("/etc/resolv.conf.vpn-backup").exists() {
        std::fs::copy("/etc/resolv.conf.vpn-backup", "/etc/resolv.conf")?;
        let _ = std::fs::remove_file("/etc/resolv.conf.vpn-backup");
        log::info!("✓ DNS restored");
    }
    Ok(())
}

/// Full server gateway setup
pub fn setup_server_gateway(external_iface: &str, vpn_subnet: &str) -> io::Result<()> {
    enable_ip_forward()?;
    setup_masquerade(external_iface, vpn_subnet)?;
    Ok(())
}

/// Full client routing setup
pub fn setup_client_routing(
    vpn_gateway: &str, 
    server_ip: &str,
    dns_servers: &[String],
    route_all: bool,
    specific_routes: &[String],
) -> io::Result<Option<String>> {
    let original_gw = get_default_gateway().ok();
    
    if route_all {
        if let Some(ref gw) = original_gw {
            set_default_gateway(vpn_gateway, gw, server_ip)?;
        }
    } else {
        // Add specific routes only
        for route in specific_routes {
            add_route(route, vpn_gateway)?;
        }
    }
    
    if !dns_servers.is_empty() {
        set_dns(dns_servers)?;
    }
    
    Ok(original_gw)
}

/// Cleanup client routing
pub fn cleanup_client_routing(
    original_gateway: Option<&str>,
    server_ip: &str,
    specific_routes: &[String],
) -> io::Result<()> {
    if let Some(gw) = original_gateway {
        restore_default_gateway(gw, server_ip)?;
    }
    
    for route in specific_routes {
        del_route(route)?;
    }
    
    restore_dns()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_gateway() {
        // This would need to run with actual network
    }
}
