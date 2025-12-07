//! # Windows Routing Module
//!
//! Route management for Windows using netsh.

#![cfg(windows)]

use std::io;
use std::process::Command;

/// Get routing status for an interface
pub fn get_routing_status(tun_name: &str) -> RoutingStatus {
    let mut status = RoutingStatus::default();

    // Check interface via netsh
    if let Ok(output) = Command::new("netsh")
        .args(["interface", "show", "interface", tun_name])
        .output()
    {
        status.interface_exists = output.status.success();
    }

    // Check IPv4 configuration
    if let Ok(output) = Command::new("netsh")
        .args(["interface", "ip", "show", "addresses", tun_name])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("IP Address") {
            // Parse address from output
            for line in stdout.lines() {
                if line.contains("IP Address") {
                    if let Some(addr) = line.split_whitespace().last() {
                        status.ipv4_address = Some(addr.to_string());
                    }
                }
            }
        }
    }

    // Check default route
    if let Ok(output) = Command::new("route").args(["print", "0.0.0.0"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        status.default_route_v4_via_tun = stdout.contains(tun_name);
    }

    // Check IP forwarding
    if let Ok(output) = Command::new("netsh")
        .args(["interface", "ipv4", "show", "global"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        status.ipv4_forwarding = stdout.contains("enabled");
    }

    status
}

#[derive(Debug, Default)]
pub struct RoutingStatus {
    pub interface_exists: bool,
    pub ipv4_address: Option<String>,
    pub ipv6_address: Option<String>,
    pub default_route_v4_via_tun: bool,
    pub default_route_v6_via_tun: bool,
    pub ipv4_forwarding: bool,
    pub ipv6_forwarding: bool,
}

impl RoutingStatus {
    pub fn is_full_tunnel(&self) -> bool {
        self.default_route_v4_via_tun || self.default_route_v6_via_tun
    }
}

/// Add IPv4 route on Windows
pub fn add_route_v4(destination: &str, gateway: &str) -> io::Result<()> {
    let _ = Command::new("route")
        .args(["add", destination, gateway])
        .output()?;
    Ok(())
}

/// Delete IPv4 route on Windows
pub fn del_route_v4(destination: &str) -> io::Result<()> {
    let _ = Command::new("route")
        .args(["delete", destination])
        .output();
    Ok(())
}

/// Set default gateway on Windows
pub fn set_default_gateway_v4(vpn_gateway: &str, _original_gateway: &str, server_ip: &str) -> io::Result<()> {
    // Add route to server via original gateway
    let _ = Command::new("route")
        .args(["add", server_ip, "mask", "255.255.255.255", _original_gateway])
        .output();

    // Set new default route
    let _ = Command::new("route")
        .args(["add", "0.0.0.0", "mask", "0.0.0.0", vpn_gateway, "metric", "1"])
        .output()?;

    Ok(())
}

/// Restore original default gateway
pub fn restore_default_gateway_v4(original_gateway: &str, server_ip: &str) -> io::Result<()> {
    let _ = Command::new("route")
        .args(["delete", "0.0.0.0", "mask", "0.0.0.0"])
        .output();
    let _ = Command::new("route")
        .args(["delete", server_ip])
        .output();
    Ok(())
}

/// Get current default gateway
pub fn get_default_gateway_v4() -> io::Result<String> {
    let output = Command::new("route")
        .args(["print", "0.0.0.0", "mask", "0.0.0.0"])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Parse the gateway from route print output
    for line in stdout.lines() {
        if line.contains("0.0.0.0") && !line.contains("On-link") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                return Ok(parts[2].to_string());
            }
        }
    }

    Err(io::Error::new(io::ErrorKind::NotFound, "No default gateway found"))
}

/// Enable IP forwarding on Windows
pub fn enable_ipv4_forward() -> io::Result<()> {
    let _ = Command::new("netsh")
        .args(["interface", "ipv4", "set", "global", "forwarding=enabled"])
        .output()?;
    Ok(())
}

/// Setup server gateway (NAT) on Windows using ICS
pub fn setup_server_gateway_v4(_external_iface: &str, _vpn_subnet: &str) -> io::Result<()> {
    // Windows NAT requires different approach (ICS or netsh routing)
    enable_ipv4_forward()?;
    log::info!("Note: Full NAT on Windows requires manual ICS configuration");
    Ok(())
}
