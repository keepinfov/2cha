//! # Windows Routing Module
//!
//! Configure routing tables and network settings for Windows.
//! Uses netsh commands and Windows APIs for route management.

#![cfg(windows)]

use std::io::{self};
use std::process::Command;
use std::net::IpAddr;

// =============================================================================
// IP FORWARDING
// =============================================================================

/// Enable IPv4 forwarding
pub fn enable_ipv4_forward() -> io::Result<()> {
    log::info!("Enabling IPv4 forwarding...");

    // Use netsh to enable IP forwarding
    let output = Command::new("netsh")
        .args(["interface", "ipv4", "set", "global", "forwarding=enabled"])
        .output()?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        log::warn!("Failed to enable IPv4 forwarding: {}", err);
        // Try registry method as fallback
        let _ = Command::new("reg")
            .args([
                "add", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                "/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", "1", "/f"
            ])
            .output();
    }

    log::info!("IPv4 forwarding enabled");
    Ok(())
}

/// Enable IPv6 forwarding
pub fn enable_ipv6_forward() -> io::Result<()> {
    log::info!("Enabling IPv6 forwarding...");

    let output = Command::new("netsh")
        .args(["interface", "ipv6", "set", "global", "forwarding=enabled"])
        .output()?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        log::warn!("Failed to enable IPv6 forwarding: {}", err);
    }

    log::info!("IPv6 forwarding enabled");
    Ok(())
}

/// Disable IPv4 forwarding
#[allow(dead_code)]
pub fn disable_ipv4_forward() -> io::Result<()> {
    let _ = Command::new("netsh")
        .args(["interface", "ipv4", "set", "global", "forwarding=disabled"])
        .output();
    Ok(())
}

/// Disable IPv6 forwarding
#[allow(dead_code)]
pub fn disable_ipv6_forward() -> io::Result<()> {
    let _ = Command::new("netsh")
        .args(["interface", "ipv6", "set", "global", "forwarding=disabled"])
        .output();
    Ok(())
}

/// Check if IPv4 forwarding is enabled
pub fn is_ipv4_forward_enabled() -> bool {
    if let Ok(output) = Command::new("netsh")
        .args(["interface", "ipv4", "show", "global"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        return stdout.contains("Forwarding") && stdout.contains("enabled");
    }
    false
}

/// Check if IPv6 forwarding is enabled
pub fn is_ipv6_forward_enabled() -> bool {
    if let Ok(output) = Command::new("netsh")
        .args(["interface", "ipv6", "show", "global"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        return stdout.contains("Forwarding") && stdout.contains("enabled");
    }
    false
}

// =============================================================================
// NAT / ICS (Internet Connection Sharing)
// =============================================================================

/// Setup NAT using Windows ICS (Internet Connection Sharing)
/// Note: Full NAT on Windows typically requires ICS or third-party software
pub fn setup_masquerade_v4(external_iface: &str, _vpn_subnet: &str) -> io::Result<()> {
    log::info!("Setting up Windows ICS on {}", external_iface);

    // Windows NAT requires either:
    // 1. Internet Connection Sharing (ICS) - GUI based
    // 2. Windows Server with RRAS
    // 3. netsh routing (on Windows Server)

    // Try to enable routing on the interface
    let output = Command::new("netsh")
        .args([
            "routing", "ip", "nat", "add", "interface",
            external_iface, "mode=full"
        ])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            log::info!("NAT configured on {}", external_iface);
        }
        _ => {
            log::warn!("NAT configuration not available. Windows ICS may need manual setup.");
            log::warn!("For full NAT support, consider using Windows Server with RRAS.");
        }
    }

    Ok(())
}

/// Setup IPv6 NAT (limited support on Windows)
pub fn setup_masquerade_v6(external_iface: &str, _vpn_subnet: &str) -> io::Result<()> {
    log::info!("IPv6 NAT on Windows has limited support");
    log::info!("Interface: {}", external_iface);
    // IPv6 NAT is not commonly used or well-supported on Windows
    Ok(())
}

/// Remove NAT rules
#[allow(dead_code)]
pub fn remove_masquerade_v4(external_iface: &str, _vpn_subnet: &str) -> io::Result<()> {
    let _ = Command::new("netsh")
        .args(["routing", "ip", "nat", "delete", "interface", external_iface])
        .output();
    Ok(())
}

#[allow(dead_code)]
pub fn remove_masquerade_v6(_external_iface: &str, _vpn_subnet: &str) -> io::Result<()> {
    Ok(())
}

// =============================================================================
// ROUTING
// =============================================================================

/// Add IPv4 route
pub fn add_route_v4(destination: &str, gateway: &str) -> io::Result<()> {
    log::info!("Adding IPv4 route: {} via {}", destination, gateway);

    let output = Command::new("route")
        .args(["add", destination, gateway])
        .output()?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        // Try netsh as fallback
        let output2 = Command::new("netsh")
            .args([
                "interface", "ipv4", "add", "route",
                destination, "nexthop=", gateway
            ])
            .output()?;

        if !output2.status.success() && !err.contains("already exists") {
            log::warn!("Route add warning: {}", err);
        }
    }

    Ok(())
}

/// Add IPv6 route
pub fn add_route_v6(destination: &str, gateway: &str) -> io::Result<()> {
    log::info!("Adding IPv6 route: {} via {}", destination, gateway);

    let output = Command::new("netsh")
        .args([
            "interface", "ipv6", "add", "route",
            destination, &format!("nexthop={}", gateway)
        ])
        .output()?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        if !err.contains("already exists") {
            log::warn!("Route add warning: {}", err);
        }
    }

    Ok(())
}

/// Remove IPv4 route
pub fn del_route_v4(destination: &str) -> io::Result<()> {
    let _ = Command::new("route")
        .args(["delete", destination])
        .output();
    Ok(())
}

/// Remove IPv6 route
pub fn del_route_v6(destination: &str) -> io::Result<()> {
    let _ = Command::new("netsh")
        .args(["interface", "ipv6", "delete", "route", destination])
        .output();
    Ok(())
}

/// Set default IPv4 gateway through VPN
pub fn set_default_gateway_v4(vpn_gateway: &str, _original_gateway: &str, server_ip: &str) -> io::Result<()> {
    log::info!("Setting IPv4 default gateway to {}...", vpn_gateway);

    // Add route to VPN server via original gateway
    let _ = Command::new("route")
        .args(["add", server_ip, "mask", "255.255.255.255"])
        .output();

    // Change default route
    let output = Command::new("route")
        .args(["change", "0.0.0.0", "mask", "0.0.0.0", vpn_gateway])
        .output()?;

    if !output.status.success() {
        // Try adding instead of changing
        let _ = Command::new("route")
            .args(["add", "0.0.0.0", "mask", "0.0.0.0", vpn_gateway, "metric", "1"])
            .output();
    }

    log::info!("IPv4 default gateway set to {}", vpn_gateway);
    Ok(())
}

/// Set default IPv6 gateway through VPN
pub fn set_default_gateway_v6(vpn_gateway: &str, _original_gateway: Option<&str>, server_ip: Option<&str>) -> io::Result<()> {
    log::info!("Setting IPv6 default gateway to {}...", vpn_gateway);

    // Add route to VPN server
    if let Some(srv) = server_ip {
        let _ = Command::new("netsh")
            .args([
                "interface", "ipv6", "add", "route",
                &format!("{}/128", srv)
            ])
            .output();
    }

    // Add default route through VPN
    let _ = Command::new("netsh")
        .args([
            "interface", "ipv6", "add", "route",
            "::/0", &format!("nexthop={}", vpn_gateway), "metric=1"
        ])
        .output();

    log::info!("IPv6 default gateway set to {}", vpn_gateway);
    Ok(())
}

/// Restore original default IPv4 gateway
pub fn restore_default_gateway_v4(original_gateway: &str, server_ip: &str) -> io::Result<()> {
    log::info!("Restoring IPv4 gateway to {}...", original_gateway);

    // Restore default route
    let _ = Command::new("route")
        .args(["change", "0.0.0.0", "mask", "0.0.0.0", original_gateway])
        .output();

    // Remove route to VPN server
    let _ = Command::new("route")
        .args(["delete", server_ip])
        .output();

    Ok(())
}

/// Restore original default IPv6 gateway
pub fn restore_default_gateway_v6(original_gateway: Option<&str>, server_ip: Option<&str>) -> io::Result<()> {
    if let Some(gw) = original_gateway {
        log::info!("Restoring IPv6 gateway to {}...", gw);

        let _ = Command::new("netsh")
            .args([
                "interface", "ipv6", "delete", "route", "::/0"
            ])
            .output();
    }

    if let Some(srv) = server_ip {
        let _ = Command::new("netsh")
            .args([
                "interface", "ipv6", "delete", "route",
                &format!("{}/128", srv)
            ])
            .output();
    }

    Ok(())
}

/// Get current default IPv4 gateway
pub fn get_default_gateway_v4() -> io::Result<String> {
    let output = Command::new("route")
        .args(["print", "0.0.0.0"])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse Windows route output
    for line in stdout.lines() {
        if line.contains("0.0.0.0") && line.contains("0.0.0.0") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                return Ok(parts[2].to_string());
            }
        }
    }

    Err(io::Error::new(io::ErrorKind::NotFound, "No default gateway found"))
}

/// Get current default IPv6 gateway
pub fn get_default_gateway_v6() -> io::Result<String> {
    let output = Command::new("netsh")
        .args(["interface", "ipv6", "show", "route"])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        if line.contains("::/0") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // Find the gateway address in the output
            for part in parts {
                if part.contains("::") || part.contains("fe80") {
                    return Ok(part.to_string());
                }
            }
        }
    }

    Err(io::Error::new(io::ErrorKind::NotFound, "No default IPv6 gateway found"))
}

// =============================================================================
// DNS
// =============================================================================

/// Set DNS servers
pub fn set_dns(servers_v4: &[String], servers_v6: &[String], _search: &[String]) -> io::Result<()> {
    if servers_v4.is_empty() && servers_v6.is_empty() {
        return Ok(());
    }

    log::info!("Setting DNS servers: v4={:?}, v6={:?}", servers_v4, servers_v6);

    // Get the VPN interface name (typically the TUN adapter name)
    let interface = "2cha";

    // Set IPv4 DNS
    for (i, server) in servers_v4.iter().enumerate() {
        let args = if i == 0 {
            vec![
                "interface", "ipv4", "set", "dnsservers",
                &format!("name={}", interface), "static", server, "primary"
            ]
        } else {
            vec![
                "interface", "ipv4", "add", "dnsservers",
                &format!("name={}", interface), server
            ]
        };

        let _ = Command::new("netsh").args(&args).output();
    }

    // Set IPv6 DNS
    for (i, server) in servers_v6.iter().enumerate() {
        let args = if i == 0 {
            vec![
                "interface", "ipv6", "set", "dnsservers",
                &format!("name={}", interface), "static", server, "primary"
            ]
        } else {
            vec![
                "interface", "ipv6", "add", "dnsservers",
                &format!("name={}", interface), server
            ]
        };

        let _ = Command::new("netsh").args(&args).output();
    }

    log::info!("DNS configured");
    Ok(())
}

/// Restore original DNS (set to DHCP)
pub fn restore_dns() -> io::Result<()> {
    let interface = "2cha";

    let _ = Command::new("netsh")
        .args([
            "interface", "ipv4", "set", "dnsservers",
            &format!("name={}", interface), "dhcp"
        ])
        .output();

    let _ = Command::new("netsh")
        .args([
            "interface", "ipv6", "set", "dnsservers",
            &format!("name={}", interface), "dhcp"
        ])
        .output();

    log::info!("DNS restored");
    Ok(())
}

// =============================================================================
// GATEWAY SETUP (SERVER)
// =============================================================================

/// Full server gateway setup for IPv4
pub fn setup_server_gateway_v4(external_iface: &str, vpn_subnet: &str) -> io::Result<()> {
    enable_ipv4_forward()?;
    setup_masquerade_v4(external_iface, vpn_subnet)?;
    Ok(())
}

/// Full server gateway setup for IPv6
pub fn setup_server_gateway_v6(external_iface: &str, vpn_subnet: &str) -> io::Result<()> {
    enable_ipv6_forward()?;
    setup_masquerade_v6(external_iface, vpn_subnet)?;
    Ok(())
}

// =============================================================================
// CLIENT ROUTING SETUP
// =============================================================================

/// Client routing context for cleanup
#[derive(Debug, Default)]
pub struct ClientRoutingContext {
    pub original_gateway_v4: Option<String>,
    pub original_gateway_v6: Option<String>,
    pub server_ip_v4: Option<String>,
    pub server_ip_v6: Option<String>,
    pub added_routes_v4: Vec<String>,
    pub added_routes_v6: Vec<String>,
    pub dns_modified: bool,
}

impl ClientRoutingContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// Setup client routing
    pub fn setup(
        &mut self,
        ipv4_gateway: Option<&str>,
        ipv6_gateway: Option<&str>,
        server_addr: &std::net::SocketAddr,
        route_all_v4: bool,
        route_all_v6: bool,
        routes_v4: &[String],
        routes_v6: &[String],
        dns_v4: &[String],
        dns_v6: &[String],
        dns_search: &[String],
    ) -> io::Result<()> {
        // Store server IP
        match server_addr.ip() {
            IpAddr::V4(ip) => self.server_ip_v4 = Some(ip.to_string()),
            IpAddr::V6(ip) => self.server_ip_v6 = Some(ip.to_string()),
        }

        // IPv4 routing
        if let Some(gw) = ipv4_gateway {
            if route_all_v4 {
                self.original_gateway_v4 = get_default_gateway_v4().ok();
                if let Some(ref orig_gw) = self.original_gateway_v4 {
                    if let Some(ref srv) = self.server_ip_v4 {
                        set_default_gateway_v4(gw, orig_gw, srv)?;
                    }
                }
            } else {
                for route in routes_v4 {
                    add_route_v4(route, gw)?;
                    self.added_routes_v4.push(route.clone());
                }
            }
        }

        // IPv6 routing
        if let Some(gw) = ipv6_gateway {
            if route_all_v6 {
                self.original_gateway_v6 = get_default_gateway_v6().ok();
                set_default_gateway_v6(gw, self.original_gateway_v6.as_deref(), self.server_ip_v6.as_deref())?;
            } else {
                for route in routes_v6 {
                    add_route_v6(route, gw)?;
                    self.added_routes_v6.push(route.clone());
                }
            }
        }

        // DNS
        if !dns_v4.is_empty() || !dns_v6.is_empty() {
            set_dns(dns_v4, dns_v6, dns_search)?;
            self.dns_modified = true;
        }

        Ok(())
    }

    /// Cleanup routing
    pub fn cleanup(&self) -> io::Result<()> {
        // Restore IPv4 gateway
        if let (Some(ref orig_gw), Some(ref srv)) = (&self.original_gateway_v4, &self.server_ip_v4) {
            let _ = restore_default_gateway_v4(orig_gw, srv);
        }

        // Restore IPv6 gateway
        if self.original_gateway_v6.is_some() || self.server_ip_v6.is_some() {
            let _ = restore_default_gateway_v6(
                self.original_gateway_v6.as_deref(),
                self.server_ip_v6.as_deref()
            );
        }

        // Remove added routes
        for route in &self.added_routes_v4 {
            let _ = del_route_v4(route);
        }
        for route in &self.added_routes_v6 {
            let _ = del_route_v6(route);
        }

        // Restore DNS
        if self.dns_modified {
            let _ = restore_dns();
        }

        Ok(())
    }
}

// =============================================================================
// STATUS
// =============================================================================

/// Get current routing status
pub fn get_routing_status(tun_name: &str) -> RoutingStatus {
    let mut status = RoutingStatus::default();

    // Check if interface exists using netsh
    if let Ok(output) = Command::new("netsh")
        .args(["interface", "show", "interface", tun_name])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        status.interface_exists = stdout.contains("Connected") || stdout.contains("Enabled");
    }

    // Get IPv4 address
    if let Ok(output) = Command::new("netsh")
        .args(["interface", "ipv4", "show", "addresses", tun_name])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("IP Address") || line.contains("IP address") {
                if let Some(addr) = line.split_whitespace().last() {
                    status.ipv4_address = Some(addr.to_string());
                }
            }
        }
    }

    // Get IPv6 address
    if let Ok(output) = Command::new("netsh")
        .args(["interface", "ipv6", "show", "addresses", tun_name])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("Address") && !line.contains("link-local") {
                if let Some(addr) = line.split_whitespace().last() {
                    if addr.contains("::") || addr.contains(":") {
                        status.ipv6_address = Some(addr.to_string());
                    }
                }
            }
        }
    }

    // Check default routes
    if let Ok(output) = Command::new("route").args(["print"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("0.0.0.0") && line.contains(tun_name) {
                status.default_route_v4_via_tun = true;
            }
        }
    }

    // Check forwarding status
    status.ipv4_forwarding = is_ipv4_forward_enabled();
    status.ipv6_forwarding = is_ipv6_forward_enabled();

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
