//! # Routing Module
//!
//! Configure IP forwarding, NAT, and routing tables for IPv4/IPv6.
//! Linux-specific routing and NAT configuration.
//!
//! Note: This module is only available on Unix platforms (Linux).

#![cfg(unix)]
#![allow(clippy::io_other_error)]
#![allow(clippy::too_many_arguments)]

use std::io::{self, Write};
use std::process::Command;
use std::net::IpAddr;

// ═══════════════════════════════════════════════════════════════════════════
// IP FORWARDING
// ═══════════════════════════════════════════════════════════════════════════

/// Enable IPv4 forwarding
pub fn enable_ipv4_forward() -> io::Result<()> {
    log::info!("Enabling IPv4 forwarding...");
    
    // Try sysctl first
    let output = Command::new("sysctl")
        .args(["-w", "net.ipv4.ip_forward=1"])
        .output();
    
    match output {
        Ok(o) if o.status.success() => {
            log::info!("✓ IPv4 forwarding enabled via sysctl");
            return Ok(());
        }
        _ => {}
    }
    
    // Fallback to direct write
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
    log::info!("✓ IPv4 forwarding enabled");
    Ok(())
}

/// Enable IPv6 forwarding
pub fn enable_ipv6_forward() -> io::Result<()> {
    log::info!("Enabling IPv6 forwarding...");
    
    let output = Command::new("sysctl")
        .args(["-w", "net.ipv6.conf.all.forwarding=1"])
        .output();
    
    match output {
        Ok(o) if o.status.success() => {
            log::info!("✓ IPv6 forwarding enabled via sysctl");
            return Ok(());
        }
        _ => {}
    }
    
    // Fallback
    std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1")?;
    log::info!("✓ IPv6 forwarding enabled");
    Ok(())
}

/// Disable IPv4 forwarding
#[allow(dead_code)]
pub fn disable_ipv4_forward() -> io::Result<()> {
    let _ = Command::new("sysctl")
        .args(["-w", "net.ipv4.ip_forward=0"])
        .output();
    let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "0");
    Ok(())
}

/// Disable IPv6 forwarding
#[allow(dead_code)]
pub fn disable_ipv6_forward() -> io::Result<()> {
    let _ = Command::new("sysctl")
        .args(["-w", "net.ipv6.conf.all.forwarding=0"])
        .output();
    let _ = std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "0");
    Ok(())
}

/// Check if IPv4 forwarding is enabled
pub fn is_ipv4_forward_enabled() -> bool {
    std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

/// Check if IPv6 forwarding is enabled
pub fn is_ipv6_forward_enabled() -> bool {
    std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding")
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

// ═══════════════════════════════════════════════════════════════════════════
// NAT / MASQUERADING
// ═══════════════════════════════════════════════════════════════════════════

/// Setup IPv4 NAT/masquerading
pub fn setup_masquerade_v4(external_iface: &str, vpn_subnet: &str) -> io::Result<()> {
    log::info!("Setting up IPv4 NAT on {} for {}", external_iface, vpn_subnet);
    
    // Try nftables first (modern)
    if setup_nat_nftables_v4(external_iface, vpn_subnet).is_ok() {
        log::info!("✓ IPv4 NAT configured via nftables");
        return Ok(());
    }
    
    // Fallback to iptables
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
    
    // Forward rules
    let _ = Command::new("iptables")
        .args(["-A", "FORWARD", "-i", "tun0", "-o", external_iface, "-j", "ACCEPT"])
        .output();
    
    let _ = Command::new("iptables")
        .args([
            "-A", "FORWARD",
            "-i", external_iface, "-o", "tun0",
            "-m", "state", "--state", "RELATED,ESTABLISHED",
            "-j", "ACCEPT"
        ])
        .output();
    
    log::info!("✓ IPv4 NAT configured via iptables");
    Ok(())
}

/// Setup IPv6 NAT/masquerading
pub fn setup_masquerade_v6(external_iface: &str, vpn_subnet: &str) -> io::Result<()> {
    log::info!("Setting up IPv6 NAT on {} for {}", external_iface, vpn_subnet);
    
    // Try nftables first
    if setup_nat_nftables_v6(external_iface, vpn_subnet).is_ok() {
        log::info!("✓ IPv6 NAT configured via nftables");
        return Ok(());
    }
    
    // Fallback to ip6tables
    let output = Command::new("ip6tables")
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
        log::error!("ip6tables error: {}", err);
        return Err(io::Error::new(io::ErrorKind::Other, err.to_string()));
    }
    
    // Forward rules
    let _ = Command::new("ip6tables")
        .args(["-A", "FORWARD", "-i", "tun0", "-o", external_iface, "-j", "ACCEPT"])
        .output();
    
    let _ = Command::new("ip6tables")
        .args([
            "-A", "FORWARD",
            "-i", external_iface, "-o", "tun0",
            "-m", "state", "--state", "RELATED,ESTABLISHED",
            "-j", "ACCEPT"
        ])
        .output();
    
    log::info!("✓ IPv6 NAT configured via ip6tables");
    Ok(())
}

fn setup_nat_nftables_v4(external_iface: &str, vpn_subnet: &str) -> io::Result<()> {
    let rules = format!(
        r#"table ip 2cha_nat {{
    chain postrouting {{
        type nat hook postrouting priority srcnat;
        ip saddr {} oifname "{}" masquerade
    }}
}}
table ip 2cha_filter {{
    chain forward {{
        type filter hook forward priority filter;
        iifname "tun0" oifname "{}" accept
        iifname "{}" oifname "tun0" ct state related,established accept
    }}
}}"#,
        vpn_subnet, external_iface, external_iface, external_iface
    );
    
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()?;
    
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(rules.as_bytes())?;
    }
    
    child.wait()?;
    Ok(())
}

fn setup_nat_nftables_v6(external_iface: &str, vpn_subnet: &str) -> io::Result<()> {
    let rules = format!(
        r#"table ip6 2cha_nat6 {{
    chain postrouting {{
        type nat hook postrouting priority srcnat;
        ip6 saddr {} oifname "{}" masquerade
    }}
}}
table ip6 2cha_filter6 {{
    chain forward {{
        type filter hook forward priority filter;
        iifname "tun0" oifname "{}" accept
        iifname "{}" oifname "tun0" ct state related,established accept
    }}
}}"#,
        vpn_subnet, external_iface, external_iface, external_iface
    );
    
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()?;
    
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        stdin.write_all(rules.as_bytes())?;
    }
    
    child.wait()?;
    Ok(())
}

/// Remove IPv4 NAT rules
#[allow(dead_code)]
pub fn remove_masquerade_v4(external_iface: &str, vpn_subnet: &str) -> io::Result<()> {
    // Try nftables first
    let _ = Command::new("nft").args(["delete", "table", "ip", "2cha_nat"]).output();
    let _ = Command::new("nft").args(["delete", "table", "ip", "2cha_filter"]).output();
    
    // iptables cleanup
    let _ = Command::new("iptables")
        .args(["-t", "nat", "-D", "POSTROUTING", "-s", vpn_subnet, "-o", external_iface, "-j", "MASQUERADE"])
        .output();
    
    Ok(())
}

/// Remove IPv6 NAT rules
#[allow(dead_code)]
pub fn remove_masquerade_v6(external_iface: &str, vpn_subnet: &str) -> io::Result<()> {
    let _ = Command::new("nft").args(["delete", "table", "ip6", "2cha_nat6"]).output();
    let _ = Command::new("nft").args(["delete", "table", "ip6", "2cha_filter6"]).output();
    
    let _ = Command::new("ip6tables")
        .args(["-t", "nat", "-D", "POSTROUTING", "-s", vpn_subnet, "-o", external_iface, "-j", "MASQUERADE"])
        .output();
    
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// ROUTING
// ═══════════════════════════════════════════════════════════════════════════

/// Add IPv4 route
pub fn add_route_v4(destination: &str, gateway: &str) -> io::Result<()> {
    log::info!("Adding IPv4 route: {} via {}", destination, gateway);
    
    let output = Command::new("ip")
        .args(["-4", "route", "add", destination, "via", gateway])
        .output()?;
    
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        if !err.contains("File exists") {
            log::warn!("Route add warning: {}", err);
        }
    }
    
    Ok(())
}

/// Add IPv6 route
pub fn add_route_v6(destination: &str, gateway: &str) -> io::Result<()> {
    log::info!("Adding IPv6 route: {} via {}", destination, gateway);
    
    let output = Command::new("ip")
        .args(["-6", "route", "add", destination, "via", gateway])
        .output()?;
    
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        if !err.contains("File exists") {
            log::warn!("Route add warning: {}", err);
        }
    }
    
    Ok(())
}

/// Remove IPv4 route
pub fn del_route_v4(destination: &str) -> io::Result<()> {
    let _ = Command::new("ip")
        .args(["-4", "route", "del", destination])
        .output();
    Ok(())
}

/// Remove IPv6 route
pub fn del_route_v6(destination: &str) -> io::Result<()> {
    let _ = Command::new("ip")
        .args(["-6", "route", "del", destination])
        .output();
    Ok(())
}

/// Set default IPv4 gateway through VPN
pub fn set_default_gateway_v4(vpn_gateway: &str, original_gateway: &str, server_ip: &str) -> io::Result<()> {
    log::info!("Setting IPv4 default gateway to {}...", vpn_gateway);
    
    // Add route to VPN server via original gateway
    let _ = Command::new("ip")
        .args(["-4", "route", "add", &format!("{}/32", server_ip), "via", original_gateway])
        .output();
    
    // Replace default route
    let output = Command::new("ip")
        .args(["-4", "route", "replace", "default", "via", vpn_gateway])
        .output()?;
    
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        log::error!("Failed to set default gateway: {}", err);
        return Err(io::Error::new(io::ErrorKind::Other, err.to_string()));
    }
    
    log::info!("✓ IPv4 default gateway set to {}", vpn_gateway);
    Ok(())
}

/// Set default IPv6 gateway through VPN
pub fn set_default_gateway_v6(vpn_gateway: &str, original_gateway: Option<&str>, server_ip: Option<&str>) -> io::Result<()> {
    log::info!("Setting IPv6 default gateway to {}...", vpn_gateway);
    
    // Add route to VPN server via original gateway (if IPv6 server)
    if let (Some(orig), Some(srv)) = (original_gateway, server_ip) {
        let _ = Command::new("ip")
            .args(["-6", "route", "add", &format!("{}/128", srv), "via", orig])
            .output();
    }
    
    // Replace default route
    let output = Command::new("ip")
        .args(["-6", "route", "replace", "default", "via", vpn_gateway])
        .output()?;
    
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        log::error!("Failed to set IPv6 default gateway: {}", err);
        return Err(io::Error::new(io::ErrorKind::Other, err.to_string()));
    }
    
    log::info!("✓ IPv6 default gateway set to {}", vpn_gateway);
    Ok(())
}

/// Restore original default IPv4 gateway
pub fn restore_default_gateway_v4(original_gateway: &str, server_ip: &str) -> io::Result<()> {
    log::info!("Restoring IPv4 gateway to {}...", original_gateway);
    
    let _ = Command::new("ip")
        .args(["-4", "route", "replace", "default", "via", original_gateway])
        .output();
    
    let _ = Command::new("ip")
        .args(["-4", "route", "del", &format!("{}/32", server_ip)])
        .output();
    
    Ok(())
}

/// Restore original default IPv6 gateway
pub fn restore_default_gateway_v6(original_gateway: Option<&str>, server_ip: Option<&str>) -> io::Result<()> {
    if let Some(gw) = original_gateway {
        log::info!("Restoring IPv6 gateway to {}...", gw);
        
        let _ = Command::new("ip")
            .args(["-6", "route", "replace", "default", "via", gw])
            .output();
    }
    
    if let Some(srv) = server_ip {
        let _ = Command::new("ip")
            .args(["-6", "route", "del", &format!("{}/128", srv)])
            .output();
    }
    
    Ok(())
}

/// Get current default IPv4 gateway
pub fn get_default_gateway_v4() -> io::Result<String> {
    let output = Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_gateway(&stdout)
}

/// Get current default IPv6 gateway
pub fn get_default_gateway_v6() -> io::Result<String> {
    let output = Command::new("ip")
        .args(["-6", "route", "show", "default"])
        .output()?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_gateway(&stdout)
}

fn parse_gateway(route_output: &str) -> io::Result<String> {
    // Parse: "default via 192.168.1.1 dev eth0"
    if let Some(via_idx) = route_output.find("via ") {
        let rest = &route_output[via_idx + 4..];
        if let Some(space_idx) = rest.find(' ') {
            return Ok(rest[..space_idx].to_string());
        }
        if let Some(newline_idx) = rest.find('\n') {
            return Ok(rest[..newline_idx].trim().to_string());
        }
    }
    
    Err(io::Error::new(io::ErrorKind::NotFound, "No default gateway found"))
}

// ═══════════════════════════════════════════════════════════════════════════
// DNS
// ═══════════════════════════════════════════════════════════════════════════

/// Set DNS servers
pub fn set_dns(servers_v4: &[String], servers_v6: &[String], search: &[String]) -> io::Result<()> {
    if servers_v4.is_empty() && servers_v6.is_empty() {
        return Ok(());
    }
    
    log::info!("Setting DNS servers: v4={:?}, v6={:?}", servers_v4, servers_v6);
    
    // Backup original resolv.conf
    let _ = std::fs::copy("/etc/resolv.conf", "/etc/resolv.conf.2cha-backup");
    
    let mut content = String::new();
    
    // Search domains
    if !search.is_empty() {
        content.push_str(&format!("search {}\n", search.join(" ")));
    }
    
    // IPv4 servers
    for server in servers_v4 {
        content.push_str(&format!("nameserver {}\n", server));
    }
    
    // IPv6 servers
    for server in servers_v6 {
        content.push_str(&format!("nameserver {}\n", server));
    }
    
    std::fs::write("/etc/resolv.conf", content)?;
    log::info!("✓ DNS configured");
    Ok(())
}

/// Restore original DNS
pub fn restore_dns() -> io::Result<()> {
    let backup_path = std::path::Path::new("/etc/resolv.conf.2cha-backup");
    if backup_path.exists() {
        std::fs::copy(backup_path, "/etc/resolv.conf")?;
        let _ = std::fs::remove_file(backup_path);
        log::info!("✓ DNS restored");
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// GATEWAY SETUP (SERVER)
// ═══════════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════════
// CLIENT ROUTING SETUP
// ═══════════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════════
// STATUS
// ═══════════════════════════════════════════════════════════════════════════

/// Get current routing status
pub fn get_routing_status(tun_name: &str) -> RoutingStatus {
    let mut status = RoutingStatus::default();
    
    // Check if interface exists
    if let Ok(output) = Command::new("ip").args(["link", "show", tun_name]).output() {
        status.interface_exists = output.status.success();
    }
    
    // Check IPv4 address
    if let Ok(output) = Command::new("ip").args(["-4", "addr", "show", tun_name]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(line) = stdout.lines().find(|l| l.contains("inet ")) {
            status.ipv4_address = line.split_whitespace()
                .nth(1)
                .map(|s| s.to_string());
        }
    }
    
    // Check IPv6 address
    if let Ok(output) = Command::new("ip").args(["-6", "addr", "show", tun_name, "scope", "global"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(line) = stdout.lines().find(|l| l.contains("inet6 ")) {
            status.ipv6_address = line.split_whitespace()
                .nth(1)
                .map(|s| s.to_string());
        }
    }
    
    // Check if default route goes through TUN
    if let Ok(output) = Command::new("ip").args(["-4", "route", "show", "default"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        status.default_route_v4_via_tun = stdout.contains(tun_name);
    }
    
    if let Ok(output) = Command::new("ip").args(["-6", "route", "show", "default"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        status.default_route_v6_via_tun = stdout.contains(tun_name);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_gateway() {
        let output = "default via 192.168.1.1 dev eth0 proto static";
        assert_eq!(parse_gateway(output).unwrap(), "192.168.1.1");

        let output6 = "default via fe80::1 dev eth0 proto ra metric 100";
        assert_eq!(parse_gateway(output6).unwrap(), "fe80::1");
    }
}
