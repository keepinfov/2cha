//! # Routing Module (Unix)
//!
//! IP forwarding, NAT, and routing table configuration.

#![allow(clippy::io_other_error)]
#![allow(clippy::too_many_arguments)]

use super::netlink;
use std::io::{self, Write};
use std::net::IpAddr;
use std::process::Command;

// ═══════════════════════════════════════════════════════════════════════════
// IP FORWARDING
// ═══════════════════════════════════════════════════════════════════════════

pub fn enable_ipv4_forward() -> io::Result<()> {
    log::info!("Enabling IPv4 forwarding...");
    let output = Command::new("sysctl")
        .args(["-w", "net.ipv4.ip_forward=1"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            log::info!("IPv4 forwarding enabled via sysctl");
            return Ok(());
        }
        _ => {}
    }

    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
    log::info!("IPv4 forwarding enabled");
    Ok(())
}

pub fn enable_ipv6_forward() -> io::Result<()> {
    log::info!("Enabling IPv6 forwarding...");
    let output = Command::new("sysctl")
        .args(["-w", "net.ipv6.conf.all.forwarding=1"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            log::info!("IPv6 forwarding enabled via sysctl");
            return Ok(());
        }
        _ => {}
    }

    std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1")?;
    log::info!("IPv6 forwarding enabled");
    Ok(())
}

pub fn is_ipv4_forward_enabled() -> bool {
    std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

pub fn is_ipv6_forward_enabled() -> bool {
    std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding")
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

// ═══════════════════════════════════════════════════════════════════════════
// NAT / MASQUERADING
// ═══════════════════════════════════════════════════════════════════════════

/// Whether a binary is resolvable on `PATH` (so we can fail loudly with an
/// actionable message instead of an opaque "No such file or directory").
fn command_exists(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn setup_masquerade_v4(
    external_iface: &str,
    vpn_subnet: &str,
    tun_iface: &str,
) -> io::Result<()> {
    log::info!(
        "Setting up IPv4 NAT on {} for {} (tun {})",
        external_iface,
        vpn_subnet,
        tun_iface
    );

    match setup_nat_nftables_v4(external_iface, vpn_subnet) {
        Ok(()) => {
            log::info!("IPv4 NAT configured via nftables");
            return Ok(());
        }
        Err(e) => log::warn!("nftables NAT setup failed, falling back to iptables: {}", e),
    }

    if !command_exists("iptables") {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "neither nft nor iptables is available to configure IPv4 NAT",
        ));
    }

    let output = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            vpn_subnet,
            "-o",
            external_iface,
            "-j",
            "MASQUERADE",
        ])
        .output()?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        log::error!("iptables error: {}", err);
        return Err(io::Error::new(io::ErrorKind::Other, err.to_string()));
    }

    let fwd_out = Command::new("iptables")
        .args([
            "-A",
            "FORWARD",
            "-i",
            tun_iface,
            "-o",
            external_iface,
            "-j",
            "ACCEPT",
        ])
        .output()?;
    if !fwd_out.status.success() {
        log::warn!(
            "iptables FORWARD (out) rule failed: {}",
            String::from_utf8_lossy(&fwd_out.stderr)
        );
    }

    let fwd_in = Command::new("iptables")
        .args([
            "-A",
            "FORWARD",
            "-i",
            external_iface,
            "-o",
            tun_iface,
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ])
        .output()?;
    if !fwd_in.status.success() {
        log::warn!(
            "iptables FORWARD (in) rule failed: {}",
            String::from_utf8_lossy(&fwd_in.stderr)
        );
    }

    log::info!("IPv4 NAT configured via iptables");
    Ok(())
}

pub fn setup_masquerade_v6(
    external_iface: &str,
    vpn_subnet: &str,
    _tun_iface: &str,
) -> io::Result<()> {
    log::info!(
        "Setting up IPv6 NAT on {} for {}",
        external_iface,
        vpn_subnet
    );

    match setup_nat_nftables_v6(external_iface, vpn_subnet) {
        Ok(()) => {
            log::info!("IPv6 NAT configured via nftables");
            return Ok(());
        }
        Err(e) => log::warn!(
            "nftables NAT setup failed, falling back to ip6tables: {}",
            e
        ),
    }

    if !command_exists("ip6tables") {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "neither nft nor ip6tables is available to configure IPv6 NAT",
        ));
    }

    let output = Command::new("ip6tables")
        .args([
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            vpn_subnet,
            "-o",
            external_iface,
            "-j",
            "MASQUERADE",
        ])
        .output()?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::new(io::ErrorKind::Other, err.to_string()));
    }

    log::info!("IPv6 NAT configured via ip6tables");
    Ok(())
}

/// Feed an nftables ruleset on stdin and surface a non-zero exit as an error
/// (the previous version ignored the exit status, so a rejected ruleset was
/// silently treated as success and the iptables fallback never ran).
fn apply_nftables(rules: &str) -> io::Result<()> {
    if !command_exists("nft") {
        return Err(io::Error::new(io::ErrorKind::NotFound, "nft not available"));
    }

    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(rules.as_bytes())?;
    }

    let status = child.wait()?;
    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("nft exited with status {}", status),
        ));
    }
    Ok(())
}

fn setup_nat_nftables_v4(external_iface: &str, vpn_subnet: &str) -> io::Result<()> {
    let rules = format!(
        r#"table ip 2cha_nat {{
    chain postrouting {{
        type nat hook postrouting priority srcnat;
        ip saddr {} oifname "{}" masquerade
    }}
}}"#,
        vpn_subnet, external_iface
    );
    apply_nftables(&rules)
}

fn setup_nat_nftables_v6(external_iface: &str, vpn_subnet: &str) -> io::Result<()> {
    let rules = format!(
        r#"table ip6 2cha_nat6 {{
    chain postrouting {{
        type nat hook postrouting priority srcnat;
        ip6 saddr {} oifname "{}" masquerade
    }}
}}"#,
        vpn_subnet, external_iface
    );
    apply_nftables(&rules)
}

// ═══════════════════════════════════════════════════════════════════════════
// ROUTING
// ═══════════════════════════════════════════════════════════════════════════

pub fn add_route_v4(destination: &str, gateway: &str) -> io::Result<()> {
    log::info!("Adding IPv4 route: {} via {}", destination, gateway);
    let dst = netlink::parse_cidr(destination)?;
    let gw: IpAddr = gateway
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{e}")))?;
    netlink::replace_route(Some(dst), gw)
}

pub fn add_route_v6(destination: &str, gateway: &str) -> io::Result<()> {
    add_route_v4(destination, gateway)
}

pub fn del_route_v4(destination: &str) -> io::Result<()> {
    let dst = netlink::parse_cidr(destination)?;
    if let Err(e) = netlink::delete_route(dst) {
        log::warn!("Route delete warning for {}: {}", destination, e);
    }
    Ok(())
}

pub fn del_route_v6(destination: &str) -> io::Result<()> {
    del_route_v4(destination)
}

pub fn set_default_gateway_v4(
    vpn_gateway: &str,
    original_gateway: &str,
    server_ip: &str,
) -> io::Result<()> {
    log::info!("Setting IPv4 default gateway to {}", vpn_gateway);

    // Pin the route to the real server through the original gateway so the
    // encrypted tunnel traffic does not loop back into the tunnel.
    if let (Ok(orig), Ok(srv)) = (
        original_gateway.parse::<IpAddr>(),
        server_ip.parse::<IpAddr>(),
    ) {
        if let Err(e) = netlink::replace_route(Some((srv, 32)), orig) {
            log::warn!("Failed to pin server host route: {}", e);
        }
    }

    let vpn_gw: IpAddr = vpn_gateway
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{e}")))?;
    netlink::replace_route(None, vpn_gw)?;

    log::info!("IPv4 default gateway set to {}", vpn_gateway);
    Ok(())
}

pub fn set_default_gateway_v6(
    vpn_gateway: &str,
    original_gateway: Option<&str>,
    server_ip: Option<&str>,
) -> io::Result<()> {
    log::info!("Setting IPv6 default gateway to {}", vpn_gateway);

    if let (Some(orig), Some(srv)) = (original_gateway, server_ip) {
        if let (Ok(orig), Ok(srv)) = (orig.parse::<IpAddr>(), srv.parse::<IpAddr>()) {
            if let Err(e) = netlink::replace_route(Some((srv, 128)), orig) {
                log::warn!("Failed to pin server host route: {}", e);
            }
        }
    }

    let vpn_gw: IpAddr = vpn_gateway
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{e}")))?;
    netlink::replace_route(None, vpn_gw)?;

    Ok(())
}

pub fn restore_default_gateway_v4(original_gateway: &str, server_ip: &str) -> io::Result<()> {
    log::info!("Restoring IPv4 gateway to {}", original_gateway);
    if let Ok(orig) = original_gateway.parse::<IpAddr>() {
        let _ = netlink::replace_route(None, orig);
    }
    if let Ok(srv) = server_ip.parse::<IpAddr>() {
        let _ = netlink::delete_route((srv, 32));
    }
    Ok(())
}

pub fn restore_default_gateway_v6(
    original_gateway: Option<&str>,
    server_ip: Option<&str>,
) -> io::Result<()> {
    if let Some(gw) = original_gateway {
        log::info!("Restoring IPv6 gateway to {}", gw);
        if let Ok(orig) = gw.parse::<IpAddr>() {
            let _ = netlink::replace_route(None, orig);
        }
    }
    if let Some(srv) = server_ip {
        if let Ok(srv) = srv.parse::<IpAddr>() {
            let _ = netlink::delete_route((srv, 128));
        }
    }
    Ok(())
}

pub fn get_default_gateway_v4() -> io::Result<String> {
    netlink::default_gateway_v4().map(|ip| ip.to_string())
}

pub fn get_default_gateway_v6() -> io::Result<String> {
    netlink::default_gateway_v6().map(|ip| ip.to_string())
}

// ═══════════════════════════════════════════════════════════════════════════
// DNS
// ═══════════════════════════════════════════════════════════════════════════

pub fn set_dns(servers_v4: &[String], servers_v6: &[String], search: &[String]) -> io::Result<()> {
    if servers_v4.is_empty() && servers_v6.is_empty() {
        return Ok(());
    }

    log::info!("Setting DNS servers");
    let _ = std::fs::copy("/etc/resolv.conf", "/etc/resolv.conf.2cha-backup");

    let mut content = String::new();
    if !search.is_empty() {
        content.push_str(&format!("search {}\n", search.join(" ")));
    }
    for server in servers_v4 {
        content.push_str(&format!("nameserver {}\n", server));
    }
    for server in servers_v6 {
        content.push_str(&format!("nameserver {}\n", server));
    }

    std::fs::write("/etc/resolv.conf", content)?;
    log::info!("DNS configured");
    Ok(())
}

pub fn restore_dns() -> io::Result<()> {
    let backup_path = std::path::Path::new("/etc/resolv.conf.2cha-backup");
    if backup_path.exists() {
        std::fs::copy(backup_path, "/etc/resolv.conf")?;
        let _ = std::fs::remove_file(backup_path);
        log::info!("DNS restored");
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// SERVER GATEWAY SETUP
// ═══════════════════════════════════════════════════════════════════════════

pub fn setup_server_gateway_v4(
    external_iface: &str,
    vpn_subnet: &str,
    tun_iface: &str,
) -> io::Result<()> {
    enable_ipv4_forward()?;
    setup_masquerade_v4(external_iface, vpn_subnet, tun_iface)?;
    Ok(())
}

pub fn setup_server_gateway_v6(
    external_iface: &str,
    vpn_subnet: &str,
    tun_iface: &str,
) -> io::Result<()> {
    enable_ipv6_forward()?;
    setup_masquerade_v6(external_iface, vpn_subnet, tun_iface)?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// CLIENT ROUTING CONTEXT
// ═══════════════════════════════════════════════════════════════════════════

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
        match server_addr.ip() {
            IpAddr::V4(ip) => self.server_ip_v4 = Some(ip.to_string()),
            IpAddr::V6(ip) => self.server_ip_v6 = Some(ip.to_string()),
        }

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

        if let Some(gw) = ipv6_gateway {
            if route_all_v6 {
                self.original_gateway_v6 = get_default_gateway_v6().ok();
                set_default_gateway_v6(
                    gw,
                    self.original_gateway_v6.as_deref(),
                    self.server_ip_v6.as_deref(),
                )?;
            } else {
                for route in routes_v6 {
                    add_route_v6(route, gw)?;
                    self.added_routes_v6.push(route.clone());
                }
            }
        }

        if !dns_v4.is_empty() || !dns_v6.is_empty() {
            set_dns(dns_v4, dns_v6, dns_search)?;
            self.dns_modified = true;
        }

        Ok(())
    }

    pub fn cleanup(&self) -> io::Result<()> {
        if let (Some(ref orig_gw), Some(ref srv)) = (&self.original_gateway_v4, &self.server_ip_v4)
        {
            let _ = restore_default_gateway_v4(orig_gw, srv);
        }

        if self.original_gateway_v6.is_some() || self.server_ip_v6.is_some() {
            let _ = restore_default_gateway_v6(
                self.original_gateway_v6.as_deref(),
                self.server_ip_v6.as_deref(),
            );
        }

        for route in &self.added_routes_v4 {
            let _ = del_route_v4(route);
        }
        for route in &self.added_routes_v6 {
            let _ = del_route_v6(route);
        }

        if self.dns_modified {
            let _ = restore_dns();
        }

        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// NAT TEARDOWN
// ═══════════════════════════════════════════════════════════════════════════

/// Remove the IPv4 NAT/forwarding rules installed by [`setup_masquerade_v4`].
/// Best-effort: both the nftables table and the iptables rules are removed so
/// whichever backend was used is cleaned up regardless of which one succeeded.
pub fn teardown_masquerade_v4(external_iface: &str, vpn_subnet: &str, tun_iface: &str) {
    let _ = Command::new("nft")
        .args(["delete", "table", "ip", "2cha_nat"])
        .output();

    let _ = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-s",
            vpn_subnet,
            "-o",
            external_iface,
            "-j",
            "MASQUERADE",
        ])
        .output();
    let _ = Command::new("iptables")
        .args([
            "-D",
            "FORWARD",
            "-i",
            tun_iface,
            "-o",
            external_iface,
            "-j",
            "ACCEPT",
        ])
        .output();
    let _ = Command::new("iptables")
        .args([
            "-D",
            "FORWARD",
            "-i",
            external_iface,
            "-o",
            tun_iface,
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ])
        .output();
}

/// Remove the IPv6 NAT rules installed by [`setup_masquerade_v6`].
pub fn teardown_masquerade_v6(external_iface: &str, vpn_subnet: &str, _tun_iface: &str) {
    let _ = Command::new("nft")
        .args(["delete", "table", "ip6", "2cha_nat6"])
        .output();

    let _ = Command::new("ip6tables")
        .args([
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-s",
            vpn_subnet,
            "-o",
            external_iface,
            "-j",
            "MASQUERADE",
        ])
        .output();
}

fn set_ipv4_forward(enabled: bool) {
    let v = if enabled { "1" } else { "0" };
    let _ = Command::new("sysctl")
        .args(["-w", &format!("net.ipv4.ip_forward={}", v)])
        .output();
    let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", v);
}

fn set_ipv6_forward(enabled: bool) {
    let v = if enabled { "1" } else { "0" };
    let _ = Command::new("sysctl")
        .args(["-w", &format!("net.ipv6.conf.all.forwarding={}", v)])
        .output();
    let _ = std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", v);
}

// ═══════════════════════════════════════════════════════════════════════════
// SERVER ROUTING CONTEXT
// ═══════════════════════════════════════════════════════════════════════════

/// Tracks the NAT/forwarding state the server applied so it can be rolled back
/// on shutdown, mirroring [`ClientRoutingContext`]. Previously the server set
/// up masquerading and IP forwarding but never tore them down, leaving stale
/// nftables/iptables rules and a globally-enabled `ip_forward` behind.
#[derive(Debug, Default)]
pub struct ServerRoutingContext {
    nat_v4: Option<(String, String, String)>,
    nat_v6: Option<(String, String, String)>,
    forward_v4_prev: Option<bool>,
    forward_v6_prev: Option<bool>,
}

impl ServerRoutingContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn setup_v4(
        &mut self,
        external_iface: &str,
        vpn_subnet: &str,
        tun_iface: &str,
    ) -> io::Result<()> {
        self.forward_v4_prev = Some(is_ipv4_forward_enabled());
        setup_server_gateway_v4(external_iface, vpn_subnet, tun_iface)?;
        self.nat_v4 = Some((
            external_iface.to_string(),
            vpn_subnet.to_string(),
            tun_iface.to_string(),
        ));
        Ok(())
    }

    pub fn setup_v6(
        &mut self,
        external_iface: &str,
        vpn_subnet: &str,
        tun_iface: &str,
    ) -> io::Result<()> {
        self.forward_v6_prev = Some(is_ipv6_forward_enabled());
        setup_server_gateway_v6(external_iface, vpn_subnet, tun_iface)?;
        self.nat_v6 = Some((
            external_iface.to_string(),
            vpn_subnet.to_string(),
            tun_iface.to_string(),
        ));
        Ok(())
    }

    pub fn cleanup(&self) {
        if let Some((ref iface, ref subnet, ref tun_iface)) = self.nat_v4 {
            log::info!("Tearing down IPv4 NAT");
            teardown_masquerade_v4(iface, subnet, tun_iface);
        }
        if let Some((ref iface, ref subnet, ref tun_iface)) = self.nat_v6 {
            log::info!("Tearing down IPv6 NAT");
            teardown_masquerade_v6(iface, subnet, tun_iface);
        }
        // Only restore forwarding if we are the ones who enabled it.
        if self.forward_v4_prev == Some(false) {
            set_ipv4_forward(false);
        }
        if self.forward_v6_prev == Some(false) {
            set_ipv6_forward(false);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// STATUS
// ═══════════════════════════════════════════════════════════════════════════

pub fn get_routing_status(tun_name: &str) -> RoutingStatus {
    let mut status = RoutingStatus::default();

    if let Ok(output) = Command::new("ip").args(["link", "show", tun_name]).output() {
        status.interface_exists = output.status.success();
    }

    if let Ok(output) = Command::new("ip")
        .args(["-4", "addr", "show", tun_name])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(line) = stdout.lines().find(|l| l.contains("inet ")) {
            status.ipv4_address = line.split_whitespace().nth(1).map(|s| s.to_string());
        }
    }

    if let Ok(output) = Command::new("ip")
        .args(["-6", "addr", "show", tun_name, "scope", "global"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(line) = stdout.lines().find(|l| l.contains("inet6 ")) {
            status.ipv6_address = line.split_whitespace().nth(1).map(|s| s.to_string());
        }
    }

    if let Ok(output) = Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        status.default_route_v4_via_tun = stdout.contains(tun_name);
    }

    if let Ok(output) = Command::new("ip")
        .args(["-6", "route", "show", "default"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        status.default_route_v6_via_tun = stdout.contains(tun_name);
    }

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
