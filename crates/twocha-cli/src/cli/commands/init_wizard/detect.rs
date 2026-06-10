//! Local network detection for the init wizard.
//!
//! No external network requests: everything is derived from local
//! interfaces (`getifaddrs`) and the kernel routing table.

use std::net::{IpAddr, Ipv4Addr};

/// A local network interface with its addresses
#[derive(Debug, Clone)]
pub struct IfaceInfo {
    pub name: String,
    pub addrs: Vec<IpAddr>,
    pub is_up: bool,
    pub is_loopback: bool,
}

/// Enumerate local interfaces and their addresses
#[cfg(unix)]
pub fn local_interfaces() -> Vec<IfaceInfo> {
    use std::collections::HashMap;
    use std::ffi::CStr;

    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return Vec::new();
    }

    let mut map: HashMap<String, IfaceInfo> = HashMap::new();
    let mut order: Vec<String> = Vec::new();

    let mut cur = ifap;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;

        if ifa.ifa_name.is_null() {
            continue;
        }
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();

        let entry = map.entry(name.clone()).or_insert_with(|| {
            order.push(name.clone());
            IfaceInfo {
                name,
                addrs: Vec::new(),
                is_up: ifa.ifa_flags & libc::IFF_UP as u32 != 0,
                is_loopback: ifa.ifa_flags & libc::IFF_LOOPBACK as u32 != 0,
            }
        });

        if let Some(ip) = unsafe { sockaddr_to_ip(ifa.ifa_addr) } {
            entry.addrs.push(ip);
        }
    }

    unsafe { libc::freeifaddrs(ifap) };

    order.into_iter().filter_map(|n| map.remove(&n)).collect()
}

#[cfg(windows)]
pub fn local_interfaces() -> Vec<IfaceInfo> {
    Vec::new()
}

#[cfg(unix)]
unsafe fn sockaddr_to_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
    use std::net::Ipv6Addr;

    if sa.is_null() {
        return None;
    }
    match i32::from((*sa).sa_family) {
        libc::AF_INET => {
            let sin = &*(sa as *const libc::sockaddr_in);
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                sin.sin_addr.s_addr,
            ))))
        }
        libc::AF_INET6 => {
            let sin6 = &*(sa as *const libc::sockaddr_in6);
            Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

/// Name of the interface carrying the default route
#[cfg(target_os = "linux")]
pub fn default_route_interface() -> Option<String> {
    const RTF_UP: u32 = 0x1;
    let content = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let flags = u32::from_str_radix(fields[3], 16).unwrap_or(0);
        if fields[1] == "00000000" && flags & RTF_UP != 0 {
            return Some(fields[0].to_string());
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
pub fn default_route_interface() -> Option<String> {
    None
}

/// IPv4 routes (network, prefix) from the kernel routing table
#[cfg(target_os = "linux")]
fn local_routes_v4() -> Vec<(Ipv4Addr, u8)> {
    let Ok(content) = std::fs::read_to_string("/proc/net/route") else {
        return Vec::new();
    };
    let mut routes = Vec::new();
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 {
            continue;
        }
        // /proc/net/route stores addresses as little-endian hex
        let Ok(dest) = u32::from_str_radix(fields[1], 16) else {
            continue;
        };
        let Ok(mask) = u32::from_str_radix(fields[7], 16) else {
            continue;
        };
        let prefix = u32::from_be(mask).count_ones() as u8;
        if prefix == 0 {
            continue; // default route covers everything; not a conflict
        }
        routes.push((Ipv4Addr::from(u32::from_be(dest)), prefix));
    }
    routes
}

#[cfg(not(target_os = "linux"))]
fn local_routes_v4() -> Vec<(Ipv4Addr, u8)> {
    Vec::new()
}

fn prefix_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        !((1u64 << (32 - prefix as u64)) - 1) as u32
    }
}

fn overlaps(a: Ipv4Addr, a_prefix: u8, b: Ipv4Addr, b_prefix: u8) -> bool {
    let p = a_prefix.min(b_prefix);
    let mask = prefix_mask(p);
    u32::from(a) & mask == u32::from(b) & mask
}

/// Suggest a /24 VPN subnet that does not conflict with local
/// addresses or routes. Falls back to 10.8.0.0/24.
pub fn suggest_subnet() -> (Ipv4Addr, u8) {
    let candidates = [
        Ipv4Addr::new(10, 8, 0, 0),
        Ipv4Addr::new(10, 9, 0, 0),
        Ipv4Addr::new(10, 66, 66, 0),
        Ipv4Addr::new(10, 100, 0, 0),
        Ipv4Addr::new(10, 200, 200, 0),
        Ipv4Addr::new(172, 16, 222, 0),
        Ipv4Addr::new(192, 168, 222, 0),
    ];

    let mut used: Vec<(Ipv4Addr, u8)> = local_routes_v4();
    for iface in local_interfaces() {
        for addr in iface.addrs {
            if let IpAddr::V4(v4) = addr {
                used.push((v4, 24));
            }
        }
    }

    for cand in candidates {
        if !used.iter().any(|(net, p)| overlaps(cand, 24, *net, *p)) {
            return (cand, 24);
        }
    }
    (Ipv4Addr::new(10, 8, 0, 0), 24)
}

/// Candidate public addresses for the server endpoint, best first:
/// global IPv4 addresses, then private non-loopback IPv4.
pub fn endpoint_candidates() -> Vec<Ipv4Addr> {
    let mut global = Vec::new();
    let mut private = Vec::new();
    for iface in local_interfaces() {
        if iface.is_loopback || !iface.is_up {
            continue;
        }
        for addr in iface.addrs {
            if let IpAddr::V4(v4) = addr {
                if v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() {
                    continue;
                }
                if v4.is_private() {
                    private.push(v4);
                } else {
                    global.push(v4);
                }
            }
        }
    }
    global.extend(private);
    global
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_mask() {
        assert_eq!(prefix_mask(0), 0);
        assert_eq!(prefix_mask(24), 0xFFFF_FF00);
        assert_eq!(prefix_mask(32), 0xFFFF_FFFF);
    }

    #[test]
    fn test_overlaps() {
        let a = Ipv4Addr::new(10, 8, 0, 0);
        assert!(overlaps(a, 24, Ipv4Addr::new(10, 8, 0, 5), 24));
        assert!(overlaps(a, 24, Ipv4Addr::new(10, 0, 0, 0), 8));
        assert!(!overlaps(a, 24, Ipv4Addr::new(10, 9, 0, 0), 24));
        assert!(!overlaps(a, 24, Ipv4Addr::new(192, 168, 1, 0), 24));
    }

    #[test]
    fn test_suggest_subnet_returns_slash_24() {
        let (net, prefix) = suggest_subnet();
        assert_eq!(prefix, 24);
        assert_eq!(u32::from(net) & 0xFF, 0);
    }
}
