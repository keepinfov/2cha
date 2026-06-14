//! # Netlink routing helpers (Linux)
//!
//! Route-table manipulation via rtnetlink, using the synchronous `neli`
//! router. This replaces the previous `ip route` shell-outs so route changes
//! are typed, atomic, and report kernel errors instead of being parsed out of
//! `ip`'s stderr.
//!
//! Only the mutating route operations and default-gateway discovery live here.
//! IP forwarding, NAT and DNS remain in [`super::routing`].

use std::io;
use std::net::IpAddr;

use neli::{
    consts::{
        nl::{NlTypeWrapper, NlmF},
        rtnl::{RtAddrFamily, RtScope, RtTable, Rta, Rtm, Rtn, Rtprot},
        socket::NlFamily,
    },
    nl::NlPayload,
    router::synchronous::NlRouter,
    rtnl::{RtattrBuilder, Rtmsg, RtmsgBuilder},
    types::{Buffer, RtBuffer},
    utils::Groups,
};

fn other<E: std::fmt::Display>(ctx: &str, e: E) -> io::Error {
    io::Error::other(format!("{ctx}: {e}"))
}

fn invalid<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
}

fn connect() -> io::Result<NlRouter> {
    let (rtnl, _) = NlRouter::connect(NlFamily::Route, None, Groups::empty())
        .map_err(|e| other("netlink connect", e))?;
    Ok(rtnl)
}

fn family_of(ip: IpAddr) -> RtAddrFamily {
    match ip {
        IpAddr::V4(_) => RtAddrFamily::Inet,
        IpAddr::V6(_) => RtAddrFamily::Inet6,
    }
}

/// Raw network-order address octets as an attribute payload. Using the octets
/// directly (rather than an integer + `to_be()`) keeps this endianness-safe.
fn addr_octets(ip: IpAddr) -> Buffer {
    match ip {
        IpAddr::V4(a) => Buffer::from(a.octets().to_vec()),
        IpAddr::V6(a) => Buffer::from(a.octets().to_vec()),
    }
}

fn bytes_to_ip(b: &[u8]) -> Option<IpAddr> {
    match b.len() {
        4 => {
            let o: [u8; 4] = b.try_into().ok()?;
            Some(IpAddr::from(o))
        }
        16 => {
            let o: [u8; 16] = b.try_into().ok()?;
            Some(IpAddr::from(o))
        }
        _ => None,
    }
}

/// Parse `"10.0.0.0/24"` (or a bare address, treated as a host route) into an
/// address and prefix length.
pub fn parse_cidr(s: &str) -> io::Result<(IpAddr, u8)> {
    if let Some((ip_s, plen_s)) = s.split_once('/') {
        let ip: IpAddr = ip_s.trim().parse().map_err(invalid)?;
        let plen: u8 = plen_s.trim().parse().map_err(invalid)?;
        Ok((ip, plen))
    } else {
        let ip: IpAddr = s.trim().parse().map_err(invalid)?;
        let plen = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Ok((ip, plen))
    }
}

/// Issue an RTM_NEWROUTE / RTM_DELROUTE for a route in the main table.
///
/// `dst == None` targets the default route (destination length 0). All routes
/// here are unicast routes reached via a gateway, so scope is universe.
fn modify_route(
    op: Rtm,
    flags: NlmF,
    family: RtAddrFamily,
    dst: Option<(IpAddr, u8)>,
    gateway: Option<IpAddr>,
) -> io::Result<()> {
    let rtnl = connect()?;

    let mut attrs = RtBuffer::new();
    let mut dst_len = 0u8;
    if let Some((d, plen)) = dst {
        dst_len = plen;
        attrs.push(
            RtattrBuilder::default()
                .rta_type(Rta::Dst)
                .rta_payload(addr_octets(d))
                .build()
                .map_err(|e| other("build RTA_DST", e))?,
        );
    }
    if let Some(gw) = gateway {
        attrs.push(
            RtattrBuilder::default()
                .rta_type(Rta::Gateway)
                .rta_payload(addr_octets(gw))
                .build()
                .map_err(|e| other("build RTA_GATEWAY", e))?,
        );
    }

    let rtmsg = RtmsgBuilder::default()
        .rtm_family(family)
        .rtm_dst_len(dst_len)
        .rtm_src_len(0)
        .rtm_tos(0)
        .rtm_table(RtTable::Main)
        .rtm_protocol(Rtprot::Boot)
        .rtm_scope(RtScope::Universe)
        .rtm_type(Rtn::Unicast)
        .rtattrs(attrs)
        .build()
        .map_err(|e| other("build rtmsg", e))?;

    let recv = rtnl
        .send::<_, _, NlTypeWrapper, Rtmsg>(op, flags | NlmF::ACK, NlPayload::Payload(rtmsg))
        .map_err(|e| other("netlink send", e))?;

    for resp in recv {
        resp.map_err(|e| other("netlink route op", e))?;
    }
    Ok(())
}

/// `ip route replace <dst> via <gateway>` — idempotent create-or-replace.
pub fn replace_route(dst: Option<(IpAddr, u8)>, gateway: IpAddr) -> io::Result<()> {
    modify_route(
        Rtm::Newroute,
        NlmF::CREATE | NlmF::REPLACE,
        family_of(gateway),
        dst,
        Some(gateway),
    )
}

/// `ip route del <dst>`.
pub fn delete_route(dst: (IpAddr, u8)) -> io::Result<()> {
    modify_route(
        Rtm::Delroute,
        NlmF::empty(),
        family_of(dst.0),
        Some(dst),
        None,
    )
}

/// Discover the current default gateway for the given family by dumping the
/// route table and returning the first default (destination length 0) route's
/// gateway.
pub fn default_gateway(family: RtAddrFamily) -> io::Result<IpAddr> {
    let rtnl = connect()?;

    let rtmsg = RtmsgBuilder::default()
        .rtm_family(family)
        .rtm_dst_len(0)
        .rtm_src_len(0)
        .rtm_tos(0)
        .rtm_table(RtTable::Unspec)
        .rtm_protocol(Rtprot::Unspec)
        .rtm_scope(RtScope::Universe)
        .rtm_type(Rtn::Unspec)
        .build()
        .map_err(|e| other("build rtmsg", e))?;

    let recv = rtnl
        .send::<_, _, NlTypeWrapper, Rtmsg>(Rtm::Getroute, NlmF::DUMP, NlPayload::Payload(rtmsg))
        .map_err(|e| other("netlink dump", e))?;

    for msg in recv {
        let msg = msg.map_err(|e| other("netlink dump recv", e))?;
        if let Some(p) = msg.get_payload() {
            if *p.rtm_dst_len() != 0 || p.rtm_table() != &RtTable::Main {
                continue;
            }
            for attr in p.rtattrs().iter() {
                if attr.rta_type() == &Rta::Gateway {
                    if let Some(ip) = bytes_to_ip(attr.rta_payload().as_ref()) {
                        return Ok(ip);
                    }
                }
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no default gateway found",
    ))
}

/// Current IPv4 default gateway.
pub fn default_gateway_v4() -> io::Result<IpAddr> {
    default_gateway(RtAddrFamily::Inet)
}

/// Current IPv6 default gateway.
pub fn default_gateway_v6() -> io::Result<IpAddr> {
    default_gateway(RtAddrFamily::Inet6)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn parse_cidr_v4() {
        let (ip, plen) = parse_cidr("10.0.0.0/24").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
        assert_eq!(plen, 24);
    }

    #[test]
    fn parse_cidr_bare_host() {
        let (ip, plen) = parse_cidr("192.168.1.5").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)));
        assert_eq!(plen, 32);
    }

    #[test]
    fn parse_cidr_v6() {
        let (ip, plen) = parse_cidr("2001:db8::/32").unwrap();
        assert_eq!(ip, IpAddr::V6("2001:db8::".parse::<Ipv6Addr>().unwrap()));
        assert_eq!(plen, 32);
    }

    #[test]
    fn parse_cidr_rejects_garbage() {
        assert!(parse_cidr("not-an-ip/24").is_err());
        assert!(parse_cidr("10.0.0.0/999").is_err());
    }

    #[test]
    fn addr_octets_preserve_order() {
        let b = addr_octets(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(b.as_ref(), &[1, 2, 3, 4]);
    }
}
