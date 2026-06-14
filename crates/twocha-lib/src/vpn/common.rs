//! # Shared VPN Handler Logic
//!
//! Run-flag and signal handling plus inner IP-packet inspection shared by
//! the client and server event loops.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};

static RUNNING: AtomicBool = AtomicBool::new(true);

pub fn running() -> bool {
    RUNNING.load(Ordering::SeqCst)
}

/// Stop all running handlers (also used as the signal handler target)
pub fn stop() {
    RUNNING.store(false, Ordering::SeqCst);
}

/// Re-arm the run flag; call at handler startup so a previous stop() does
/// not abort a fresh run in the same process.
pub fn reset_running() {
    RUNNING.store(true, Ordering::SeqCst);
}

/// Install SIGINT/SIGTERM handlers that flip the run flag so the event loops
/// exit cleanly. Uses `signal-hook` (sigaction-based) rather than the
/// deprecated `libc::signal()`. The handler only does an atomic store, which is
/// async-signal-safe.
#[cfg(unix)]
pub fn setup_signal_handler() {
    for sig in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        // Safety: the registered action calls only `stop()`, an atomic store,
        // which is sound to run in signal context.
        if let Err(e) = unsafe { signal_hook::low_level::register(sig, stop) } {
            log::warn!("failed to install handler for signal {}: {}", sig, e);
        }
    }
}

/// Source IP of a raw IPv4/IPv6 packet read from TUN
pub fn inner_src_ip(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => {
            let octets: [u8; 4] = packet[12..16].try_into().ok()?;
            Some(IpAddr::from(octets))
        }
        6 if packet.len() >= 40 => {
            let octets: [u8; 16] = packet[8..24].try_into().ok()?;
            Some(IpAddr::from(octets))
        }
        _ => None,
    }
}

/// Destination IP of a raw IPv4/IPv6 packet read from TUN
pub fn inner_dst_ip(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => {
            let octets: [u8; 4] = packet[16..20].try_into().ok()?;
            Some(IpAddr::from(octets))
        }
        6 if packet.len() >= 40 => {
            let octets: [u8; 16] = packet[24..40].try_into().ok()?;
            Some(IpAddr::from(octets))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inner_ips_v4() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 2]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 1]);
        assert_eq!(inner_src_ip(&pkt), Some("10.0.0.2".parse().unwrap()));
        assert_eq!(inner_dst_ip(&pkt), Some("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_inner_ips_v6() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60;
        pkt[23] = 2; // src ::2
        pkt[39] = 1; // dst ::1
        assert_eq!(inner_src_ip(&pkt), Some("::2".parse().unwrap()));
        assert_eq!(inner_dst_ip(&pkt), Some("::1".parse().unwrap()));
    }

    #[test]
    fn test_inner_ips_garbage() {
        assert_eq!(inner_src_ip(&[]), None);
        assert_eq!(inner_dst_ip(&[0x45]), None);
        assert_eq!(inner_src_ip(&[0x00; 40]), None);
    }
}
