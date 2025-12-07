//! # Windows TUN Device Module
//!
//! High-performance TUN device for Windows using WinTun driver.
//! Requires wintun.dll to be present in the system or application directory.

#![cfg(windows)]

use crate::error::{Result, TunError, VpnError};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use wintun::{Adapter, Session};

// =============================================================================
// CONSTANTS
// =============================================================================

const WINTUN_RING_CAPACITY: u32 = 0x400000; // 4MB ring buffer
const ADAPTER_GUID: &str = "2CHA-VPN0-0000-0000-000000000000";

// =============================================================================
// TUN DEVICE
// =============================================================================

/// High-performance TUN device for Windows using WinTun
pub struct TunDevice {
    adapter: Arc<Adapter>,
    session: Arc<Session>,
    name: String,
    mtu: u16,
    ipv4_addr: Option<Ipv4Addr>,
    ipv6_addr: Option<Ipv6Addr>,
}

impl TunDevice {
    /// Create a new TUN device
    pub fn create(name: &str) -> Result<Self> {
        Self::create_with_options(name, false)
    }

    /// Create a TUN device with options
    pub fn create_with_options(name: &str, _multi_queue: bool) -> Result<Self> {
        log::info!("Creating WinTun adapter: {}", name);

        // Load wintun.dll
        let wintun = unsafe { wintun::load() }.map_err(|e| {
            VpnError::Tun(TunError::OpenFailed)
        })?;

        // Create or open the adapter
        let adapter = match Adapter::open(&wintun, name) {
            Ok(adapter) => {
                log::info!("Opened existing adapter: {}", name);
                adapter
            }
            Err(_) => {
                log::info!("Creating new adapter: {}", name);
                Adapter::create(&wintun, name, "2cha VPN", None).map_err(|e| {
                    log::error!("Failed to create adapter: {:?}", e);
                    VpnError::Tun(TunError::PermissionDenied)
                })?
            }
        };

        // Start a session
        let session = adapter.start_session(WINTUN_RING_CAPACITY).map_err(|e| {
            log::error!("Failed to start session: {:?}", e);
            VpnError::Tun(TunError::IoctlFailed("start_session failed".into()))
        })?;

        log::info!("WinTun adapter created: {}", name);

        Ok(TunDevice {
            adapter,
            session: Arc::new(session),
            name: name.to_string(),
            mtu: 1500,
            ipv4_addr: None,
            ipv6_addr: None,
        })
    }

    /// Get device name
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get configured MTU
    #[inline]
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Get IPv4 address if set
    #[inline]
    pub fn ipv4_addr(&self) -> Option<Ipv4Addr> {
        self.ipv4_addr
    }

    /// Get IPv6 address if set
    #[inline]
    pub fn ipv6_addr(&self) -> Option<Ipv6Addr> {
        self.ipv6_addr
    }

    /// Set IPv4 address using netsh
    pub fn set_ipv4_address(&mut self, addr: Ipv4Addr, prefix: u8) -> Result<()> {
        log::info!("Setting IPv4 address: {}/{}", addr, prefix);

        let mask = crate::config::prefix_to_netmask_v4(prefix);
        let mask_str = format!("{}.{}.{}.{}", mask[0], mask[1], mask[2], mask[3]);

        let output = std::process::Command::new("netsh")
            .args([
                "interface", "ip", "set", "address",
                &format!("name={}", self.name),
                "static", &addr.to_string(), &mask_str,
            ])
            .output()?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            // Try alternative method
            let output2 = std::process::Command::new("netsh")
                .args([
                    "interface", "ipv4", "set", "address",
                    &format!("name={}", self.name),
                    "static", &addr.to_string(), &mask_str,
                ])
                .output()?;

            if !output2.status.success() {
                log::warn!("netsh set address warning: {}", err);
            }
        }

        self.ipv4_addr = Some(addr);
        Ok(())
    }

    /// Set IPv6 address using netsh
    pub fn set_ipv6_address(&mut self, addr: Ipv6Addr, prefix: u8) -> Result<()> {
        log::info!("Setting IPv6 address: {}/{}", addr, prefix);

        let output = std::process::Command::new("netsh")
            .args([
                "interface", "ipv6", "add", "address",
                &format!("interface={}", self.name),
                &format!("address={}/{}", addr, prefix),
            ])
            .output()?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            if !err.contains("already exists") {
                log::warn!("netsh add address warning: {}", err);
            }
        }

        self.ipv6_addr = Some(addr);
        Ok(())
    }

    /// Set MTU
    pub fn set_mtu(&mut self, mtu: u16) -> Result<()> {
        log::debug!("Setting MTU: {}", mtu);

        let output = std::process::Command::new("netsh")
            .args([
                "interface", "ipv4", "set", "subinterface",
                &self.name, &format!("mtu={}", mtu), "store=persistent",
            ])
            .output()?;

        if !output.status.success() {
            log::warn!("Failed to set MTU via netsh, continuing anyway");
        }

        self.mtu = mtu;
        Ok(())
    }

    /// Bring up the interface (Windows handles this automatically)
    pub fn bring_up(&self) -> Result<()> {
        log::info!("Interface {} is UP", self.name);
        // WinTun adapter is automatically enabled when created
        Ok(())
    }

    /// Read packet from TUN
    #[inline]
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self.session.try_receive() {
            Ok(Some(packet)) => {
                let data = packet.bytes();
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                log::trace!("TUN read: {} bytes", len);
                Ok(len)
            }
            Ok(None) => Ok(0),
            Err(e) => {
                log::error!("TUN read error: {:?}", e);
                Err(VpnError::Tun(TunError::ReadFailed))
            }
        }
    }

    /// Write packet to TUN
    #[inline]
    pub fn write(&mut self, buf: &[u8]) -> Result<usize> {
        match self.session.allocate_send_packet(buf.len() as u16) {
            Ok(mut packet) => {
                packet.bytes_mut().copy_from_slice(buf);
                self.session.send_packet(packet);
                log::trace!("TUN write: {} bytes", buf.len());
                Ok(buf.len())
            }
            Err(e) => {
                log::error!("TUN write error: {:?}", e);
                Err(VpnError::Tun(TunError::WriteFailed))
            }
        }
    }

    /// Read multiple packets (batch read for performance)
    pub fn read_batch(&mut self, buffers: &mut [&mut [u8]]) -> Result<Vec<usize>> {
        let mut sizes = Vec::with_capacity(buffers.len());

        for buf in buffers {
            match self.read(buf) {
                Ok(n) if n > 0 => sizes.push(n),
                Ok(_) => break,
                Err(_) => break,
            }
        }

        Ok(sizes)
    }

    /// Set non-blocking mode (WinTun is always non-blocking with try_receive)
    pub fn set_nonblocking(&self, _nonblocking: bool) -> Result<()> {
        // WinTun session uses try_receive which is inherently non-blocking
        Ok(())
    }

    /// Get read event handle for waiting
    pub fn get_read_wait_event(&self) -> windows::Win32::Foundation::HANDLE {
        self.session.get_read_wait_event()
            .map(|h| windows::Win32::Foundation::HANDLE(h as *mut std::ffi::c_void))
            .unwrap_or(windows::Win32::Foundation::HANDLE::default())
    }
}

// =============================================================================
// IP PACKET HELPERS
// =============================================================================

/// IP packet version detection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
    Unknown,
}

impl IpVersion {
    /// Detect IP version from packet
    #[inline]
    pub fn from_packet(data: &[u8]) -> Self {
        if data.is_empty() {
            return IpVersion::Unknown;
        }
        match data[0] >> 4 {
            4 => IpVersion::V4,
            6 => IpVersion::V6,
            _ => IpVersion::Unknown,
        }
    }
}

/// Extract source IP from packet
#[allow(dead_code)]
pub fn get_source_ip(data: &[u8]) -> Option<std::net::IpAddr> {
    if data.len() < 20 {
        return None;
    }

    match IpVersion::from_packet(data) {
        IpVersion::V4 => {
            let src = [data[12], data[13], data[14], data[15]];
            Some(std::net::IpAddr::V4(Ipv4Addr::from(src)))
        }
        IpVersion::V6 if data.len() >= 40 => {
            let mut src = [0u8; 16];
            src.copy_from_slice(&data[8..24]);
            Some(std::net::IpAddr::V6(Ipv6Addr::from(src)))
        }
        _ => None,
    }
}

/// Extract destination IP from packet
#[allow(dead_code)]
pub fn get_dest_ip(data: &[u8]) -> Option<std::net::IpAddr> {
    if data.len() < 20 {
        return None;
    }

    match IpVersion::from_packet(data) {
        IpVersion::V4 => {
            let dst = [data[16], data[17], data[18], data[19]];
            Some(std::net::IpAddr::V4(Ipv4Addr::from(dst)))
        }
        IpVersion::V6 if data.len() >= 40 => {
            let mut dst = [0u8; 16];
            dst.copy_from_slice(&data[24..40]);
            Some(std::net::IpAddr::V6(Ipv6Addr::from(dst)))
        }
        _ => None,
    }
}
