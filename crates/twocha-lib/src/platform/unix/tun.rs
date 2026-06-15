//! # TUN Device Module (Unix)
//!
//! Cross-platform TUN device with IPv4/IPv6 support, backed by the `tun-rs`
//! crate. This replaces the previous hand-rolled `libc::ioctl` implementation;
//! the public `TunDevice` API is preserved so callers are unchanged.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::io::{AsRawFd, RawFd};
use tun_rs::SyncDevice;
// Device creation/configuration (DeviceBuilder, set address/mtu/up) is desktop
// only — on Android the VpnService creates and configures the interface, and we
// only wrap its fd via `from_fd`. The `tun-rs` Android backend doesn't expose
// these APIs at all.
#[cfg(not(target_os = "android"))]
use tun_rs::DeviceBuilder;
use twocha_protocol::{Result, TunError, VpnError};

fn map_io(e: std::io::Error) -> VpnError {
    if e.kind() == ErrorKind::PermissionDenied {
        VpnError::Tun(TunError::PermissionDenied)
    } else {
        VpnError::Tun(TunError::IoctlFailed(e.to_string()))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TUN DEVICE
// ═══════════════════════════════════════════════════════════════════════════

/// Cross-platform TUN device with IPv4/IPv6 support.
pub struct TunDevice {
    dev: SyncDevice,
    name: String,
    mtu: u16,
    ipv4_addr: Option<Ipv4Addr>,
    ipv6_addr: Option<Ipv6Addr>,
}

impl TunDevice {
    /// Create a new TUN device
    #[cfg(not(target_os = "android"))]
    pub fn create(name: &str) -> Result<Self> {
        Self::create_with_options(name, false)
    }

    /// Create a TUN device with options. The device is created but left
    /// unconfigured (down, no addresses); callers configure it via
    /// `set_ipv4_address`/`set_ipv6_address`/`set_mtu`/`bring_up`.
    #[cfg(not(target_os = "android"))]
    pub fn create_with_options(name: &str, multi_queue: bool) -> Result<Self> {
        log::info!("Creating TUN device: {}", name);

        let mut builder = DeviceBuilder::new().name(name).enable(false);

        #[cfg(target_os = "linux")]
        {
            builder = builder.multi_queue(multi_queue);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = multi_queue;
        }

        let dev = builder.build_sync().map_err(map_io)?;

        let actual_name = dev.name().map_err(map_io)?;
        log::info!("TUN device created: {}", actual_name);

        Ok(TunDevice {
            dev,
            name: actual_name,
            mtu: 1500,
            ipv4_addr: None,
            ipv6_addr: None,
        })
    }

    /// Wrap an externally-provided TUN file descriptor (e.g. the fd returned by
    /// Android `VpnService.Builder.establish()`).
    ///
    /// The caller has already configured addressing, routes, DNS and brought the
    /// interface up (the VpnService Builder owns the data plane on Android), so
    /// this performs no configuration — it only records the MTU for framing.
    ///
    /// # Ownership
    /// This takes ownership of `fd` and will close it when the `TunDevice` is
    /// dropped. Callers must pass a detached fd (Android: `pfd.detachFd()`); do
    /// not keep using the fd through its original owner afterwards.
    ///
    /// # Safety
    /// `fd` must be a valid, open TUN file descriptor.
    pub unsafe fn from_fd(fd: RawFd, mtu: u16) -> Result<Self> {
        let dev = SyncDevice::from_fd(fd).map_err(map_io)?;
        // `SyncDevice::name()` is unavailable on the Android tun-rs backend (the
        // VpnService owns the interface); the name is cosmetic here so default it.
        #[cfg(not(target_os = "android"))]
        let name = dev.name().unwrap_or_else(|_| "tun".to_string());
        #[cfg(target_os = "android")]
        let name = "tun".to_string();
        log::info!("Wrapped external TUN fd {} as {}", fd, name);
        Ok(TunDevice {
            dev,
            name,
            mtu,
            ipv4_addr: None,
            ipv6_addr: None,
        })
    }

    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[inline]
    pub fn fd(&self) -> RawFd {
        self.dev.as_raw_fd()
    }

    #[inline]
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    #[inline]
    pub fn ipv4_addr(&self) -> Option<Ipv4Addr> {
        self.ipv4_addr
    }

    #[inline]
    pub fn ipv6_addr(&self) -> Option<Ipv6Addr> {
        self.ipv6_addr
    }

    // Address/MTU/up configuration is desktop only; on Android the VpnService
    // Builder owns all of this before handing us the fd.
    #[cfg(not(target_os = "android"))]
    pub fn set_ipv4_address(&mut self, addr: Ipv4Addr, prefix: u8) -> Result<()> {
        log::info!("Setting IPv4 address: {}/{}", addr, prefix);
        self.dev
            .set_network_address(addr, prefix, None)
            .map_err(map_io)?;
        self.ipv4_addr = Some(addr);
        Ok(())
    }

    #[cfg(not(target_os = "android"))]
    pub fn set_ipv6_address(&mut self, addr: Ipv6Addr, prefix: u8) -> Result<()> {
        log::info!("Setting IPv6 address: {}/{}", addr, prefix);
        self.dev.add_address_v6(addr, prefix).map_err(map_io)?;
        self.ipv6_addr = Some(addr);
        Ok(())
    }

    #[cfg(not(target_os = "android"))]
    pub fn set_mtu(&mut self, mtu: u16) -> Result<()> {
        log::debug!("Setting MTU: {}", mtu);
        self.dev.set_mtu(mtu).map_err(map_io)?;
        self.mtu = mtu;
        Ok(())
    }

    #[cfg(not(target_os = "android"))]
    pub fn bring_up(&self) -> Result<()> {
        log::info!("Bringing up interface: {}", self.name);
        self.dev.enabled(true).map_err(map_io)?;
        log::info!("Interface {} is UP", self.name);
        Ok(())
    }

    #[inline]
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self.dev.recv(buf) {
            Ok(n) => {
                log::trace!("TUN read: {} bytes", n);
                Ok(n)
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(e.into()),
        }
    }

    #[inline]
    pub fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let n = self.dev.send(buf)?;
        log::trace!("TUN write: {} bytes", n);
        Ok(n)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        self.dev.set_nonblocking(nonblocking).map_err(map_io)
    }
}

impl AsRawFd for TunDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.dev.as_raw_fd()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// IP PACKET HELPERS
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
    Unknown,
}

impl IpVersion {
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
