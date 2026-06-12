//! # Windows TUN Device Module
//!
//! Windows TUN device backed by the `tun-rs` crate, which uses the WinTun
//! driver (`wintun.dll`) under the hood. This replaces the previous stub; the
//! public `TunDevice` API mirrors the Unix implementation so the higher layers
//! stay platform-agnostic.
//!
//! Note: WinTun requires `wintun.dll` to be present and the process to run with
//! Administrator privileges. Unlike Unix, WinTun does not expose a pollable
//! file descriptor — it provides a read-wait event HANDLE — so wiring the v4
//! client/server handlers (built around a `poll(2)` event loop) into a Windows
//! event loop (WSAPoll + the WinTun read-wait HANDLE) remains separate work.

#![cfg(windows)]

use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr};
use tun_rs::{DeviceBuilder, SyncDevice};
use twocha_protocol::{Result, TunError, VpnError};

fn map_io(e: std::io::Error) -> VpnError {
    if e.kind() == ErrorKind::PermissionDenied {
        VpnError::Tun(TunError::PermissionDenied)
    } else {
        VpnError::Tun(TunError::IoctlFailed(e.to_string()))
    }
}

/// IP version detection
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

/// Windows TUN device using the WinTun driver (via `tun-rs`).
pub struct TunDevice {
    dev: SyncDevice,
    name: String,
    mtu: u16,
    ipv4_addr: Option<Ipv4Addr>,
    ipv6_addr: Option<Ipv6Addr>,
}

impl TunDevice {
    pub fn create(name: &str) -> Result<Self> {
        Self::create_with_options(name, false)
    }

    /// Create a WinTun adapter, left unconfigured (no addresses); callers
    /// configure it via `set_ipv4_address`/`set_ipv6_address`/`set_mtu`.
    /// `multi_queue` has no effect on Windows (WinTun has no multi-queue mode).
    pub fn create_with_options(name: &str, _multi_queue: bool) -> Result<Self> {
        log::info!("Creating WinTun adapter: {}", name);

        let dev = DeviceBuilder::new()
            .name(name)
            .build_sync()
            .map_err(map_io)?;

        let actual_name = dev.name().map_err(map_io)?;
        log::info!("WinTun adapter created: {}", actual_name);

        Ok(TunDevice {
            dev,
            name: actual_name,
            mtu: 1500,
            ipv4_addr: None,
            ipv6_addr: None,
        })
    }

    #[inline]
    pub fn name(&self) -> &str {
        &self.name
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

    pub fn set_ipv4_address(&mut self, addr: Ipv4Addr, prefix: u8) -> Result<()> {
        log::info!("Setting IPv4 address: {}/{}", addr, prefix);
        self.dev
            .set_network_address(addr, prefix, None)
            .map_err(map_io)?;
        self.ipv4_addr = Some(addr);
        Ok(())
    }

    pub fn set_ipv6_address(&mut self, addr: Ipv6Addr, prefix: u8) -> Result<()> {
        log::info!("Setting IPv6 address: {}/{}", addr, prefix);
        self.dev.add_address_v6(addr, prefix).map_err(map_io)?;
        self.ipv6_addr = Some(addr);
        Ok(())
    }

    pub fn set_mtu(&mut self, mtu: u16) -> Result<()> {
        log::debug!("Setting MTU: {}", mtu);
        self.dev.set_mtu(mtu).map_err(map_io)?;
        self.mtu = mtu;
        Ok(())
    }

    pub fn bring_up(&self) -> Result<()> {
        // WinTun adapters are operational as soon as the session starts; there
        // is no separate "bring up" step as on Unix.
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
