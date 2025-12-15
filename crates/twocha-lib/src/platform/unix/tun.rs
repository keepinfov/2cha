//! # TUN Device Module (Unix)
//!
//! High-performance TUN device with IPv4/IPv6 support.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::io::{AsRawFd, RawFd};
use twocha_core::prefix_to_netmask_v4;
use twocha_protocol::{Result, TunError, VpnError};

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

const IFNAMSIZ: usize = 16;
const IFF_TUN: i16 = 0x0001;
const IFF_NO_PI: i16 = 0x1000;
const IFF_MULTI_QUEUE: i16 = 0x0100;

const TUNSETIFF: u32 = 0x400454ca;
const SIOCSIFMTU: u32 = 0x8922;
const SIOCSIFADDR: u32 = 0x8916;
const SIOCSIFNETMASK: u32 = 0x891c;
const SIOCGIFFLAGS: u32 = 0x8913;
const SIOCSIFFLAGS: u32 = 0x8914;
const SIOCGIFINDEX: u32 = 0x8933;

const IFF_UP: libc::c_short = 0x1;
const IFF_RUNNING: libc::c_short = 0x40;
const AF_INET: libc::sa_family_t = libc::AF_INET as libc::sa_family_t;

// ═══════════════════════════════════════════════════════════════════════════
// IOCTL WRAPPER
// ═══════════════════════════════════════════════════════════════════════════

#[inline]
unsafe fn ioctl_raw(fd: libc::c_int, request: u32, arg: *mut libc::c_void) -> libc::c_int {
    #[cfg(target_os = "linux")]
    {
        libc::ioctl(fd, request as libc::Ioctl, arg)
    }
    #[cfg(target_os = "macos")]
    {
        libc::ioctl(fd, request as libc::c_ulong, arg)
    }
    #[cfg(target_os = "android")]
    {
        libc::ioctl(fd, request as libc::c_int, arg)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "android")))]
    {
        libc::ioctl(fd, request as libc::c_ulong, arg)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// IOCTL STRUCTURES
// ═══════════════════════════════════════════════════════════════════════════

#[repr(C)]
struct IfReqFlags {
    ifr_name: [u8; IFNAMSIZ],
    ifr_flags: libc::c_short,
    _pad: [u8; 22],
}

impl IfReqFlags {
    fn new(name: &str) -> Result<Self> {
        if name.len() >= IFNAMSIZ {
            return Err(TunError::InvalidName(format!("Name too long: {}", name.len())).into());
        }
        let mut ifr = IfReqFlags {
            ifr_name: [0; IFNAMSIZ],
            ifr_flags: 0,
            _pad: [0; 22],
        };
        ifr.ifr_name[..name.len()].copy_from_slice(name.as_bytes());
        Ok(ifr)
    }
}

#[repr(C)]
struct IfReqMtu {
    ifr_name: [u8; IFNAMSIZ],
    ifr_mtu: libc::c_int,
    _pad: [u8; 20],
}

impl IfReqMtu {
    fn new(name: &str, mtu: i32) -> Result<Self> {
        if name.len() >= IFNAMSIZ {
            return Err(TunError::InvalidName(name.to_string()).into());
        }
        let mut ifr = IfReqMtu {
            ifr_name: [0; IFNAMSIZ],
            ifr_mtu: mtu,
            _pad: [0; 20],
        };
        ifr.ifr_name[..name.len()].copy_from_slice(name.as_bytes());
        Ok(ifr)
    }
}

#[repr(C)]
struct SockAddrIn {
    sin_family: libc::sa_family_t,
    sin_port: u16,
    sin_addr: [u8; 4],
    sin_zero: [u8; 8],
}

#[repr(C)]
struct IfReqAddr4 {
    ifr_name: [u8; IFNAMSIZ],
    ifr_addr: SockAddrIn,
}

impl IfReqAddr4 {
    fn new(name: &str, addr: [u8; 4]) -> Result<Self> {
        if name.len() >= IFNAMSIZ {
            return Err(TunError::InvalidName(name.to_string()).into());
        }
        let mut ifr = IfReqAddr4 {
            ifr_name: [0; IFNAMSIZ],
            ifr_addr: SockAddrIn {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: addr,
                sin_zero: [0; 8],
            },
        };
        ifr.ifr_name[..name.len()].copy_from_slice(name.as_bytes());
        Ok(ifr)
    }
}

#[repr(C)]
struct In6IfReq {
    ifr6_addr: [u8; 16],
    ifr6_prefixlen: u32,
    ifr6_ifindex: libc::c_int,
}

// ═══════════════════════════════════════════════════════════════════════════
// TUN DEVICE
// ═══════════════════════════════════════════════════════════════════════════

/// High-performance TUN device with IPv4/IPv6 support
pub struct TunDevice {
    file: File,
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
    pub fn create_with_options(name: &str, multi_queue: bool) -> Result<Self> {
        log::info!("Creating TUN device: {}", name);

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    VpnError::Tun(TunError::PermissionDenied)
                } else {
                    VpnError::Tun(TunError::OpenFailed)
                }
            })?;

        let mut flags = IFF_TUN | IFF_NO_PI;
        if multi_queue {
            flags |= IFF_MULTI_QUEUE;
        }

        #[repr(C)]
        struct IfReqTun {
            ifr_name: [u8; IFNAMSIZ],
            ifr_flags: i16,
            _pad: [u8; 22],
        }

        let mut ifr = IfReqTun {
            ifr_name: [0; IFNAMSIZ],
            ifr_flags: flags,
            _pad: [0; 22],
        };

        let name_len = name.len().min(IFNAMSIZ - 1);
        ifr.ifr_name[..name_len].copy_from_slice(&name.as_bytes()[..name_len]);

        let result = unsafe {
            ioctl_raw(
                file.as_raw_fd(),
                TUNSETIFF,
                &mut ifr as *mut _ as *mut libc::c_void,
            )
        };
        if result < 0 {
            let errno = std::io::Error::last_os_error();
            return Err(TunError::IoctlFailed(format!("TUNSETIFF: {}", errno)).into());
        }

        let actual_name = ifr
            .ifr_name
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as char)
            .collect::<String>();

        log::info!("TUN device created: {}", actual_name);

        Ok(TunDevice {
            file,
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
    pub fn fd(&self) -> RawFd {
        self.file.as_raw_fd()
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

        let addr_bytes = addr.octets();
        let ifr = IfReqAddr4::new(&self.name, addr_bytes)?;
        self.ioctl_with_socket(AF_INET, SIOCSIFADDR, &ifr, "SIOCSIFADDR")?;

        let mask = prefix_to_netmask_v4(prefix);
        let ifr_mask = IfReqAddr4::new(&self.name, mask)?;
        self.ioctl_with_socket(AF_INET, SIOCSIFNETMASK, &ifr_mask, "SIOCSIFNETMASK")?;

        self.ipv4_addr = Some(addr);
        Ok(())
    }

    pub fn set_ipv6_address(&mut self, addr: Ipv6Addr, prefix: u8) -> Result<()> {
        log::info!("Setting IPv6 address: {}/{}", addr, prefix);

        let ifindex = self.get_ifindex()?;

        let ifr6 = In6IfReq {
            ifr6_addr: addr.octets(),
            ifr6_prefixlen: prefix as u32,
            ifr6_ifindex: ifindex,
        };

        const SIOCSIFADDR_IN6: u32 = 0x8916;

        let sock = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
        if sock < 0 {
            return Err(TunError::IoctlFailed("Failed to create IPv6 socket".into()).into());
        }

        let result = unsafe {
            ioctl_raw(
                sock,
                SIOCSIFADDR_IN6,
                &ifr6 as *const _ as *mut libc::c_void,
            )
        };
        unsafe { libc::close(sock) };

        if result < 0 {
            log::debug!("ioctl failed, using ip command");
            let addr_str = format!("{}/{}", addr, prefix);
            let output = std::process::Command::new("ip")
                .args(["-6", "addr", "add", &addr_str, "dev", &self.name])
                .output()?;

            if !output.status.success() {
                let err = String::from_utf8_lossy(&output.stderr);
                if !err.contains("File exists") {
                    return Err(TunError::IoctlFailed(format!("ip -6 addr add: {}", err)).into());
                }
            }
        }

        self.ipv6_addr = Some(addr);
        Ok(())
    }

    pub fn set_mtu(&mut self, mtu: u16) -> Result<()> {
        log::debug!("Setting MTU: {}", mtu);
        let ifr = IfReqMtu::new(&self.name, mtu as i32)?;
        self.ioctl_with_socket(AF_INET, SIOCSIFMTU, &ifr, "SIOCSIFMTU")?;
        self.mtu = mtu;
        Ok(())
    }

    pub fn bring_up(&self) -> Result<()> {
        log::info!("Bringing up interface: {}", self.name);

        let mut ifr = IfReqFlags::new(&self.name)?;
        let sock = self.create_socket(AF_INET)?;

        let result =
            unsafe { ioctl_raw(sock, SIOCGIFFLAGS, &mut ifr as *mut _ as *mut libc::c_void) };
        if result < 0 {
            unsafe { libc::close(sock) };
            return Err(TunError::IoctlFailed("SIOCGIFFLAGS failed".into()).into());
        }

        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

        let result =
            unsafe { ioctl_raw(sock, SIOCSIFFLAGS, &ifr as *const _ as *mut libc::c_void) };
        unsafe { libc::close(sock) };

        if result < 0 {
            let err = std::io::Error::last_os_error();
            return Err(TunError::IoctlFailed(format!("SIOCSIFFLAGS: {}", err)).into());
        }

        log::info!("Interface {} is UP", self.name);
        Ok(())
    }

    #[inline]
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self.file.read(buf) {
            Ok(n) => {
                log::trace!("TUN read: {} bytes", n);
                Ok(n)
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(e.into()),
        }
    }

    #[inline]
    pub fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let n = self.file.write(buf)?;
        log::trace!("TUN write: {} bytes", n);
        Ok(n)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        let flags = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        let new_flags = if nonblocking {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };

        let result = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_SETFL, new_flags) };
        if result < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        Ok(())
    }

    fn get_ifindex(&self) -> Result<libc::c_int> {
        #[repr(C)]
        struct IfReqIndex {
            ifr_name: [u8; IFNAMSIZ],
            ifr_ifindex: libc::c_int,
            _pad: [u8; 20],
        }

        let mut ifr = IfReqIndex {
            ifr_name: [0; IFNAMSIZ],
            ifr_ifindex: 0,
            _pad: [0; 20],
        };
        ifr.ifr_name[..self.name.len()].copy_from_slice(self.name.as_bytes());

        let sock = self.create_socket(AF_INET)?;

        let result =
            unsafe { ioctl_raw(sock, SIOCGIFINDEX, &mut ifr as *mut _ as *mut libc::c_void) };
        unsafe { libc::close(sock) };

        if result < 0 {
            return Err(TunError::IoctlFailed("SIOCGIFINDEX failed".into()).into());
        }

        Ok(ifr.ifr_ifindex)
    }

    fn ioctl_with_socket<T>(
        &self,
        family: libc::sa_family_t,
        request: u32,
        arg: &T,
        name: &str,
    ) -> Result<()> {
        let sock = self.create_socket(family)?;
        let result = unsafe { ioctl_raw(sock, request, arg as *const T as *mut libc::c_void) };
        unsafe { libc::close(sock) };

        if result < 0 {
            let err = std::io::Error::last_os_error();
            return Err(TunError::IoctlFailed(format!("{}: {}", name, err)).into());
        }
        Ok(())
    }

    fn create_socket(&self, family: libc::sa_family_t) -> Result<RawFd> {
        let sock = unsafe { libc::socket(family as libc::c_int, libc::SOCK_DGRAM, 0) };
        if sock < 0 {
            return Err(TunError::IoctlFailed("Failed to create socket".into()).into());
        }
        Ok(sock)
    }
}

impl AsRawFd for TunDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
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
