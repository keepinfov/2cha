//! # TUN Device Module
//!
//! ЛУЧШАЯ ПРАКТИКА: Низкоуровневая работа с ОС
//! TUN (tunnel) работает на уровне IP (Layer 3)
//! 
//! Ключевые системные вызовы:
//! - open("/dev/net/tun")
//! - ioctl(TUNSETIFF)
//! - read/write

use crate::error::{Result, TunError, VpnError};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};

// Linux ioctl константы (из linux/if_tun.h)
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const IFNAMSIZ: usize = 16;
const TUNSETIFF: libc::c_ulong = 0x400454ca;
const SIOCSIFMTU: libc::c_ulong = 0x8922;
const SIOCSIFADDR: libc::c_ulong = 0x8916;
const SIOCSIFNETMASK: libc::c_ulong = 0x891c;
const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
const SIOCSIFFLAGS: libc::c_ulong = 0x8914;
const IFF_UP: libc::c_short = 0x1;
const IFF_RUNNING: libc::c_short = 0x40;

// ЛУЧШАЯ ПРАКТИКА: repr(C) для C-совместимых структур
#[repr(C)]
struct IfReq {
    ifr_name: [libc::c_char; IFNAMSIZ],
    ifr_flags: libc::c_short,
    _pad: [u8; 22],
}

impl IfReq {
    fn new(name: &str, flags: libc::c_short) -> Result<Self> {
        if name.len() >= IFNAMSIZ {
            return Err(TunError::InvalidName(format!("Name too long: {}", name.len())).into());
        }
        let mut ifr = IfReq { ifr_name: [0; IFNAMSIZ], ifr_flags: flags, _pad: [0; 22] };
        for (i, byte) in name.bytes().enumerate() {
            ifr.ifr_name[i] = byte as libc::c_char;
        }
        Ok(ifr)
    }
}

#[repr(C)]
struct SockAddrIn {
    sin_family: libc::sa_family_t,
    sin_port: u16,
    sin_addr: libc::in_addr,
    sin_zero: [u8; 8],
}

#[repr(C)]
struct IfReqAddr {
    ifr_name: [libc::c_char; IFNAMSIZ],
    ifr_addr: SockAddrIn,
}

impl IfReqAddr {
    fn new(name: &str, addr: [u8; 4]) -> Result<Self> {
        if name.len() >= IFNAMSIZ {
            return Err(TunError::InvalidName(name.to_string()).into());
        }
        let mut ifr = IfReqAddr {
            ifr_name: [0; IFNAMSIZ],
            ifr_addr: SockAddrIn {
                sin_family: libc::AF_INET as u16,
                sin_port: 0,
                sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(addr) },
                sin_zero: [0; 8],
            },
        };
        for (i, byte) in name.bytes().enumerate() {
            ifr.ifr_name[i] = byte as libc::c_char;
        }
        Ok(ifr)
    }
}

#[repr(C)]
struct IfReqMtu {
    ifr_name: [libc::c_char; IFNAMSIZ],
    ifr_mtu: libc::c_int,
    _pad: [u8; 20],
}

impl IfReqMtu {
    fn new(name: &str, mtu: i32) -> Result<Self> {
        if name.len() >= IFNAMSIZ {
            return Err(TunError::InvalidName(name.to_string()).into());
        }
        let mut ifr = IfReqMtu { ifr_name: [0; IFNAMSIZ], ifr_mtu: mtu, _pad: [0; 20] };
        for (i, byte) in name.bytes().enumerate() {
            ifr.ifr_name[i] = byte as libc::c_char;
        }
        Ok(ifr)
    }
}

#[repr(C)]
struct IfReqFlags {
    ifr_name: [libc::c_char; IFNAMSIZ],
    ifr_flags: libc::c_short,
    _pad: [u8; 22],
}

impl IfReqFlags {
    fn new(name: &str) -> Result<Self> {
        if name.len() >= IFNAMSIZ {
            return Err(TunError::InvalidName(name.to_string()).into());
        }
        let mut ifr = IfReqFlags { ifr_name: [0; IFNAMSIZ], ifr_flags: 0, _pad: [0; 22] };
        for (i, byte) in name.bytes().enumerate() {
            ifr.ifr_name[i] = byte as libc::c_char;
        }
        Ok(ifr)
    }
}

// ЛУЧШАЯ ПРАКТИКА: RAII для системных ресурсов
/// TUN устройство для чтения/записи IP пакетов
pub struct TunDevice {
    file: File,
    name: String,
}

impl TunDevice {
    /// Создаёт TUN устройство. Требует root или CAP_NET_ADMIN
    pub fn create(name: &str) -> Result<Self> {
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

        let mut ifr = IfReq::new(name, IFF_TUN | IFF_NO_PI)?;
        
        // SAFETY: ifr правильно инициализирована
        let result = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &mut ifr) };
        if result < 0 {
            let errno = std::io::Error::last_os_error();
            return Err(TunError::IoctlFailed(format!("TUNSETIFF: {}", errno)).into());
        }

        let actual_name = ifr.ifr_name.iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8 as char)
            .collect::<String>();

        log::info!("TUN device created: {}", actual_name);
        Ok(TunDevice { file, name: actual_name })
    }

    pub fn name(&self) -> &str { &self.name }
    pub fn fd(&self) -> RawFd { self.file.as_raw_fd() }

    pub fn set_address(&self, addr: [u8; 4]) -> Result<()> {
        log::debug!("Setting address: {}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);
        let ifr = IfReqAddr::new(&self.name, addr)?;
        self.ioctl_with_socket(SIOCSIFADDR, &ifr, "SIOCSIFADDR")
    }

    pub fn set_netmask(&self, mask: [u8; 4]) -> Result<()> {
        log::debug!("Setting netmask: {}.{}.{}.{}", mask[0], mask[1], mask[2], mask[3]);
        let ifr = IfReqAddr::new(&self.name, mask)?;
        self.ioctl_with_socket(SIOCSIFNETMASK, &ifr, "SIOCSIFNETMASK")
    }

    pub fn set_mtu(&self, mtu: u16) -> Result<()> {
        log::debug!("Setting MTU: {}", mtu);
        let ifr = IfReqMtu::new(&self.name, mtu as i32)?;
        self.ioctl_with_socket(SIOCSIFMTU, &ifr, "SIOCSIFMTU")
    }

    pub fn bring_up(&self) -> Result<()> {
        log::info!("Bringing up interface: {}", self.name);
        let mut ifr = IfReqFlags::new(&self.name)?;
        let sock = self.create_ioctl_socket()?;

        let result = unsafe { libc::ioctl(sock, SIOCGIFFLAGS, &mut ifr) };
        if result < 0 {
            unsafe { libc::close(sock) };
            return Err(TunError::IoctlFailed("SIOCGIFFLAGS failed".into()).into());
        }

        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        let result = unsafe { libc::ioctl(sock, SIOCSIFFLAGS, &ifr) };
        unsafe { libc::close(sock) };

        if result < 0 {
            return Err(TunError::IoctlFailed(format!("SIOCSIFFLAGS: {}", std::io::Error::last_os_error())).into());
        }
        Ok(())
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let n = self.file.read(buf)?;
        log::trace!("TUN read: {} bytes", n);
        Ok(n)
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let n = self.file.write(buf)?;
        log::trace!("TUN write: {} bytes", n);
        Ok(n)
    }

    fn ioctl_with_socket<T>(&self, request: libc::c_ulong, arg: &T, name: &str) -> Result<()> {
        let sock = self.create_ioctl_socket()?;
        let result = unsafe { libc::ioctl(sock, request, arg) };
        unsafe { libc::close(sock) };
        if result < 0 {
            return Err(TunError::IoctlFailed(format!("{}: {}", name, std::io::Error::last_os_error())).into());
        }
        Ok(())
    }

    fn create_ioctl_socket(&self) -> Result<RawFd> {
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 {
            return Err(TunError::IoctlFailed("Failed to create socket".into()).into());
        }
        Ok(sock)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        let flags = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 { return Err(std::io::Error::last_os_error().into()); }
        
        let new_flags = if nonblocking { flags | libc::O_NONBLOCK } else { flags & !libc::O_NONBLOCK };
        let result = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_SETFL, new_flags) };
        if result < 0 { return Err(std::io::Error::last_os_error().into()); }
        Ok(())
    }
}

impl AsRawFd for TunDevice {
    fn as_raw_fd(&self) -> RawFd { self.file.as_raw_fd() }
}
