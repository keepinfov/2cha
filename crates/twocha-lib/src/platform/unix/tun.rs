//! # TUN Device Module (Unix)
//!
//! Cross-platform TUN device with IPv4/IPv6 support, backed by the `tun-rs`
//! crate. This replaces the previous hand-rolled `libc::ioctl` implementation;
//! the public `TunDevice` API is preserved so callers are unchanged.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(target_os = "linux")]
use std::sync::Mutex;
use tun_rs::SyncDevice;
// GSO/GRO offload (virtio-net header) is Linux-only and never available on
// Android (the VpnService owns the interface and 2cha only wraps its fd, so
// IFF_VNET_HDR can't be set). `target_os = "linux"` already excludes Android.
#[cfg(target_os = "linux")]
use tun_rs::{IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};
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

/// Staging state for offloaded (GSO/GRO) reads. When the device carries an
/// `IFF_VNET_HDR`, a single `recv` may return one large TSO super-segment that
/// `recv_multiple` splits into a burst of MTU-sized inner packets. We read one
/// burst per syscall into this buffer and dispense the packets one-by-one so
/// the per-packet `read` API (and every datapath call site) stays unchanged.
#[cfg(target_os = "linux")]
struct ReadBatch {
    /// Raw receive staging (virtio header + up to a 64 KiB super-segment).
    scratch: Vec<u8>,
    /// Split inner packets, `bufs[i][..sizes[i]]`.
    bufs: Vec<Vec<u8>>,
    sizes: Vec<usize>,
    /// Number of valid packets currently staged and the next one to dispense.
    n: usize,
    pos: usize,
}

#[cfg(target_os = "linux")]
impl ReadBatch {
    fn new(mtu: u16) -> Self {
        // Split segments never exceed the device MTU; size each slot to the MTU
        // plus the virtio header and a little slack. (`recv_multiple` writes the
        // packet at offset 0 here — the header stays in `scratch`.)
        let per = (mtu as usize).max(1500) + VIRTIO_NET_HDR_LEN + 64;
        ReadBatch {
            scratch: vec![0u8; VIRTIO_NET_HDR_LEN + 65535],
            bufs: vec![vec![0u8; per]; IDEAL_BATCH_SIZE],
            sizes: vec![0usize; IDEAL_BATCH_SIZE],
            n: 0,
            pos: 0,
        }
    }
}

/// Cross-platform TUN device with IPv4/IPv6 support.
pub struct TunDevice {
    dev: SyncDevice,
    name: String,
    mtu: u16,
    ipv4_addr: Option<Ipv4Addr>,
    ipv6_addr: Option<Ipv6Addr>,
    /// Whether GSO/GRO offload (virtio-net header) is active on this device.
    /// When true, every `read`/`write` transparently handles the virtio header.
    /// Always false off Linux and on externally-provided fds (Android).
    offload: bool,
    /// Lazily-allocated read staging, used only when `offload` is true. Behind a
    /// `Mutex` because `read` takes `&self` (the data plane shares the device
    /// via an `Arc`); a given queue is only read by one thread, so this is
    /// uncontended in practice.
    #[cfg(target_os = "linux")]
    read_batch: Mutex<Option<ReadBatch>>,
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

        // On Linux, prefer a device with GSO/GRO offload (virtio-net header):
        // the kernel then hands us large TSO super-segments to split on read and
        // coalesces our MTU packets on write, collapsing per-packet syscalls.
        // If the kernel rejects offload (e.g. very old), fall back to a plain
        // device. The build is retried because `DeviceBuilder` is consumed.
        #[cfg(target_os = "linux")]
        let (dev, offload) = {
            let build = |offload: bool| {
                DeviceBuilder::new()
                    .name(name)
                    .enable(false)
                    .multi_queue(multi_queue)
                    .offload(offload)
                    .build_sync()
            };
            // Escape hatch (ops / testing): force the portable per-packet path,
            // e.g. to sidestep a misbehaving kernel or to reproduce the fallback.
            if std::env::var_os("TWOCHA_NO_TUN_OFFLOAD").is_some() {
                log::info!("TWOCHA_NO_TUN_OFFLOAD set; TUN offload disabled");
                (build(false).map_err(map_io)?, false)
            } else {
                match build(true) {
                    Ok(dev) => {
                        let on = dev.tcp_gso();
                        if !on {
                            log::info!("TUN offload requested but not negotiated; per-packet I/O");
                        }
                        (dev, on)
                    }
                    Err(e) => {
                        log::info!("TUN offload unavailable ({e}); retrying without it");
                        (build(false).map_err(map_io)?, false)
                    }
                }
            }
        };
        #[cfg(not(target_os = "linux"))]
        let (dev, offload) = {
            let _ = multi_queue;
            (
                DeviceBuilder::new()
                    .name(name)
                    .enable(false)
                    .build_sync()
                    .map_err(map_io)?,
                false,
            )
        };

        let actual_name = dev.name().map_err(map_io)?;
        log::info!(
            "TUN device created: {} (offload: {})",
            actual_name,
            offload
        );

        Ok(TunDevice {
            dev,
            name: actual_name,
            mtu: 1500,
            ipv4_addr: None,
            ipv6_addr: None,
            offload,
            #[cfg(target_os = "linux")]
            read_batch: Mutex::new(None),
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
            // An externally-provided fd (Android VpnService) was attached
            // without IFF_VNET_HDR, which cannot be added after the fact.
            offload: false,
            #[cfg(target_os = "linux")]
            read_batch: Mutex::new(None),
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

    // I/O takes &self (tun-rs SyncDevice recv/send already do): the
    // multithreaded data plane reads and writes one device from two threads
    // behind an Arc.
    #[inline]
    pub fn read(&self, buf: &mut [u8]) -> Result<usize> {
        // With offload the fd carries an IFF_VNET_HDR and a single `recv` can
        // return a coalesced TSO super-segment; drain it through the batched
        // splitter and dispense one inner packet per call.
        #[cfg(target_os = "linux")]
        if self.offload {
            return self.read_offload(buf);
        }
        match self.dev.recv(buf) {
            Ok(n) => {
                log::trace!("TUN read: {} bytes", n);
                Ok(n)
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(e.into()),
        }
    }

    /// Dispense one inner packet from the offload read batch, refilling it with
    /// a single `recv_multiple` syscall when empty. Returns `Ok(0)` on
    /// would-block (batch drained and the fd has no more data).
    #[cfg(target_os = "linux")]
    fn read_offload(&self, buf: &mut [u8]) -> Result<usize> {
        let mut guard = self.read_batch.lock().expect("tun read_batch poisoned");
        let batch = guard.get_or_insert_with(|| ReadBatch::new(self.mtu));
        if batch.pos >= batch.n {
            // Offset 0: `recv_multiple` writes each split packet at the start of
            // its slot (the virtio header stays in `scratch`).
            let k = match self.dev.recv_multiple(
                &mut batch.scratch,
                &mut batch.bufs,
                &mut batch.sizes,
                0,
            ) {
                Ok(k) => k,
                Err(e) if e.kind() == ErrorKind::WouldBlock => 0,
                Err(e) => return Err(e.into()),
            };
            batch.n = k;
            batch.pos = 0;
            if k == 0 {
                return Ok(0);
            }
        }
        let i = batch.pos;
        let len = batch.sizes[i].min(buf.len());
        buf[..len].copy_from_slice(&batch.bufs[i][..len]);
        batch.pos += 1;
        log::trace!("TUN read (offload): {} bytes", len);
        Ok(len)
    }

    #[inline]
    pub fn write(&self, buf: &[u8]) -> Result<usize> {
        // With offload the fd expects every frame prefixed by a virtio-net
        // header. A zeroed header means GSO_NONE (a plain, un-segmented packet),
        // which is exactly what our decrypted inner IP packets are.
        #[cfg(target_os = "linux")]
        if self.offload {
            let total = VIRTIO_NET_HDR_LEN + buf.len();
            let mut stack = [0u8; VIRTIO_NET_HDR_LEN + 2048];
            if total <= stack.len() {
                stack[VIRTIO_NET_HDR_LEN..total].copy_from_slice(buf);
                self.dev.send(&stack[..total])?;
            } else {
                let mut framed = vec![0u8; total];
                framed[VIRTIO_NET_HDR_LEN..].copy_from_slice(buf);
                self.dev.send(&framed)?;
            }
            log::trace!("TUN write (offload): {} bytes", buf.len());
            return Ok(buf.len());
        }
        let n = self.dev.send(buf)?;
        log::trace!("TUN write: {} bytes", n);
        Ok(n)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        self.dev.set_nonblocking(nonblocking).map_err(map_io)
    }

    /// Open another queue of a multi-queue TUN device (Linux). Requires the
    /// device to have been created with `multi_queue = true`; each clone is
    /// an independent fd the kernel hashes flows onto.
    #[cfg(target_os = "linux")]
    pub fn clone_queue(&self) -> Result<TunDevice> {
        // `try_clone` opens a new queue fd; tun-rs re-applies the virtio-net
        // header + TUNSETOFFLOAD on it, so the clone inherits offload state.
        let dev = self.dev.try_clone().map_err(map_io)?;
        Ok(TunDevice {
            dev,
            name: self.name.clone(),
            mtu: self.mtu,
            ipv4_addr: self.ipv4_addr,
            ipv6_addr: self.ipv6_addr,
            offload: self.offload,
            read_batch: Mutex::new(None),
        })
    }

    /// Whether GSO/GRO offload (transparent virtio-header handling) is active.
    #[inline]
    pub fn offload_active(&self) -> bool {
        self.offload
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
