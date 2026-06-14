# Windows Support — Status and Remaining Work

## Current state

- **TUN device: implemented.** `crates/twocha-lib/src/platform/windows/tun.rs` is a real
  WinTun-backed device via the `tun-rs` crate (which loads `wintun.dll`). Its public
  `TunDevice` API mirrors the Unix implementation (`create`/`set_ipv4_address`/
  `set_ipv6_address`/`set_mtu`/`bring_up`/`read`/`write`/`set_nonblocking`), so the higher
  layers stay platform-agnostic. Requires `wintun.dll` present and Administrator privileges.
- **Dependency graph: Windows-clean.** `neli` (Linux/Unix netlink) is gated to
  `cfg(unix)` in `crates/twocha-lib/Cargo.toml`, so it is not pulled into a Windows build.
  `tun-rs` is cross-platform and stays ungated.

## Not yet working on Windows (remaining work)

The VPN does **not** yet run on Windows. The client/server handlers
(`crates/twocha-lib/src/vpn/{client,server}/handler.rs`) are written directly against the
Unix stack and are not platform-gated:

- They `use crate::platform::unix::{...}` (`EventLoop`, `POLLIN`, `BatchBuffer`, `UdpTunnel`,
  raw `fd()`) and the `#[cfg(unix)] transport` module.
- The event loop is built on `poll(2)`. WinTun does **not** expose a pollable file
  descriptor — it provides a read-wait event HANDLE — so there is no drop-in fd to feed
  into the existing loop.

To make Windows fully operational, the following are required (all currently unverifiable
in CI without a Windows host / cross-compile toolchain, so they are deferred):

1. **Gate or port the handlers.** Mark the current handlers `#[cfg(unix)]`, or extract the
   transport-neutral logic and provide Windows handlers. `lib.rs` re-exports
   (`pub use vpn::{client, server}`) must stay consistent per target.
2. **Windows event loop.** A WSAPoll-based loop (or IOCP) that waits on the UDP/TCP socket
   handles *and* the WinTun read-wait HANDLE, replacing the `poll(2)` `EventLoop`.
3. **Windows routing.** Implement `platform/windows/routing.rs` against `netsh` and/or the
   IP Helper API (route add/delete, default-gateway pinning, DNS), mirroring the Unix
   netlink path in `platform/unix/{netlink.rs, routing.rs}`.

## Verification gap

This work was authored without a Windows build or test environment available. The TUN
implementation reuses the exact cross-platform `tun-rs` API that the (verified) Unix path
compiles against, but it has **not** been compiled or run on Windows. Treat the Windows
target as untested until built and exercised on a real Windows host with `wintun.dll`.
