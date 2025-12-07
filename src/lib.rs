//! # 2cha - High-Performance VPN Utility
//!
//! A lightweight VPN implementation with:
//! - IPv4/IPv6 dual-stack support
//! - ChaCha20-Poly1305 or AES-256-GCM encryption
//! - Static binary support (musl)
//! - Full/split tunnel modes
//!
//! ## Architecture
//!
//! ```text
//! src/
//! ├── core/           # Platform-independent core
//! │   ├── config/     # Configuration handling
//! │   ├── crypto/     # Cryptographic primitives
//! │   ├── protocol/   # VPN protocol
//! │   └── error.rs    # Error types
//! ├── platform/       # Platform-specific implementations
//! │   ├── unix/       # Linux/macOS support
//! │   └── windows/    # Windows support
//! ├── vpn/            # VPN client and server
//! │   ├── client/     # Client implementation
//! │   └── server/     # Server implementation
//! └── cli/            # Command-line interface
//! ```

pub mod cli;
pub mod constants;
pub mod core;
pub mod platform;
pub mod vpn;

// Re-export commonly used types
pub use constants::*;
pub use core::config::{CipherSuite, ClientConfig, ConfigError, ServerConfig};
pub use core::crypto::{Aes256Gcm, ChaCha20, ChaCha20Poly1305, Cipher, Poly1305};
pub use core::error::{Result, VpnError};
pub use core::protocol::{Packet, PacketType};

// Platform-specific re-exports
#[cfg(unix)]
pub use platform::unix::{TunDevice, TunnelConfig, UdpTunnel};

#[cfg(windows)]
pub use platform::windows::{TunDevice, TunnelConfig, UdpTunnel};
