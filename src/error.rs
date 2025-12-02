//! # Error Module
//!
//! Unified error handling for the VPN.

use std::fmt;
use std::io;

#[derive(Debug)]
pub enum VpnError {
    Io(io::Error),
    Tun(TunError),
    Crypto(CryptoError),
    Protocol(ProtocolError),
    Network(NetworkError),
    Config(String),
}

#[derive(Debug)]
pub enum TunError {
    OpenFailed,
    IoctlFailed(String),
    DeviceNotFound(String),
    PermissionDenied,
    InvalidName(String),
}

#[derive(Debug)]
pub enum CryptoError {
    InvalidKeyLength { expected: usize, got: usize },
    InvalidNonceLength { expected: usize, got: usize },
    AuthenticationFailed,
    NonceReuse,
    DataTooLarge,
}

#[derive(Debug)]
pub enum ProtocolError {
    InvalidVersion { expected: u8, got: u8 },
    InvalidPacketType(u8),
    PacketTooSmall { min: usize, got: usize },
    PacketTooLarge { max: usize, got: usize },
    CorruptedPacket(String),
    UnexpectedPacket(String),
}

#[derive(Debug)]
pub enum NetworkError {
    SocketCreationFailed,
    BindFailed(String),
    ConnectionClosed,
    Timeout,
    HostUnreachable(String),
    WouldBlock,
}

impl std::error::Error for VpnError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VpnError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for VpnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VpnError::Io(e) => write!(f, "I/O error: {}", e),
            VpnError::Tun(e) => write!(f, "TUN error: {:?}", e),
            VpnError::Crypto(e) => write!(f, "Crypto error: {:?}", e),
            VpnError::Protocol(e) => write!(f, "Protocol error: {:?}", e),
            VpnError::Network(e) => write!(f, "Network error: {:?}", e),
            VpnError::Config(msg) => write!(f, "Config error: {}", msg),
        }
    }
}

impl From<io::Error> for VpnError {
    fn from(e: io::Error) -> Self {
        VpnError::Io(e)
    }
}

impl From<TunError> for VpnError {
    fn from(e: TunError) -> Self {
        VpnError::Tun(e)
    }
}

impl From<CryptoError> for VpnError {
    fn from(e: CryptoError) -> Self {
        VpnError::Crypto(e)
    }
}

impl From<ProtocolError> for VpnError {
    fn from(e: ProtocolError) -> Self {
        VpnError::Protocol(e)
    }
}

impl From<NetworkError> for VpnError {
    fn from(e: NetworkError) -> Self {
        VpnError::Network(e)
    }
}

pub type Result<T> = std::result::Result<T, VpnError>;
