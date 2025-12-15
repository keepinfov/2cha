//! # Key File Module
//!
//! Provides serialization and deserialization of .2cha-key files for protocol v4.
//!
//! Key file format:
//! ```text
//! ┌────────────────────────────────────────┐
//! │ Magic: "2CHA" (4 bytes)                │
//! │ Version: u8                            │
//! │ Key Type: u8 (0=ed25519, 1=symmetric)  │
//! │ Creation Time: u64 (Unix timestamp)    │
//! │ Private Key: [u8; 32]                  │
//! │ Public Key: [u8; 32] (or zeros)        │
//! │ Checksum: [u8; 4] (CRC32)              │
//! └────────────────────────────────────────┘
//! Total: 78 bytes
//! ```

use crate::crypto::{Ed25519KeyPair, Ed25519PublicKey};
use std::io::{Read, Write};
use std::fs::File;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use std::fmt;
use zeroize::Zeroizing;

/// Magic bytes for .2cha-key files
pub const KEY_FILE_MAGIC: &[u8; 4] = b"2CHA";

/// Current key file format version
pub const KEY_FILE_VERSION: u8 = 1;

/// Total size of key file in bytes
/// 4 (magic) + 1 (version) + 1 (type) + 8 (timestamp) + 32 (private) + 32 (public) + 4 (checksum)
pub const KEY_FILE_SIZE: usize = 82;

/// Key type identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyType {
    /// Ed25519 key pair (asymmetric, protocol v4)
    Ed25519 = 0,
    /// Symmetric key (legacy, protocol v3)
    Symmetric = 1,
}

impl KeyType {
    /// Create from byte value
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(KeyType::Ed25519),
            1 => Some(KeyType::Symmetric),
            _ => None,
        }
    }
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyType::Ed25519 => write!(f, "Ed25519"),
            KeyType::Symmetric => write!(f, "Symmetric"),
        }
    }
}

/// Error type for key file operations
#[derive(Debug)]
pub enum KeyFileError {
    /// I/O error
    Io(std::io::Error),
    /// Invalid magic bytes
    InvalidMagic,
    /// Unsupported version
    UnsupportedVersion { expected: u8, got: u8 },
    /// Unknown key type
    UnknownKeyType(u8),
    /// Checksum mismatch
    ChecksumMismatch { expected: u32, got: u32 },
    /// Invalid key data
    InvalidKeyData(String),
    /// File too small
    FileTooSmall { expected: usize, got: usize },
}

impl fmt::Display for KeyFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyFileError::Io(e) => write!(f, "I/O error: {}", e),
            KeyFileError::InvalidMagic => write!(f, "Invalid magic bytes (not a .2cha-key file)"),
            KeyFileError::UnsupportedVersion { expected, got } => {
                write!(f, "Unsupported key file version: expected {}, got {}", expected, got)
            }
            KeyFileError::UnknownKeyType(t) => write!(f, "Unknown key type: {}", t),
            KeyFileError::ChecksumMismatch { expected, got } => {
                write!(f, "Checksum mismatch: expected {:08x}, got {:08x}", expected, got)
            }
            KeyFileError::InvalidKeyData(msg) => write!(f, "Invalid key data: {}", msg),
            KeyFileError::FileTooSmall { expected, got } => {
                write!(f, "File too small: expected {} bytes, got {}", expected, got)
            }
        }
    }
}

impl std::error::Error for KeyFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            KeyFileError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for KeyFileError {
    fn from(e: std::io::Error) -> Self {
        KeyFileError::Io(e)
    }
}

/// Key file container
pub struct KeyFile {
    /// Key type
    pub key_type: KeyType,
    /// Creation timestamp (Unix seconds)
    pub created_at: u64,
    /// Private key (32 bytes)
    private_key: Zeroizing<[u8; 32]>,
    /// Public key (32 bytes, zeros for symmetric keys)
    public_key: [u8; 32],
}

impl KeyFile {
    /// Create a new Ed25519 key file
    pub fn new_ed25519(keypair: &Ed25519KeyPair) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            key_type: KeyType::Ed25519,
            created_at: timestamp,
            private_key: keypair.private_key(),
            public_key: keypair.public_key(),
        }
    }

    /// Create a new symmetric key file (legacy)
    pub fn new_symmetric(key: &[u8; 32]) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            key_type: KeyType::Symmetric,
            created_at: timestamp,
            private_key: Zeroizing::new(*key),
            public_key: [0u8; 32],
        }
    }

    /// Generate a new Ed25519 key file
    pub fn generate_ed25519() -> Result<Self, KeyFileError> {
        let keypair = Ed25519KeyPair::generate()
            .map_err(|e| KeyFileError::InvalidKeyData(e.to_string()))?;
        Ok(Self::new_ed25519(&keypair))
    }

    /// Get the key type
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }

    /// Get the creation timestamp
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Get the private key bytes
    pub fn private_key(&self) -> &[u8; 32] {
        &self.private_key
    }

    /// Get the public key bytes (zeros for symmetric keys)
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Get the Ed25519 key pair (only for Ed25519 keys)
    pub fn to_ed25519_keypair(&self) -> Result<Ed25519KeyPair, KeyFileError> {
        if self.key_type != KeyType::Ed25519 {
            return Err(KeyFileError::InvalidKeyData(
                "Not an Ed25519 key".to_string(),
            ));
        }

        Ed25519KeyPair::from_private_key(&self.private_key[..])
            .map_err(|e| KeyFileError::InvalidKeyData(e.to_string()))
    }

    /// Get the Ed25519 public key (only for Ed25519 keys)
    pub fn to_ed25519_public_key(&self) -> Result<Ed25519PublicKey, KeyFileError> {
        if self.key_type != KeyType::Ed25519 {
            return Err(KeyFileError::InvalidKeyData(
                "Not an Ed25519 key".to_string(),
            ));
        }

        Ed25519PublicKey::from_bytes(&self.public_key)
            .map_err(|e| KeyFileError::InvalidKeyData(e.to_string()))
    }

    /// Calculate CRC32 checksum for the key file data
    fn calculate_checksum(data: &[u8]) -> u32 {
        crc32fast::hash(data)
    }

    /// Serialize key file to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(KEY_FILE_SIZE);

        // Magic (4 bytes)
        buf.extend_from_slice(KEY_FILE_MAGIC);

        // Version (1 byte)
        buf.push(KEY_FILE_VERSION);

        // Key type (1 byte)
        buf.push(self.key_type as u8);

        // Creation time (8 bytes, little-endian)
        buf.extend_from_slice(&self.created_at.to_le_bytes());

        // Private key (32 bytes)
        buf.extend_from_slice(&self.private_key[..]);

        // Public key (32 bytes)
        buf.extend_from_slice(&self.public_key);

        // Calculate checksum over all previous data (74 bytes)
        let checksum = Self::calculate_checksum(&buf);
        buf.extend_from_slice(&checksum.to_le_bytes());

        buf
    }

    /// Deserialize key file from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, KeyFileError> {
        if data.len() < KEY_FILE_SIZE {
            return Err(KeyFileError::FileTooSmall {
                expected: KEY_FILE_SIZE,
                got: data.len(),
            });
        }

        // Check magic
        if &data[0..4] != KEY_FILE_MAGIC {
            return Err(KeyFileError::InvalidMagic);
        }

        // Check version
        let version = data[4];
        if version != KEY_FILE_VERSION {
            return Err(KeyFileError::UnsupportedVersion {
                expected: KEY_FILE_VERSION,
                got: version,
            });
        }

        // Parse key type
        let key_type = KeyType::from_u8(data[5])
            .ok_or(KeyFileError::UnknownKeyType(data[5]))?;

        // Parse creation time
        let created_at = u64::from_le_bytes([
            data[6], data[7], data[8], data[9],
            data[10], data[11], data[12], data[13],
        ]);

        // Parse private key
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&data[14..46]);

        // Parse public key
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&data[46..78]);

        // Verify checksum (stored at bytes 78-81, calculated over 0-77)
        let stored_checksum = u32::from_le_bytes([
            data[78], data[79], data[80], data[81],
        ]);
        let calculated_checksum = Self::calculate_checksum(&data[0..78]);

        if stored_checksum != calculated_checksum {
            return Err(KeyFileError::ChecksumMismatch {
                expected: stored_checksum,
                got: calculated_checksum,
            });
        }

        Ok(Self {
            key_type,
            created_at,
            private_key: Zeroizing::new(private_key),
            public_key,
        })
    }

    /// Write key file to path
    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), KeyFileError> {
        let bytes = self.to_bytes();
        let mut file = File::create(path)?;
        file.write_all(&bytes)?;
        Ok(())
    }

    /// Read key file from path
    pub fn read_from_file<P: AsRef<Path>>(path: P) -> Result<Self, KeyFileError> {
        let mut file = File::open(path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Self::from_bytes(&data)
    }

    /// Export public key to base64 string
    pub fn public_key_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.public_key)
    }

    /// Export private key hex (for symmetric keys, for display only)
    pub fn private_key_hex(&self) -> String {
        hex_encode(&self.private_key[..])
    }
}

impl fmt::Debug for KeyFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyFile")
            .field("key_type", &self.key_type)
            .field("created_at", &self.created_at)
            .field("public_key", &hex_encode(&self.public_key))
            .finish_non_exhaustive()
    }
}

/// Simple hex encoding helper
fn hex_encode(data: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(data.len() * 2);
    for byte in data {
        hex.push(HEX_CHARS[(byte >> 4) as usize] as char);
        hex.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
    }
    hex
}

/// Information about a key file (without exposing private key)
#[derive(Debug, Clone)]
pub struct KeyFileInfo {
    /// Key type
    pub key_type: KeyType,
    /// Creation timestamp (Unix seconds)
    pub created_at: u64,
    /// Public key (base64 encoded)
    pub public_key_base64: String,
    /// Public key (hex encoded)
    pub public_key_hex: String,
}

impl KeyFileInfo {
    /// Extract info from a key file
    pub fn from_keyfile(keyfile: &KeyFile) -> Self {
        Self {
            key_type: keyfile.key_type,
            created_at: keyfile.created_at,
            public_key_base64: keyfile.public_key_base64(),
            public_key_hex: hex_encode(&keyfile.public_key),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_key_file_roundtrip() {
        let keyfile = KeyFile::generate_ed25519().unwrap();

        let bytes = keyfile.to_bytes();
        assert_eq!(bytes.len(), KEY_FILE_SIZE);

        let restored = KeyFile::from_bytes(&bytes).unwrap();
        assert_eq!(restored.key_type, KeyType::Ed25519);
        assert_eq!(restored.created_at, keyfile.created_at);
        assert_eq!(restored.private_key(), keyfile.private_key());
        assert_eq!(restored.public_key(), keyfile.public_key());
    }

    #[test]
    fn test_symmetric_key_file_roundtrip() {
        let key = [42u8; 32];
        let keyfile = KeyFile::new_symmetric(&key);

        let bytes = keyfile.to_bytes();
        let restored = KeyFile::from_bytes(&bytes).unwrap();

        assert_eq!(restored.key_type, KeyType::Symmetric);
        assert_eq!(restored.private_key(), &key);
        assert_eq!(restored.public_key(), &[0u8; 32]);
    }

    #[test]
    fn test_magic_validation() {
        let mut data = vec![0u8; KEY_FILE_SIZE];
        data[0..4].copy_from_slice(b"XXXX");

        let result = KeyFile::from_bytes(&data);
        assert!(matches!(result, Err(KeyFileError::InvalidMagic)));
    }

    #[test]
    fn test_version_validation() {
        let keyfile = KeyFile::generate_ed25519().unwrap();
        let mut bytes = keyfile.to_bytes();
        bytes[4] = 99; // Invalid version

        let result = KeyFile::from_bytes(&bytes);
        assert!(matches!(result, Err(KeyFileError::UnsupportedVersion { .. })));
    }

    #[test]
    fn test_checksum_validation() {
        let keyfile = KeyFile::generate_ed25519().unwrap();
        let mut bytes = keyfile.to_bytes();
        bytes[20] ^= 0xff; // Corrupt data

        let result = KeyFile::from_bytes(&bytes);
        assert!(matches!(result, Err(KeyFileError::ChecksumMismatch { .. })));
    }

    #[test]
    fn test_file_too_small() {
        let data = vec![0u8; 10];
        let result = KeyFile::from_bytes(&data);
        assert!(matches!(result, Err(KeyFileError::FileTooSmall { .. })));
    }

    #[test]
    fn test_ed25519_keypair_extraction() {
        let keyfile = KeyFile::generate_ed25519().unwrap();
        let keypair = keyfile.to_ed25519_keypair().unwrap();

        assert_eq!(keypair.public_key(), *keyfile.public_key());
    }

    #[test]
    fn test_symmetric_keypair_extraction_fails() {
        let keyfile = KeyFile::new_symmetric(&[0u8; 32]);
        let result = keyfile.to_ed25519_keypair();
        assert!(matches!(result, Err(KeyFileError::InvalidKeyData(_))));
    }

    #[test]
    fn test_public_key_base64() {
        let keyfile = KeyFile::generate_ed25519().unwrap();
        let base64 = keyfile.public_key_base64();

        // Base64 of 32 bytes should be 44 characters (with padding)
        assert_eq!(base64.len(), 44);
    }

    #[test]
    fn test_key_file_info() {
        let keyfile = KeyFile::generate_ed25519().unwrap();
        let info = KeyFileInfo::from_keyfile(&keyfile);

        assert_eq!(info.key_type, KeyType::Ed25519);
        assert_eq!(info.created_at, keyfile.created_at);
        assert_eq!(info.public_key_hex.len(), 64); // 32 bytes = 64 hex chars
    }
}
