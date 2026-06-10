//! # Identity Keys
//!
//! X25519 static identity keypairs used by the Noise_IK handshake.
//! Private keys are stored as raw 32 bytes on disk (mode 0600),
//! public keys are exchanged as base64 strings in config files.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rand::rngs::OsRng;
use std::fs;
use std::io::Write;
use std::path::Path;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use twocha_protocol::{Result, VpnError};

pub const KEY_LEN: usize = 32;

/// X25519 static keypair
pub struct Identity {
    secret: StaticSecret,
    public: PublicKey,
}

impl Identity {
    /// Generate a fresh keypair from the OS CSPRNG
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Identity { secret, public }
    }

    pub fn from_private_bytes(bytes: &[u8; KEY_LEN]) -> Self {
        let secret = StaticSecret::from(*bytes);
        let public = PublicKey::from(&secret);
        Identity { secret, public }
    }

    /// Load a private key from a raw 32-byte file, rejecting insecure permissions
    pub fn load(path: &Path) -> Result<Self> {
        check_key_file_permissions(path)?;
        let data = Zeroizing::new(fs::read(path)?);
        let bytes: [u8; KEY_LEN] = data.as_slice().try_into().map_err(|_| {
            VpnError::Config(format!(
                "key file '{}' must be exactly {} raw bytes (got {})",
                path.display(),
                KEY_LEN,
                data.len()
            ))
        })?;
        Ok(Self::from_private_bytes(&bytes))
    }

    /// Write the private key to a file created with mode 0600
    pub fn save(&self, path: &Path) -> Result<()> {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(path).map_err(|e| {
            VpnError::Config(format!(
                "cannot create key file '{}': {}",
                path.display(),
                e
            ))
        })?;
        file.write_all(&self.secret.to_bytes())?;
        Ok(())
    }

    pub fn private_bytes(&self) -> Zeroizing<[u8; KEY_LEN]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    pub fn public_bytes(&self) -> [u8; KEY_LEN] {
        *self.public.as_bytes()
    }

    pub fn public_base64(&self) -> String {
        BASE64.encode(self.public.as_bytes())
    }
}

/// Decode a base64-encoded public key from config
pub fn decode_public_key(s: &str) -> Result<[u8; KEY_LEN]> {
    let bytes = BASE64
        .decode(s.trim())
        .map_err(|e| VpnError::Config(format!("invalid base64 public key: {}", e)))?;
    bytes.as_slice().try_into().map_err(|_| {
        VpnError::Config(format!(
            "public key must be {} bytes, got {}",
            KEY_LEN,
            bytes.len()
        ))
    })
}

pub fn encode_public_key(key: &[u8; KEY_LEN]) -> String {
    BASE64.encode(key)
}

/// Refuse to use key files readable by group/other
#[cfg(unix)]
fn check_key_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata(path).map_err(|e| {
        VpnError::Config(format!("cannot read key file '{}': {}", path.display(), e))
    })?;
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(VpnError::Config(format!(
            "key file '{}' has insecure permissions {:o}; run: chmod 600 {}",
            path.display(),
            mode,
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_key_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_roundtrip() {
        let id = Identity::generate();
        let restored = Identity::from_private_bytes(&id.private_bytes());
        assert_eq!(id.public_bytes(), restored.public_bytes());
    }

    #[test]
    fn test_public_key_base64_roundtrip() {
        let id = Identity::generate();
        let b64 = id.public_base64();
        let decoded = decode_public_key(&b64).unwrap();
        assert_eq!(decoded, id.public_bytes());
    }

    #[test]
    fn test_decode_rejects_wrong_length() {
        assert!(decode_public_key("aGVsbG8=").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn test_save_load_with_permissions() {
        use std::os::unix::fs::MetadataExt;
        let dir = std::env::temp_dir().join(format!("2cha-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.key");
        let _ = std::fs::remove_file(&path);

        let id = Identity::generate();
        id.save(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let loaded = Identity::load(&path).unwrap();
        assert_eq!(loaded.public_bytes(), id.public_bytes());

        std::fs::remove_file(&path).unwrap();
        let _ = std::fs::remove_dir(&dir);
    }
}
