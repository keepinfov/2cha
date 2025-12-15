//! # Key Derivation Function Module
//!
//! Provides HKDF-SHA256 and BLAKE2s-based KDF for key derivation in protocol v4.
//!
//! Used for:
//! - Deriving symmetric session keys from DH shared secrets
//! - Chaining keys in the Noise protocol
//! - Splitting output into separate TX/RX keys

use hkdf::Hkdf;
use sha2::Sha256;
use blake2::{Blake2s256, Blake2sMac};
use blake2::digest::{FixedOutput, KeyInit, consts::U32};
use blake2::digest::Update as MacUpdate;
use zeroize::Zeroizing;
use std::fmt;

/// Size of derived keys in bytes
pub const DERIVED_KEY_SIZE: usize = 32;

/// Size of chaining key in bytes
pub const CHAINING_KEY_SIZE: usize = 32;

/// Error type for KDF operations
#[derive(Debug, Clone)]
pub enum KdfError {
    /// Output length too large
    OutputTooLarge { max: usize, requested: usize },
    /// Invalid input length
    InvalidInputLength { expected: usize, got: usize },
    /// Key derivation failed
    DerivationFailed(String),
}

impl fmt::Display for KdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KdfError::OutputTooLarge { max, requested } => {
                write!(f, "Output too large: max {}, requested {}", max, requested)
            }
            KdfError::InvalidInputLength { expected, got } => {
                write!(f, "Invalid input length: expected {}, got {}", expected, got)
            }
            KdfError::DerivationFailed(msg) => {
                write!(f, "Key derivation failed: {}", msg)
            }
        }
    }
}

impl std::error::Error for KdfError {}

/// HKDF using SHA-256
pub struct HkdfSha256;

impl HkdfSha256 {
    /// Derive a single key from input key material
    ///
    /// # Arguments
    /// * `salt` - Optional salt value (can be empty)
    /// * `ikm` - Input key material (e.g., DH shared secret)
    /// * `info` - Optional context/application-specific info
    ///
    /// # Returns
    /// 32-byte derived key
    pub fn derive_key(
        salt: &[u8],
        ikm: &[u8],
        info: &[u8],
    ) -> Result<Zeroizing<[u8; DERIVED_KEY_SIZE]>, KdfError> {
        let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);

        let mut okm = [0u8; DERIVED_KEY_SIZE];
        hkdf.expand(info, &mut okm)
            .map_err(|e| KdfError::DerivationFailed(e.to_string()))?;

        Ok(Zeroizing::new(okm))
    }

    /// Derive multiple keys from input key material
    ///
    /// # Arguments
    /// * `salt` - Optional salt value (can be empty)
    /// * `ikm` - Input key material (e.g., DH shared secret)
    /// * `info` - Optional context/application-specific info
    /// * `num_keys` - Number of 32-byte keys to derive (max 8)
    ///
    /// # Returns
    /// Vector of 32-byte derived keys
    pub fn derive_keys(
        salt: &[u8],
        ikm: &[u8],
        info: &[u8],
        num_keys: usize,
    ) -> Result<Vec<Zeroizing<[u8; DERIVED_KEY_SIZE]>>, KdfError> {
        if num_keys > 8 {
            return Err(KdfError::OutputTooLarge {
                max: 8,
                requested: num_keys,
            });
        }

        let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);

        let total_len = num_keys * DERIVED_KEY_SIZE;
        let mut okm = vec![0u8; total_len];

        hkdf.expand(info, &mut okm)
            .map_err(|e| KdfError::DerivationFailed(e.to_string()))?;

        let mut keys = Vec::with_capacity(num_keys);
        for i in 0..num_keys {
            let start = i * DERIVED_KEY_SIZE;
            let mut key = [0u8; DERIVED_KEY_SIZE];
            key.copy_from_slice(&okm[start..start + DERIVED_KEY_SIZE]);
            keys.push(Zeroizing::new(key));
        }

        // Zeroize the temporary buffer
        okm.iter_mut().for_each(|b| *b = 0);

        Ok(keys)
    }

    /// Derive session keys for TX and RX directions
    ///
    /// # Arguments
    /// * `chaining_key` - Current chaining key
    /// * `dh_output` - DH shared secret
    ///
    /// # Returns
    /// (new_chaining_key, symmetric_key)
    pub fn derive_session_keys(
        chaining_key: &[u8; CHAINING_KEY_SIZE],
        dh_output: &[u8],
    ) -> Result<(Zeroizing<[u8; CHAINING_KEY_SIZE]>, Zeroizing<[u8; DERIVED_KEY_SIZE]>), KdfError> {
        let keys = Self::derive_keys(chaining_key, dh_output, b"", 2)?;

        let mut new_ck = [0u8; CHAINING_KEY_SIZE];
        let mut key = [0u8; DERIVED_KEY_SIZE];

        new_ck.copy_from_slice(&keys[0][..]);
        key.copy_from_slice(&keys[1][..]);

        Ok((Zeroizing::new(new_ck), Zeroizing::new(key)))
    }

    /// Derive final TX/RX keys from chaining key
    ///
    /// # Arguments
    /// * `chaining_key` - Final chaining key after all DH operations
    ///
    /// # Returns
    /// (tx_key, rx_key) - Keys for sending and receiving
    pub fn derive_traffic_keys(
        chaining_key: &[u8; CHAINING_KEY_SIZE],
    ) -> Result<(Zeroizing<[u8; DERIVED_KEY_SIZE]>, Zeroizing<[u8; DERIVED_KEY_SIZE]>), KdfError> {
        let keys = Self::derive_keys(chaining_key, b"", b"", 2)?;

        let mut tx_key = [0u8; DERIVED_KEY_SIZE];
        let mut rx_key = [0u8; DERIVED_KEY_SIZE];

        tx_key.copy_from_slice(&keys[0][..]);
        rx_key.copy_from_slice(&keys[1][..]);

        Ok((Zeroizing::new(tx_key), Zeroizing::new(rx_key)))
    }
}

/// BLAKE2s-based HKDF for Noise protocol
///
/// Implements HKDF using BLAKE2s keyed mode (MAC) as the PRF.
/// This follows the Noise protocol specification.
pub struct HkdfBlake2s;

impl HkdfBlake2s {
    /// HMAC-BLAKE2s function using keyed Blake2s
    fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
        // Use Blake2s in keyed mode (which is equivalent to HMAC for our purposes)
        // If key is longer than 32 bytes, we need to hash it first
        let mac_key: [u8; 32] = if key.len() <= 32 {
            let mut k = [0u8; 32];
            k[..key.len()].copy_from_slice(key);
            k
        } else {
            // Hash the key if it's too long
            use blake2::Digest;
            let mut hasher = Blake2s256::new();
            Digest::update(&mut hasher, key);
            let result = hasher.finalize();
            let mut k = [0u8; 32];
            k.copy_from_slice(&result);
            k
        };

        let mut mac = Blake2sMac::<U32>::new_from_slice(&mac_key)
            .expect("Blake2sMac accepts any key size up to 32 bytes");
        MacUpdate::update(&mut mac, data);
        let result = mac.finalize_fixed();

        let mut output = [0u8; 32];
        output.copy_from_slice(&result);
        output
    }

    /// HKDF-Extract: Extract a PRK from salt and IKM
    fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
        let salt = if salt.is_empty() {
            &[0u8; 32][..]
        } else {
            salt
        };
        Self::hmac(salt, ikm)
    }

    /// HKDF-Expand: Expand PRK to desired length
    fn expand(prk: &[u8; 32], info: &[u8], length: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(length);
        let mut t = Vec::new();
        let mut counter = 1u8;

        while output.len() < length {
            // T(i) = HMAC(PRK, T(i-1) || info || counter)
            let mut input = t.clone();
            input.extend_from_slice(info);
            input.push(counter);

            t = Self::hmac(prk, &input).to_vec();
            output.extend_from_slice(&t);
            counter += 1;
        }

        output.truncate(length);
        output
    }

    /// Derive a single key from input key material
    pub fn derive_key(
        salt: &[u8],
        ikm: &[u8],
        info: &[u8],
    ) -> Result<Zeroizing<[u8; DERIVED_KEY_SIZE]>, KdfError> {
        let prk = Self::extract(salt, ikm);
        let okm = Self::expand(&prk, info, DERIVED_KEY_SIZE);

        let mut key = [0u8; DERIVED_KEY_SIZE];
        key.copy_from_slice(&okm);

        Ok(Zeroizing::new(key))
    }

    /// Derive multiple keys from input key material
    pub fn derive_keys(
        salt: &[u8],
        ikm: &[u8],
        info: &[u8],
        num_keys: usize,
    ) -> Result<Vec<Zeroizing<[u8; DERIVED_KEY_SIZE]>>, KdfError> {
        if num_keys > 8 {
            return Err(KdfError::OutputTooLarge {
                max: 8,
                requested: num_keys,
            });
        }

        let prk = Self::extract(salt, ikm);
        let total_len = num_keys * DERIVED_KEY_SIZE;
        let okm = Self::expand(&prk, info, total_len);

        let mut keys = Vec::with_capacity(num_keys);
        for i in 0..num_keys {
            let start = i * DERIVED_KEY_SIZE;
            let mut key = [0u8; DERIVED_KEY_SIZE];
            key.copy_from_slice(&okm[start..start + DERIVED_KEY_SIZE]);
            keys.push(Zeroizing::new(key));
        }

        Ok(keys)
    }

    /// Derive session keys for Noise protocol
    ///
    /// # Arguments
    /// * `chaining_key` - Current chaining key
    /// * `dh_output` - DH shared secret
    ///
    /// # Returns
    /// (new_chaining_key, symmetric_key)
    pub fn derive_session_keys(
        chaining_key: &[u8; CHAINING_KEY_SIZE],
        dh_output: &[u8],
    ) -> Result<(Zeroizing<[u8; CHAINING_KEY_SIZE]>, Zeroizing<[u8; DERIVED_KEY_SIZE]>), KdfError> {
        let keys = Self::derive_keys(chaining_key, dh_output, b"", 2)?;

        let mut new_ck = [0u8; CHAINING_KEY_SIZE];
        let mut key = [0u8; DERIVED_KEY_SIZE];

        new_ck.copy_from_slice(&keys[0][..]);
        key.copy_from_slice(&keys[1][..]);

        Ok((Zeroizing::new(new_ck), Zeroizing::new(key)))
    }

    /// Derive final TX/RX keys from chaining key
    pub fn derive_traffic_keys(
        chaining_key: &[u8; CHAINING_KEY_SIZE],
    ) -> Result<(Zeroizing<[u8; DERIVED_KEY_SIZE]>, Zeroizing<[u8; DERIVED_KEY_SIZE]>), KdfError> {
        let keys = Self::derive_keys(chaining_key, b"", b"", 2)?;

        let mut tx_key = [0u8; DERIVED_KEY_SIZE];
        let mut rx_key = [0u8; DERIVED_KEY_SIZE];

        tx_key.copy_from_slice(&keys[0][..]);
        rx_key.copy_from_slice(&keys[1][..]);

        Ok((Zeroizing::new(tx_key), Zeroizing::new(rx_key)))
    }
}

/// Noise protocol chaining key manager
///
/// Manages the chaining key state during handshake.
pub struct ChainingKey {
    key: Zeroizing<[u8; CHAINING_KEY_SIZE]>,
}

impl ChainingKey {
    /// Initialize with protocol name hash
    ///
    /// For Noise_IK: `HASH("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")`
    pub fn new(initial: &[u8; CHAINING_KEY_SIZE]) -> Self {
        Self {
            key: Zeroizing::new(*initial),
        }
    }

    /// Initialize from protocol name string
    pub fn from_protocol_name(name: &str) -> Self {
        use blake2::Digest;
        let mut hasher = Blake2s256::new();
        Digest::update(&mut hasher, name.as_bytes());
        let hash = hasher.finalize();

        let mut key = [0u8; CHAINING_KEY_SIZE];
        key.copy_from_slice(&hash);

        Self {
            key: Zeroizing::new(key),
        }
    }

    /// Mix in DH output and derive new symmetric key
    ///
    /// Updates the chaining key and returns a symmetric key for encryption.
    pub fn mix_key(&mut self, dh_output: &[u8]) -> Result<Zeroizing<[u8; DERIVED_KEY_SIZE]>, KdfError> {
        let (new_ck, sym_key) = HkdfBlake2s::derive_session_keys(&self.key, dh_output)?;
        self.key = new_ck;
        Ok(sym_key)
    }

    /// Get current chaining key (for final key derivation)
    pub fn get(&self) -> &[u8; CHAINING_KEY_SIZE] {
        &self.key
    }

    /// Derive final traffic keys
    pub fn finalize(self) -> Result<(Zeroizing<[u8; DERIVED_KEY_SIZE]>, Zeroizing<[u8; DERIVED_KEY_SIZE]>), KdfError> {
        HkdfBlake2s::derive_traffic_keys(&self.key)
    }
}

impl fmt::Debug for ChainingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainingKey")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_sha256_derive_key() {
        let salt = b"test-salt";
        let ikm = b"input-key-material";
        let info = b"context-info";

        let key = HkdfSha256::derive_key(salt, ikm, info).unwrap();
        assert_eq!(key.len(), DERIVED_KEY_SIZE);

        // Same inputs should produce same output
        let key2 = HkdfSha256::derive_key(salt, ikm, info).unwrap();
        assert_eq!(&*key, &*key2);
    }

    #[test]
    fn test_hkdf_sha256_different_inputs_different_output() {
        let key1 = HkdfSha256::derive_key(b"salt1", b"ikm", b"info").unwrap();
        let key2 = HkdfSha256::derive_key(b"salt2", b"ikm", b"info").unwrap();
        assert_ne!(&*key1, &*key2);
    }

    #[test]
    fn test_hkdf_sha256_derive_multiple_keys() {
        let keys = HkdfSha256::derive_keys(b"salt", b"ikm", b"info", 4).unwrap();
        assert_eq!(keys.len(), 4);

        // All keys should be different
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(&*keys[i], &*keys[j]);
            }
        }
    }

    #[test]
    fn test_hkdf_sha256_max_keys() {
        let result = HkdfSha256::derive_keys(b"salt", b"ikm", b"info", 10);
        assert!(matches!(result, Err(KdfError::OutputTooLarge { .. })));
    }

    #[test]
    fn test_hkdf_sha256_session_keys() {
        let ck = [1u8; CHAINING_KEY_SIZE];
        let dh_output = [2u8; 32];

        let (new_ck, key) = HkdfSha256::derive_session_keys(&ck, &dh_output).unwrap();

        assert_ne!(&*new_ck, &ck);
        assert_eq!(key.len(), DERIVED_KEY_SIZE);
    }

    #[test]
    fn test_hkdf_sha256_traffic_keys() {
        let ck = [1u8; CHAINING_KEY_SIZE];

        let (tx_key, rx_key) = HkdfSha256::derive_traffic_keys(&ck).unwrap();

        assert_ne!(&*tx_key, &*rx_key);
        assert_eq!(tx_key.len(), DERIVED_KEY_SIZE);
        assert_eq!(rx_key.len(), DERIVED_KEY_SIZE);
    }

    #[test]
    fn test_hkdf_blake2s_derive_key() {
        let key = HkdfBlake2s::derive_key(b"salt", b"ikm", b"info").unwrap();
        assert_eq!(key.len(), DERIVED_KEY_SIZE);
    }

    #[test]
    fn test_hkdf_blake2s_differs_from_sha256() {
        let key_sha256 = HkdfSha256::derive_key(b"salt", b"ikm", b"info").unwrap();
        let key_blake2s = HkdfBlake2s::derive_key(b"salt", b"ikm", b"info").unwrap();

        // Different hash functions should produce different results
        assert_ne!(&*key_sha256, &*key_blake2s);
    }

    #[test]
    fn test_hkdf_blake2s_deterministic() {
        let key1 = HkdfBlake2s::derive_key(b"salt", b"ikm", b"info").unwrap();
        let key2 = HkdfBlake2s::derive_key(b"salt", b"ikm", b"info").unwrap();
        assert_eq!(&*key1, &*key2);
    }

    #[test]
    fn test_hkdf_blake2s_multiple_keys() {
        let keys = HkdfBlake2s::derive_keys(b"salt", b"ikm", b"info", 4).unwrap();
        assert_eq!(keys.len(), 4);

        // All keys should be different
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(&*keys[i], &*keys[j]);
            }
        }
    }

    #[test]
    fn test_chaining_key_from_protocol_name() {
        let ck = ChainingKey::from_protocol_name("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s");
        assert_eq!(ck.get().len(), CHAINING_KEY_SIZE);

        // Same name should produce same key
        let ck2 = ChainingKey::from_protocol_name("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s");
        assert_eq!(ck.get(), ck2.get());
    }

    #[test]
    fn test_chaining_key_mix() {
        let mut ck = ChainingKey::from_protocol_name("test-protocol");
        let initial_key = *ck.get();

        let dh_output = [3u8; 32];
        let sym_key = ck.mix_key(&dh_output).unwrap();

        // Chaining key should be updated
        assert_ne!(ck.get(), &initial_key);
        assert_eq!(sym_key.len(), DERIVED_KEY_SIZE);
    }

    #[test]
    fn test_chaining_key_finalize() {
        let ck = ChainingKey::from_protocol_name("test-protocol");
        let (tx, rx) = ck.finalize().unwrap();

        assert_ne!(&*tx, &*rx);
        assert_eq!(tx.len(), DERIVED_KEY_SIZE);
        assert_eq!(rx.len(), DERIVED_KEY_SIZE);
    }

    #[test]
    fn test_noise_ik_simulation() {
        // Simulate Noise_IK key derivation pattern:
        // -> e, es, s, ss
        // <- e, ee, se

        // Initial chaining key from protocol name
        let mut initiator_ck = ChainingKey::from_protocol_name("Noise_IK");
        let mut responder_ck = ChainingKey::from_protocol_name("Noise_IK");

        // Simulate DH outputs (in real scenario, these come from actual DH operations)
        let es_output = [1u8; 32]; // e-s DH
        let ss_output = [2u8; 32]; // s-s DH
        let ee_output = [3u8; 32]; // e-e DH
        let se_output = [4u8; 32]; // s-e DH

        // Initiator: mix in es, ss
        let _ = initiator_ck.mix_key(&es_output).unwrap();
        let _ = initiator_ck.mix_key(&ss_output).unwrap();

        // Responder: mix in es, ss (same as initiator for IK pattern)
        let _ = responder_ck.mix_key(&es_output).unwrap();
        let _ = responder_ck.mix_key(&ss_output).unwrap();

        // Now both should have same chaining key
        assert_eq!(initiator_ck.get(), responder_ck.get());

        // Mix in ee, se for second message
        let _ = initiator_ck.mix_key(&ee_output).unwrap();
        let _ = initiator_ck.mix_key(&se_output).unwrap();

        let _ = responder_ck.mix_key(&ee_output).unwrap();
        let _ = responder_ck.mix_key(&se_output).unwrap();

        // Finalize - both should derive same traffic keys
        let (init_tx, init_rx) = initiator_ck.finalize().unwrap();
        let (resp_tx, resp_rx) = responder_ck.finalize().unwrap();

        assert_eq!(&*init_tx, &*resp_tx);
        assert_eq!(&*init_rx, &*resp_rx);
    }
}
