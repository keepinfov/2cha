//! # Handshake MACs, Cookies and Counter Masking
//!
//! - MAC1: cheap keyed-BLAKE2s check on handshake packets, verified before
//!   any DH work. Packets failing MAC1 are dropped silently, so the server
//!   never responds to unauthenticated traffic (no amplification).
//! - MAC2 + cookie: stateless source-IP proof under load (WireGuard-style).
//! - Counter masking: the data-packet counter is XORed with a keyed mask
//!   derived from a ciphertext sample, so no monotonic plaintext counter is
//!   visible on the wire (analogous to QUIC header protection).

use blake2::digest::{KeyInit, Mac};
use blake2::{Blake2s256, Blake2sMac, Digest};
use chacha20poly1305::aead::generic_array::typenum::U16;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use twocha_protocol::{CryptoError, Result};

type Blake2sMac128 = Blake2sMac<U16>;

pub const MAC_LEN: usize = 16;
pub const COOKIE_LEN: usize = 16;
pub const COOKIE_NONCE_LEN: usize = 24;
pub const COOKIE_SEALED_LEN: usize = COOKIE_LEN + 16;

const MAC1_LABEL: &[u8] = b"2cha-v4-mac1";
const COOKIE_KEY_LABEL: &[u8] = b"2cha-v4-cookie-key";
const HP_LABEL: &[u8] = b"2cha-v4-hp";

/// MAC1 key: BLAKE2s(label || receiver_static_public)
pub fn mac1_key(receiver_public: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut h = Blake2s256::new();
    h.update(MAC1_LABEL);
    h.update(receiver_public);
    Zeroizing::new(h.finalize().into())
}

/// Keyed-BLAKE2s-128 over `data`; key may be 1..=32 bytes (cookies are 16)
pub fn mac_with(key: &[u8], data: &[u8]) -> [u8; MAC_LEN] {
    let mut m =
        <Blake2sMac128 as KeyInit>::new_from_slice(key).expect("blake2s key must be 1..=32 bytes");
    Mac::update(&mut m, data);
    m.finalize().into_bytes().into()
}

/// Keyed-BLAKE2s-128 over `data`
pub fn mac(key: &[u8; 32], data: &[u8]) -> [u8; MAC_LEN] {
    mac_with(key, data)
}

pub fn mac_verify_with(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    if tag.len() != MAC_LEN {
        return false;
    }
    let computed = mac_with(key, data);
    computed.ct_eq(tag).into()
}

pub fn mac_verify(key: &[u8; 32], data: &[u8], tag: &[u8]) -> bool {
    mac_verify_with(key, data, tag)
}

/// Server-side rotating cookie secret. Rotation invalidates old cookies,
/// bounding how long a captured cookie is useful.
pub struct CookieFactory {
    secret: Zeroizing<[u8; 32]>,
    cookie_key: Zeroizing<[u8; 32]>,
}

impl CookieFactory {
    /// `server_public` keys the cookie-reply encryption; `secret` is random
    /// and should be rotated every ~2 minutes by the caller.
    pub fn new(server_public: &[u8; 32], secret: [u8; 32]) -> Self {
        let mut h = Blake2s256::new();
        h.update(COOKIE_KEY_LABEL);
        h.update(server_public);
        CookieFactory {
            secret: Zeroizing::new(secret),
            cookie_key: Zeroizing::new(h.finalize().into()),
        }
    }

    pub fn rotate(&mut self, secret: [u8; 32]) {
        self.secret = Zeroizing::new(secret);
    }

    /// Cookie for a source address: keyed-BLAKE2s(secret, addr_bytes)
    pub fn cookie_for(&self, addr_bytes: &[u8]) -> [u8; COOKIE_LEN] {
        mac(&self.secret, addr_bytes)
    }

    /// Seal a cookie for transmission. AAD binds the cookie reply to the
    /// initiator's mac1, so it cannot be replayed against other handshakes.
    pub fn seal(
        &self,
        nonce: &[u8; COOKIE_NONCE_LEN],
        cookie: &[u8; COOKIE_LEN],
        init_mac1: &[u8],
    ) -> Result<[u8; COOKIE_SEALED_LEN]> {
        let aead = XChaCha20Poly1305::new((&*self.cookie_key).into());
        let ct = aead
            .encrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: cookie,
                    aad: init_mac1,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)?;
        ct.as_slice()
            .try_into()
            .map_err(|_| CryptoError::EncryptionFailed.into())
    }
}

/// Client side: open a sealed cookie from a cookie reply
pub fn open_cookie(
    server_public: &[u8; 32],
    nonce: &[u8],
    sealed: &[u8],
    init_mac1: &[u8],
) -> Result<[u8; COOKIE_LEN]> {
    let mut h = Blake2s256::new();
    h.update(COOKIE_KEY_LABEL);
    h.update(server_public);
    let key: Zeroizing<[u8; 32]> = Zeroizing::new(h.finalize().into());
    if nonce.len() != COOKIE_NONCE_LEN {
        return Err(CryptoError::AuthenticationFailed.into());
    }
    let aead = XChaCha20Poly1305::new((&*key).into());
    let pt = aead
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: sealed,
                aad: init_mac1,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    pt.as_slice()
        .try_into()
        .map_err(|_| CryptoError::AuthenticationFailed.into())
}

/// Per-direction counter-masking keys derived from the obfs seeds both sides
/// exchanged inside the encrypted handshake payloads.
pub struct HeaderMask {
    key: Zeroizing<[u8; 32]>,
}

impl HeaderMask {
    /// `direction` disambiguates client->server (0x01) from server->client (0x02)
    pub fn new(seed_initiator: &[u8; 32], seed_responder: &[u8; 32], direction: u8) -> Self {
        let mut h = Blake2s256::new();
        h.update(HP_LABEL);
        h.update(seed_initiator);
        h.update(seed_responder);
        h.update([direction]);
        HeaderMask {
            key: Zeroizing::new(h.finalize().into()),
        }
    }

    /// Mask/unmask a counter using a sample of the AEAD ciphertext.
    /// XOR is its own inverse, so the same call works both ways.
    pub fn apply(&self, counter_bytes: [u8; 8], ciphertext_sample: &[u8]) -> [u8; 8] {
        let m = mac(&self.key, ciphertext_sample);
        let mut out = counter_bytes;
        for i in 0..8 {
            out[i] ^= m[i];
        }
        out
    }

    pub fn mask_counter(&self, counter: u64, ciphertext: &[u8]) -> [u8; 8] {
        self.apply(counter.to_le_bytes(), sample(ciphertext))
    }

    pub fn unmask_counter(&self, masked: [u8; 8], ciphertext: &[u8]) -> u64 {
        u64::from_le_bytes(self.apply(masked, sample(ciphertext)))
    }
}

/// First 16 bytes of ciphertext (always present: tag alone is 16 bytes)
fn sample(ciphertext: &[u8]) -> &[u8] {
    &ciphertext[..ciphertext.len().min(16)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac1_verify() {
        let key = mac1_key(&[7u8; 32]);
        let tag = mac(&key, b"packet bytes");
        assert!(mac_verify(&key, b"packet bytes", &tag));
        assert!(!mac_verify(&key, b"other bytes", &tag));
        assert!(!mac_verify(&key, b"packet bytes", &tag[..8]));
    }

    #[test]
    fn test_mac1_key_depends_on_pubkey() {
        assert_ne!(*mac1_key(&[1u8; 32]), *mac1_key(&[2u8; 32]));
    }

    #[test]
    fn test_cookie_roundtrip() {
        let server_pub = [9u8; 32];
        let factory = CookieFactory::new(&server_pub, [3u8; 32]);
        let cookie = factory.cookie_for(b"203.0.113.7:51000");
        let nonce = [5u8; COOKIE_NONCE_LEN];
        let mac1 = [0xAAu8; 16];

        let sealed = factory.seal(&nonce, &cookie, &mac1).unwrap();
        let opened = open_cookie(&server_pub, &nonce, &sealed, &mac1).unwrap();
        assert_eq!(opened, cookie);

        // wrong AAD (different handshake) must fail
        assert!(open_cookie(&server_pub, &nonce, &sealed, &[0xBBu8; 16]).is_err());
    }

    #[test]
    fn test_cookie_rotation_changes_cookie() {
        let mut factory = CookieFactory::new(&[9u8; 32], [3u8; 32]);
        let c1 = factory.cookie_for(b"addr");
        factory.rotate([4u8; 32]);
        assert_ne!(c1, factory.cookie_for(b"addr"));
    }

    #[test]
    fn test_counter_mask_roundtrip() {
        let hm = HeaderMask::new(&[1u8; 32], &[2u8; 32], 0x01);
        let ct = [0x42u8; 32];
        let masked = hm.mask_counter(123456789, &ct);
        assert_ne!(masked, 123456789u64.to_le_bytes());
        assert_eq!(hm.unmask_counter(masked, &ct), 123456789);
    }

    #[test]
    fn test_counter_mask_direction_separation() {
        let a = HeaderMask::new(&[1u8; 32], &[2u8; 32], 0x01);
        let b = HeaderMask::new(&[1u8; 32], &[2u8; 32], 0x02);
        let ct = [0u8; 16];
        assert_ne!(a.mask_counter(1, &ct), b.mask_counter(1, &ct));
    }
}
