//! # REALITY-style ClientHello authentication
//!
//! Standalone crypto for the anti-active-probing gate. A provisioned client
//! proves — *inside the TLS ClientHello* — that it knows the server's REALITY
//! public key and a short id, so the server can decide, **before presenting any
//! certificate**, whether to run the tunnel or hand the connection off to a real
//! decoy site. That pre-certificate decision is what lets an active prober see
//! the genuine target's certificate (see `docs/reality.md`).
//!
//! This module is deliberately transport-agnostic: it neither builds nor parses
//! TLS records. It seals/opens the 32-byte blob that rides in the ClientHello
//! `session_id`, using the client's ephemeral X25519 `key_share` as the ECDH
//! input — the same construction as XTLS-REALITY, but expressed with 2cha's
//! in-tree primitives (BLAKE2s KDF + ChaCha20-Poly1305, matching [`super::mac`])
//! rather than pulling in HKDF-SHA256 + AES-GCM.
//!
//! The transport layer supplies three fields read straight from the ClientHello
//! — `key_share` (client ephemeral public), `client_random`, and `session_id` —
//! and this module says authenticated-or-not.

use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use rand::rngs::OsRng;
use subtle::{Choice, ConstantTimeEq};
use x25519_dalek::{PublicKey, StaticSecret};

/// Length of a short id: an 8-byte tag distinguishing provisioned clients.
pub const SHORT_ID_LEN: usize = 8;
/// The TLS legacy `session_id` is 32 bytes; we fill it entirely with the sealed
/// auth blob (16 bytes plaintext + 16 bytes AEAD tag).
pub const SESSION_ID_LEN: usize = 32;

/// Sealed plaintext = short id (8) followed by a little-endian u64 timestamp (8).
const PLAINTEXT_LEN: usize = SHORT_ID_LEN + 8;
/// Domain-separation label mixed into every KDF call.
const KDF_CONTEXT: &[u8] = b"2cha-reality-v1";

/// Auth material a client embeds in its ClientHello.
pub struct ClientAuth {
    /// X25519 ephemeral public key — belongs in the TLS `key_share` extension.
    pub key_share: [u8; 32],
    /// 32-byte sealed blob — belongs in the TLS `session_id` field.
    pub session_id: [u8; SESSION_ID_LEN],
}

/// What the server recovers when authentication succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opened {
    pub short_id: [u8; SHORT_ID_LEN],
    /// Unix seconds the client claimed at seal time. The caller checks freshness
    /// with [`timestamp_fresh`] and replay-rejects non-increasing values.
    pub timestamp: u64,
}

/// Derive the per-handshake AEAD key and nonce from the ECDH secret and the
/// ClientHello random. The ephemeral key_share makes the shared secret unique
/// per connection, so a deterministic nonce is safe (the key never repeats).
fn derive_key_nonce(shared: &[u8; 32], client_random: &[u8; 32]) -> ([u8; 32], [u8; 12]) {
    let block = |tag: &[u8]| -> [u8; 32] {
        let mut h = Blake2s256::new();
        h.update(KDF_CONTEXT);
        h.update(tag);
        h.update(shared);
        h.update(client_random);
        h.finalize().into()
    };
    let key = block(b"key");
    let nonce_full = block(b"nonce");
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_full[..12]);
    (key, nonce)
}

/// AEAD associated data binds the sealed blob to this exact key_share and server
/// identity, so a captured `session_id` cannot be transplanted onto a different
/// ClientHello or replayed against a different server.
fn aad(key_share: &[u8; 32], server_public: &[u8; 32]) -> [u8; 64] {
    let mut a = [0u8; 64];
    a[..32].copy_from_slice(key_share);
    a[32..].copy_from_slice(server_public);
    a
}

/// Client side: produce the ClientHello auth material for one connection.
///
/// `client_random` must be the same 32-byte value the client places in the
/// ClientHello `random` field; the server reads it back to reconstruct the KDF.
pub fn seal(
    server_public: &[u8; 32],
    short_id: &[u8; SHORT_ID_LEN],
    timestamp: u64,
    client_random: &[u8; 32],
) -> ClientAuth {
    let eph = StaticSecret::random_from_rng(OsRng);
    let key_share = *PublicKey::from(&eph).as_bytes();
    let shared = eph.diffie_hellman(&PublicKey::from(*server_public));
    let (key, nonce) = derive_key_nonce(shared.as_bytes(), client_random);

    let mut pt = [0u8; PLAINTEXT_LEN];
    pt[..SHORT_ID_LEN].copy_from_slice(short_id);
    pt[SHORT_ID_LEN..].copy_from_slice(&timestamp.to_le_bytes());

    let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("32-byte key");
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &pt,
                aad: &aad(&key_share, server_public),
            },
        )
        .expect("aead encrypt of fixed-size plaintext cannot fail");
    debug_assert_eq!(ct.len(), SESSION_ID_LEN);

    let mut session_id = [0u8; SESSION_ID_LEN];
    session_id.copy_from_slice(&ct);
    ClientAuth {
        key_share,
        session_id,
    }
}

/// Server side: attempt to recover the auth blob from a ClientHello.
///
/// Returns `None` on any failure — not our client, tampered blob, or a blind
/// probe that never carried real auth. The caller treats `None` as "probe" and
/// redirects the connection to the decoy target. A `Some` still requires the
/// caller to check the short id ([`short_id_allowed`]), timestamp freshness
/// ([`timestamp_fresh`]), and replay.
pub fn open(
    server_private: &[u8; 32],
    key_share: &[u8; 32],
    session_id: &[u8; SESSION_ID_LEN],
    client_random: &[u8; 32],
) -> Option<Opened> {
    let secret = StaticSecret::from(*server_private);
    let server_public = *PublicKey::from(&secret).as_bytes();
    let shared = secret.diffie_hellman(&PublicKey::from(*key_share));
    let (key, nonce) = derive_key_nonce(shared.as_bytes(), client_random);

    let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("32-byte key");
    let pt = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: session_id,
                aad: &aad(key_share, &server_public),
            },
        )
        .ok()?;
    if pt.len() != PLAINTEXT_LEN {
        return None;
    }
    let mut short_id = [0u8; SHORT_ID_LEN];
    short_id.copy_from_slice(&pt[..SHORT_ID_LEN]);
    let timestamp = u64::from_le_bytes(pt[SHORT_ID_LEN..].try_into().expect("8 bytes"));
    Some(Opened {
        short_id,
        timestamp,
    })
}

/// Constant-time membership test of a recovered short id against the configured
/// set. Constant-time so a probe cannot learn valid short ids by timing.
pub fn short_id_allowed(short_id: &[u8; SHORT_ID_LEN], allowed: &[[u8; SHORT_ID_LEN]]) -> bool {
    let mut hit = Choice::from(0u8);
    for a in allowed {
        hit |= short_id.ct_eq(a);
    }
    hit.into()
}

/// Whether a sealed timestamp is within `window_secs` of `now` (both Unix
/// seconds). Bounds clock skew and caps how long a captured ClientHello stays
/// replayable before the freshness window closes.
pub fn timestamp_fresh(timestamp: u64, now: u64, window_secs: u64) -> bool {
    now.abs_diff(timestamp) <= window_secs
}

/// Generate a random short id from the OS CSPRNG.
pub fn generate_short_id() -> [u8; SHORT_ID_LEN] {
    use rand::RngCore;
    let mut id = [0u8; SHORT_ID_LEN];
    OsRng.fill_bytes(&mut id);
    id
}

/// Render a short id as lowercase hex (the config/CLI representation).
pub fn short_id_hex(id: &[u8; SHORT_ID_LEN]) -> String {
    let mut s = String::with_capacity(SHORT_ID_LEN * 2);
    for b in id {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Parse a short id from hex (exactly `SHORT_ID_LEN * 2` hex digits). Returns
/// `None` on wrong length or non-hex input.
pub fn parse_short_id(hex: &str) -> Option<[u8; SHORT_ID_LEN]> {
    let hex = hex.trim();
    if hex.len() != SHORT_ID_LEN * 2 {
        return None;
    }
    let mut out = [0u8; SHORT_ID_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Identity;

    fn server() -> ([u8; 32], [u8; 32]) {
        let id = Identity::generate();
        (*id.private_bytes(), id.public_bytes())
    }

    #[test]
    fn seal_open_roundtrip() {
        let (priv_k, pub_k) = server();
        let short_id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let random = [0x42u8; 32];
        let ts = 1_700_000_000u64;

        let auth = seal(&pub_k, &short_id, ts, &random);
        let opened = open(&priv_k, &auth.key_share, &auth.session_id, &random).unwrap();
        assert_eq!(opened.short_id, short_id);
        assert_eq!(opened.timestamp, ts);
    }

    #[test]
    fn wrong_server_key_fails() {
        let (_priv_k, pub_k) = server();
        let (other_priv, _other_pub) = server();
        let auth = seal(&pub_k, &[9u8; SHORT_ID_LEN], 1, &[7u8; 32]);
        // A server holding a different private key cannot open it: looks like a probe.
        assert!(open(&other_priv, &auth.key_share, &auth.session_id, &[7u8; 32]).is_none());
    }

    #[test]
    fn tampered_session_id_fails() {
        let (priv_k, pub_k) = server();
        let mut auth = seal(&pub_k, &[3u8; SHORT_ID_LEN], 1, &[7u8; 32]);
        auth.session_id[0] ^= 0x01;
        assert!(open(&priv_k, &auth.key_share, &auth.session_id, &[7u8; 32]).is_none());
    }

    #[test]
    fn wrong_client_random_fails() {
        let (priv_k, pub_k) = server();
        let auth = seal(&pub_k, &[3u8; SHORT_ID_LEN], 1, &[7u8; 32]);
        // client_random is bound into the KDF; a different one won't decrypt.
        assert!(open(&priv_k, &auth.key_share, &auth.session_id, &[8u8; 32]).is_none());
    }

    #[test]
    fn transplanted_key_share_fails() {
        let (priv_k, pub_k) = server();
        let auth = seal(&pub_k, &[3u8; SHORT_ID_LEN], 1, &[7u8; 32]);
        // Swap in a different (valid) key_share: AAD binding rejects it.
        let other = seal(&pub_k, &[4u8; SHORT_ID_LEN], 1, &[7u8; 32]);
        assert!(open(&priv_k, &other.key_share, &auth.session_id, &[7u8; 32]).is_none());
    }

    #[test]
    fn short_id_membership() {
        let a = [1u8; SHORT_ID_LEN];
        let b = [2u8; SHORT_ID_LEN];
        let set = [a, b];
        assert!(short_id_allowed(&a, &set));
        assert!(short_id_allowed(&b, &set));
        assert!(!short_id_allowed(&[3u8; SHORT_ID_LEN], &set));
        assert!(!short_id_allowed(&a, &[]));
    }

    #[test]
    fn timestamp_freshness() {
        assert!(timestamp_fresh(1000, 1005, 10));
        assert!(timestamp_fresh(1005, 1000, 10));
        assert!(!timestamp_fresh(1000, 1020, 10));
    }

    #[test]
    fn short_id_hex_roundtrip() {
        let id = generate_short_id();
        let hex = short_id_hex(&id);
        assert_eq!(hex.len(), SHORT_ID_LEN * 2);
        assert_eq!(parse_short_id(&hex), Some(id));
    }

    #[test]
    fn parse_short_id_rejects_bad_input() {
        assert!(parse_short_id("abc").is_none()); // too short
        assert!(parse_short_id(&"a".repeat(SHORT_ID_LEN * 2 + 2)).is_none()); // too long
        assert!(parse_short_id(&"zz".repeat(SHORT_ID_LEN)).is_none()); // non-hex
        assert!(parse_short_id("00").is_none()); // wrong length
    }
}
