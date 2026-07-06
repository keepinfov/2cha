//! # REALITY short-id utilities
//!
//! Helpers for the REALITY short id: an 8-byte tag a provisioned client
//! presents (hex, sealed into its forged ClientHello `session_id`) so the
//! server can recognize it against a configured allow-list. Generation and hex
//! encode/decode only — the ClientHello sealing/authentication itself is
//! entirely inside the Go `xtls/reality` core (`native/goreality`), which
//! implements the real xtls/reality wire construction (HKDF-SHA256 +
//! AES-GCM); see `docs/reality-go-design.md`.

use rand::rngs::OsRng;

/// Length of a short id: an 8-byte tag distinguishing provisioned clients.
pub const SHORT_ID_LEN: usize = 8;

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
