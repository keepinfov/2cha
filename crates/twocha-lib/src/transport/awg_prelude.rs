//! # AmneziaWG pre-handshake prelude (junk + signature packets)
//!
//! Before each handshake an AWG client sends, in order:
//!
//! 1. **Signature packets I1–I5** — crafted UDP datagrams built from a CPS
//!    (Custom Protocol Signature) template that can mimic a real protocol's
//!    opening bytes (e.g. a QUIC Initial). Tags:
//!    - `<b HEX>`  — literal bytes from a hex string (whitespace ignored)
//!    - `<t>`      — current Unix time as a 32-bit big-endian integer
//!    - `<r N>`    — N cryptographically-random bytes
//!    - `<rc N>`   — N random ASCII letters `[A-Za-z]`
//!    - `<rd N>`   — N random decimal digits `[0-9]`
//!
//!    Text outside `<...>` tags is ignored. Lengths are capped at 1000.
//! 2. **Junk packets** — `Jc` datagrams of random size in `[Jmin, Jmax]` filled
//!    with random bytes.
//!
//! The server needs no special handling: none of these match a configured magic
//! header, so `wire::parse_profile` rejects them and the datapath drops them
//! silently (it never replies to unauthenticated bytes).

use rand::{Rng, RngCore};
use std::time::{SystemTime, UNIX_EPOCH};

use twocha_core::AwgSection;

/// Hard cap on any single random run in a CPS template (matches AmneziaWG).
const MAX_RUN: usize = 1000;

/// Build the ordered list of prelude datagrams (signature packets first, then
/// junk) to send before a handshake init. Empty when nothing is configured.
pub fn build_prelude(awg: &AwgSection) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut rng = rand::thread_rng();

    // I1–I5 signature packets.
    for (i, tmpl) in awg.signature_templates().iter().enumerate() {
        match render_cps(tmpl, &mut rng) {
            Ok(bytes) if !bytes.is_empty() => out.push(bytes),
            Ok(_) => {}
            Err(e) => log::warn!("awg: ignoring signature packet I{}: {}", i + 1, e),
        }
    }

    // Jc junk packets sized in [Jmin, Jmax].
    if awg.jc > 0 && awg.jmax > 0 {
        let (lo, hi) = (awg.jmin.min(awg.jmax), awg.jmax);
        for _ in 0..awg.jc {
            let n = rng.gen_range(lo..=hi) as usize;
            let mut pkt = vec![0u8; n];
            rng.fill_bytes(&mut pkt);
            out.push(pkt);
        }
    }

    out
}

/// Render one CPS template into bytes. Returns a human-readable error on a
/// malformed tag so the offending `IN` can be named in the log.
fn render_cps(tmpl: &str, rng: &mut impl Rng) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let bytes = tmpl.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            let end = tmpl[i..]
                .find('>')
                .map(|off| i + off)
                .ok_or_else(|| "unterminated '<' tag".to_string())?;
            render_tag(tmpl[i + 1..end].trim(), rng, &mut out)?;
            i = end + 1;
        } else {
            // Text outside tags is ignored (AmneziaWG's format is tag-only).
            i += 1;
        }
    }
    Ok(out)
}

fn render_tag(tag: &str, rng: &mut impl Rng, out: &mut Vec<u8>) -> Result<(), String> {
    let mut parts = tag.split_whitespace();
    let name = parts.next().ok_or_else(|| "empty tag".to_string())?;
    match name {
        "b" => {
            let hex: String = parts.collect::<Vec<_>>().concat();
            let bytes = decode_hex(&hex)?;
            out.extend_from_slice(&bytes);
        }
        "t" => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0);
            out.extend_from_slice(&now.to_be_bytes());
        }
        "r" => {
            let n = parse_run_len(parts.next())?;
            let start = out.len();
            out.resize(start + n, 0);
            rng.fill_bytes(&mut out[start..]);
        }
        "rc" => {
            let n = parse_run_len(parts.next())?;
            const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
            for _ in 0..n {
                out.push(ALPHA[rng.gen_range(0..ALPHA.len())]);
            }
        }
        "rd" => {
            let n = parse_run_len(parts.next())?;
            for _ in 0..n {
                out.push(b'0' + rng.gen_range(0..10));
            }
        }
        other => return Err(format!("unknown tag '{}'", other)),
    }
    Ok(())
}

fn parse_run_len(tok: Option<&str>) -> Result<usize, String> {
    let n: usize = tok
        .ok_or_else(|| "tag needs a length".to_string())?
        .parse()
        .map_err(|_| "tag length is not a number".to_string())?;
    if n > MAX_RUN {
        return Err(format!("tag length {} exceeds max {}", n, MAX_RUN));
    }
    Ok(n)
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("hex must have an even number of digits".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "invalid hex".to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cps_static_and_time() {
        let mut rng = rand::thread_rng();
        let b = render_cps("<b 00010203> <t>", &mut rng).unwrap();
        assert_eq!(&b[..4], &[0, 1, 2, 3]);
        assert_eq!(b.len(), 8); // 4 static + 4-byte timestamp
    }

    #[test]
    fn cps_random_runs_have_right_length_and_charset() {
        let mut rng = rand::thread_rng();
        let out = render_cps("<r 5><rc 4><rd 3>", &mut rng).unwrap();
        assert_eq!(out.len(), 12);
        assert!(out[5..9].iter().all(|c| c.is_ascii_alphabetic()));
        assert!(out[9..12].iter().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn cps_errors() {
        let mut rng = rand::thread_rng();
        assert!(render_cps("<b 0>", &mut rng).is_err()); // odd hex
        assert!(render_cps("<zz 3>", &mut rng).is_err()); // unknown tag
        assert!(render_cps("<r 99999>", &mut rng).is_err()); // over cap
        assert!(render_cps("<b 00", &mut rng).is_err()); // unterminated
    }

    #[test]
    fn prelude_counts_signatures_then_junk() {
        let mut awg = AwgSection {
            jc: 3,
            jmin: 10,
            jmax: 20,
            i1: Some("<b deadbeef>".into()),
            ..Default::default()
        };
        let pre = build_prelude(&awg);
        assert_eq!(pre.len(), 4); // 1 signature + 3 junk
        assert_eq!(&pre[0], &[0xde, 0xad, 0xbe, 0xef]);
        for junk in &pre[1..] {
            assert!((10..=20).contains(&junk.len()));
        }
        awg.jc = 0;
        awg.i1 = None;
        assert!(build_prelude(&awg).is_empty());
    }
}
