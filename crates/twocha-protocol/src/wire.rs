//! # v4 Wire Format (QUIC-mimicry)
//!
//! Every datagram is framed to be indistinguishable from QUIC v1 (RFC 9000)
//! for a passive observer:
//!
//! - Handshake init  -> QUIC Initial   (long header, type 00)
//! - Handshake resp  -> QUIC Handshake (long header, type 10)
//! - Cookie reply    -> QUIC Retry     (long header, type 11)
//! - Data/keepalive  -> QUIC 1-RTT     (short header)
//!
//! No 2cha field appears in plaintext: connection IDs visible on the wire are
//! random throwaways (real session CIDs travel inside the Noise payload),
//! the data-packet counter is masked, everything else is ciphertext or
//! random padding. The only structured plaintext bytes are the ones a real
//! QUIC packet would also have (fixed bit, version 0x00000001, CID lengths).
//!
//! This module is pure byte layout: no crypto, no RNG for secrets. Callers
//! supply random bytes for throwaway CIDs/padding and compute/patch MACs.

use crate::error::{ProtocolError, Result};

/// QUIC version field used in long headers
pub const QUIC_VERSION: u32 = 0x0000_0001;

/// Wire connection ID length (both real session CIDs and throwaway ones)
pub const CID_LEN: usize = 8;

/// Noise_IK message 1 size: e(32) + enc_static(48) + enc_payload(48+16)
pub const NOISE_INIT_LEN: usize = 144;
/// Noise_IK message 2 size: e(32) + enc_payload(40+16)
pub const NOISE_RESP_LEN: usize = 88;

/// Handshake-init Noise payload: receiver CID (8) + obfs seed (32) + timestamp (8)
pub const INIT_PAYLOAD_LEN: usize = 48;
/// Handshake-resp Noise payload: receiver CID (8) + obfs seed (32)
pub const RESP_PAYLOAD_LEN: usize = 40;

pub const MAC_LEN: usize = 16;
pub const COOKIE_NONCE_LEN: usize = 24;
/// Sealed cookie: 16-byte cookie + 16-byte AEAD tag
pub const COOKIE_SEALED_LEN: usize = 32;

/// Long header prefix: byte0 + version(4) + dcil(1) + dcid(8) + scil(1) + scid(8)
const LONG_PREFIX_LEN: usize = 1 + 4 + 1 + CID_LEN + 1 + CID_LEN;
/// Init adds a zero token-length byte; all long headers add a 2-byte length varint
const INIT_HEADER_LEN: usize = LONG_PREFIX_LEN + 1 + 2; // 26
const RESP_HEADER_LEN: usize = LONG_PREFIX_LEN + 2; // 25
const COOKIE_HEADER_LEN: usize = LONG_PREFIX_LEN + 2; // 25

/// Short header: byte0 + dcid(8) + masked counter(8)
pub const DATA_HEADER_LEN: usize = 1 + CID_LEN + 8;

/// Real QUIC clients pad Initials to at least 1200 bytes; so do we.
/// This also caps server response amplification well below 1x.
pub const INIT_MIN_DATAGRAM: usize = 1200;

/// A parsed inbound datagram (zero-copy views into the receive buffer)
#[derive(Debug)]
pub enum WireMsg<'a> {
    /// Client -> server handshake initiation
    Init {
        noise: &'a [u8],
        /// Everything covered by mac1 (datagram up to mac1)
        mac1_region: &'a [u8],
        mac1: &'a [u8],
        /// Everything covered by mac2 (datagram up to mac2)
        mac2_region: &'a [u8],
        mac2: &'a [u8],
    },
    /// Server -> client handshake response
    Resp {
        noise: &'a [u8],
        mac1_region: &'a [u8],
        mac1: &'a [u8],
    },
    /// Server -> client cookie challenge (under load)
    Cookie { nonce: &'a [u8], sealed: &'a [u8] },
    /// Data / keepalive
    Data {
        receiver_cid: [u8; CID_LEN],
        masked_counter: [u8; 8],
        ciphertext: &'a [u8],
    },
}

/// Classify and parse an inbound datagram.
///
/// Returns an error for anything that is not plausibly ours; callers MUST
/// drop such datagrams silently (never respond to unauthenticated garbage).
pub fn parse(buf: &[u8]) -> Result<WireMsg<'_>> {
    if buf.len() < DATA_HEADER_LEN + MAC_LEN + 2 {
        return Err(too_small(buf.len()));
    }
    let b0 = buf[0];
    // Fixed bit must be set in all QUIC packets (and all of ours)
    if b0 & 0x40 == 0 {
        return Err(ProtocolError::CorruptedPacket("fixed bit".into()).into());
    }
    if b0 & 0x80 == 0 {
        // Short header -> data packet
        let mut receiver_cid = [0u8; CID_LEN];
        receiver_cid.copy_from_slice(&buf[1..1 + CID_LEN]);
        let mut masked_counter = [0u8; 8];
        masked_counter.copy_from_slice(&buf[1 + CID_LEN..DATA_HEADER_LEN]);
        return Ok(WireMsg::Data {
            receiver_cid,
            masked_counter,
            ciphertext: &buf[DATA_HEADER_LEN..],
        });
    }

    // Long header
    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    if version != QUIC_VERSION {
        return Err(ProtocolError::InvalidVersion {
            expected: 1,
            got: (version & 0xff) as u8,
        }
        .into());
    }
    if buf[5] as usize != CID_LEN {
        return Err(ProtocolError::CorruptedPacket("dcid len".into()).into());
    }
    let scil_off = 6 + CID_LEN;
    if buf[scil_off] as usize != CID_LEN {
        return Err(ProtocolError::CorruptedPacket("scid len".into()).into());
    }

    match (b0 >> 4) & 0x03 {
        0b00 => {
            // Initial -> handshake init
            if buf.len() < INIT_HEADER_LEN + NOISE_INIT_LEN + 2 * MAC_LEN {
                return Err(too_small(buf.len()));
            }
            if buf[LONG_PREFIX_LEN] != 0x00 {
                return Err(ProtocolError::CorruptedPacket("token len".into()).into());
            }
            check_length_varint(&buf[LONG_PREFIX_LEN + 1..], buf.len() - INIT_HEADER_LEN)?;
            let len = buf.len();
            Ok(WireMsg::Init {
                noise: &buf[INIT_HEADER_LEN..INIT_HEADER_LEN + NOISE_INIT_LEN],
                mac1_region: &buf[..len - 2 * MAC_LEN],
                mac1: &buf[len - 2 * MAC_LEN..len - MAC_LEN],
                mac2_region: &buf[..len - MAC_LEN],
                mac2: &buf[len - MAC_LEN..],
            })
        }
        0b10 => {
            // Handshake -> handshake response
            if buf.len() < RESP_HEADER_LEN + NOISE_RESP_LEN + MAC_LEN {
                return Err(too_small(buf.len()));
            }
            check_length_varint(&buf[LONG_PREFIX_LEN..], buf.len() - RESP_HEADER_LEN)?;
            let len = buf.len();
            Ok(WireMsg::Resp {
                noise: &buf[RESP_HEADER_LEN..RESP_HEADER_LEN + NOISE_RESP_LEN],
                mac1_region: &buf[..len - MAC_LEN],
                mac1: &buf[len - MAC_LEN..],
            })
        }
        0b11 => {
            // Retry -> cookie reply
            let need = COOKIE_HEADER_LEN + COOKIE_NONCE_LEN + COOKIE_SEALED_LEN;
            if buf.len() < need {
                return Err(too_small(buf.len()));
            }
            check_length_varint(&buf[LONG_PREFIX_LEN..], buf.len() - COOKIE_HEADER_LEN)?;
            Ok(WireMsg::Cookie {
                nonce: &buf[COOKIE_HEADER_LEN..COOKIE_HEADER_LEN + COOKIE_NONCE_LEN],
                sealed: &buf[COOKIE_HEADER_LEN + COOKIE_NONCE_LEN
                    ..COOKIE_HEADER_LEN + COOKIE_NONCE_LEN + COOKIE_SEALED_LEN],
            })
        }
        _ => Err(ProtocolError::InvalidPacketType(b0).into()),
    }
}

fn too_small(got: usize) -> crate::VpnError {
    ProtocolError::PacketTooSmall {
        min: DATA_HEADER_LEN + MAC_LEN,
        got,
    }
    .into()
}

fn check_length_varint(buf: &[u8], expected: usize) -> Result<()> {
    if buf.len() < 2 || buf[0] & 0xC0 != 0x40 {
        return Err(ProtocolError::CorruptedPacket("length varint".into()).into());
    }
    let v = ((buf[0] as usize & 0x3F) << 8) | buf[1] as usize;
    if v != expected {
        return Err(ProtocolError::CorruptedPacket("length mismatch".into()).into());
    }
    Ok(())
}

fn put_length_varint(out: &mut Vec<u8>, v: usize) {
    debug_assert!(v <= 0x3FFF);
    out.push(0x40 | (v >> 8) as u8);
    out.push((v & 0xFF) as u8);
}

/// Random bytes the caller must supply to build a long-header packet:
/// low nibble noise for byte0, throwaway DCID/SCID.
pub struct LongHeaderRandom {
    pub byte0_noise: u8,
    pub dcid: [u8; CID_LEN],
    pub scid: [u8; CID_LEN],
}

fn push_long_prefix(out: &mut Vec<u8>, type_bits: u8, rnd: &LongHeaderRandom) {
    out.push(0xC0 | (type_bits << 4) | (rnd.byte0_noise & 0x0F));
    out.extend_from_slice(&QUIC_VERSION.to_be_bytes());
    out.push(CID_LEN as u8);
    out.extend_from_slice(&rnd.dcid);
    out.push(CID_LEN as u8);
    out.extend_from_slice(&rnd.scid);
}

/// Build a handshake-init datagram with zeroed MAC fields.
///
/// `padding` is caller-supplied random bytes sized so that the final datagram
/// is at least [`INIT_MIN_DATAGRAM`] bytes. Returns the buffer plus the byte
/// offsets of mac1 and mac2 for the caller to patch in.
pub fn encode_init(
    noise: &[u8],
    padding: &[u8],
    rnd: &LongHeaderRandom,
) -> Result<(Vec<u8>, usize, usize)> {
    if noise.len() != NOISE_INIT_LEN {
        return Err(ProtocolError::CorruptedPacket("init noise len".into()).into());
    }
    let body = noise.len() + padding.len() + 2 * MAC_LEN;
    let mut out = Vec::with_capacity(INIT_HEADER_LEN + body);
    push_long_prefix(&mut out, 0b00, rnd);
    out.push(0x00); // token length
    put_length_varint(&mut out, body);
    out.extend_from_slice(noise);
    out.extend_from_slice(padding);
    let mac1_off = out.len();
    out.extend_from_slice(&[0u8; MAC_LEN]);
    let mac2_off = out.len();
    out.extend_from_slice(&[0u8; MAC_LEN]);
    Ok((out, mac1_off, mac2_off))
}

/// Padding needed so an init datagram reaches the QUIC-typical minimum,
/// plus 0..=extra_jitter random extra bytes.
pub fn init_padding_len(extra_jitter: usize) -> usize {
    INIT_MIN_DATAGRAM - (INIT_HEADER_LEN + NOISE_INIT_LEN + 2 * MAC_LEN) + extra_jitter
}

/// Build a handshake-response datagram with a zeroed MAC1 field.
pub fn encode_resp(
    noise: &[u8],
    padding: &[u8],
    rnd: &LongHeaderRandom,
) -> Result<(Vec<u8>, usize)> {
    if noise.len() != NOISE_RESP_LEN {
        return Err(ProtocolError::CorruptedPacket("resp noise len".into()).into());
    }
    let body = noise.len() + padding.len() + MAC_LEN;
    let mut out = Vec::with_capacity(RESP_HEADER_LEN + body);
    push_long_prefix(&mut out, 0b10, rnd);
    put_length_varint(&mut out, body);
    out.extend_from_slice(noise);
    out.extend_from_slice(padding);
    let mac1_off = out.len();
    out.extend_from_slice(&[0u8; MAC_LEN]);
    Ok((out, mac1_off))
}

/// Build a cookie-reply datagram (no MAC: it is stateless and self-contained)
pub fn encode_cookie(
    nonce: &[u8; COOKIE_NONCE_LEN],
    sealed: &[u8; COOKIE_SEALED_LEN],
    padding: &[u8],
    rnd: &LongHeaderRandom,
) -> Vec<u8> {
    let body = COOKIE_NONCE_LEN + COOKIE_SEALED_LEN + padding.len();
    let mut out = Vec::with_capacity(COOKIE_HEADER_LEN + body);
    push_long_prefix(&mut out, 0b11, rnd);
    put_length_varint(&mut out, body);
    out.extend_from_slice(nonce);
    out.extend_from_slice(sealed);
    out.extend_from_slice(padding);
    out
}

/// Build a data datagram (short header). `byte0_noise` randomizes the
/// spin/reserved/key-phase/pn-length bits like header protection would.
pub fn encode_data(
    receiver_cid: &[u8; CID_LEN],
    masked_counter: &[u8; 8],
    ciphertext: &[u8],
    byte0_noise: u8,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(DATA_HEADER_LEN + ciphertext.len());
    out.push(0x40 | (byte0_noise & 0x3F));
    out.extend_from_slice(receiver_cid);
    out.extend_from_slice(masked_counter);
    out.extend_from_slice(ciphertext);
    out
}

/// Frame an inner payload before encryption: u16-BE length + payload + padding.
/// Keepalives are simply empty payloads with random padding.
pub fn frame_inner(payload: &[u8], padding: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(ProtocolError::PacketTooLarge {
            max: u16::MAX as usize,
            got: payload.len(),
        }
        .into());
    }
    let mut out = Vec::with_capacity(2 + payload.len() + padding.len());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(padding);
    Ok(out)
}

/// Strip inner framing after decryption, returning the payload.
pub fn unframe_inner(plaintext: &[u8]) -> Result<&[u8]> {
    if plaintext.len() < 2 {
        return Err(too_small(plaintext.len()));
    }
    let len = u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize;
    plaintext
        .get(2..2 + len)
        .ok_or_else(|| ProtocolError::CorruptedPacket("inner length".into()).into())
}

// ═══════════════════════════════════════════════════════════════════════════
// AmneziaWG-2.0-style framing
//
// No fixed bytes: every datagram opens with a random 4-byte "magic header"
// drawn from a configured per-class range. The receiver classifies by which
// range the leading big-endian u32 falls into. Layouts:
//   init:   H1(4) + noise(144) + S1 pad + mac1(16) + mac2(16)
//   resp:   H2(4) + noise(88)  + S2 pad + mac1(16)
//   cookie: H3(4) + nonce(24)  + sealed(32) + S3 pad
//   data:   H4(4) + receiver_cid(8) + masked_counter(8) + ciphertext
// (Data padding is carried inside the AEAD, not appended, since trailing bytes
// can't be told from ciphertext — see `AwgParams::padding`.)
// ═══════════════════════════════════════════════════════════════════════════

use crate::obfs::{AwgParams, MsgClass, ObfsProfile};

/// Length of the AmneziaWG magic header.
pub const AWG_HEADER_LEN: usize = 4;
/// AmneziaWG data header: magic header + receiver CID + masked counter.
pub const AWG_DATA_HEADER_LEN: usize = AWG_HEADER_LEN + CID_LEN + 8;

/// Build an AWG handshake-init datagram with zeroed MAC fields, returning the
/// buffer plus the mac1/mac2 offsets for the caller to patch.
pub fn encode_init_awg(
    header: u32,
    noise: &[u8],
    padding: &[u8],
) -> Result<(Vec<u8>, usize, usize)> {
    if noise.len() != NOISE_INIT_LEN {
        return Err(ProtocolError::CorruptedPacket("init noise len".into()).into());
    }
    let mut out = Vec::with_capacity(AWG_HEADER_LEN + noise.len() + padding.len() + 2 * MAC_LEN);
    out.extend_from_slice(&header.to_be_bytes());
    out.extend_from_slice(noise);
    out.extend_from_slice(padding);
    let mac1_off = out.len();
    out.extend_from_slice(&[0u8; MAC_LEN]);
    let mac2_off = out.len();
    out.extend_from_slice(&[0u8; MAC_LEN]);
    Ok((out, mac1_off, mac2_off))
}

/// Build an AWG handshake-response datagram with a zeroed MAC1 field.
pub fn encode_resp_awg(header: u32, noise: &[u8], padding: &[u8]) -> Result<(Vec<u8>, usize)> {
    if noise.len() != NOISE_RESP_LEN {
        return Err(ProtocolError::CorruptedPacket("resp noise len".into()).into());
    }
    let mut out = Vec::with_capacity(AWG_HEADER_LEN + noise.len() + padding.len() + MAC_LEN);
    out.extend_from_slice(&header.to_be_bytes());
    out.extend_from_slice(noise);
    out.extend_from_slice(padding);
    let mac1_off = out.len();
    out.extend_from_slice(&[0u8; MAC_LEN]);
    Ok((out, mac1_off))
}

/// Build an AWG cookie-reply datagram (stateless, no MAC).
pub fn encode_cookie_awg(
    header: u32,
    nonce: &[u8; COOKIE_NONCE_LEN],
    sealed: &[u8; COOKIE_SEALED_LEN],
    padding: &[u8],
) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(AWG_HEADER_LEN + COOKIE_NONCE_LEN + COOKIE_SEALED_LEN + padding.len());
    out.extend_from_slice(&header.to_be_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(sealed);
    out.extend_from_slice(padding);
    out
}

/// Classify and parse an inbound AWG datagram against the header ranges.
/// Returns an error for anything that matches no range or is too small;
/// callers MUST drop such datagrams silently.
pub fn parse_awg<'a>(params: &AwgParams, buf: &'a [u8]) -> Result<WireMsg<'a>> {
    if buf.len() < AWG_HEADER_LEN {
        return Err(too_small(buf.len()));
    }
    let header = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let class = params
        .classify(header)
        .ok_or_else(|| ProtocolError::CorruptedPacket("awg magic header".into()))?;
    let len = buf.len();
    match class {
        MsgClass::Init => {
            if len < AWG_HEADER_LEN + NOISE_INIT_LEN + 2 * MAC_LEN {
                return Err(too_small(len));
            }
            Ok(WireMsg::Init {
                noise: &buf[AWG_HEADER_LEN..AWG_HEADER_LEN + NOISE_INIT_LEN],
                mac1_region: &buf[..len - 2 * MAC_LEN],
                mac1: &buf[len - 2 * MAC_LEN..len - MAC_LEN],
                mac2_region: &buf[..len - MAC_LEN],
                mac2: &buf[len - MAC_LEN..],
            })
        }
        MsgClass::Resp => {
            if len < AWG_HEADER_LEN + NOISE_RESP_LEN + MAC_LEN {
                return Err(too_small(len));
            }
            Ok(WireMsg::Resp {
                noise: &buf[AWG_HEADER_LEN..AWG_HEADER_LEN + NOISE_RESP_LEN],
                mac1_region: &buf[..len - MAC_LEN],
                mac1: &buf[len - MAC_LEN..],
            })
        }
        MsgClass::Cookie => {
            let need = AWG_HEADER_LEN + COOKIE_NONCE_LEN + COOKIE_SEALED_LEN;
            if len < need {
                return Err(too_small(len));
            }
            Ok(WireMsg::Cookie {
                nonce: &buf[AWG_HEADER_LEN..AWG_HEADER_LEN + COOKIE_NONCE_LEN],
                sealed: &buf[AWG_HEADER_LEN + COOKIE_NONCE_LEN..need],
            })
        }
        MsgClass::Data => {
            if len < AWG_DATA_HEADER_LEN {
                return Err(too_small(len));
            }
            let mut receiver_cid = [0u8; CID_LEN];
            receiver_cid.copy_from_slice(&buf[AWG_HEADER_LEN..AWG_HEADER_LEN + CID_LEN]);
            let mut masked_counter = [0u8; 8];
            masked_counter.copy_from_slice(&buf[AWG_HEADER_LEN + CID_LEN..AWG_DATA_HEADER_LEN]);
            Ok(WireMsg::Data {
                receiver_cid,
                masked_counter,
                ciphertext: &buf[AWG_DATA_HEADER_LEN..],
            })
        }
    }
}

/// Parse an inbound datagram under the active obfuscation profile.
pub fn parse_profile<'a>(profile: &ObfsProfile, buf: &'a [u8]) -> Result<WireMsg<'a>> {
    match profile {
        ObfsProfile::Quic => parse(buf),
        ObfsProfile::Awg(p) => parse_awg(p, buf),
    }
}

/// On-wire data header length for a profile: the bytes before the ciphertext.
pub fn data_header_len(profile: &ObfsProfile) -> usize {
    match profile {
        ObfsProfile::Quic => DATA_HEADER_LEN,
        ObfsProfile::Awg(_) => AWG_DATA_HEADER_LEN,
    }
}

/// Byte offset of the (masked) counter within a data header, for a profile.
pub fn data_counter_offset(profile: &ObfsProfile) -> usize {
    match profile {
        ObfsProfile::Quic => 1 + CID_LEN,
        ObfsProfile::Awg(_) => AWG_HEADER_LEN + CID_LEN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rnd() -> LongHeaderRandom {
        LongHeaderRandom {
            byte0_noise: 0x0A,
            dcid: [1; CID_LEN],
            scid: [2; CID_LEN],
        }
    }

    #[test]
    fn test_init_roundtrip() {
        let noise = [7u8; NOISE_INIT_LEN];
        let padding = vec![9u8; init_padding_len(13)];
        let (mut pkt, mac1_off, mac2_off) = encode_init(&noise, &padding, &rnd()).unwrap();
        assert!(pkt.len() >= INIT_MIN_DATAGRAM);
        pkt[mac1_off..mac1_off + MAC_LEN].copy_from_slice(&[0xAA; MAC_LEN]);
        pkt[mac2_off..mac2_off + MAC_LEN].copy_from_slice(&[0xBB; MAC_LEN]);

        match parse(&pkt).unwrap() {
            WireMsg::Init {
                noise: n,
                mac1,
                mac2,
                mac1_region,
                mac2_region,
            } => {
                assert_eq!(n, &noise[..]);
                assert_eq!(mac1, &[0xAA; MAC_LEN]);
                assert_eq!(mac2, &[0xBB; MAC_LEN]);
                assert_eq!(mac1_region.len(), pkt.len() - 2 * MAC_LEN);
                assert_eq!(mac2_region.len(), pkt.len() - MAC_LEN);
            }
            other => panic!("wrong variant: {:?}", other),
        }
    }

    #[test]
    fn test_resp_roundtrip() {
        let noise = [3u8; NOISE_RESP_LEN];
        let (pkt, mac1_off) = encode_resp(&noise, &[5u8; 40], &rnd()).unwrap();
        assert_eq!(mac1_off, pkt.len() - MAC_LEN);
        match parse(&pkt).unwrap() {
            WireMsg::Resp { noise: n, .. } => assert_eq!(n, &noise[..]),
            other => panic!("wrong variant: {:?}", other),
        }
    }

    #[test]
    fn test_cookie_roundtrip() {
        let pkt = encode_cookie(
            &[4; COOKIE_NONCE_LEN],
            &[6; COOKIE_SEALED_LEN],
            &[0; 20],
            &rnd(),
        );
        match parse(&pkt).unwrap() {
            WireMsg::Cookie { nonce, sealed } => {
                assert_eq!(nonce, &[4; COOKIE_NONCE_LEN]);
                assert_eq!(sealed, &[6; COOKIE_SEALED_LEN]);
            }
            other => panic!("wrong variant: {:?}", other),
        }
    }

    #[test]
    fn test_data_roundtrip() {
        let ct = vec![8u8; 64];
        let pkt = encode_data(&[1; CID_LEN], &[2; 8], &ct, 0xFF);
        assert_eq!(pkt[0] & 0xC0, 0x40); // short header, fixed bit set
        match parse(&pkt).unwrap() {
            WireMsg::Data {
                receiver_cid,
                masked_counter,
                ciphertext,
            } => {
                assert_eq!(receiver_cid, [1; CID_LEN]);
                assert_eq!(masked_counter, [2; 8]);
                assert_eq!(ciphertext, &ct[..]);
            }
            other => panic!("wrong variant: {:?}", other),
        }
    }

    #[test]
    fn test_inner_framing() {
        let framed = frame_inner(b"payload", &[0xCC; 17]).unwrap();
        assert_eq!(unframe_inner(&framed).unwrap(), b"payload");
        // keepalive: empty payload
        let ka = frame_inner(b"", &[0xCC; 31]).unwrap();
        assert_eq!(unframe_inner(&ka).unwrap(), b"");
    }

    #[test]
    fn test_parse_rejects_garbage() {
        assert!(parse(&[]).is_err());
        assert!(parse(&[0u8; 10]).is_err());
        // fixed bit clear
        let mut pkt = encode_data(&[1; CID_LEN], &[2; 8], &[0; 40], 0);
        pkt[0] &= !0x40;
        assert!(parse(&pkt).is_err());
        // wrong version in long header
        let noise = [3u8; NOISE_RESP_LEN];
        let (mut pkt, _) = encode_resp(&noise, &[], &rnd()).unwrap();
        pkt[4] = 0x05;
        assert!(parse(&pkt).is_err());
    }

    #[test]
    fn test_length_varint_mismatch_rejected() {
        let noise = [3u8; NOISE_RESP_LEN];
        let (mut pkt, _) = encode_resp(&noise, &[5u8; 40], &rnd()).unwrap();
        pkt.push(0xEE); // trailing junk breaks declared length
        assert!(parse(&pkt).is_err());
    }

    fn awg_params() -> AwgParams {
        AwgParams {
            headers: [
                crate::obfs::HeaderRange::new(0x1000_0000, 0x1000_ffff),
                crate::obfs::HeaderRange::new(0x2000_0000, 0x2000_ffff),
                crate::obfs::HeaderRange::new(0x3000_0000, 0x3000_ffff),
                crate::obfs::HeaderRange::new(0x4000_0000, 0x4000_ffff),
            ],
            padding: [24, 24, 24, 24],
        }
    }

    #[test]
    fn test_awg_init_roundtrip() {
        let p = awg_params();
        let noise = [7u8; NOISE_INIT_LEN];
        let (mut pkt, mac1_off, mac2_off) =
            encode_init_awg(0x1000_1234, &noise, &[9u8; 20]).unwrap();
        pkt[mac1_off..mac1_off + MAC_LEN].copy_from_slice(&[0xAA; MAC_LEN]);
        pkt[mac2_off..mac2_off + MAC_LEN].copy_from_slice(&[0xBB; MAC_LEN]);
        match parse_awg(&p, &pkt).unwrap() {
            WireMsg::Init {
                noise: n,
                mac1,
                mac2,
                mac1_region,
                mac2_region,
            } => {
                assert_eq!(n, &noise[..]);
                assert_eq!(mac1, &[0xAA; MAC_LEN]);
                assert_eq!(mac2, &[0xBB; MAC_LEN]);
                assert_eq!(mac1_region.len(), pkt.len() - 2 * MAC_LEN);
                assert_eq!(mac2_region.len(), pkt.len() - MAC_LEN);
            }
            other => panic!("wrong variant: {:?}", other),
        }
    }

    #[test]
    fn test_awg_resp_and_cookie_roundtrip() {
        let p = awg_params();
        let noise = [3u8; NOISE_RESP_LEN];
        let (pkt, mac1_off) = encode_resp_awg(0x2000_abcd, &noise, &[5u8; 8]).unwrap();
        assert_eq!(mac1_off, pkt.len() - MAC_LEN);
        assert!(matches!(parse_awg(&p, &pkt).unwrap(), WireMsg::Resp { .. }));

        let ck = encode_cookie_awg(
            0x3000_0001,
            &[4; COOKIE_NONCE_LEN],
            &[6; COOKIE_SEALED_LEN],
            &[0; 12],
        );
        match parse_awg(&p, &ck).unwrap() {
            WireMsg::Cookie { nonce, sealed } => {
                assert_eq!(nonce, &[4; COOKIE_NONCE_LEN]);
                assert_eq!(sealed, &[6; COOKIE_SEALED_LEN]);
            }
            other => panic!("wrong variant: {:?}", other),
        }
    }

    #[test]
    fn test_awg_data_layout_and_reject() {
        let p = awg_params();
        // Build a data datagram by hand the way the session hot path does.
        let ct = vec![8u8; 40];
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0x4000_5678u32.to_be_bytes());
        pkt.extend_from_slice(&[1u8; CID_LEN]);
        pkt.extend_from_slice(&[2u8; 8]);
        pkt.extend_from_slice(&ct);
        match parse_awg(&p, &pkt).unwrap() {
            WireMsg::Data {
                receiver_cid,
                masked_counter,
                ciphertext,
            } => {
                assert_eq!(receiver_cid, [1u8; CID_LEN]);
                assert_eq!(masked_counter, [2u8; 8]);
                assert_eq!(ciphertext, &ct[..]);
            }
            other => panic!("wrong variant: {:?}", other),
        }
        // A header matching no configured range is rejected (junk drops silently).
        let mut junk = pkt.clone();
        junk[0..4].copy_from_slice(&0x0BAD_0000u32.to_be_bytes());
        assert!(parse_awg(&p, &junk).is_err());
        assert!(parse_awg(&p, &[0u8; 3]).is_err());
    }
}
