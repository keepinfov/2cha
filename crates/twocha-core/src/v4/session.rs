//! # Established v4 Session
//!
//! Owns the transport keys, deterministic u64 counters, counter masking,
//! replay window and rekey bookkeeping for one tunnel session.

use rand::{Rng, RngCore};
use std::time::{Duration, Instant};

use crate::crypto::mac::HeaderMask;
use crate::crypto::noise::SessionCrypto;
use twocha_protocol::wire::{self, CID_LEN};
use twocha_protocol::{
    CryptoError, ProtocolError, ReplayWindow, Result, MAX_PACKET_SIZE, POLY1305_TAG_SIZE,
};

/// Initiate a new handshake after this much session time
pub const REKEY_AFTER: Duration = Duration::from_secs(120);
/// Refuse to use session keys older than this
pub const REJECT_AFTER: Duration = Duration::from_secs(180);
/// Initiate rekey after this many outgoing messages
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 48;
/// Keepalive base interval (jittered by the caller)
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Fixed on-wire overhead of a data datagram: short header (17) + inner
/// length prefix (2) + AEAD tag (16) = 35 bytes.
pub const DATA_OVERHEAD: usize = wire::DATA_HEADER_LEN + 2 + POLY1305_TAG_SIZE;

/// Largest tun MTU whose full-size packets always fit in [`MAX_PACKET_SIZE`]
/// even before padding (1500 − 35 = 1465). Config validation rejects larger
/// MTUs; receive paths size their buffers off `MAX_PACKET_SIZE` and drop
/// anything bigger as truncated.
pub const MAX_TUN_MTU: u16 = (MAX_PACKET_SIZE - DATA_OVERHEAD) as u16;

/// Max random padding appended inside the AEAD for data packets.
///
/// Padding policy: the pad is additionally capped so the finished datagram
/// never exceeds [`MAX_PACKET_SIZE`] — an oversized datagram would be
/// truncated by MAX_PACKET_SIZE-sized receive buffers, fail authentication
/// and be silently dropped (~29% of full-MTU packets before the cap).
const DATA_PAD_MAX: usize = 64;
/// Keepalive padding range: their plaintext is empty, so the padding alone
/// determines the on-wire size — keep it wide to kill the size fingerprint
const KEEPALIVE_PAD_MIN: usize = 24;
const KEEPALIVE_PAD_MAX: usize = 256;

/// Reusable scratch space for [`Session::seal_data_into`]: holds the inner
/// plaintext frame between calls so the hot path allocates nothing.
#[derive(Default)]
pub struct SealScratch {
    inner: Vec<u8>,
}

pub struct Session {
    crypto: SessionCrypto,
    tx_mask: HeaderMask,
    rx_mask: HeaderMask,
    /// CID the peer puts on datagrams addressed to us
    pub local_cid: [u8; CID_LEN],
    /// CID we put on datagrams addressed to the peer
    pub remote_cid: [u8; CID_LEN],
    tx_counter: u64,
    replay: ReplayWindow,
    created: Instant,
    pub last_send: Instant,
    pub last_recv: Instant,
    /// True if we initiated the handshake (initiator drives rekeying)
    pub initiator: bool,
}

impl Session {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        crypto: SessionCrypto,
        tx_mask: HeaderMask,
        rx_mask: HeaderMask,
        local_cid: [u8; CID_LEN],
        remote_cid: [u8; CID_LEN],
        initiator: bool,
    ) -> Self {
        let now = Instant::now();
        Session {
            crypto,
            tx_mask,
            rx_mask,
            local_cid,
            remote_cid,
            tx_counter: 0,
            replay: ReplayWindow::new(),
            created: now,
            last_send: now,
            last_recv: now,
            initiator,
        }
    }

    /// Encrypt a payload into a complete on-wire datagram.
    /// An empty payload produces a keepalive (random-size on the wire).
    ///
    /// Convenience wrapper over [`Session::seal_data_into`]; hot paths should
    /// hoist a [`SealScratch`] + output buffer and call the `_into` variant.
    pub fn seal_data(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut scratch = SealScratch::default();
        let mut out = Vec::new();
        self.seal_data_into(payload, &mut scratch, &mut out)?;
        Ok(out)
    }

    /// Encrypt a payload into a complete on-wire datagram written to `out`,
    /// reusing `scratch` and `out` allocations across calls.
    ///
    /// Layout: short header + zeroed counter go into `out` first, the inner
    /// frame (length + payload + random pad) is built in `scratch` and
    /// encrypted directly at `out[DATA_HEADER_LEN..]`, then the counter mask
    /// (which samples the first ciphertext bytes) is patched in.
    pub fn seal_data_into(
        &mut self,
        payload: &[u8],
        scratch: &mut SealScratch,
        out: &mut Vec<u8>,
    ) -> Result<()> {
        if self.expired() {
            return Err(CryptoError::EncryptionFailed.into());
        }
        if payload.len() > u16::MAX as usize {
            return Err(ProtocolError::PacketTooLarge {
                max: u16::MAX as usize,
                got: payload.len(),
            }
            .into());
        }
        self.tx_counter += 1;
        let counter = self.tx_counter;

        let mut rng = rand::thread_rng();
        let pad_len = if payload.is_empty() {
            // Keepalives (35 + at most 256 bytes) always fit in MAX_PACKET_SIZE
            rng.gen_range(KEEPALIVE_PAD_MIN..=KEEPALIVE_PAD_MAX)
        } else {
            let budget = MAX_PACKET_SIZE.saturating_sub(DATA_OVERHEAD + payload.len());
            rng.gen_range(0..=DATA_PAD_MAX.min(budget))
        };

        // Inner framing (u16-BE length + payload + pad), padded in place
        let inner = &mut scratch.inner;
        inner.clear();
        inner.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        inner.extend_from_slice(payload);
        let pad_start = inner.len();
        inner.resize(pad_start + pad_len, 0);
        rng.fill_bytes(&mut inner[pad_start..]);

        out.clear();
        out.resize(wire::DATA_HEADER_LEN + inner.len() + POLY1305_TAG_SIZE, 0);
        out[0] = 0x40 | (rng.gen::<u8>() & 0x3F);
        out[1..1 + CID_LEN].copy_from_slice(&self.remote_cid);
        // out[9..17] stays zeroed until the mask is derived from the ciphertext
        let n = self
            .crypto
            .encrypt_into(counter, inner, &mut out[wire::DATA_HEADER_LEN..])?;
        out.truncate(wire::DATA_HEADER_LEN + n);
        let masked = self
            .tx_mask
            .mask_counter(counter, &out[wire::DATA_HEADER_LEN..]);
        out[1 + CID_LEN..wire::DATA_HEADER_LEN].copy_from_slice(&masked);

        self.last_send = Instant::now();
        Ok(())
    }

    /// Authenticate and decrypt an inbound data datagram (already parsed),
    /// returning the inner payload (empty for keepalives).
    ///
    /// Convenience wrapper over [`Session::open_data_into`]; hot paths should
    /// hoist the output buffer and call the `_into` variant.
    pub fn open_data(&mut self, masked_counter: [u8; 8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.open_data_into(masked_counter, ciphertext, &mut out)?;
        Ok(out)
    }

    /// Authenticate and decrypt an inbound data datagram into `out`, reusing
    /// its allocation across calls. `out` ends holding exactly the inner
    /// payload (empty for keepalives).
    pub fn open_data_into(
        &mut self,
        masked_counter: [u8; 8],
        ciphertext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<()> {
        if self.created.elapsed() > REJECT_AFTER + KEEPALIVE_INTERVAL * 6 {
            return Err(CryptoError::AuthenticationFailed.into());
        }
        let counter = self.rx_mask.unmask_counter(masked_counter, ciphertext);
        out.clear();
        out.resize(ciphertext.len(), 0);
        let n = self.crypto.decrypt_into(counter, ciphertext, out)?;
        out.truncate(n);
        // Replay check AFTER authentication: forged counters must not be able
        // to poison the window.
        if !self.replay.check_and_update(counter) {
            return Err(CryptoError::NonceReuse.into());
        }
        // Strip the inner framing in place (validates the length prefix)
        let payload_len = wire::unframe_inner(out)?.len();
        out.copy_within(2..2 + payload_len, 0);
        out.truncate(payload_len);
        self.last_recv = Instant::now();
        Ok(())
    }

    /// Initiator should start a new handshake (PFS ratchet)
    pub fn should_rekey(&self) -> bool {
        self.initiator
            && (self.created.elapsed() > REKEY_AFTER || self.tx_counter >= REKEY_AFTER_MESSAGES)
    }

    /// Session keys must no longer be used for sending
    pub fn expired(&self) -> bool {
        self.created.elapsed() > REJECT_AFTER || self.tx_counter >= u64::MAX - 1
    }

    pub fn age(&self) -> Duration {
        self.created.elapsed()
    }
}

/// Jittered keepalive interval: base ±30%
pub fn keepalive_jitter() -> Duration {
    let base = KEEPALIVE_INTERVAL.as_millis() as u64;
    let jitter = rand::thread_rng().gen_range(0..=(base * 6 / 10));
    Duration::from_millis(base * 7 / 10 + jitter)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CipherSuite;
    use crate::crypto::noise::Handshake;
    use crate::crypto::Identity;

    fn session_pair() -> (Session, Session) {
        let client_id = Identity::generate();
        let server_id = Identity::generate();

        let mut client = Handshake::new_initiator(
            CipherSuite::ChaCha20Poly1305,
            &client_id.private_bytes(),
            &server_id.public_bytes(),
        )
        .unwrap();
        let mut server =
            Handshake::new_responder(CipherSuite::ChaCha20Poly1305, &server_id.private_bytes())
                .unwrap();

        server
            .read_message(&client.write_message(b"").unwrap())
            .unwrap();
        client
            .read_message(&server.write_message(b"").unwrap())
            .unwrap();

        let seed_client = [1u8; 32];
        let seed_server = [2u8; 32];
        let client_session = Session::new(
            client.into_session().unwrap(),
            HeaderMask::new(&seed_client, &seed_server, 0x01),
            HeaderMask::new(&seed_client, &seed_server, 0x02),
            [3; CID_LEN],
            [4; CID_LEN],
            true,
        );
        let server_session = Session::new(
            server.into_session().unwrap(),
            HeaderMask::new(&seed_client, &seed_server, 0x02),
            HeaderMask::new(&seed_client, &seed_server, 0x01),
            [4; CID_LEN],
            [3; CID_LEN],
            false,
        );
        (client_session, server_session)
    }

    /// Regression for the padding-overflow packet-loss bug: a full-MTU payload
    /// plus random padding must never exceed MAX_PACKET_SIZE, and must still
    /// round-trip through the peer.
    #[test]
    fn seal_data_never_exceeds_max_packet_size() {
        let (mut client, mut server) = session_pair();
        for payload_len in [1420usize, MAX_TUN_MTU as usize] {
            let payload = vec![0xABu8; payload_len];
            for _ in 0..500 {
                let dg = client.seal_data(&payload).unwrap();
                assert!(
                    dg.len() <= MAX_PACKET_SIZE,
                    "datagram {} > MAX_PACKET_SIZE for payload {}",
                    dg.len(),
                    payload_len
                );
                match wire::parse(&dg).unwrap() {
                    wire::WireMsg::Data {
                        masked_counter,
                        ciphertext,
                        ..
                    } => {
                        assert_eq!(
                            server.open_data(masked_counter, ciphertext).unwrap(),
                            payload
                        )
                    }
                    other => panic!("wrong variant: {:?}", other),
                }
            }
        }
    }

    /// The reusable-buffer path must round-trip with shared scratch/out
    /// buffers across many packets (wrapper tests only cover fresh buffers).
    #[test]
    fn seal_open_into_reuses_buffers() {
        let (mut client, mut server) = session_pair();
        let mut scratch = SealScratch::default();
        let mut out = Vec::new();
        let mut payload_buf = Vec::new();
        for i in 0..50usize {
            let payload = vec![i as u8; 64 + i * 7];
            client
                .seal_data_into(&payload, &mut scratch, &mut out)
                .unwrap();
            assert!(out.len() <= MAX_PACKET_SIZE);
            match wire::parse(&out).unwrap() {
                wire::WireMsg::Data {
                    receiver_cid,
                    masked_counter,
                    ciphertext,
                } => {
                    assert_eq!(receiver_cid, client.remote_cid);
                    server
                        .open_data_into(masked_counter, ciphertext, &mut payload_buf)
                        .unwrap();
                    assert_eq!(payload_buf, payload);
                }
                other => panic!("wrong variant: {:?}", other),
            }
        }
    }

    /// Small payloads keep their full random pad range.
    #[test]
    fn seal_data_small_payload_pads_vary() {
        let (mut client, _) = session_pair();
        let sizes: std::collections::HashSet<usize> = (0..200)
            .map(|_| client.seal_data(b"x").unwrap().len())
            .collect();
        assert!(
            sizes.len() > 10,
            "expected varied pad sizes, got {:?}",
            sizes
        );
    }

    /// Keepalive wire size must stay randomized (traffic-shape defense) and
    /// always fit in MAX_PACKET_SIZE.
    #[test]
    fn keepalive_sizes_vary_and_fit() {
        let (mut client, _) = session_pair();
        let sizes: std::collections::HashSet<usize> = (0..200)
            .map(|_| {
                let dg = client.seal_data(b"").unwrap();
                assert!(dg.len() <= MAX_PACKET_SIZE);
                dg.len()
            })
            .collect();
        assert!(
            sizes.len() > 20,
            "expected varied keepalive sizes, got {}",
            sizes.len()
        );
    }
}
