//! # Established v4 Session
//!
//! Owns the transport keys, deterministic u64 counters, counter masking,
//! replay window and rekey bookkeeping for one tunnel session.

use rand::{Rng, RngCore};
use std::time::{Duration, Instant};

use crate::crypto::mac::HeaderMask;
use crate::crypto::noise::SessionCrypto;
use twocha_protocol::wire::{self, CID_LEN};
use twocha_protocol::{CryptoError, ReplayWindow, Result};

/// Initiate a new handshake after this much session time
pub const REKEY_AFTER: Duration = Duration::from_secs(120);
/// Refuse to use session keys older than this
pub const REJECT_AFTER: Duration = Duration::from_secs(180);
/// Initiate rekey after this many outgoing messages
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 48;
/// Keepalive base interval (jittered by the caller)
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Max random padding appended inside the AEAD for data packets
const DATA_PAD_MAX: usize = 64;
/// Keepalive padding range: their plaintext is empty, so the padding alone
/// determines the on-wire size — keep it wide to kill the size fingerprint
const KEEPALIVE_PAD_MIN: usize = 24;
const KEEPALIVE_PAD_MAX: usize = 256;

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
    pub fn seal_data(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        if self.expired() {
            return Err(CryptoError::EncryptionFailed.into());
        }
        self.tx_counter += 1;
        let counter = self.tx_counter;

        let mut rng = rand::thread_rng();
        let pad_len = if payload.is_empty() {
            rng.gen_range(KEEPALIVE_PAD_MIN..=KEEPALIVE_PAD_MAX)
        } else {
            rng.gen_range(0..=DATA_PAD_MAX)
        };
        let mut padding = vec![0u8; pad_len];
        rng.fill_bytes(&mut padding);

        let inner = wire::frame_inner(payload, &padding)?;
        let ciphertext = self.crypto.encrypt(counter, &inner)?;
        let masked = self.tx_mask.mask_counter(counter, &ciphertext);

        self.last_send = Instant::now();
        Ok(wire::encode_data(
            &self.remote_cid,
            &masked,
            &ciphertext,
            rng.gen(),
        ))
    }

    /// Authenticate and decrypt an inbound data datagram (already parsed),
    /// returning the inner payload (empty for keepalives).
    pub fn open_data(&mut self, masked_counter: [u8; 8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if self.created.elapsed() > REJECT_AFTER + KEEPALIVE_INTERVAL * 6 {
            return Err(CryptoError::AuthenticationFailed.into());
        }
        let counter = self.rx_mask.unmask_counter(masked_counter, ciphertext);
        let plaintext = self.crypto.decrypt(counter, ciphertext)?;
        // Replay check AFTER authentication: forged counters must not be able
        // to poison the window.
        if !self.replay.check_and_update(counter) {
            return Err(CryptoError::NonceReuse.into());
        }
        self.last_recv = Instant::now();
        Ok(wire::unframe_inner(&plaintext)?.to_vec())
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
