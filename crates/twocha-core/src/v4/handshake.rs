//! # Handshake Orchestration
//!
//! Builds and consumes complete handshake datagrams (Noise_IK inside the
//! QUIC-mimic framing), including MAC1 verification, cookie challenges and
//! the encrypted exchange of session CIDs and obfuscation seeds.

use rand::{Rng, RngCore};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

use crate::config::CipherSuite;
use crate::crypto::identity::Identity;
use crate::crypto::mac::{
    mac, mac1_key, mac_verify, mac_verify_with, mac_with, open_cookie, CookieFactory, HeaderMask,
    COOKIE_NONCE_LEN,
};
use crate::crypto::noise::Handshake;
use crate::v4::session::Session;
use twocha_protocol::obfs::{AwgParams, MsgClass};
use twocha_protocol::wire::{
    self, LongHeaderRandom, WireMsg, CID_LEN, INIT_PAYLOAD_LEN, MAC_LEN, RESP_PAYLOAD_LEN,
};
use twocha_protocol::{CryptoError, ObfsProfile, ProtocolError, Result, VpnError};

/// Pick a random magic-header value inside the configured range for `class`.
fn pick_header(p: &AwgParams, class: MsgClass) -> u32 {
    let h = p.header(class);
    if h.min == h.max {
        h.min
    } else {
        rand::thread_rng().gen_range(h.min..=h.max)
    }
}

fn long_header_random() -> LongHeaderRandom {
    let mut rng = rand::thread_rng();
    let mut dcid = [0u8; CID_LEN];
    let mut scid = [0u8; CID_LEN];
    rng.fill_bytes(&mut dcid);
    rng.fill_bytes(&mut scid);
    LongHeaderRandom {
        byte0_noise: rng.gen(),
        dcid,
        scid,
    }
}

fn unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

fn random_padding(min: usize, max: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut pad = vec![0u8; rng.gen_range(min..=max)];
    rng.fill_bytes(&mut pad);
    pad
}

/// Client side of one handshake attempt
pub struct ClientHandshake {
    hs: Handshake,
    profile: ObfsProfile,
    local_cid: [u8; CID_LEN],
    seed_local: Zeroizing<[u8; 32]>,
    local_public: [u8; 32],
    server_public: [u8; 32],
    init: Vec<u8>,
    mac1_off: usize,
    mac2_off: usize,
    pub started: Instant,
}

impl ClientHandshake {
    pub fn new(suite: CipherSuite, identity: &Identity, server_public: [u8; 32]) -> Result<Self> {
        Self::with_profile(suite, identity, server_public, ObfsProfile::Quic)
    }

    pub fn with_profile(
        suite: CipherSuite,
        identity: &Identity,
        server_public: [u8; 32],
        profile: ObfsProfile,
    ) -> Result<Self> {
        let mut rng = rand::thread_rng();
        let mut local_cid = [0u8; CID_LEN];
        rng.fill_bytes(&mut local_cid);
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let seed_local = Zeroizing::new(seed);

        let mut hs = Handshake::new_initiator(suite, &identity.private_bytes(), &server_public)?;

        let mut payload = [0u8; INIT_PAYLOAD_LEN];
        payload[..CID_LEN].copy_from_slice(&local_cid);
        payload[CID_LEN..CID_LEN + 32].copy_from_slice(&*seed_local);
        payload[CID_LEN + 32..].copy_from_slice(&unix_nanos().to_le_bytes());

        let noise = hs.write_message(&payload)?;
        let (mut init, mac1_off, mac2_off) = match &profile {
            ObfsProfile::Quic => {
                let padding =
                    random_padding(wire::init_padding_len(0), wire::init_padding_len(120));
                wire::encode_init(&noise, &padding, &long_header_random())?
            }
            ObfsProfile::Awg(p) => {
                let padding = random_padding(0, p.pad_max(MsgClass::Init));
                wire::encode_init_awg(pick_header(p, MsgClass::Init), &noise, &padding)?
            }
        };

        let m1 = mac(&mac1_key(&server_public), &init[..mac1_off]);
        init[mac1_off..mac1_off + MAC_LEN].copy_from_slice(&m1);

        Ok(ClientHandshake {
            hs,
            profile,
            local_cid,
            seed_local,
            local_public: identity.public_bytes(),
            server_public,
            init,
            mac1_off,
            mac2_off,
            started: Instant::now(),
        })
    }

    /// The init datagram to (re)transmit
    pub fn datagram(&self) -> &[u8] {
        &self.init
    }

    /// Process a cookie reply: patch MAC2 into the stored init datagram,
    /// which should then be retransmitted via [`Self::datagram`].
    pub fn apply_cookie(&mut self, nonce: &[u8], sealed: &[u8]) -> Result<()> {
        let mac1 = self.init[self.mac1_off..self.mac1_off + MAC_LEN].to_vec();
        let cookie = open_cookie(&self.server_public, nonce, sealed, &mac1)?;
        let m2 = mac_with(&cookie, &self.init[..self.mac2_off]);
        self.init[self.mac2_off..self.mac2_off + MAC_LEN].copy_from_slice(&m2);
        Ok(())
    }

    /// Consume the server's response datagram and establish the session
    pub fn complete(mut self, resp_datagram: &[u8]) -> Result<Session> {
        let (noise, mac1_region, mac1) = match wire::parse_profile(&self.profile, resp_datagram)? {
            WireMsg::Resp {
                noise,
                mac1_region,
                mac1,
            } => (noise, mac1_region, mac1),
            _ => {
                return Err(
                    ProtocolError::UnexpectedPacket("not a handshake response".into()).into(),
                )
            }
        };
        // Cheap check first: response must carry MAC1 keyed by our public key
        if !mac_verify(&mac1_key(&self.local_public), mac1_region, mac1) {
            return Err(CryptoError::AuthenticationFailed.into());
        }

        let payload = self.hs.read_message(noise)?;
        if payload.len() != RESP_PAYLOAD_LEN {
            return Err(ProtocolError::CorruptedPacket("resp payload".into()).into());
        }
        let mut remote_cid = [0u8; CID_LEN];
        remote_cid.copy_from_slice(&payload[..CID_LEN]);
        let mut seed_remote = [0u8; 32];
        seed_remote.copy_from_slice(&payload[CID_LEN..]);

        if !self.hs.is_handshake_finished() {
            return Err(CryptoError::AuthenticationFailed.into());
        }
        let crypto = self.hs.into_session()?;
        let tx_mask = HeaderMask::new(&self.seed_local, &seed_remote, 0x01);
        let rx_mask = HeaderMask::new(&self.seed_local, &seed_remote, 0x02);
        Ok(Session::new(
            crypto,
            tx_mask,
            rx_mask,
            self.profile.clone(),
            self.local_cid,
            remote_cid,
            true,
        ))
    }
}

/// Result of processing a handshake init on the server
#[allow(clippy::large_enum_variant)] // one-per-handshake, size is irrelevant
pub enum InitOutcome {
    /// Valid handshake: send `datagram` back to the source, install `session`
    Established {
        datagram: Vec<u8>,
        session: Session,
        peer_public: [u8; 32],
    },
    /// Under load: send a cookie challenge back to the source
    CookieReply(Vec<u8>),
    /// Invalid or unauthorized: drop silently, never respond
    Drop,
}

/// Server-side handshake processor (stateless except handshake timestamps)
pub struct ServerHandshakeEngine {
    suite: CipherSuite,
    profile: ObfsProfile,
    identity_private: Zeroizing<[u8; 32]>,
    own_mac1_key: Zeroizing<[u8; 32]>,
    cookie: CookieFactory,
    /// Greatest handshake timestamp seen per peer (anti-replay)
    last_timestamps: HashMap<[u8; 32], u64>,
}

impl ServerHandshakeEngine {
    pub fn new(suite: CipherSuite, identity: &Identity) -> Self {
        Self::with_profile(suite, identity, ObfsProfile::Quic)
    }

    pub fn with_profile(suite: CipherSuite, identity: &Identity, profile: ObfsProfile) -> Self {
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        let public = identity.public_bytes();
        ServerHandshakeEngine {
            suite,
            profile,
            identity_private: identity.private_bytes(),
            own_mac1_key: mac1_key(&public),
            cookie: CookieFactory::new(&public, secret),
            last_timestamps: HashMap::new(),
        }
    }

    /// Rotate the cookie secret (call every ~2 minutes)
    pub fn rotate_cookie_secret(&mut self) {
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        self.cookie.rotate(secret);
    }

    /// Process a datagram already classified as a handshake init.
    ///
    /// `is_allowed` is the peer whitelist check. Any failure results in
    /// [`InitOutcome::Drop`] — the caller must not respond in that case.
    pub fn handle_init(
        &mut self,
        datagram: &[u8],
        src: &SocketAddr,
        under_load: bool,
        is_allowed: impl Fn(&[u8; 32]) -> bool,
    ) -> InitOutcome {
        match self.try_handle_init(datagram, src, under_load, is_allowed) {
            Ok(outcome) => outcome,
            Err(e) => {
                log::debug!("handshake init from {} rejected: {}", src, e);
                InitOutcome::Drop
            }
        }
    }

    fn try_handle_init(
        &mut self,
        datagram: &[u8],
        src: &SocketAddr,
        under_load: bool,
        is_allowed: impl Fn(&[u8; 32]) -> bool,
    ) -> Result<InitOutcome> {
        let (noise, mac1_region, mac1, mac2_region, mac2) =
            match wire::parse_profile(&self.profile, datagram)? {
                WireMsg::Init {
                noise,
                mac1_region,
                mac1,
                mac2_region,
                mac2,
            } => (noise, mac1_region, mac1, mac2_region, mac2),
            _ => return Err(ProtocolError::UnexpectedPacket("not an init".into()).into()),
        };

        // 1. Cheapest check first; failure = silent drop (anti-amplification)
        if !mac_verify(&self.own_mac1_key, mac1_region, mac1) {
            return Ok(InitOutcome::Drop);
        }

        // 2. Under load, require proof of source address via cookie
        let addr_bytes = src.to_string().into_bytes();
        if under_load {
            let cookie = self.cookie.cookie_for(&addr_bytes);
            if !mac_verify_with(&cookie, mac2_region, mac2) {
                let mut nonce = [0u8; COOKIE_NONCE_LEN];
                rand::thread_rng().fill_bytes(&mut nonce);
                let sealed = self.cookie.seal(&nonce, &cookie, mac1)?;
                let reply = match &self.profile {
                    ObfsProfile::Quic => wire::encode_cookie(
                        &nonce,
                        &sealed,
                        &random_padding(8, 64),
                        &long_header_random(),
                    ),
                    ObfsProfile::Awg(p) => wire::encode_cookie_awg(
                        pick_header(p, MsgClass::Cookie),
                        &nonce,
                        &sealed,
                        &random_padding(0, p.pad_max(MsgClass::Cookie)),
                    ),
                };
                return Ok(InitOutcome::CookieReply(reply));
            }
        }

        // 3. Expensive part: Noise_IK message 1 (DH + decrypt static + payload)
        let mut hs = Handshake::new_responder(self.suite, &self.identity_private)?;
        let payload = hs.read_message(noise)?;
        if payload.len() != INIT_PAYLOAD_LEN {
            return Err(ProtocolError::CorruptedPacket("init payload".into()).into());
        }

        // 4. Authorization: peer static key must be whitelisted
        let peer_public = hs
            .remote_static()
            .ok_or_else(|| VpnError::from(CryptoError::AuthenticationFailed))?;
        if !is_allowed(&peer_public) {
            log::warn!("handshake from {} with unauthorized key, dropping", src);
            return Ok(InitOutcome::Drop);
        }

        // 5. Handshake replay protection: timestamp must strictly increase
        let mut client_cid = [0u8; CID_LEN];
        client_cid.copy_from_slice(&payload[..CID_LEN]);
        let mut seed_client = [0u8; 32];
        seed_client.copy_from_slice(&payload[CID_LEN..CID_LEN + 32]);
        let ts = u64::from_le_bytes(payload[CID_LEN + 32..].try_into().expect("8 bytes"));
        if let Some(&last) = self.last_timestamps.get(&peer_public) {
            if ts <= last {
                return Ok(InitOutcome::Drop);
            }
        }
        self.last_timestamps.insert(peer_public, ts);

        // 6. Build response
        let mut rng = rand::thread_rng();
        let mut server_cid = [0u8; CID_LEN];
        rng.fill_bytes(&mut server_cid);
        let mut seed_server = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut *seed_server);

        let mut resp_payload = [0u8; RESP_PAYLOAD_LEN];
        resp_payload[..CID_LEN].copy_from_slice(&server_cid);
        resp_payload[CID_LEN..].copy_from_slice(&*seed_server);
        let resp_noise = hs.write_message(&resp_payload)?;

        let (mut resp, mac1_off) = match &self.profile {
            ObfsProfile::Quic => {
                wire::encode_resp(&resp_noise, &random_padding(24, 160), &long_header_random())?
            }
            ObfsProfile::Awg(p) => wire::encode_resp_awg(
                pick_header(p, MsgClass::Resp),
                &resp_noise,
                &random_padding(0, p.pad_max(MsgClass::Resp)),
            )?,
        };
        let m1 = mac(&mac1_key(&peer_public), &resp[..mac1_off]);
        resp[mac1_off..mac1_off + MAC_LEN].copy_from_slice(&m1);

        let crypto = hs.into_session()?;
        // Responder directions are mirrored relative to the initiator
        let tx_mask = HeaderMask::new(&seed_client, &seed_server, 0x02);
        let rx_mask = HeaderMask::new(&seed_client, &seed_server, 0x01);
        let session = Session::new(
            crypto,
            tx_mask,
            rx_mask,
            self.profile.clone(),
            server_cid,
            client_cid,
            false,
        );

        Ok(InitOutcome::Established {
            datagram: resp,
            session,
            peer_public,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> SocketAddr {
        "203.0.113.7:51000".parse().unwrap()
    }

    fn setup() -> (Identity, Identity, ServerHandshakeEngine) {
        let client_id = Identity::generate();
        let server_id = Identity::generate();
        let engine = ServerHandshakeEngine::new(CipherSuite::ChaCha20Poly1305, &server_id);
        (client_id, server_id, engine)
    }

    #[test]
    fn test_full_handshake_and_data() {
        let (client_id, server_id, mut engine) = setup();
        let client_pub = client_id.public_bytes();

        let ch = ClientHandshake::new(
            CipherSuite::ChaCha20Poly1305,
            &client_id,
            server_id.public_bytes(),
        )
        .unwrap();
        assert!(ch.datagram().len() >= wire::INIT_MIN_DATAGRAM);

        let outcome = engine.handle_init(ch.datagram(), &addr(), false, |k| *k == client_pub);
        let (resp, server_session, peer) = match outcome {
            InitOutcome::Established {
                datagram,
                session,
                peer_public,
            } => (datagram, session, peer_public),
            _ => panic!("expected established"),
        };
        assert_eq!(peer, client_pub);

        let client_session = ch.complete(&resp).unwrap();

        // CIDs are mirrored
        assert_eq!(client_session.remote_cid, server_session.local_cid);
        assert_eq!(client_session.local_cid, server_session.remote_cid);

        // data client -> server
        let dg = client_session.seal_data(b"ping").unwrap();
        match wire::parse(&dg).unwrap() {
            WireMsg::Data {
                receiver_cid,
                masked_counter,
                ciphertext,
            } => {
                assert_eq!(receiver_cid, server_session.local_cid);
                let payload = server_session
                    .open_data(masked_counter, ciphertext)
                    .unwrap();
                assert_eq!(payload, b"ping");
            }
            _ => panic!("expected data"),
        }

        // data server -> client
        let dg = server_session.seal_data(b"pong").unwrap();
        match wire::parse(&dg).unwrap() {
            WireMsg::Data {
                masked_counter,
                ciphertext,
                ..
            } => {
                let payload = client_session
                    .open_data(masked_counter, ciphertext)
                    .unwrap();
                assert_eq!(payload, b"pong");
            }
            _ => panic!("expected data"),
        }
    }

    #[test]
    fn test_full_handshake_and_data_awg() {
        use twocha_protocol::obfs::{AwgParams, HeaderRange};

        // Four disjoint quadrant ranges + non-trivial padding, mirroring what
        // the wizard/config produce.
        let span = 0x00ff_ffffu32;
        let profile = ObfsProfile::Awg(AwgParams {
            headers: [
                HeaderRange::new(0x1000_0000, 0x1000_0000 + span),
                HeaderRange::new(0x5000_0000, 0x5000_0000 + span),
                HeaderRange::new(0x9000_0000, 0x9000_0000 + span),
                HeaderRange::new(0xD000_0000, 0xD000_0000 + span),
            ],
            padding: [24, 40, 24, 16],
        });

        let client_id = Identity::generate();
        let server_id = Identity::generate();
        let client_pub = client_id.public_bytes();
        let mut engine = ServerHandshakeEngine::with_profile(
            CipherSuite::ChaCha20Poly1305,
            &server_id,
            profile.clone(),
        );

        let ch = ClientHandshake::with_profile(
            CipherSuite::ChaCha20Poly1305,
            &client_id,
            server_id.public_bytes(),
            profile.clone(),
        )
        .unwrap();

        // The init must classify as AWG (not the QUIC long header): its leading
        // u32 falls in H1's range and there is no fixed QUIC version byte.
        assert!(matches!(
            wire::parse_profile(&profile, ch.datagram()).unwrap(),
            WireMsg::Init { .. }
        ));

        let (resp, server_session) =
            match engine.handle_init(ch.datagram(), &addr(), false, |k| *k == client_pub) {
                InitOutcome::Established {
                    datagram, session, ..
                } => (datagram, session),
                _ => panic!("expected established"),
            };
        let client_session = ch.complete(&resp).unwrap();

        assert_eq!(client_session.remote_cid, server_session.local_cid);

        // Data round-trips both ways through the AWG framing.
        let dg = client_session.seal_data(b"ping").unwrap();
        match wire::parse_profile(&profile, &dg).unwrap() {
            WireMsg::Data {
                receiver_cid,
                masked_counter,
                ciphertext,
            } => {
                assert_eq!(receiver_cid, server_session.local_cid);
                let payload = server_session
                    .open_data(masked_counter, ciphertext)
                    .unwrap();
                assert_eq!(payload, b"ping");
            }
            _ => panic!("expected data"),
        }

        let dg = server_session.seal_data(b"pong").unwrap();
        match wire::parse_profile(&profile, &dg).unwrap() {
            WireMsg::Data {
                masked_counter,
                ciphertext,
                ..
            } => {
                let payload = client_session
                    .open_data(masked_counter, ciphertext)
                    .unwrap();
                assert_eq!(payload, b"pong");
            }
            _ => panic!("expected data"),
        }
    }

    #[test]
    fn test_profile_mismatch_never_establishes() {
        use twocha_protocol::obfs::{AwgParams, HeaderRange};

        let span = 0x00ff_ffffu32;
        let awg = ObfsProfile::Awg(AwgParams {
            headers: [
                HeaderRange::new(0x1000_0000, 0x1000_0000 + span),
                HeaderRange::new(0x5000_0000, 0x5000_0000 + span),
                HeaderRange::new(0x9000_0000, 0x9000_0000 + span),
                HeaderRange::new(0xD000_0000, 0xD000_0000 + span),
            ],
            padding: [24, 40, 24, 16],
        });

        let client_id = Identity::generate();
        let server_id = Identity::generate();
        let client_pub = client_id.public_bytes();

        // AWG client init against a QUIC server: the server can't classify the
        // datagram as an init, so it drops it (Ignored) — never Established.
        let ch = ClientHandshake::with_profile(
            CipherSuite::ChaCha20Poly1305,
            &client_id,
            server_id.public_bytes(),
            awg.clone(),
        )
        .unwrap();
        let mut quic_engine = ServerHandshakeEngine::new(CipherSuite::ChaCha20Poly1305, &server_id);
        assert!(!matches!(
            quic_engine.handle_init(ch.datagram(), &addr(), false, |k| *k == client_pub),
            InitOutcome::Established { .. }
        ));

        // QUIC client init against an AWG server: same outcome the other way.
        let ch = ClientHandshake::new(
            CipherSuite::ChaCha20Poly1305,
            &client_id,
            server_id.public_bytes(),
        )
        .unwrap();
        let mut awg_engine =
            ServerHandshakeEngine::with_profile(CipherSuite::ChaCha20Poly1305, &server_id, awg);
        assert!(!matches!(
            awg_engine.handle_init(ch.datagram(), &addr(), false, |k| *k == client_pub),
            InitOutcome::Established { .. }
        ));
    }

    #[test]
    fn test_replayed_datagram_rejected() {
        let (client_id, server_id, mut engine) = setup();
        let client_pub = client_id.public_bytes();
        let ch = ClientHandshake::new(
            CipherSuite::ChaCha20Poly1305,
            &client_id,
            server_id.public_bytes(),
        )
        .unwrap();
        let (resp, server_session) =
            match engine.handle_init(ch.datagram(), &addr(), false, |k| *k == client_pub) {
                InitOutcome::Established {
                    datagram, session, ..
                } => (datagram, session),
                _ => panic!(),
            };
        let client_session = ch.complete(&resp).unwrap();

        let dg = client_session.seal_data(b"once").unwrap();
        if let WireMsg::Data {
            masked_counter,
            ciphertext,
            ..
        } = wire::parse(&dg).unwrap()
        {
            assert!(server_session.open_data(masked_counter, ciphertext).is_ok());
            // exact replay must be rejected
            assert!(server_session
                .open_data(masked_counter, ciphertext)
                .is_err());
        } else {
            panic!();
        }
    }

    #[test]
    fn test_unauthorized_peer_dropped() {
        let (client_id, server_id, mut engine) = setup();
        let ch = ClientHandshake::new(
            CipherSuite::ChaCha20Poly1305,
            &client_id,
            server_id.public_bytes(),
        )
        .unwrap();
        // whitelist rejects everyone
        match engine.handle_init(ch.datagram(), &addr(), false, |_| false) {
            InitOutcome::Drop => {}
            _ => panic!("expected drop"),
        }
    }

    #[test]
    fn test_bad_mac1_dropped_silently() {
        let (client_id, server_id, mut engine) = setup();
        let client_pub = client_id.public_bytes();
        let ch = ClientHandshake::new(
            CipherSuite::ChaCha20Poly1305,
            &client_id,
            server_id.public_bytes(),
        )
        .unwrap();
        let mut dg = ch.datagram().to_vec();
        let n = dg.len();
        dg[n - 40] ^= 0xFF; // corrupt inside mac1 region... actually corrupt mac1 itself
        match engine.handle_init(&dg, &addr(), false, |k| *k == client_pub) {
            InitOutcome::Drop => {}
            _ => panic!("expected drop"),
        }
        // pure garbage of plausible size
        let garbage = vec![0x55u8; 1300];
        match engine.handle_init(&garbage, &addr(), false, |_| true) {
            InitOutcome::Drop => {}
            _ => panic!("expected drop"),
        }
    }

    #[test]
    fn test_init_replay_rejected_by_timestamp() {
        let (client_id, server_id, mut engine) = setup();
        let client_pub = client_id.public_bytes();
        let ch = ClientHandshake::new(
            CipherSuite::ChaCha20Poly1305,
            &client_id,
            server_id.public_bytes(),
        )
        .unwrap();
        match engine.handle_init(ch.datagram(), &addr(), false, |k| *k == client_pub) {
            InitOutcome::Established { .. } => {}
            _ => panic!(),
        }
        // replaying the same captured init must be dropped
        match engine.handle_init(ch.datagram(), &addr(), false, |k| *k == client_pub) {
            InitOutcome::Drop => {}
            _ => panic!("expected drop on replayed init"),
        }
    }

    #[test]
    fn test_cookie_flow_under_load() {
        let (client_id, server_id, mut engine) = setup();
        let client_pub = client_id.public_bytes();
        let mut ch = ClientHandshake::new(
            CipherSuite::ChaCha20Poly1305,
            &client_id,
            server_id.public_bytes(),
        )
        .unwrap();

        // under load, init without mac2 gets a cookie challenge
        let reply = match engine.handle_init(ch.datagram(), &addr(), true, |k| *k == client_pub) {
            InitOutcome::CookieReply(r) => r,
            _ => panic!("expected cookie reply"),
        };
        let (nonce, sealed) = match wire::parse(&reply).unwrap() {
            WireMsg::Cookie { nonce, sealed } => (nonce.to_vec(), sealed.to_vec()),
            _ => panic!("expected cookie wire msg"),
        };

        ch.apply_cookie(&nonce, &sealed).unwrap();

        // retransmit with mac2 now succeeds even under load
        match engine.handle_init(ch.datagram(), &addr(), true, |k| *k == client_pub) {
            InitOutcome::Established { datagram, .. } => {
                ch.complete(&datagram).unwrap();
            }
            _ => panic!("expected established after cookie"),
        }
    }

    #[test]
    fn test_keepalive_sizes_vary() {
        let (client_id, server_id, mut engine) = setup();
        let client_pub = client_id.public_bytes();
        let ch = ClientHandshake::new(
            CipherSuite::ChaCha20Poly1305,
            &client_id,
            server_id.public_bytes(),
        )
        .unwrap();
        let resp = match engine.handle_init(ch.datagram(), &addr(), false, |k| *k == client_pub) {
            InitOutcome::Established { datagram, .. } => datagram,
            _ => panic!(),
        };
        let session = ch.complete(&resp).unwrap();

        let sizes: std::collections::HashSet<usize> = (0..16)
            .map(|_| session.seal_data(b"").unwrap().len())
            .collect();
        assert!(
            sizes.len() > 1,
            "keepalive sizes must vary, got {:?}",
            sizes
        );
    }
}
