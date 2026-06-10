//! # Noise_IK Handshake
//!
//! Thin wrapper over `snow` implementing the v4 key exchange:
//! `Noise_IK_25519_<cipher>_<hash>`. The initiator (client) knows the
//! responder's (server's) static public key in advance; the responder
//! learns and authenticates the initiator's static key from message 1.
//!
//! After the 2-message handshake both sides hold a [`SessionCrypto`]
//! (stateless transport) addressed by explicit u64 counters, which fits
//! out-of-order UDP delivery and deterministic counter nonces.

use snow::{Builder, HandshakeState, StatelessTransportState};

use crate::config::CipherSuite;
use twocha_protocol::{CryptoError, Result, VpnError};

/// Maximum Noise message size we ever produce (handshake payloads are tiny)
pub const MAX_NOISE_MSG: usize = 1024;

fn pattern(suite: CipherSuite) -> &'static str {
    match suite {
        CipherSuite::ChaCha20Poly1305 => "Noise_IK_25519_ChaChaPoly_BLAKE2s",
        CipherSuite::Aes256Gcm => "Noise_IK_25519_AESGCM_SHA256",
    }
}

fn crypto_err<E: std::fmt::Display>(e: E) -> VpnError {
    log::debug!("noise: {}", e);
    CryptoError::AuthenticationFailed.into()
}

/// One side of an in-progress IK handshake
pub struct Handshake {
    state: HandshakeState,
}

impl Handshake {
    /// Client side: requires our static private key and the server's public key
    pub fn new_initiator(
        suite: CipherSuite,
        local_private: &[u8; 32],
        server_public: &[u8; 32],
    ) -> Result<Self> {
        let state = Builder::new(pattern(suite).parse().map_err(crypto_err)?)
            .local_private_key(local_private)
            .remote_public_key(server_public)
            .build_initiator()
            .map_err(crypto_err)?;
        Ok(Handshake { state })
    }

    /// Server side: requires only our static private key
    pub fn new_responder(suite: CipherSuite, local_private: &[u8; 32]) -> Result<Self> {
        let state = Builder::new(pattern(suite).parse().map_err(crypto_err)?)
            .local_private_key(local_private)
            .build_responder()
            .map_err(crypto_err)?;
        Ok(Handshake { state })
    }

    /// Produce the next handshake message (with optional payload)
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; MAX_NOISE_MSG];
        let n = self
            .state
            .write_message(payload, &mut buf)
            .map_err(crypto_err)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Consume a handshake message, returning its payload
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; MAX_NOISE_MSG];
        let n = self
            .state
            .read_message(message, &mut buf)
            .map_err(crypto_err)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Static public key of the remote peer (known after reading message 1
    /// on the responder side). Used for whitelist checks.
    pub fn remote_static(&self) -> Option<[u8; 32]> {
        self.state
            .get_remote_static()
            .and_then(|s| s.try_into().ok())
    }

    pub fn is_handshake_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Finish the handshake and derive transport keys
    pub fn into_session(self) -> Result<SessionCrypto> {
        let transport = self
            .state
            .into_stateless_transport_mode()
            .map_err(crypto_err)?;
        Ok(SessionCrypto { transport })
    }
}

/// Established session crypto with explicit nonces (out-of-order safe)
pub struct SessionCrypto {
    transport: StatelessTransportState,
}

impl SessionCrypto {
    /// Encrypt `plaintext` under the given counter. Output = ciphertext || tag.
    pub fn encrypt(&self, counter: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; plaintext.len() + 16];
        let n = self
            .transport
            .write_message(counter, plaintext, &mut buf)
            .map_err(|_| VpnError::from(CryptoError::EncryptionFailed))?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Decrypt and authenticate a message sent under `counter`
    pub fn decrypt(&self, counter: u64, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 16 {
            return Err(CryptoError::AuthenticationFailed.into());
        }
        let mut buf = vec![0u8; ciphertext.len()];
        let n = self
            .transport
            .read_message(counter, ciphertext, &mut buf)
            .map_err(|_| VpnError::from(CryptoError::AuthenticationFailed))?;
        buf.truncate(n);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::Identity;

    fn handshake_pair(suite: CipherSuite) -> (SessionCrypto, SessionCrypto, [u8; 32]) {
        let client_id = Identity::generate();
        let server_id = Identity::generate();

        let mut client =
            Handshake::new_initiator(suite, &client_id.private_bytes(), &server_id.public_bytes())
                .unwrap();
        let mut server = Handshake::new_responder(suite, &server_id.private_bytes()).unwrap();

        // msg 1: client -> server
        let m1 = client.write_message(b"").unwrap();
        server.read_message(&m1).unwrap();

        // server learns and can authenticate the client's static key
        let remote = server.remote_static().unwrap();
        assert_eq!(remote, client_id.public_bytes());

        // msg 2: server -> client
        let m2 = server.write_message(b"").unwrap();
        client.read_message(&m2).unwrap();

        assert!(client.is_handshake_finished());
        assert!(server.is_handshake_finished());

        (
            client.into_session().unwrap(),
            server.into_session().unwrap(),
            remote,
        )
    }

    #[test]
    fn test_ik_handshake_chacha() {
        let (client, server, _) = handshake_pair(CipherSuite::ChaCha20Poly1305);
        let ct = client.encrypt(0, b"hello").unwrap();
        assert_eq!(server.decrypt(0, &ct).unwrap(), b"hello");
        // and the reverse direction
        let ct = server.encrypt(0, b"world").unwrap();
        assert_eq!(client.decrypt(0, &ct).unwrap(), b"world");
    }

    #[test]
    fn test_ik_handshake_aesgcm() {
        let (client, server, _) = handshake_pair(CipherSuite::Aes256Gcm);
        let ct = client.encrypt(7, b"data").unwrap();
        assert_eq!(server.decrypt(7, &ct).unwrap(), b"data");
    }

    #[test]
    fn test_out_of_order_counters() {
        let (client, server, _) = handshake_pair(CipherSuite::ChaCha20Poly1305);
        let c5 = client.encrypt(5, b"five").unwrap();
        let c3 = client.encrypt(3, b"three").unwrap();
        assert_eq!(server.decrypt(5, &c5).unwrap(), b"five");
        assert_eq!(server.decrypt(3, &c3).unwrap(), b"three");
    }

    #[test]
    fn test_wrong_counter_fails() {
        let (client, server, _) = handshake_pair(CipherSuite::ChaCha20Poly1305);
        let ct = client.encrypt(1, b"x").unwrap();
        assert!(server.decrypt(2, &ct).is_err());
    }

    #[test]
    fn test_initiator_with_wrong_server_key_fails() {
        let client_id = Identity::generate();
        let server_id = Identity::generate();
        let wrong = Identity::generate();

        let mut client = Handshake::new_initiator(
            CipherSuite::ChaCha20Poly1305,
            &client_id.private_bytes(),
            &wrong.public_bytes(), // not the real server key
        )
        .unwrap();
        let mut server =
            Handshake::new_responder(CipherSuite::ChaCha20Poly1305, &server_id.private_bytes())
                .unwrap();

        let m1 = client.write_message(b"").unwrap();
        assert!(server.read_message(&m1).is_err());
    }
}
