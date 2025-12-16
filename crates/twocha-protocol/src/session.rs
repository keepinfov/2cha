//! # Session Management and Handshake Logic
//!
//! Implements the complete Noise_IK handshake and session management for protocol v4.
//!
//! ## Usage
//!
//! ### Initiator (Client)
//! ```ignore
//! let mut initiator = NoiseInitiator::new(my_static_key, server_public_key);
//! let init_message = initiator.create_init()?;
//! // Send init_message to server...
//! // Receive response from server...
//! let session = initiator.process_response(&response)?;
//! // Use session for encrypted communication
//! ```
//!
//! ### Responder (Server)
//! ```ignore
//! let mut responder = NoiseResponder::new(my_static_key);
//! // Receive init from client...
//! let response = responder.process_init(&init_message)?;
//! // Send response to client...
//! let session = responder.finalize()?;
//! // Use session for encrypted communication
//! ```

use crate::handshake::{HandshakeInit, HandshakeResponse, Tai64n, ENCRYPTED_STATIC_SIZE, ENCRYPTED_TIMESTAMP_SIZE, ENCRYPTED_EMPTY_SIZE};
use crate::noise::{SymmetricState, TransportKey, NoiseError, NOISE_CONSTRUCTION, NOISE_IDENTIFIER};
use crate::mac::MacCalculator;
use crate::constants::X25519_PUBLIC_KEY_SIZE;

use zeroize::Zeroizing;
use std::time::{Duration, Instant};

// ═══════════════════════════════════════════════════════════════════════════
// SESSION INDEX
// ═══════════════════════════════════════════════════════════════════════════

/// Generate a random session index
pub fn random_session_index() -> u32 {
    let mut bytes = [0u8; 4];
    fill_random(&mut bytes);
    u32::from_le_bytes(bytes)
}

// ═══════════════════════════════════════════════════════════════════════════
// NOISE INITIATOR
// ═══════════════════════════════════════════════════════════════════════════

/// Noise_IK handshake initiator (client side)
pub struct NoiseInitiator {
    /// Our static X25519 key pair
    static_private: Zeroizing<[u8; 32]>,
    static_public: [u8; 32],
    /// Responder's static public key (known in advance)
    responder_static: [u8; 32],
    /// Ephemeral key pair (generated during handshake)
    ephemeral_private: Option<Zeroizing<[u8; 32]>>,
    ephemeral_public: Option<[u8; 32]>,
    /// Symmetric state
    symmetric_state: Option<SymmetricState>,
    /// Our session index
    sender_index: u32,
    /// Responder's session index
    receiver_index: Option<u32>,
    /// MAC calculator
    mac_calc: MacCalculator,
    /// Cookie for MAC2 (if provided)
    cookie: Option<[u8; 16]>,
}

impl NoiseInitiator {
    /// Create a new initiator with our static key and responder's public key
    pub fn new(static_private: [u8; 32], responder_static: [u8; 32]) -> Self {
        let static_public = derive_x25519_public(&static_private);
        let mac_calc = MacCalculator::new(&responder_static);

        Self {
            static_private: Zeroizing::new(static_private),
            static_public,
            responder_static,
            ephemeral_private: None,
            ephemeral_public: None,
            symmetric_state: None,
            sender_index: random_session_index(),
            receiver_index: None,
            mac_calc,
            cookie: None,
        }
    }

    /// Set a cookie for MAC2 (received from CookieReply)
    pub fn set_cookie(&mut self, cookie: [u8; 16]) {
        self.cookie = Some(cookie);
    }

    /// Get our session index
    pub fn sender_index(&self) -> u32 {
        self.sender_index
    }

    /// Create the handshake init message
    ///
    /// Noise pattern: -> e, es, s, ss
    pub fn create_init(&mut self) -> Result<HandshakeInit, NoiseError> {
        // Generate ephemeral key pair
        let mut ephemeral_private = [0u8; 32];
        fill_random(&mut ephemeral_private);
        let ephemeral_public = derive_x25519_public(&ephemeral_private);

        // Initialize symmetric state
        let mut sym = SymmetricState::new(NOISE_CONSTRUCTION);

        // Mix in protocol identifier and responder's static public key
        sym.mix_hash(NOISE_IDENTIFIER);
        sym.mix_hash(&self.responder_static);

        // -> e: Send ephemeral public
        sym.mix_hash(&ephemeral_public);

        // -> es: DH(ephemeral, responder_static)
        let es = x25519_dh(&ephemeral_private, &self.responder_static)?;
        sym.mix_key(&es);

        // -> s: Encrypt and send static public
        let encrypted_static = sym.encrypt_and_hash(&self.static_public)?;
        if encrypted_static.len() != ENCRYPTED_STATIC_SIZE {
            return Err(NoiseError::InvalidLength {
                expected: ENCRYPTED_STATIC_SIZE,
                got: encrypted_static.len(),
            });
        }

        // -> ss: DH(static, responder_static)
        let ss = x25519_dh(&self.static_private, &self.responder_static)?;
        sym.mix_key(&ss);

        // Encrypt timestamp
        let timestamp = Tai64n::now();
        let encrypted_timestamp = sym.encrypt_and_hash(timestamp.as_bytes())?;
        if encrypted_timestamp.len() != ENCRYPTED_TIMESTAMP_SIZE {
            return Err(NoiseError::InvalidLength {
                expected: ENCRYPTED_TIMESTAMP_SIZE,
                got: encrypted_timestamp.len(),
            });
        }

        // Store state
        self.ephemeral_private = Some(Zeroizing::new(ephemeral_private));
        self.ephemeral_public = Some(ephemeral_public);
        self.symmetric_state = Some(sym);

        // Create message
        let mut encrypted_static_arr = [0u8; ENCRYPTED_STATIC_SIZE];
        encrypted_static_arr.copy_from_slice(&encrypted_static);

        let mut encrypted_timestamp_arr = [0u8; ENCRYPTED_TIMESTAMP_SIZE];
        encrypted_timestamp_arr.copy_from_slice(&encrypted_timestamp);

        let mut init = HandshakeInit::new(
            self.sender_index,
            ephemeral_public,
            encrypted_static_arr,
            encrypted_timestamp_arr,
        );

        // Compute MAC1
        let init_bytes = init.to_bytes();
        init.mac1 = self.mac_calc.compute_mac1(&init_bytes);

        // Compute MAC2 if we have a cookie
        if let Some(cookie) = &self.cookie {
            let init_bytes = init.to_bytes();
            init.mac2 = MacCalculator::compute_mac2(cookie, &init_bytes);
        }

        Ok(init)
    }

    /// Process the handshake response from responder
    ///
    /// Noise pattern: <- e, ee, se
    pub fn process_response(&mut self, response: &HandshakeResponse) -> Result<Session, NoiseError> {
        // Verify response is for us
        if response.receiver_index != self.sender_index {
            return Err(NoiseError::HandshakeFailed(
                "Response receiver_index doesn't match our sender_index".to_string()
            ));
        }

        let ephemeral_private = self.ephemeral_private.as_ref()
            .ok_or(NoiseError::InvalidState(crate::noise::HandshakeState::Initial))?;

        let mut sym = self.symmetric_state.take()
            .ok_or(NoiseError::InvalidState(crate::noise::HandshakeState::Initial))?;

        // <- e: Receive responder's ephemeral
        sym.mix_hash(&response.ephemeral_public);

        // <- ee: DH(our_ephemeral, their_ephemeral)
        let ee = x25519_dh(ephemeral_private, &response.ephemeral_public)?;
        sym.mix_key(&ee);

        // <- se: DH(our_static, their_ephemeral)
        let se = x25519_dh(&self.static_private, &response.ephemeral_public)?;
        sym.mix_key(&se);

        // Decrypt empty payload (key confirmation)
        let _ = sym.decrypt_and_hash(&response.encrypted_empty)?;

        // Store receiver index
        self.receiver_index = Some(response.sender_index);

        // Split into transport keys
        let (tx_key, rx_key) = sym.split()?;

        Ok(Session::new(
            self.sender_index,
            response.sender_index,
            tx_key,
            rx_key,
            true, // is_initiator
        ))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// NOISE RESPONDER
// ═══════════════════════════════════════════════════════════════════════════

/// Noise_IK handshake responder (server side)
pub struct NoiseResponder {
    /// Our static X25519 key pair
    static_private: Zeroizing<[u8; 32]>,
    static_public: [u8; 32],
    /// Initiator's static public key (learned during handshake)
    initiator_static: Option<[u8; 32]>,
    /// Ephemeral key pair (generated during handshake)
    ephemeral_private: Option<Zeroizing<[u8; 32]>>,
    ephemeral_public: Option<[u8; 32]>,
    /// Symmetric state
    symmetric_state: Option<SymmetricState>,
    /// Our session index
    sender_index: u32,
    /// Initiator's session index
    receiver_index: Option<u32>,
    /// MAC calculator
    mac_calc: MacCalculator,
    /// Timestamp from initiator (for replay check)
    initiator_timestamp: Option<Tai64n>,
}

impl NoiseResponder {
    /// Create a new responder with our static key
    pub fn new(static_private: [u8; 32]) -> Self {
        let static_public = derive_x25519_public(&static_private);
        let mac_calc = MacCalculator::new(&static_public);

        Self {
            static_private: Zeroizing::new(static_private),
            static_public,
            initiator_static: None,
            ephemeral_private: None,
            ephemeral_public: None,
            symmetric_state: None,
            sender_index: random_session_index(),
            receiver_index: None,
            mac_calc,
            initiator_timestamp: None,
        }
    }

    /// Get our session index
    pub fn sender_index(&self) -> u32 {
        self.sender_index
    }

    /// Get our static public key
    pub fn static_public(&self) -> &[u8; 32] {
        &self.static_public
    }

    /// Verify MAC1 of incoming handshake init
    pub fn verify_mac1(&self, init: &HandshakeInit) -> bool {
        let bytes = init.to_bytes();
        self.mac_calc.verify_mac1(&bytes, &init.mac1)
    }

    /// Process the handshake init from initiator
    ///
    /// Noise pattern: -> e, es, s, ss
    /// Returns the response to send back
    pub fn process_init(&mut self, init: &HandshakeInit) -> Result<HandshakeResponse, NoiseError> {
        // Verify MAC1
        if !self.verify_mac1(init) {
            return Err(NoiseError::HandshakeFailed("Invalid MAC1".to_string()));
        }

        // Initialize symmetric state
        let mut sym = SymmetricState::new(NOISE_CONSTRUCTION);

        // Mix in protocol identifier and our static public key
        sym.mix_hash(NOISE_IDENTIFIER);
        sym.mix_hash(&self.static_public);

        // -> e: Receive initiator's ephemeral
        sym.mix_hash(&init.ephemeral_public);

        // -> es: DH(our_static, their_ephemeral)
        let es = x25519_dh(&self.static_private, &init.ephemeral_public)?;
        sym.mix_key(&es);

        // -> s: Decrypt initiator's static
        let initiator_static_bytes = sym.decrypt_and_hash(&init.encrypted_static)?;
        if initiator_static_bytes.len() != X25519_PUBLIC_KEY_SIZE {
            return Err(NoiseError::InvalidLength {
                expected: X25519_PUBLIC_KEY_SIZE,
                got: initiator_static_bytes.len(),
            });
        }
        let mut initiator_static = [0u8; 32];
        initiator_static.copy_from_slice(&initiator_static_bytes);

        // -> ss: DH(our_static, their_static)
        let ss = x25519_dh(&self.static_private, &initiator_static)?;
        sym.mix_key(&ss);

        // Decrypt timestamp
        let timestamp_bytes = sym.decrypt_and_hash(&init.encrypted_timestamp)?;
        let timestamp = Tai64n::from_bytes(&timestamp_bytes)
            .ok_or(NoiseError::HandshakeFailed("Invalid timestamp".to_string()))?;

        // Store initiator info
        self.initiator_static = Some(initiator_static);
        self.receiver_index = Some(init.sender_index);
        self.initiator_timestamp = Some(timestamp);

        // Generate our ephemeral key
        let mut ephemeral_private = [0u8; 32];
        fill_random(&mut ephemeral_private);
        let ephemeral_public = derive_x25519_public(&ephemeral_private);

        // <- e: Send our ephemeral
        sym.mix_hash(&ephemeral_public);

        // <- ee: DH(our_ephemeral, their_ephemeral)
        let ee = x25519_dh(&ephemeral_private, &init.ephemeral_public)?;
        sym.mix_key(&ee);

        // <- se: DH(our_ephemeral, their_static)
        let se = x25519_dh(&ephemeral_private, &initiator_static)?;
        sym.mix_key(&se);

        // Encrypt empty payload (key confirmation)
        let encrypted_empty = sym.encrypt_and_hash(&[])?;
        if encrypted_empty.len() != ENCRYPTED_EMPTY_SIZE {
            return Err(NoiseError::InvalidLength {
                expected: ENCRYPTED_EMPTY_SIZE,
                got: encrypted_empty.len(),
            });
        }

        // Store state
        self.ephemeral_private = Some(Zeroizing::new(ephemeral_private));
        self.ephemeral_public = Some(ephemeral_public);
        self.symmetric_state = Some(sym);

        // Create response
        let mut encrypted_empty_arr = [0u8; ENCRYPTED_EMPTY_SIZE];
        encrypted_empty_arr.copy_from_slice(&encrypted_empty);

        let mut response = HandshakeResponse::new(
            self.sender_index,
            init.sender_index,
            ephemeral_public,
            encrypted_empty_arr,
        );

        // Compute MAC1 (use initiator's static as the key)
        let initiator_mac_calc = MacCalculator::new(&initiator_static);
        let response_bytes = response.to_bytes();
        response.mac1 = initiator_mac_calc.compute_mac1(&response_bytes);

        Ok(response)
    }

    /// Finalize the handshake and create session
    pub fn finalize(self) -> Result<Session, NoiseError> {
        let sym = self.symmetric_state
            .ok_or(NoiseError::InvalidState(crate::noise::HandshakeState::Initial))?;

        let receiver_index = self.receiver_index
            .ok_or(NoiseError::InvalidState(crate::noise::HandshakeState::Initial))?;

        // Split into transport keys
        let (rx_key, tx_key) = sym.split()?; // Note: reversed for responder

        Ok(Session::new(
            self.sender_index,
            receiver_index,
            tx_key,
            rx_key,
            false, // is_initiator
        ))
    }

    /// Get the initiator's static public key (after process_init)
    pub fn initiator_static(&self) -> Option<&[u8; 32]> {
        self.initiator_static.as_ref()
    }

    /// Get the initiator's timestamp (after process_init)
    pub fn initiator_timestamp(&self) -> Option<&Tai64n> {
        self.initiator_timestamp.as_ref()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SESSION
// ═══════════════════════════════════════════════════════════════════════════

/// Established session for encrypted communication
pub struct Session {
    /// Our session index
    pub local_index: u32,
    /// Peer's session index
    pub remote_index: u32,
    /// Key for sending
    tx_key: TransportKey,
    /// Key for receiving
    rx_key: TransportKey,
    /// Whether we initiated this session
    pub is_initiator: bool,
    /// Session creation time
    pub created_at: Instant,
    /// Last activity time
    pub last_activity: Instant,
}

impl Session {
    /// Create a new session
    fn new(
        local_index: u32,
        remote_index: u32,
        tx_key: TransportKey,
        rx_key: TransportKey,
        is_initiator: bool,
    ) -> Self {
        let now = Instant::now();
        Self {
            local_index,
            remote_index,
            tx_key,
            rx_key,
            is_initiator,
            created_at: now,
            last_activity: now,
        }
    }

    /// Encrypt data for sending
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        self.last_activity = Instant::now();
        self.tx_key.encrypt(plaintext)
    }

    /// Decrypt received data
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        self.last_activity = Instant::now();
        self.rx_key.decrypt(ciphertext)
    }

    /// Get current TX nonce (counter)
    pub fn tx_nonce(&self) -> u64 {
        self.tx_key.nonce()
    }

    /// Get current RX nonce (counter)
    pub fn rx_nonce(&self) -> u64 {
        self.rx_key.nonce()
    }

    /// Check if session needs rekeying
    pub fn needs_rekey(&self, max_age: Duration, max_messages: u64) -> bool {
        let age = Instant::now().duration_since(self.created_at);
        age > max_age || self.tx_key.needs_rekey(max_messages)
    }

    /// Check if session has been idle too long
    pub fn is_idle(&self, timeout: Duration) -> bool {
        Instant::now().duration_since(self.last_activity) > timeout
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("local_index", &format!("{:#x}", self.local_index))
            .field("remote_index", &format!("{:#x}", self.remote_index))
            .field("is_initiator", &self.is_initiator)
            .field("tx_nonce", &self.tx_nonce())
            .field("rx_nonce", &self.rx_nonce())
            .finish()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════

/// Derive X25519 public key from private key
fn derive_x25519_public(private: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{StaticSecret, PublicKey};

    let secret = StaticSecret::from(*private);
    let public = PublicKey::from(&secret);
    *public.as_bytes()
}

/// Perform X25519 Diffie-Hellman
fn x25519_dh(private: &[u8; 32], public: &[u8; 32]) -> Result<[u8; 32], NoiseError> {
    use x25519_dalek::{StaticSecret, PublicKey};

    let secret = StaticSecret::from(*private);
    let their_public = PublicKey::from(*public);
    let shared = secret.diffie_hellman(&their_public);

    // Check for zero shared secret (indicates invalid peer key)
    if shared.as_bytes().iter().all(|&b| b == 0) {
        return Err(NoiseError::ZeroDhOutput);
    }

    Ok(*shared.as_bytes())
}

/// Fill buffer with random bytes
fn fill_random(buf: &mut [u8]) {
    if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = file.read_exact(buf);
    } else {
        // Fallback
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = ((ts >> (i % 8 * 8)) ^ (i as u64)) as u8;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_keypair() -> ([u8; 32], [u8; 32]) {
        let mut private = [0u8; 32];
        fill_random(&mut private);
        let public = derive_x25519_public(&private);
        (private, public)
    }

    #[test]
    fn test_full_handshake() {
        // Generate keys
        let (initiator_private, initiator_public) = generate_keypair();
        let (responder_private, responder_public) = generate_keypair();

        // Initiator creates init message
        let mut initiator = NoiseInitiator::new(initiator_private, responder_public);
        let init = initiator.create_init().unwrap();

        // Responder processes init and creates response
        let mut responder = NoiseResponder::new(responder_private);
        let response = responder.process_init(&init).unwrap();

        // Verify responder learned initiator's public key
        assert_eq!(responder.initiator_static(), Some(&initiator_public));

        // Initiator processes response
        let mut initiator_session = initiator.process_response(&response).unwrap();

        // Responder finalizes
        let mut responder_session = responder.finalize().unwrap();

        // Test bidirectional communication
        let plaintext = b"Hello from initiator!";
        let ciphertext = initiator_session.encrypt(plaintext).unwrap();
        let decrypted = responder_session.decrypt(&ciphertext).unwrap();
        assert_eq!(&decrypted[..], plaintext);

        let reply = b"Hello from responder!";
        let ciphertext2 = responder_session.encrypt(reply).unwrap();
        let decrypted2 = initiator_session.decrypt(&ciphertext2).unwrap();
        assert_eq!(&decrypted2[..], reply);
    }

    #[test]
    fn test_handshake_session_indices() {
        let (initiator_private, _) = generate_keypair();
        let (responder_private, responder_public) = generate_keypair();

        let mut initiator = NoiseInitiator::new(initiator_private, responder_public);
        let init = initiator.create_init().unwrap();

        let mut responder = NoiseResponder::new(responder_private);
        let response = responder.process_init(&init).unwrap();

        // Response should reference initiator's index
        assert_eq!(response.receiver_index, initiator.sender_index());

        let initiator_session = initiator.process_response(&response).unwrap();
        let responder_session = responder.finalize().unwrap();

        // Session indices should match up
        assert_eq!(initiator_session.local_index, responder_session.remote_index);
        assert_eq!(initiator_session.remote_index, responder_session.local_index);
    }

    #[test]
    fn test_handshake_mac1_verification() {
        let (initiator_private, _) = generate_keypair();
        let (responder_private, responder_public) = generate_keypair();

        let mut initiator = NoiseInitiator::new(initiator_private, responder_public);
        let init = initiator.create_init().unwrap();

        let responder = NoiseResponder::new(responder_private);

        // MAC1 should verify
        assert!(responder.verify_mac1(&init));

        // Tamper with message
        let mut tampered = init.clone();
        tampered.sender_index ^= 1;
        assert!(!responder.verify_mac1(&tampered));
    }

    #[test]
    fn test_handshake_wrong_response_receiver() {
        let (initiator_private, _) = generate_keypair();
        let (responder_private, responder_public) = generate_keypair();

        let mut initiator = NoiseInitiator::new(initiator_private, responder_public);
        let init = initiator.create_init().unwrap();

        let mut responder = NoiseResponder::new(responder_private);
        let mut response = responder.process_init(&init).unwrap();

        // Tamper with receiver_index
        response.receiver_index = response.receiver_index.wrapping_add(1);

        let result = initiator.process_response(&response);
        assert!(result.is_err());
    }

    #[test]
    fn test_session_encrypt_decrypt() {
        let (initiator_private, _) = generate_keypair();
        let (responder_private, responder_public) = generate_keypair();

        let mut initiator = NoiseInitiator::new(initiator_private, responder_public);
        let init = initiator.create_init().unwrap();

        let mut responder = NoiseResponder::new(responder_private);
        let response = responder.process_init(&init).unwrap();

        let mut i_session = initiator.process_response(&response).unwrap();
        let mut r_session = responder.finalize().unwrap();

        // Multiple messages
        for i in 0..10 {
            let msg = format!("Message {}", i);
            let ct = i_session.encrypt(msg.as_bytes()).unwrap();
            let pt = r_session.decrypt(&ct).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }

        // Check nonces increment
        assert_eq!(i_session.tx_nonce(), 10);
        assert_eq!(r_session.rx_nonce(), 10);
    }

    #[test]
    fn test_session_needs_rekey() {
        let (initiator_private, _) = generate_keypair();
        let (responder_private, responder_public) = generate_keypair();

        let mut initiator = NoiseInitiator::new(initiator_private, responder_public);
        let init = initiator.create_init().unwrap();

        let mut responder = NoiseResponder::new(responder_private);
        let response = responder.process_init(&init).unwrap();

        let mut session = initiator.process_response(&response).unwrap();

        // Should not need rekey initially
        assert!(!session.needs_rekey(Duration::from_secs(120), 1000));

        // Encrypt many messages
        for _ in 0..100 {
            session.encrypt(b"test").unwrap();
        }

        // Now should need rekey (max_messages = 100)
        assert!(session.needs_rekey(Duration::from_secs(120), 100));
    }

    #[test]
    fn test_x25519_dh() {
        let (alice_priv, alice_pub) = generate_keypair();
        let (bob_priv, bob_pub) = generate_keypair();

        let shared_ab = x25519_dh(&alice_priv, &bob_pub).unwrap();
        let shared_ba = x25519_dh(&bob_priv, &alice_pub).unwrap();

        assert_eq!(shared_ab, shared_ba);
    }

    #[test]
    fn test_derive_x25519_public() {
        let (private, public) = generate_keypair();
        let derived = derive_x25519_public(&private);
        assert_eq!(derived, public);
    }

    #[test]
    fn test_random_session_index() {
        let idx1 = random_session_index();
        let idx2 = random_session_index();
        // Very unlikely to be equal
        assert_ne!(idx1, idx2);
    }
}
