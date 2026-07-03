//! # twocha-mobile
//!
//! uniffi FFI surface that embeds the `2cha` v4 client engine in a sandboxed
//! host app (Android `VpnService`). The host owns the data plane — it builds
//! the tunnel interface, sets addresses/routes/DNS/MTU, and hands us the
//! established tun fd plus a `protect(fd)` callback. We own the protocol: the
//! Noise_IK handshake, the obfuscation transport, PFS rekeys and the packet
//! pump, all reused verbatim from `twocha-lib`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use twocha_core::{decode_public_key, ClientConfig, Identity};

uniffi::setup_scaffolding!();

/// Errors surfaced across the FFI boundary. Each carries a human-readable
/// message rather than a structured cause — the host only logs/displays it.
#[derive(Debug, uniffi::Error)]
pub enum TwochaError {
    /// The config TOML was invalid or incomplete.
    Config(String),
    /// A base64 key could not be decoded into a valid X25519 key.
    InvalidKey(String),
    /// The tunnel failed at runtime (handshake, transport or I/O).
    Vpn(String),
}

impl std::fmt::Display for TwochaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TwochaError::Config(m) => write!(f, "config error: {m}"),
            TwochaError::InvalidKey(m) => write!(f, "invalid key: {m}"),
            TwochaError::Vpn(m) => write!(f, "vpn error: {m}"),
        }
    }
}

impl std::error::Error for TwochaError {}

/// Host-implemented hook around Android `VpnService.protect(int)`: marks a
/// socket so its traffic bypasses the VPN routing loop. Returns whether the
/// protect succeeded.
#[uniffi::export(callback_interface)]
pub trait SocketProtector: Send + Sync {
    fn protect(&self, fd: i32) -> bool;
}

/// Host-implemented lifecycle hook. `on_connected` fires exactly once, when the
/// Noise_IK handshake has completed and the data plane is live — so the host can
/// distinguish "connecting" from a genuinely established tunnel rather than
/// guessing before `start` has done any work.
///
/// `on_stats` fires roughly once per second while the tunnel runs, carrying
/// cumulative payload byte counters since tunnel start (drives the host's
/// live traffic UI).
#[uniffi::export(callback_interface)]
pub trait TunnelObserver: Send + Sync {
    fn on_connected(&self);
    fn on_stats(&self, tx_bytes: u64, rx_bytes: u64);
}

/// A freshly generated X25519 identity, both halves base64-encoded.
#[derive(uniffi::Record)]
pub struct Keypair {
    pub private_key_b64: String,
    pub public_key_b64: String,
}

/// Generate a new client identity. Store `private_key_b64` securely on device
/// (Keystore / EncryptedSharedPreferences) and paste `public_key_b64` into the
/// server's peer list.
#[uniffi::export]
pub fn generate_keypair() -> Keypair {
    let id = Identity::generate();
    Keypair {
        private_key_b64: twocha_core::encode_public_key(&id.private_bytes()),
        public_key_b64: id.public_base64(),
    }
}

/// Derive the base64 public key for a stored base64 private key.
#[uniffi::export]
pub fn public_key_for(private_key_b64: String) -> Result<String, TwochaError> {
    let bytes =
        decode_public_key(&private_key_b64).map_err(|e| TwochaError::InvalidKey(format!("{e}")))?;
    Ok(Identity::from_private_bytes(&bytes).public_base64())
}

/// Route engine logs to logcat (Android) — no-op elsewhere. Safe to call more
/// than once.
#[uniffi::export]
pub fn init_logging() {
    #[cfg(target_os = "android")]
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Debug)
            .with_tag("twocha"),
    );
}

/// A managed v4 tunnel. The engine owns the run loop, so `start` blocks until
/// `stop` is called from another thread; the host should run `start` on a
/// dedicated thread inside its `VpnService`.
///
/// Each tunnel owns its own run flag, so a `stop` only affects the tunnel it was
/// called on. This avoids a disconnect racing a fresh connect through a shared
/// process-global flag, and means a stale (slow-to-exit) engine can't terminate
/// a newer session.
#[derive(uniffi::Object)]
pub struct TwochaTunnel {
    running: Arc<AtomicBool>,
}

#[uniffi::export]
impl TwochaTunnel {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(TwochaTunnel {
            running: Arc::new(AtomicBool::new(true)),
        })
    }

    /// Connect and run until [`stop`](TwochaTunnel::stop). Parses `config_toml`
    /// (the client config schema), derives the identity from `private_key_b64`,
    /// protects every carrier socket via `protector`, completes the handshake
    /// over the configured transport, then pumps packets across `tun_fd`.
    ///
    /// `tun_fd` ownership is transferred to the engine (closed on teardown);
    /// pass a detached fd (`pfd.detachFd()`).
    pub fn start(
        &self,
        config_toml: String,
        private_key_b64: String,
        tun_fd: i32,
        protector: Box<dyn SocketProtector>,
        observer: Box<dyn TunnelObserver>,
    ) -> Result<(), TwochaError> {
        let cfg =
            ClientConfig::parse(&config_toml).map_err(|e| TwochaError::Config(format!("{e}")))?;
        let key = decode_public_key(&private_key_b64)
            .map_err(|e| TwochaError::InvalidKey(format!("{e}")))?;
        let identity = Identity::from_private_bytes(&key);
        let server_public = cfg
            .server_public()
            .map_err(|e| TwochaError::Config(format!("{e}")))?;

        // Arm this tunnel's flag; a `stop` from a previous run on the same
        // instance left it false.
        self.running.store(true, Ordering::SeqCst);

        #[cfg(unix)]
        {
            let protect = move |fd: std::os::unix::io::RawFd| protector.protect(fd);
            // Both callbacks funnel into the one host observer.
            let observer: Arc<dyn TunnelObserver> = Arc::from(observer);
            let stats_observer = Arc::clone(&observer);
            let on_connected = move || observer.on_connected();
            let on_stats = move |tx: u64, rx: u64| stats_observer.on_stats(tx, rx);

            // SAFETY: `tun_fd` is a valid fd whose ownership the host transfers
            // to us; the engine closes it on teardown.
            unsafe {
                twocha_lib::vpn::client::run_mobile(
                    cfg,
                    identity,
                    server_public,
                    tun_fd,
                    &protect,
                    &self.running,
                    &on_connected,
                    &on_stats,
                )
            }
            .map_err(|e| TwochaError::Vpn(format!("{e}")))
        }

        // The mobile tunnel binds to a host-provided tun fd + `protect`
        // callback, which only exist on the Android/unix target. The crate
        // still compiles on other hosts (so a `cargo build --workspace` on
        // Windows/macOS CI passes) but `start` is a no-op stub there.
        #[cfg(not(unix))]
        {
            let _ = (cfg, identity, server_public, tun_fd, protector, observer);
            Err(TwochaError::Vpn(
                "mobile tunnel is only supported on unix (Android) targets".to_string(),
            ))
        }
    }

    /// Signal this tunnel to stop; its blocking `start` then returns.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}
