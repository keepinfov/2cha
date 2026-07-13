//! Interactive config-creation wizard for `2cha init`.

pub mod client;
pub mod detect;
pub mod mobile;
pub mod render;
pub mod server;
pub mod write;

use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};
use twocha_protocol::Result;
use write::wizard_io_err;

/// Default DNS servers suggested by the wizard (single source of truth)
pub const DEFAULT_DNS: [&str; 2] = ["1.1.1.1", "8.8.8.8"];

/// The wizard's DNS defaults as owned strings (the shape configs want)
pub fn default_dns_servers() -> Vec<String> {
    DEFAULT_DNS.iter().map(|s| s.to_string()).collect()
}

/// Prompt for the cipher suite
fn prompt_cipher(theme: &ColorfulTheme) -> Result<String> {
    let ciphers = ["chacha20-poly1305", "aes-256-gcm"];
    let idx = Select::with_theme(theme)
        .with_prompt("Cipher")
        .items(ciphers)
        .default(0)
        .interact()
        .map_err(wizard_io_err)?;
    Ok(ciphers[idx].to_string())
}

/// AmneziaWG obfuscation parameters generated once per wizard run and shared,
/// byte-for-byte, between the server and every client it emits (the magic
/// headers and padding are part of the wire format — both ends must agree).
#[derive(Clone)]
pub struct AwgWizard {
    pub h: [u32; 4],
    pub header_span: u32,
    pub s: [u16; 4],
    pub jc: u8,
    pub jmin: u16,
    pub jmax: u16,
}

impl AwgWizard {
    /// Roll a fresh set of parameters: four non-overlapping magic-header ranges
    /// (one random base per 2^30 quadrant, so the `header_span`-wide ranges can
    /// never collide) plus sane default padding and junk sizes.
    fn generate() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        const QUADRANT: u32 = 0x4000_0000;
        const SPAN: u32 = 0x00ff_ffff;
        // Base within a quadrant, leaving room for the span so the range stays
        // inside its quadrant and thus disjoint from the others.
        let mut base = |k: u32| k * QUADRANT + rng.gen_range(0..(QUADRANT - SPAN));
        AwgWizard {
            h: [base(0), base(1), base(2), base(3)],
            header_span: SPAN,
            s: [24, 40, 24, 16],
            jc: 4,
            jmin: 64,
            jmax: 1024,
        }
    }
}

/// The obfuscation transport choice gathered from the wizard.
#[derive(Default)]
pub struct TransportChoice {
    pub kind: String,
    pub sni: Option<String>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub awg: Option<AwgWizard>,
}

impl TransportChoice {
    fn quic() -> Self {
        TransportChoice {
            kind: "quic".to_string(),
            ..Default::default()
        }
    }

    fn awg() -> Self {
        TransportChoice {
            kind: "awg".to_string(),
            awg: Some(AwgWizard::generate()),
            ..Default::default()
        }
    }
}

/// Prompt for the obfuscation transport. When `server` is true and TLS is
/// chosen, also offer to supply a custom certificate/key (otherwise the server
/// auto-generates a self-signed cert for the SNI at startup).
fn prompt_transport(theme: &ColorfulTheme, server: bool) -> Result<TransportChoice> {
    let items = [
        "quic  — UDP, QUIC-mimicry framing (default)",
        "tls   — TCP, real TLS 1.3 with Noise inside (e.g. on :443)",
        "awg   — UDP, AmneziaWG-style randomized headers + junk packets",
    ];

    let idx = Select::with_theme(theme)
        .with_prompt("Transport")
        .items(items)
        .default(0)
        .interact()
        .map_err(wizard_io_err)?;

    match idx {
        0 => Ok(TransportChoice::quic()),
        1 => prompt_tls(theme, server),
        2 => Ok(TransportChoice::awg()),
        _ => unreachable!("transport selection out of range"),
    }
}

/// TLS transport prompts (SNI + optional server certificate).
fn prompt_tls(theme: &ColorfulTheme, server: bool) -> Result<TransportChoice> {
    let sni: String = Input::with_theme(theme)
        .with_prompt("  TLS SNI (hostname to blend in as)")
        .default("www.cloudflare.com".to_string())
        .interact_text()
        .map_err(wizard_io_err)?;

    let (cert_file, key_file) = if server {
        let custom = Confirm::with_theme(theme)
            .with_prompt("  Provide your own certificate? (No = auto self-signed)")
            .default(false)
            .interact()
            .map_err(wizard_io_err)?;
        if custom {
            let cert: String = Input::with_theme(theme)
                .with_prompt("    Certificate file (PEM fullchain)")
                .interact_text()
                .map_err(wizard_io_err)?;
            let key: String = Input::with_theme(theme)
                .with_prompt("    Private key file (PEM PKCS#8)")
                .interact_text()
                .map_err(wizard_io_err)?;
            (Some(cert), Some(key))
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    Ok(TransportChoice {
        kind: "tls".to_string(),
        sni: Some(sni),
        cert_file,
        key_file,
        awg: None,
    })
}

/// Validate a "host:port" endpoint (domain names allowed)
pub fn validate_endpoint(s: &str) -> std::result::Result<(), String> {
    let Some((host, port)) = s.rsplit_once(':') else {
        return Err("expected host:port, e.g. vpn.example.com:51820".to_string());
    };
    if host.is_empty() {
        return Err("host must not be empty".to_string());
    }
    port.parse::<u16>()
        .map(|_| ())
        .map_err(|_| format!("'{}' is not a valid port", port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_endpoint() {
        assert!(validate_endpoint("vpn.example.com:51820").is_ok());
        assert!(validate_endpoint("1.2.3.4:51820").is_ok());
        assert!(validate_endpoint("no-port").is_err());
        assert!(validate_endpoint(":51820").is_err());
        assert!(validate_endpoint("host:99999").is_err());
    }
}

