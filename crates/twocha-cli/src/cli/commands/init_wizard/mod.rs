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

/// The obfuscation transport choice gathered from the wizard.
#[derive(Default)]
pub struct TransportChoice {
    pub kind: String,
    pub sni: Option<String>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    /// REALITY: the real HTTPS site to borrow/mimic (server_names + client SNI).
    pub reality_server_name: Option<String>,
    /// REALITY server-side: real `host:port` that non-clients are proxied to.
    pub reality_dest: Option<String>,
    /// REALITY client-side: the server's REALITY public key (base64).
    pub reality_public_key: Option<String>,
    /// REALITY client-side: the shared short id (hex).
    pub reality_short_id: Option<String>,
}

impl TransportChoice {
    fn quic() -> Self {
        TransportChoice {
            kind: "quic".to_string(),
            ..Default::default()
        }
    }
}

/// Prompt for the obfuscation transport. When `server` is true and TLS is
/// chosen, also offer to supply a custom certificate/key (otherwise the server
/// auto-generates a self-signed cert for the SNI at startup). The REALITY
/// option is only offered when the binary was built with the `reality` feature.
fn prompt_transport(theme: &ColorfulTheme, server: bool) -> Result<TransportChoice> {
    // `items` is only mutated when the reality feature adds a third option.
    #[cfg_attr(not(feature = "reality"), allow(unused_mut))]
    let mut items = vec![
        "quic  — UDP, QUIC-mimicry framing (default)",
        "tls   — TCP, real TLS 1.3 with Noise inside (e.g. on :443)",
    ];
    #[cfg(feature = "reality")]
    items.push("reality — TCP :443; borrows a real site's TLS, probes see that site");

    let idx = Select::with_theme(theme)
        .with_prompt("Transport")
        .items(&items)
        .default(0)
        .interact()
        .map_err(wizard_io_err)?;

    match idx {
        0 => Ok(TransportChoice::quic()),
        1 => prompt_tls(theme, server),
        #[cfg(feature = "reality")]
        2 => prompt_reality(theme, server),
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
        ..Default::default()
    })
}

/// REALITY transport prompts. The server side generates keys later (in the
/// server wizard) and only needs the borrowed site + probe fallback; the client
/// side takes the server's REALITY public key and short id.
#[cfg(feature = "reality")]
fn prompt_reality(theme: &ColorfulTheme, server: bool) -> Result<TransportChoice> {
    let server_name: String = Input::with_theme(theme)
        .with_prompt("  REALITY site to borrow (a real HTTPS host, e.g. www.cloudflare.com)")
        .default("www.cloudflare.com".to_string())
        .interact_text()
        .map_err(wizard_io_err)?;

    if server {
        let dest: String = Input::with_theme(theme)
            .with_prompt("  Probe fallback target (host:port non-clients are proxied to)")
            .default(format!("{}:443", server_name))
            .validate_with(|s: &String| validate_endpoint(s))
            .interact_text()
            .map_err(wizard_io_err)?;
        Ok(TransportChoice {
            kind: "reality".to_string(),
            reality_server_name: Some(server_name),
            reality_dest: Some(dest),
            ..Default::default()
        })
    } else {
        let public_key: String = Input::with_theme(theme)
            .with_prompt("  Server REALITY public key (base64, from 2cha reality-keygen)")
            .validate_with(|s: &String| -> std::result::Result<(), String> {
                twocha_core::decode_public_key(s.trim())
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            })
            .interact_text()
            .map_err(wizard_io_err)?;
        let short_id: String = Input::with_theme(theme)
            .with_prompt("  REALITY short id (hex)")
            .validate_with(|s: &String| -> std::result::Result<(), String> {
                twocha_core::crypto::reality::parse_short_id(s.trim())
                    .map(|_| ())
                    .ok_or_else(|| "expected 1–16 hex digits".to_string())
            })
            .interact_text()
            .map_err(wizard_io_err)?;
        Ok(TransportChoice {
            kind: "reality".to_string(),
            reality_server_name: Some(server_name),
            reality_public_key: Some(public_key.trim().to_string()),
            reality_short_id: Some(short_id.trim().to_string()),
            ..Default::default()
        })
    }
}

/// Validate a "host:port" endpoint (domain names allowed)
fn validate_endpoint(s: &str) -> std::result::Result<(), String> {
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
