//! Interactive config-creation wizard for `2cha init`.

pub mod client;
pub mod detect;
pub mod render;
pub mod server;
pub mod write;

use dialoguer::{theme::ColorfulTheme, Select};
use twocha_protocol::Result;
use write::wizard_io_err;

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
