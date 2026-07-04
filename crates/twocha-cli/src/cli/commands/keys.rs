//! Key management commands.

use console::style;
use dialoguer::theme::ColorfulTheme;
use dialoguer::Input;
use std::path::Path;
use twocha_core::Identity;
use twocha_protocol::{Result, VpnError};

use crate::cli::output::icon_success;

fn prompt_path(prompt: &str, default: Option<String>) -> Result<String> {
    let theme = ColorfulTheme::default();
    let mut input = Input::with_theme(&theme).with_prompt(prompt);
    if let Some(default) = default {
        input = input.default(default);
    }
    input
        .interact_text()
        .map(|s: String| s.trim().to_string())
        .map_err(|e| VpnError::Config(format!("prompt failed: {}", e)))
}

/// Default location for a fresh private key: system dir for root, else the
/// user config dir (mirrors the init wizard's default_config_dir policy).
fn default_key_path() -> String {
    super::init_wizard::write::default_config_dir()
        .join("client.key")
        .to_string_lossy()
        .into_owned()
}

/// Generate an X25519 keypair: private key to file (0600), public key to stdout
pub fn cmd_genkey(output: Option<&str>) -> Result<()> {
    let output = match output {
        Some(path) => path.to_string(),
        None => super::prompt_if_tty("output path for the private key", || {
            prompt_path("Where to save the private key", Some(default_key_path()))
        })?,
    };
    let identity = Identity::generate();
    identity.save(Path::new(&output))?;
    eprintln!(
        "  {} Private key saved to {}",
        icon_success(),
        style(&output).cyan()
    );
    eprintln!("  Public key:");
    println!("{}", identity.public_base64());
    Ok(())
}

/// Default location for a fresh REALITY private key.
fn default_reality_key_path() -> String {
    super::init_wizard::write::default_config_dir()
        .join("reality.key")
        .to_string_lossy()
        .into_owned()
}

/// Generate a REALITY keypair (X25519) plus a random short id for the anti-probe
/// TLS gate. The private key is written to a 0600 file; the public key and short
/// id are printed for embedding in client configs.
pub fn cmd_reality_keygen(output: Option<&str>) -> Result<()> {
    use twocha_core::crypto::reality;

    let output = match output {
        Some(path) => path.to_string(),
        None => super::prompt_if_tty("output path for the REALITY private key", || {
            prompt_path(
                "Where to save the REALITY private key",
                Some(default_reality_key_path()),
            )
        })?,
    };
    let identity = Identity::generate();
    identity.save(Path::new(&output))?;
    let short_id = reality::short_id_hex(&reality::generate_short_id());

    eprintln!(
        "  {} REALITY private key saved to {}",
        icon_success(),
        style(&output).cyan()
    );
    eprintln!("  Server (transport = \"reality\"): set reality.private_key_file to that file,");
    eprintln!("  and add this short id to reality.short_ids:");
    println!("{}", short_id);
    eprintln!("  Client config values:");
    eprintln!("    reality.public_key:");
    println!("{}", identity.public_base64());
    eprintln!("    reality.short_id:");
    println!("{}", short_id);
    Ok(())
}

/// Print the public key derived from a private key file
pub fn cmd_pubkey(key_file: Option<&str>) -> Result<()> {
    let key_file = match key_file {
        Some(path) => path.to_string(),
        None => super::prompt_if_tty("private key file path", || {
            prompt_path("Private key file", None)
        })?,
    };
    let identity = Identity::load(Path::new(&key_file))?;
    println!("{}", identity.public_base64());
    Ok(())
}
