//! Key management commands.

use console::style;
use std::path::Path;
use twocha_core::Identity;
use twocha_protocol::Result;

/// Generate an X25519 keypair: private key to file (0600), public key to stdout
pub fn cmd_genkey(output: &str) -> Result<()> {
    let identity = Identity::generate();
    identity.save(Path::new(output))?;
    eprintln!(
        "  {} Private key saved to {}",
        style("✓").green().bold(),
        style(output).cyan()
    );
    eprintln!("  Public key:");
    println!("{}", identity.public_base64());
    Ok(())
}

/// Print the public key derived from a private key file
pub fn cmd_pubkey(key_file: &str) -> Result<()> {
    let identity = Identity::load(Path::new(key_file))?;
    println!("{}", identity.public_base64());
    Ok(())
}
