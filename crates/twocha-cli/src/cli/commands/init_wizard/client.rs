//! Interactive client setup wizard.

use std::path::{Path, PathBuf};

use console::style;
use dialoguer::{theme::ColorfulTheme, Confirm, Input};
use twocha_protocol::{Result, VpnError};

use super::render::{render_client, ClientParams};
use super::write::{
    default_config_dir, load_or_generate_key, summary_line, wizard_io_err, write_config,
};
use super::{prompt_cipher, prompt_transport, validate_endpoint};
use crate::cli::output::icon_success;

pub fn run(output_dir: Option<&Path>) -> Result<()> {
    let theme = ColorfulTheme::default();

    println!();
    println!(
        " {} {}",
        style("◆").cyan().bold(),
        style("2cha client setup").cyan().bold()
    );
    println!(
        "   {}",
        style("You will need the server's address and public key.").dim()
    );
    println!();

    let dir: PathBuf = match output_dir {
        Some(d) => d.to_path_buf(),
        None => Input::with_theme(&theme)
            .with_prompt("Directory for configs and keys")
            .default(default_config_dir().display().to_string())
            .interact_text()
            .map_err(wizard_io_err)?
            .into(),
    };

    let endpoint: String = Input::with_theme(&theme)
        .with_prompt("Server address (host:port)")
        .validate_with(|s: &String| validate_endpoint(s))
        .interact_text()
        .map_err(wizard_io_err)?;

    let server_public_key: String = Input::with_theme(&theme)
        .with_prompt("Server public key (base64)")
        .validate_with(|s: &String| -> std::result::Result<(), String> {
            twocha_core::decode_public_key(s)
                .map(|_| ())
                .map_err(|e| e.to_string())
        })
        .interact_text()
        .map_err(wizard_io_err)?;

    let cipher = prompt_cipher(&theme)?;
    let transport = prompt_transport(&theme, false)?;

    let key_path: PathBuf = Input::with_theme(&theme)
        .with_prompt("Client private key file")
        .default(dir.join("client.key").display().to_string())
        .interact_text()
        .map_err(wizard_io_err)?
        .into();
    let (identity, generated) = load_or_generate_key(&key_path)?;
    println!(
        "   {} {} key {} public key: {}",
        icon_success(),
        if generated { "Generated" } else { "Loaded" },
        style(key_path.display()).dim(),
        style(identity.public_base64()).green().bold()
    );

    let address: String = Input::with_theme(&theme)
        .with_prompt("Tunnel address (assigned by the server admin)")
        .default("10.8.0.2".to_string())
        .validate_with(|s: &String| -> std::result::Result<(), String> {
            s.parse::<std::net::Ipv4Addr>()
                .map(|_| ())
                .map_err(|_| format!("'{}' is not a valid IPv4 address", s))
        })
        .interact_text()
        .map_err(wizard_io_err)?;

    let route_all = Confirm::with_theme(&theme)
        .with_prompt("Route all traffic through the VPN?")
        .default(true)
        .interact()
        .map_err(wizard_io_err)?;

    let config = render_client(&ClientParams {
        endpoint,
        cipher,
        key_file: key_path.display().to_string(),
        server_public_key,
        address: address.parse().expect("validated above"),
        prefix: 24,
        route_all,
        dns_servers: if route_all {
            super::default_dns_servers()
        } else {
            Vec::new()
        },
        transport: transport.kind,
        tls_sni: transport.sni,
    });

    twocha_core::ClientConfig::parse(&config)
        .map_err(|e| VpnError::Config(format!("generated config is invalid: {}", e)))?
        .validate()
        .map_err(|e| VpnError::Config(format!("generated config is invalid: {}", e)))?;

    let config_path = dir.join("client.toml");
    write_config(&theme, &config_path, &config)?;

    println!();
    println!(" {} {}", icon_success(), style("Client ready").bold());
    summary_line("Config", config_path.display());
    summary_line("Private key", key_path.display());
    summary_line("Public key", style(identity.public_base64()).green());
    println!();
    println!(
        " {} Add this client on the server (server.toml):",
        style("◇").cyan()
    );
    println!(
        "   {}",
        style(format!(
            "[[peers]]\n   public_key = \"{}\"",
            identity.public_base64()
        ))
        .dim()
    );
    println!();
    println!(
        "   Connect: {}",
        style(format!("sudo 2cha up -c {}", config_path.display())).cyan()
    );
    println!();

    Ok(())
}
