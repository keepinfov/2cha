//! Interactive server setup wizard.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use console::style;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};
use twocha_protocol::{Result, VpnError};

use super::detect;
use super::render::{
    client_address, render_client, render_server, server_address, ClientParams, PeerParams,
    ServerParams,
};
use super::write::{
    default_config_dir, load_or_generate_key, summary_line, wizard_io_err, write_config,
};
use super::{prompt_cipher, prompt_transport, validate_endpoint};
use crate::cli::output::{icon_success, icon_warning};

struct GeneratedClient {
    name: String,
    config_path: PathBuf,
    key_path: PathBuf,
    public_key: String,
    address: Ipv4Addr,
}

pub fn run(output_dir: Option<&Path>) -> Result<()> {
    let theme = ColorfulTheme::default();

    println!();
    println!(
        " {} {}",
        style("◆").cyan().bold(),
        style("2cha server setup").cyan().bold()
    );
    println!(
        "   {}",
        style("Answer a few questions to generate a ready-to-run config.").dim()
    );
    println!();

    // ── Paths ────────────────────────────────────────────────────────────
    let dir: PathBuf = match output_dir {
        Some(d) => d.to_path_buf(),
        None => Input::with_theme(&theme)
            .with_prompt("Directory for configs and keys")
            .default(default_config_dir().display().to_string())
            .interact_text()
            .map_err(wizard_io_err)?
            .into(),
    };

    // ── Listen address ───────────────────────────────────────────────────
    let listen: String = Input::with_theme(&theme)
        .with_prompt("Listen address (ip:port)")
        .default("0.0.0.0:51820".to_string())
        .validate_with(|s: &String| -> std::result::Result<(), String> {
            s.parse::<SocketAddr>()
                .map(|_| ())
                .map_err(|_| format!("'{}' is not a valid ip:port", s))
        })
        .interact_text()
        .map_err(wizard_io_err)?;
    let listen_port = listen.rsplit(':').next().unwrap_or("51820").to_string();

    let cipher = prompt_cipher(&theme)?;
    let transport = prompt_transport(&theme, true)?;

    // ── Server key ───────────────────────────────────────────────────────
    let key_path: PathBuf = Input::with_theme(&theme)
        .with_prompt("Server private key file")
        .default(dir.join("server.key").display().to_string())
        .interact_text()
        .map_err(wizard_io_err)?
        .into();
    let (identity, generated) = load_or_generate_key(&key_path)?;
    let server_public = identity.public_base64();
    println!(
        "   {} {} key {} public key: {}",
        icon_success(),
        if generated { "Generated" } else { "Loaded" },
        style(key_path.display()).dim(),
        style(&server_public).green().bold()
    );

    // ── VPN subnet ───────────────────────────────────────────────────────
    let (suggested_net, suggested_prefix) = detect::suggest_subnet();
    let subnet_str: String = Input::with_theme(&theme)
        .with_prompt("VPN subnet (CIDR)")
        .default(format!("{}/{}", suggested_net, suggested_prefix))
        .validate_with(|s: &String| parse_cidr(s).map(|_| ()))
        .interact_text()
        .map_err(wizard_io_err)?;
    let (subnet, prefix) = parse_cidr(&subnet_str).map_err(VpnError::Config)?;
    println!(
        "   {} server tunnel address: {}",
        icon_success(),
        style(format!("{}/{}", server_address(subnet), prefix)).green()
    );

    // ── Gateway / NAT ────────────────────────────────────────────────────
    let gateway = Confirm::with_theme(&theme)
        .with_prompt("Route client internet traffic (NAT gateway)?")
        .default(true)
        .interact()
        .map_err(wizard_io_err)?;

    let external_interface = if gateway {
        let detected = detect::default_route_interface();
        let mut ifaces: Vec<String> = detect::local_interfaces()
            .into_iter()
            .filter(|i| !i.is_loopback && i.is_up)
            .map(|i| i.name)
            .collect();
        if ifaces.is_empty() {
            ifaces.push(detected.clone().unwrap_or_else(|| "eth0".to_string()));
        }
        let default_idx = detected
            .as_deref()
            .and_then(|d| ifaces.iter().position(|i| i == d))
            .unwrap_or(0);
        let idx = Select::with_theme(&theme)
            .with_prompt("External (internet-facing) interface")
            .items(&ifaces)
            .default(default_idx)
            .interact()
            .map_err(wizard_io_err)?;
        Some(ifaces[idx].clone())
    } else {
        None
    };

    let max_clients: usize = Input::with_theme(&theme)
        .with_prompt("Max clients")
        .default(256)
        .interact_text()
        .map_err(wizard_io_err)?;

    // ── Paired clients ───────────────────────────────────────────────────
    let mut peers: Vec<PeerParams> = Vec::new();
    let mut clients: Vec<(GeneratedClient, String)> = Vec::new();

    let mut endpoint_default = detect::endpoint_candidates()
        .first()
        .map(|ip| format!("{}:{}", ip, listen_port))
        .unwrap_or_else(|| format!("vpn.example.com:{}", listen_port));

    let mut add_client = Confirm::with_theme(&theme)
        .with_prompt("Generate a paired client config now?")
        .default(true)
        .interact()
        .map_err(wizard_io_err)?;

    while add_client {
        let n = clients.len();
        let name: String = Input::with_theme(&theme)
            .with_prompt("  Client name")
            .default(format!("client{}", n + 1))
            .validate_with(|s: &String| -> std::result::Result<(), &str> {
                if !s.is_empty()
                    && s.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                {
                    Ok(())
                } else {
                    Err("use letters, digits, '-' or '_'")
                }
            })
            .interact_text()
            .map_err(wizard_io_err)?;

        let endpoint: String = Input::with_theme(&theme)
            .with_prompt("  Server endpoint as seen by clients (host:port)")
            .default(endpoint_default.clone())
            .validate_with(|s: &String| validate_endpoint(s))
            .interact_text()
            .map_err(wizard_io_err)?;
        endpoint_default = endpoint.clone();

        let route_all = Confirm::with_theme(&theme)
            .with_prompt("  Route all client traffic through the VPN?")
            .default(true)
            .interact()
            .map_err(wizard_io_err)?;

        let key_path = dir.join(format!("{}.key", name));
        let (client_id, _) = load_or_generate_key(&key_path)?;
        let address = client_address(subnet, n);

        let client_cfg = render_client(&ClientParams {
            endpoint,
            cipher: cipher.clone(),
            key_file: key_path.display().to_string(),
            server_public_key: server_public.clone(),
            address,
            prefix,
            route_all,
            dns_servers: if route_all {
                vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]
            } else {
                Vec::new()
            },
            transport: transport.kind.clone(),
            tls_sni: transport.sni.clone(),
        });

        peers.push(PeerParams {
            public_key: client_id.public_base64(),
            name: name.clone(),
        });
        clients.push((
            GeneratedClient {
                config_path: dir.join(format!("{}.toml", name)),
                public_key: client_id.public_base64(),
                key_path,
                address,
                name,
            },
            client_cfg,
        ));

        add_client = Confirm::with_theme(&theme)
            .with_prompt("Add another client?")
            .default(false)
            .interact()
            .map_err(wizard_io_err)?;
    }

    // ── Render, validate, write ──────────────────────────────────────────
    let server_cfg = render_server(&ServerParams {
        listen,
        max_clients,
        cipher,
        key_file: key_path.display().to_string(),
        peers,
        subnet,
        prefix,
        gateway,
        external_interface,
        transport: transport.kind.clone(),
        tls_sni: transport.sni.clone(),
        tls_cert_file: transport.cert_file.clone(),
        tls_key_file: transport.key_file.clone(),
    });

    let parsed = twocha_core::ServerConfig::parse(&server_cfg)
        .map_err(|e| VpnError::Config(format!("generated config is invalid: {}", e)))?;
    if !parsed.peers.is_empty() {
        parsed
            .validate()
            .map_err(|e| VpnError::Config(format!("generated config is invalid: {}", e)))?;
    }
    for (_, cfg) in &clients {
        twocha_core::ClientConfig::parse(cfg)
            .map_err(|e| VpnError::Config(format!("generated client config is invalid: {}", e)))?
            .validate()
            .map_err(|e| VpnError::Config(format!("generated client config is invalid: {}", e)))?;
    }

    let server_cfg_path = dir.join("server.toml");
    write_config(&theme, &server_cfg_path, &server_cfg)?;
    for (client, cfg) in &clients {
        write_config(&theme, &client.config_path, cfg)?;
    }

    // ── Summary ──────────────────────────────────────────────────────────
    println!();
    println!(" {} {}", icon_success(), style("Server ready").bold());
    summary_line("Config", server_cfg_path.display());
    summary_line("Private key", key_path.display());
    summary_line("Public key", style(&server_public).green());
    summary_line("Tunnel", format!("{}/{}", server_address(subnet), prefix));
    for (client, _) in &clients {
        println!();
        println!(
            "   {} client {}",
            style("◇").cyan(),
            style(&client.name).bold()
        );
        summary_line("Config", client.config_path.display());
        summary_line("Private key", client.key_path.display());
        summary_line("Public key", style(&client.public_key).green());
        summary_line("Tunnel", format!("{}/{}", client.address, prefix));
        summary_line(
            "Hand over",
            format!(
                "{} + {} (keep the key secret)",
                client.config_path.display(),
                client.key_path.display()
            ),
        );
    }
    println!();
    if clients.is_empty() {
        println!(
            " {} No clients configured: the server will not start until a [[peers]] entry is added.",
            icon_warning()
        );
    }
    println!(
        "   Start the server: {}",
        style(format!("sudo 2cha server -c {}", server_cfg_path.display())).cyan()
    );
    println!();

    Ok(())
}

/// Parse "a.b.c.d/p" into a normalized network address and prefix
fn parse_cidr(s: &str) -> std::result::Result<(Ipv4Addr, u8), String> {
    let (addr, prefix) = s
        .split_once('/')
        .ok_or_else(|| "expected CIDR like 10.8.0.0/24".to_string())?;
    let addr: Ipv4Addr = addr
        .trim()
        .parse()
        .map_err(|_| format!("'{}' is not a valid IPv4 address", addr))?;
    let prefix: u8 = prefix
        .trim()
        .parse()
        .map_err(|_| format!("'{}' is not a valid prefix", prefix))?;
    if !(8..=30).contains(&prefix) {
        return Err("prefix must be between 8 and 30".to_string());
    }
    let mask = !((1u64 << (32 - prefix as u64)) - 1) as u32;
    Ok((Ipv4Addr::from(u32::from(addr) & mask), prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cidr() {
        assert_eq!(
            parse_cidr("10.8.0.0/24").unwrap(),
            (Ipv4Addr::new(10, 8, 0, 0), 24)
        );
        // host bits are masked off
        assert_eq!(
            parse_cidr("10.8.0.5/24").unwrap(),
            (Ipv4Addr::new(10, 8, 0, 0), 24)
        );
        assert!(parse_cidr("10.8.0.0").is_err());
        assert!(parse_cidr("10.8.0.0/31").is_err());
        assert!(parse_cidr("bogus/24").is_err());
    }
}
