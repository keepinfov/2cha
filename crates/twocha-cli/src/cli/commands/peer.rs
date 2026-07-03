//! Runtime peer management commands (talk to a running server).

use console::style;
use twocha_protocol::{Result, VpnError};

use crate::cli::output::{icon_error, icon_success, print_error};

#[cfg(unix)]
fn send(request: &str) -> Result<String> {
    use twocha_lib::vpn::server::control;

    let Some(socket) = control::find_control_socket() else {
        return Err(VpnError::Config(
            "control socket not found — is the server running on this machine?".into(),
        ));
    };
    control::send_request(&socket, request)
        .map_err(|e| VpnError::Config(format!("{} (is the server running? do you need sudo?)", e)))
}

#[cfg(windows)]
fn send(_request: &str) -> Result<String> {
    Err(VpnError::Config(
        "peer management is not supported on Windows yet".into(),
    ))
}

fn validate_key(public_key: &str) -> Result<()> {
    twocha_core::decode_public_key(public_key).map(|_| ())
}

/// One authorized peer as reported by the running server.
pub(crate) struct PeerInfo {
    pub key: String,
    pub name: Option<String>,
    pub online: bool,
    pub endpoint: Option<String>,
    pub last_recv_secs: Option<u64>,
}

/// Fetch and parse the peer list from the running server's control socket.
/// Shared by `peer list`, the interactive `peer remove` picker and
/// `status --watch`.
pub(crate) fn fetch_peers() -> Result<Vec<PeerInfo>> {
    let response = send("peer-list")?;
    let mut lines = response.lines();
    let header = lines.next().unwrap_or("").trim();
    if let Some(msg) = header.strip_prefix("err") {
        return Err(VpnError::Config(msg.trim_start().to_string()));
    }
    if !header.starts_with("ok") {
        return Err(VpnError::Config(format!(
            "unexpected server reply: {}",
            header
        )));
    }

    let mut peers = Vec::new();
    for line in lines {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // peer <key> <name|-> online endpoint=<ep> last_recv_secs=<n> | peer <key> <name|-> offline
        if fields.len() < 4 || fields[0] != "peer" {
            continue;
        }
        let mut peer = PeerInfo {
            key: fields[1].to_string(),
            name: (fields[2] != "-").then(|| fields[2].to_string()),
            online: fields[3] == "online",
            endpoint: None,
            last_recv_secs: None,
        };
        for field in &fields[4..] {
            if let Some(ep) = field.strip_prefix("endpoint=") {
                peer.endpoint = Some(ep.to_string());
            } else if let Some(secs) = field.strip_prefix("last_recv_secs=") {
                peer.last_recv_secs = secs.parse().ok();
            }
        }
        peers.push(peer);
    }
    Ok(peers)
}

/// Print a server reply: `ok ...` lines as success, `err ...` as failure
fn report(response: &str) -> Result<()> {
    let response = response.trim();
    if let Some(msg) = response.strip_prefix("ok") {
        println!(" {}{}", icon_success(), msg.trim_start());
        Ok(())
    } else if let Some(msg) = response.strip_prefix("err") {
        print_error(msg.trim_start());
        std::process::exit(1);
    } else {
        Err(VpnError::Config(format!(
            "unexpected server reply: {}",
            response
        )))
    }
}

/// Interactive fallback: prompt for a key (TTY only) when none was given.
fn prompt_public_key() -> Result<String> {
    crate::cli::commands::prompt_if_tty("peer public key", || {
        dialoguer::Input::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("Client public key (base64, from: 2cha pubkey client.key)")
            .validate_with(|s: &String| {
                twocha_core::decode_public_key(s.trim())
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            })
            .interact_text()
            .map(|s: String| s.trim().to_string())
            .map_err(|e| VpnError::Config(format!("prompt failed: {}", e)))
    })
}

pub fn cmd_peer_add(public_key: Option<&str>, name: Option<&str>) -> Result<()> {
    let public_key = match public_key {
        Some(k) => k.to_string(),
        None => prompt_public_key()?,
    };
    validate_key(&public_key)?;
    if let Some(name) = name {
        if name.chars().any(char::is_whitespace) {
            return Err(VpnError::Config("peer name must not contain spaces".into()));
        }
    }
    let request = match name {
        Some(name) => format!("peer-add {} {}", public_key, name),
        None => format!("peer-add {}", public_key),
    };
    report(&send(&request)?)
}

pub fn cmd_peer_remove(public_key: Option<&str>) -> Result<()> {
    let public_key = match public_key {
        Some(k) => k.to_string(),
        // Interactive fallback: pick from the live peer list when possible,
        // else fall back to a validated text prompt.
        None => match fetch_peers() {
            Ok(peers) if !peers.is_empty() => {
                crate::cli::commands::prompt_if_tty("peer public key", || {
                    let items: Vec<String> = peers
                        .iter()
                        .map(|p| {
                            format!(
                                "{}  {} ({})",
                                p.name.as_deref().unwrap_or("-"),
                                p.key,
                                if p.online { "online" } else { "offline" }
                            )
                        })
                        .collect();
                    let idx =
                        dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
                            .with_prompt("Peer to remove")
                            .items(&items)
                            .default(0)
                            .interact()
                            .map_err(|e| VpnError::Config(format!("prompt failed: {}", e)))?;
                    Ok(peers[idx].key.clone())
                })?
            }
            _ => prompt_public_key()?,
        },
    };
    validate_key(&public_key)?;
    report(&send(&format!("peer-remove {}", public_key))?)
}

pub fn cmd_peer_list() -> Result<()> {
    let peers = match fetch_peers() {
        Ok(peers) => peers,
        Err(e) => {
            print_error(e);
            std::process::exit(1);
        }
    };

    println!();
    println!(
        " {} {}",
        style("◆").cyan().bold(),
        style("Authorized peers").bold()
    );
    for peer in &peers {
        println!("   {}", render_peer_line(peer));
    }
    if peers.is_empty() {
        println!("   {} no peers configured", icon_error());
    }
    println!();
    Ok(())
}

/// One formatted peer row, shared with `status --watch`.
pub(crate) fn render_peer_line(peer: &PeerInfo) -> String {
    let status = if peer.online {
        style("● online ").green()
    } else {
        style("○ offline").dim()
    };
    let mut details = String::new();
    if let Some(ref ep) = peer.endpoint {
        details.push_str(&format!("  {}", ep));
    }
    if let Some(secs) = peer.last_recv_secs {
        details.push_str(&format!("  last seen {}s ago", secs));
    }
    format!(
        "{}  {}  {}{}",
        status,
        style(&peer.key).cyan(),
        style(format!("{:<12}", peer.name.as_deref().unwrap_or(""))).bold(),
        style(details).dim()
    )
}
