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
    control::send_request(&socket, request).map_err(|e| {
        VpnError::Config(format!(
            "{} (is the server running? do you need sudo?)",
            e
        ))
    })
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

pub fn cmd_peer_add(public_key: &str, name: Option<&str>) -> Result<()> {
    validate_key(public_key)?;
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

pub fn cmd_peer_remove(public_key: &str) -> Result<()> {
    validate_key(public_key)?;
    report(&send(&format!("peer-remove {}", public_key))?)
}

pub fn cmd_peer_list() -> Result<()> {
    let response = send("peer-list")?;
    let mut lines = response.lines();
    let header = lines.next().unwrap_or("").trim();

    if let Some(msg) = header.strip_prefix("err") {
        print_error(msg.trim_start());
        std::process::exit(1);
    }
    if !header.starts_with("ok") {
        return Err(VpnError::Config(format!(
            "unexpected server reply: {}",
            header
        )));
    }

    println!();
    println!(
        " {} {}",
        style("◆").cyan().bold(),
        style("Authorized peers").bold()
    );
    let mut count = 0;
    for line in lines {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // peer <key> <name|-> online endpoint=<ep> last_recv_secs=<n> | peer <key> <name|-> offline
        if fields.len() < 4 || fields[0] != "peer" {
            continue;
        }
        count += 1;
        let key = fields[1];
        let name = if fields[2] == "-" { "" } else { fields[2] };
        let online = fields[3] == "online";

        let status = if online {
            style("● online ").green()
        } else {
            style("○ offline").dim()
        };
        let mut details = String::new();
        for field in &fields[4..] {
            if let Some(ep) = field.strip_prefix("endpoint=") {
                details.push_str(&format!("  {}", ep));
            } else if let Some(secs) = field.strip_prefix("last_recv_secs=") {
                details.push_str(&format!("  last seen {}s ago", secs));
            }
        }
        println!(
            "   {}  {}  {}{}",
            status,
            style(key).cyan(),
            style(format!("{:<12}", name)).bold(),
            style(details).dim()
        );
    }
    if count == 0 {
        println!("   {} no peers configured", icon_error());
    }
    println!();
    Ok(())
}
