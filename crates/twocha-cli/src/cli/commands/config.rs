//! `2cha config` — inspect and edit a config file without hand-editing TOML.
//!
//! All mutating operations validate the result against the real schema and
//! write atomically, so a bad edit never lands on disk.

use std::path::Path;

use console::style;
use dialoguer::{theme::ColorfulTheme, Confirm};
use twocha_protocol::{Result, VpnError};

use crate::cli::output::icon_success;

/// Which schema a config file follows.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ConfigKind {
    Server,
    Client,
}

impl ConfigKind {
    /// Validate a rendered config string against this kind's schema.
    fn validate(self, content: &str) -> std::result::Result<(), twocha_core::ConfigError> {
        match self {
            ConfigKind::Server => twocha_core::ServerConfig::parse(content)?.validate(),
            ConfigKind::Client => twocha_core::ClientConfig::parse(content)?.validate(),
        }
    }
}

/// Detect whether a config file is a server or client config, honouring an
/// explicit `--server`/`--client` override.
fn detect_kind(path: &Path, force_server: bool, force_client: bool) -> Result<ConfigKind> {
    if force_server && force_client {
        return Err(VpnError::Config(
            "pass at most one of --server / --client".into(),
        ));
    }
    if force_server {
        return Ok(ConfigKind::Server);
    }
    if force_client {
        return Ok(ConfigKind::Client);
    }

    let content = std::fs::read_to_string(path)
        .map_err(|e| VpnError::Config(format!("{}: {}", path.display(), e)))?;
    let doc = content
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| VpnError::Config(format!("{}: {}", path.display(), e)))?;
    match (doc.contains_key("server"), doc.contains_key("client")) {
        (true, false) => Ok(ConfigKind::Server),
        (false, true) => Ok(ConfigKind::Client),
        (true, true) => Err(VpnError::Config(
            "config has both [server] and [client]; pass --server or --client".into(),
        )),
        (false, false) => Err(VpnError::Config(
            "config has neither [server] nor [client]; pass --server or --client".into(),
        )),
    }
}

/// A one-line human summary of a valid config.
fn summary(kind: ConfigKind, content: &str) -> Option<String> {
    match kind {
        ConfigKind::Server => {
            let c = twocha_core::ServerConfig::parse(content).ok()?;
            Some(format!(
                "server listen={} transport={} peers={}",
                c.server.listen,
                c.server.transport,
                c.peers.len()
            ))
        }
        ConfigKind::Client => {
            let c = twocha_core::ClientConfig::parse(content).ok()?;
            Some(format!(
                "client server={} transport={}",
                c.client.server, c.client.transport
            ))
        }
    }
}

fn read(path: &Path) -> Result<String> {
    std::fs::read_to_string(path)
        .map_err(|e| VpnError::Config(format!("{}: {}", path.display(), e)))
}

pub fn cmd_config_validate(config: &str, force_server: bool, force_client: bool) -> Result<()> {
    let path = Path::new(config);
    let kind = detect_kind(path, force_server, force_client)?;
    let content = read(path)?;
    match kind.validate(&content) {
        Ok(()) => {
            let detail = summary(kind, &content).unwrap_or_default();
            println!(
                " {}{} is valid  {}",
                icon_success(),
                style(config).bold(),
                style(detail).dim()
            );
            Ok(())
        }
        Err(e) => Err(VpnError::Config(format!("{} is invalid: {}", config, e))),
    }
}

pub fn cmd_config_show(
    config: &str,
    force_server: bool,
    force_client: bool,
    raw: bool,
) -> Result<()> {
    let path = Path::new(config);
    let content = read(path)?;
    print!("{}", content);
    if !content.ends_with('\n') {
        println!();
    }
    if raw {
        return Ok(());
    }
    let kind = detect_kind(path, force_server, force_client)?;
    match kind.validate(&content) {
        Ok(()) => {
            println!();
            println!(
                " {}{}",
                icon_success(),
                style(summary(kind, &content).unwrap_or_else(|| "valid".into())).dim()
            );
            Ok(())
        }
        Err(e) => Err(VpnError::Config(format!("{} is invalid: {}", config, e))),
    }
}

pub fn cmd_config_get(config: &str, key: &str) -> Result<()> {
    let value = twocha_core::get_value(Path::new(config), key)
        .map_err(|e| VpnError::Config(format!("{}", e)))?;
    println!("{}", value);
    Ok(())
}

pub fn cmd_config_set(
    config: &str,
    key: &str,
    value: &str,
    force_server: bool,
    force_client: bool,
) -> Result<()> {
    let path = Path::new(config);
    let kind = detect_kind(path, force_server, force_client)?;
    let old = twocha_core::get_value(path, key).ok();

    twocha_core::set_value(path, key, value, |rendered| kind.validate(rendered))
        .map_err(|e| VpnError::Config(format!("{}", e)))?;

    let new = twocha_core::get_value(path, key).unwrap_or_else(|_| value.to_string());
    match old {
        Some(old) if old != new => println!(
            " {}{} : {} → {}",
            icon_success(),
            style(key).bold(),
            style(old).dim(),
            style(new).green()
        ),
        _ => println!(
            " {}{} = {}",
            icon_success(),
            style(key).bold(),
            style(new).green()
        ),
    }
    Ok(())
}

pub fn cmd_config_edit(config: &str, force_server: bool, force_client: bool) -> Result<()> {
    let path = Path::new(config);
    let kind = detect_kind(path, force_server, force_client)?;
    let original = read(path)?;

    let editor = std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .unwrap_or_else(|_| "vi".to_string());

    let edit_path = path.with_extension("toml.edit");
    std::fs::write(&edit_path, &original)
        .map_err(|e| VpnError::Config(format!("{}: {}", edit_path.display(), e)))?;

    let theme = ColorfulTheme::default();
    loop {
        let status = std::process::Command::new(&editor)
            .arg(&edit_path)
            .status()
            .map_err(|e| {
                let _ = std::fs::remove_file(&edit_path);
                VpnError::Config(format!("failed to launch editor '{}': {}", editor, e))
            })?;
        if !status.success() {
            let _ = std::fs::remove_file(&edit_path);
            return Err(VpnError::Config("editor exited with an error".into()));
        }

        let edited = read(&edit_path)?;
        if edited == original {
            let _ = std::fs::remove_file(&edit_path);
            println!(" {}no changes", icon_success());
            return Ok(());
        }

        match kind.validate(&edited) {
            Ok(()) => {
                std::fs::rename(&edit_path, path)
                    .map_err(|e| VpnError::Config(format!("{}: {}", path.display(), e)))?;
                println!(
                    " {}saved {}  {}",
                    icon_success(),
                    style(config).bold(),
                    style(summary(kind, &edited).unwrap_or_default()).dim()
                );
                return Ok(());
            }
            Err(e) => {
                crate::cli::output::print_error(format!("invalid config: {}", e));
                let again = Confirm::with_theme(&theme)
                    .with_prompt("Re-open the editor to fix it? (No discards your changes)")
                    .default(true)
                    .interact()
                    .unwrap_or(false);
                if !again {
                    let _ = std::fs::remove_file(&edit_path);
                    return Err(VpnError::Config(
                        "edit discarded; original config left unchanged".into(),
                    ));
                }
            }
        }
    }
}
