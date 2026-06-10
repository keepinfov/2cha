//! File-writing helpers for the init wizard.

use std::path::{Path, PathBuf};

use console::style;
use dialoguer::{theme::ColorfulTheme, Confirm};
use twocha_core::Identity;
use twocha_protocol::{Result, VpnError};

use crate::cli::utils::is_root;

/// Default directory for configs and keys: /etc/2cha for root,
/// ~/.config/2cha otherwise.
pub fn default_config_dir() -> PathBuf {
    #[cfg(unix)]
    {
        if is_root() {
            return PathBuf::from("/etc/2cha");
        }
        if let Ok(home) = std::env::var("HOME") {
            if !home.is_empty() {
                return PathBuf::from(home).join(".config/2cha");
            }
        }
        PathBuf::from(".")
    }
    #[cfg(windows)]
    {
        let _ = is_root;
        PathBuf::from("C:\\ProgramData\\2cha")
    }
}

/// Write a config file, asking before overwriting an existing one
pub fn write_config(theme: &ColorfulTheme, path: &Path, contents: &str) -> Result<()> {
    if path.exists() {
        let overwrite = Confirm::with_theme(theme)
            .with_prompt(format!("{} already exists. Overwrite?", path.display()))
            .default(false)
            .interact()
            .map_err(wizard_io_err)?;
        if !overwrite {
            return Err(VpnError::Config(format!(
                "refused to overwrite {}",
                path.display()
            )));
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| VpnError::Config(format!("cannot create {}: {}", parent.display(), e)))?;
    }
    std::fs::write(path, contents)
        .map_err(|e| VpnError::Config(format!("cannot write {}: {}", path.display(), e)))?;
    Ok(())
}

/// Load an existing key or generate and save a new one.
/// Returns the identity and whether it was freshly generated.
pub fn load_or_generate_key(path: &Path) -> Result<(Identity, bool)> {
    if path.exists() {
        let identity = Identity::load(path)?;
        return Ok((identity, false));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| VpnError::Config(format!("cannot create {}: {}", parent.display(), e)))?;
    }
    let identity = Identity::generate();
    identity.save(path)?;
    Ok((identity, true))
}

/// Map a dialoguer I/O error (including Ctrl-C/EOF) to a friendly error
pub fn wizard_io_err(e: dialoguer::Error) -> VpnError {
    let dialoguer::Error::IO(io) = e;
    if io.kind() == std::io::ErrorKind::Interrupted {
        VpnError::Config("wizard cancelled".to_string())
    } else {
        VpnError::Config(format!("input error: {}", io))
    }
}

/// Print a key-value line for the summary panel
pub fn summary_line(label: &str, value: impl std::fmt::Display) {
    println!("   {} {}", style(format!("{:<18}", label)).dim(), value);
}
