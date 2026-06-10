//! Server command.

use crate::cli::utils::{daemonize, ensure_root, setup_logging};
use twocha_lib::vpn::server;
use twocha_protocol::{Result, VpnError};

/// Run VPN server
pub fn cmd_server(config_path: &str, daemon: bool, verbose: bool, quiet: bool) -> Result<()> {
    // Ensure we have root privileges (will prompt for sudo password if needed)
    ensure_root()?;

    // Convert config path to absolute before daemonizing
    let config_path = std::fs::canonicalize(config_path)
        .map_err(|e| VpnError::Config(format!("Config file '{}' not found: {}", config_path, e)))?
        .to_string_lossy()
        .to_string();

    if daemon {
        daemonize()?;
    }

    setup_logging(verbose, quiet);

    #[cfg(windows)]
    log::info!("Note: Requires wintun.dll and Administrator privileges");

    server::run(&config_path)
}
