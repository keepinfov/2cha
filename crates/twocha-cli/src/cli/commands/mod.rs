//! # CLI Commands
//!
//! Command implementations for the VPN CLI.

mod config;
mod init;
mod init_wizard;
mod keys;
mod peer;
mod server;
mod setup;
mod status;
mod updown;

pub use config::{
    cmd_config_edit, cmd_config_get, cmd_config_set, cmd_config_show, cmd_config_validate,
};
pub use init::cmd_init;
pub use keys::{cmd_genkey, cmd_pubkey, cmd_reality_keygen};
pub use peer::{cmd_peer_add, cmd_peer_list, cmd_peer_remove};
pub use server::cmd_server;
pub use setup::cmd_setup;
pub use status::cmd_status;
pub use updown::{cmd_down, cmd_toggle, cmd_up};

use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;
use twocha_protocol::{Result, VpnError};

/// Create a spinner with consistent styling
fn create_spinner(msg: &str) -> ProgressBar {
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    spinner.set_message(msg.to_string());
    spinner.enable_steady_tick(Duration::from_millis(80));
    spinner
}

/// Interactive fallback for a missing argument: run `prompt` when both stdout
/// and stderr are terminals; otherwise fail like a missing clap argument would
/// (scripts keep deterministic behavior, humans get asked).
pub(crate) fn prompt_if_tty<T>(what: &str, prompt: impl FnOnce() -> Result<T>) -> Result<T> {
    use console::Term;
    if Term::stdout().is_term() && Term::stderr().is_term() {
        prompt()
    } else {
        Err(VpnError::Config(format!(
            "missing {} (non-interactive terminal; pass it as an argument)",
            what
        )))
    }
}
