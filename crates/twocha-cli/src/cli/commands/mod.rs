//! # CLI Commands
//!
//! Command implementations for the VPN CLI.

mod init;
mod init_wizard;
mod keys;
mod peer;
mod server;
mod status;
mod updown;

pub use init::cmd_init;
pub use keys::{cmd_genkey, cmd_pubkey};
pub use peer::{cmd_peer_add, cmd_peer_list, cmd_peer_remove};
pub use server::cmd_server;
pub use status::cmd_status;
pub use updown::{cmd_down, cmd_toggle, cmd_up};

use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

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
