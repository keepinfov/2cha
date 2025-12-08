//! # CLI Module
//!
//! Command-line interface for the VPN utility.

mod commands;
mod utils;

pub use commands::{cmd_down, cmd_genkey, cmd_init, cmd_server, cmd_status, cmd_toggle, cmd_up};

use crate::constants::PROTOCOL_VERSION;
use console::style;

const VERSION: &str = "0.6.1";

/// Print ASCII banner with styled output
pub fn print_banner() {
    let banner = r#"
  ██████╗  ██████╗██╗  ██╗ █████╗
  ╚════██╗██╔════╝██║  ██║██╔══██╗
   █████╔╝██║     ███████║███████║
  ██╔═══╝ ██║     ██╔══██║██╔══██║
  ███████╗╚██████╗██║  ██║██║  ██║
  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝"#;

    println!("{}", style(banner).cyan().bold());
    println!(
        "  {} {} | Protocol {}",
        style("v").dim(),
        style(VERSION).green().bold(),
        style(PROTOCOL_VERSION).dim()
    );
    println!();

    #[cfg(target_env = "musl")]
    println!(
        "  {} {}",
        style("Build:").dim(),
        style("static (musl)").green()
    );
    #[cfg(not(target_env = "musl"))]
    println!(
        "  {} {}",
        style("Build:").dim(),
        style("dynamic (glibc)").yellow()
    );

    println!();
    println!(
        "  High-performance VPN with {} support",
        style("IPv4/IPv6").cyan()
    );
    println!();
    println!(
        "  Run {} for available commands",
        style("2cha --help").green()
    );
    println!();
}
