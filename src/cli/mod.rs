//! # CLI Module
//!
//! Command-line interface for the VPN utility.

mod app;
mod commands;
#[allow(dead_code)]
mod output;
mod utils;

pub use app::{exit_with_error, run};

use crate::constants::PROTOCOL_VERSION;
use console::style;

const VERSION: &str = env!("CARGO_PKG_VERSION");

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
