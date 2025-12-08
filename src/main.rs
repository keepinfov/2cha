//! # 2cha - High-Performance VPN Utility
//!
//! Entry point for the command-line interface.

use clap::{Parser, Subcommand};
use console::style;
use std::process;

use twocha::cli::{
    cmd_down, cmd_genkey, cmd_init, cmd_server, cmd_status, cmd_toggle, cmd_up, print_banner,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// 2cha - High-performance VPN utility with IPv4/IPv6 support
#[derive(Parser)]
#[command(
    name = "2cha",
    version = VERSION,
    about = "High-performance VPN utility with IPv4/IPv6 support",
    long_about = None,
    after_help = "Examples:\n  \
        sudo 2cha up -c client.toml\n  \
        sudo 2cha server -c server.toml\n  \
        2cha genkey > vpn.key\n  \
        2cha init client > client.toml\n  \
        2cha status",
    styles = get_styles(),
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Connect to VPN server
    #[command(visible_alias = "connect")]
    Up {
        /// Config file path
        #[arg(short, long, default_value = default_config())]
        config: String,

        /// Run in background (daemon mode)
        #[arg(short, long)]
        daemon: bool,

        /// Enable verbose output
        #[arg(short, long)]
        verbose: bool,

        /// Minimal output
        #[arg(short, long)]
        quiet: bool,
    },

    /// Disconnect from VPN
    #[command(visible_alias = "disconnect")]
    Down,

    /// Show connection status
    #[command(visible_alias = "s")]
    Status,

    /// Toggle VPN connection on/off
    #[command(visible_alias = "t")]
    Toggle {
        /// Config file path
        #[arg(short, long, default_value = default_config())]
        config: String,

        /// Run in background (daemon mode)
        #[arg(short, long)]
        daemon: bool,

        /// Enable verbose output
        #[arg(short, long)]
        verbose: bool,

        /// Minimal output
        #[arg(short, long)]
        quiet: bool,
    },

    /// Run as VPN server
    #[command(visible_alias = "serve")]
    Server {
        /// Config file path
        #[arg(short, long, default_value = default_server_config())]
        config: String,

        /// Run in background (daemon mode)
        #[arg(short, long)]
        daemon: bool,

        /// Enable verbose output
        #[arg(short, long)]
        verbose: bool,

        /// Minimal output
        #[arg(short, long)]
        quiet: bool,
    },

    /// Generate encryption key
    #[command(visible_alias = "key")]
    Genkey,

    /// Create config template
    Init {
        /// Config type: client or server
        #[arg(default_value = "client")]
        mode: String,
    },
}

fn get_styles() -> clap::builder::Styles {
    clap::builder::Styles::styled()
        .usage(
            clap::builder::styling::AnsiColor::BrightCyan
                .on_default()
                .bold(),
        )
        .header(
            clap::builder::styling::AnsiColor::BrightCyan
                .on_default()
                .bold(),
        )
        .literal(clap::builder::styling::AnsiColor::BrightGreen.on_default())
        .placeholder(clap::builder::styling::AnsiColor::Cyan.on_default())
        .valid(clap::builder::styling::AnsiColor::BrightGreen.on_default())
        .invalid(clap::builder::styling::AnsiColor::BrightRed.on_default())
}

#[cfg(unix)]
fn default_config() -> &'static str {
    "/etc/2cha/client.toml"
}

#[cfg(windows)]
fn default_config() -> &'static str {
    "C:\\ProgramData\\2cha\\client.toml"
}

#[cfg(unix)]
fn default_server_config() -> &'static str {
    "/etc/2cha/server.toml"
}

#[cfg(windows)]
fn default_server_config() -> &'static str {
    "C:\\ProgramData\\2cha\\server.toml"
}

fn main() {
    // Show banner if no args
    if std::env::args().len() < 2 {
        print_banner();
        let _ = Cli::try_parse();
        process::exit(1);
    }

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Up {
            config,
            daemon,
            verbose,
            quiet,
        } => cmd_up(&config, daemon, verbose, quiet),

        Commands::Down => cmd_down(),

        Commands::Status => cmd_status(),

        Commands::Toggle {
            config,
            daemon,
            verbose,
            quiet,
        } => cmd_toggle(&config, daemon, verbose, quiet),

        Commands::Server {
            config,
            daemon,
            verbose,
            quiet,
        } => cmd_server(&config, daemon, verbose, quiet),

        Commands::Genkey => cmd_genkey(),

        Commands::Init { mode } => cmd_init(&mode),
    };

    if let Err(e) = result {
        eprintln!("{} Error: {}", style("✗").red().bold(), e);
        process::exit(1);
    }
}
