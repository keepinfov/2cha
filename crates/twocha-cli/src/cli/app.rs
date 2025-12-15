//! # CLI Application
//!
//! CLI definition and command dispatch using clap.

use clap::{Parser, Subcommand};

use super::commands::{cmd_down, cmd_genkey, cmd_init, cmd_keyinfo, cmd_pubkey, cmd_server, cmd_status, cmd_toggle, cmd_up};
use super::output;
use super::print_banner;
use clap::ValueEnum;
use twocha_protocol::Result;

/// 2cha - High-performance VPN utility with IPv4/IPv6 support
#[derive(Parser)]
#[command(
    name = "2cha",
    version = env!("CARGO_PKG_VERSION"),
    about = "High-performance VPN utility with IPv4/IPv6 support",
    long_about = None,
    after_help = "Examples:\n  \
        2cha up -c client.toml\n  \
        2cha server -c server.toml\n  \
        2cha genkey -t ed25519 -o server.key\n  \
        2cha pubkey server.key\n  \
        2cha keyinfo server.key\n  \
        2cha init client > client.toml\n  \
        2cha status\n\n\
        Note: Commands requiring root will automatically prompt for sudo password.",
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
    Genkey {
        /// Key type: ed25519 (default, protocol v4) or symmetric (legacy)
        #[arg(short = 't', long = "type", value_enum, default_value = "ed25519")]
        key_type: KeyTypeArg,

        /// Output file path (prints to stdout if not specified)
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Extract public key from key file
    Pubkey {
        /// Path to .2cha-key file
        key_file: String,

        /// Output format: base64 (default) or hex
        #[arg(short, long, value_enum, default_value = "base64")]
        format: OutputFormat,
    },

    /// Show key file information
    Keyinfo {
        /// Path to .2cha-key file
        key_file: String,
    },

    /// Create config template
    Init {
        /// Config type: client or server
        #[arg(default_value = "client")]
        mode: String,
    },
}

/// Key type argument for genkey command
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum KeyTypeArg {
    /// Ed25519 key pair (protocol v4, recommended)
    Ed25519,
    /// Symmetric key (legacy, protocol v3)
    Symmetric,
}

/// Output format for pubkey command
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    /// Base64 encoding
    Base64,
    /// Hexadecimal encoding
    Hex,
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

/// Run the CLI application
pub fn run() -> Result<()> {
    // Show banner if no args
    if std::env::args().len() < 2 {
        print_banner();
        let _ = Cli::try_parse();
        std::process::exit(1);
    }

    let cli = Cli::parse();

    match cli.command {
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

        Commands::Genkey { key_type, output } => cmd_genkey(key_type, output.as_deref()),

        Commands::Pubkey { key_file, format } => cmd_pubkey(&key_file, format),

        Commands::Keyinfo { key_file } => cmd_keyinfo(&key_file),

        Commands::Init { mode } => cmd_init(&mode),
    }
}

/// Print error and exit
pub fn exit_with_error(e: impl std::fmt::Display) -> ! {
    output::print_error(e);
    std::process::exit(1);
}
