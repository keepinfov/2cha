//! # CLI Application
//!
//! CLI definition and command dispatch using clap.

use clap::{Parser, Subcommand};

use super::commands::{
    cmd_config_edit, cmd_config_get, cmd_config_set, cmd_config_show, cmd_config_validate,
    cmd_down, cmd_genkey, cmd_init, cmd_peer_add, cmd_peer_list, cmd_peer_remove, cmd_pubkey,
    cmd_reality_keygen, cmd_server, cmd_setup, cmd_status, cmd_toggle, cmd_up,
};
use super::output;
use super::print_banner;
use twocha_protocol::Result;

/// 2cha - High-performance VPN utility with IPv4/IPv6 support
#[derive(Parser)]
#[command(
    name = "2cha",
    version = env!("CARGO_PKG_VERSION"),
    about = "High-performance VPN utility with IPv4/IPv6 support",
    long_about = None,
    after_help = "Examples:\n  \
        sudo 2cha setup            (turn-key server: wizard + service + firewall)\n  \
        2cha init                  (config-only wizard)\n  \
        2cha init client --template > client.toml\n  \
        2cha genkey client.key\n  \
        2cha pubkey client.key\n  \
        2cha up -c client.toml\n  \
        2cha server -c server.toml\n  \
        2cha peer add <public-key> --name laptop\n  \
        2cha peer list\n  \
        2cha config get crypto.cipher -c server.toml\n  \
        2cha config set crypto.cipher aes-256-gcm -c server.toml\n  \
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
    Status {
        /// Live view: refresh in place every second (Ctrl-C to exit)
        #[arg(short, long)]
        watch: bool,
    },

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

    /// Generate X25519 keypair: private key to file (0600), public key to stdout
    #[command(visible_alias = "key")]
    Genkey {
        /// Path for the new private key file (prompted for if omitted)
        output: Option<String>,
    },

    /// Print the public key for a private key file
    Pubkey {
        /// Private key file path (prompted for if omitted)
        key_file: Option<String>,
    },

    /// Generate a REALITY keypair + short id for the anti-probe TLS gate
    RealityKeygen {
        /// Path for the new REALITY private key file (prompted for if omitted)
        output: Option<String>,
    },

    /// Manage authorized peers on a running server (no restart needed)
    #[command(subcommand)]
    Peer(PeerCommands),

    /// Inspect and edit a config file (validated before every write)
    #[command(subcommand)]
    Config(ConfigCommands),

    /// Turn-key server provisioning: config wizard + systemd + forwarding
    /// + firewall + start (the `install.sh` one-liner runs this)
    Setup {
        /// Assume yes for every system change (unattended mode; still needs
        /// an existing config or -c)
        #[arg(short, long)]
        yes: bool,

        /// Use this server config instead of the wizard/default
        #[arg(short, long)]
        config: Option<String>,
    },

    /// Create a config (interactive wizard; use --template for stdout)
    Init {
        /// Config type: client or server (asked interactively if omitted)
        mode: Option<String>,

        /// Print a static config template to stdout instead of the wizard
        #[arg(short, long)]
        template: bool,

        /// Directory to write configs and keys to (wizard mode)
        #[arg(short, long)]
        output: Option<String>,
    },
}

#[derive(Subcommand)]
enum PeerCommands {
    /// Authorize a client public key (and persist it to server.toml)
    Add {
        /// Base64 X25519 public key (prompted for if omitted)
        public_key: Option<String>,

        /// Human-readable label for logs and listings
        #[arg(short, long)]
        name: Option<String>,
    },

    /// Revoke a peer: drops its active session immediately
    Remove {
        /// Base64 X25519 public key (picked from the peer list if omitted)
        public_key: Option<String>,
    },

    /// List authorized peers and their connection state
    List,
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Parse and validate a config against its schema
    Validate {
        /// Config file path
        #[arg(short, long, default_value = default_config())]
        config: String,
        /// Force server-schema validation
        #[arg(long)]
        server: bool,
        /// Force client-schema validation
        #[arg(long)]
        client: bool,
    },

    /// Print a config file and its validation status
    Show {
        /// Config file path
        #[arg(short, long, default_value = default_config())]
        config: String,
        /// Force server schema
        #[arg(long)]
        server: bool,
        /// Force client schema
        #[arg(long)]
        client: bool,
        /// Print the file only, without the validation summary
        #[arg(long)]
        raw: bool,
    },

    /// Print one value by dotted key (e.g. crypto.cipher)
    Get {
        /// Dotted key, e.g. server.listen or crypto.cipher
        key: String,
        /// Config file path
        #[arg(short, long, default_value = default_config())]
        config: String,
    },

    /// Set one value by dotted key (validated before writing)
    Set {
        /// Dotted key, e.g. server.listen or crypto.cipher
        key: String,
        /// New value (type inferred: bool, int, float, [a, b], else string)
        value: String,
        /// Config file path
        #[arg(short, long, default_value = default_config())]
        config: String,
        /// Force server schema
        #[arg(long)]
        server: bool,
        /// Force client schema
        #[arg(long)]
        client: bool,
    },

    /// Open the config in $EDITOR; the edit is validated before it is saved
    Edit {
        /// Config file path
        #[arg(short, long, default_value = default_config())]
        config: String,
        /// Force server schema
        #[arg(long)]
        server: bool,
        /// Force client schema
        #[arg(long)]
        client: bool,
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

        Commands::Status { watch } => cmd_status(watch),

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

        Commands::Genkey { output } => cmd_genkey(output.as_deref()),

        Commands::Pubkey { key_file } => cmd_pubkey(key_file.as_deref()),

        Commands::RealityKeygen { output } => cmd_reality_keygen(output.as_deref()),

        Commands::Peer(cmd) => match cmd {
            PeerCommands::Add { public_key, name } => {
                cmd_peer_add(public_key.as_deref(), name.as_deref())
            }
            PeerCommands::Remove { public_key } => cmd_peer_remove(public_key.as_deref()),
            PeerCommands::List => cmd_peer_list(),
        },

        Commands::Config(cmd) => match cmd {
            ConfigCommands::Validate {
                config,
                server,
                client,
            } => cmd_config_validate(&config, server, client),
            ConfigCommands::Show {
                config,
                server,
                client,
                raw,
            } => cmd_config_show(&config, server, client, raw),
            ConfigCommands::Get { key, config } => cmd_config_get(&config, &key),
            ConfigCommands::Set {
                key,
                value,
                config,
                server,
                client,
            } => cmd_config_set(&config, &key, &value, server, client),
            ConfigCommands::Edit {
                config,
                server,
                client,
            } => cmd_config_edit(&config, server, client),
        },

        Commands::Setup { yes, config } => cmd_setup(yes, config.as_deref()),

        Commands::Init {
            mode,
            template,
            output,
        } => cmd_init(mode.as_deref(), template, output.as_deref()),
    }
}

/// Print error and exit
pub fn exit_with_error(e: impl std::fmt::Display) -> ! {
    output::print_error(e);
    std::process::exit(1);
}
