//! Config creation command: interactive wizard or static template.

use std::path::Path;

use console::{style, Term};
use dialoguer::{theme::ColorfulTheme, Select};

use super::init_wizard;
use crate::cli::output::icon_error;
use twocha_core::{example_client_config, example_server_config};
use twocha_protocol::Result;

/// Create a config: interactive wizard on a TTY, template otherwise
pub fn cmd_init(mode: Option<&str>, template: bool, output: Option<&str>) -> Result<()> {
    let mode = match mode {
        Some(m) => match m {
            "client" | "c" => Some("client"),
            "server" | "s" => Some("server"),
            _ => {
                eprintln!("{} Invalid mode: {}", icon_error(), style(m).yellow());
                eprintln!(
                    "  Use {} or {}",
                    style("client").green(),
                    style("server").green()
                );
                std::process::exit(1);
            }
        },
        None => None,
    };

    let interactive = !template && Term::stdout().is_term() && Term::stderr().is_term();

    if !interactive {
        match mode.unwrap_or("client") {
            "server" => print!("{}", example_server_config()),
            _ => print!("{}", example_client_config()),
        }
        return Ok(());
    }

    let mode = match mode {
        Some(m) => m,
        None => {
            let items = [
                "client  — connect to an existing server",
                "server  — host a VPN",
            ];
            let idx = Select::with_theme(&ColorfulTheme::default())
                .with_prompt("What do you want to set up?")
                .items(items)
                .default(0)
                .interact()
                .map_err(init_wizard::write::wizard_io_err)?;
            if idx == 0 {
                "client"
            } else {
                "server"
            }
        }
    };

    let output = output.map(Path::new);
    match mode {
        "server" => init_wizard::server::run(output).map(|_| ()),
        _ => init_wizard::client::run(output),
    }
}
