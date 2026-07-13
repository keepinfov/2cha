//! `2cha setup` — turn-key server provisioning (the one-liner target).
//!
//! Wraps the config wizard (`init_wizard::server`) and continues where it
//! stops: systemd service, IP forwarding, firewall, start + verify. Every
//! system mutation is confirmed (or `--yes`), and every failure degrades to
//! printed instructions instead of aborting the remaining phases.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use console::style;
use dialoguer::{theme::ColorfulTheme, Confirm};
use twocha_core::TransportKind;
use twocha_protocol::{Result, VpnError};

use super::init_wizard;
use crate::cli::output::{icon_success, icon_warning};
use crate::cli::utils::ensure_root;

const SERVICE_NAME: &str = "2cha-server";
const SERVICE_PATH: &str = "/etc/systemd/system/2cha-server.service";
const SYSCTL_PATH: &str = "/etc/sysctl.d/99-2cha-forward.conf";

pub fn cmd_setup(yes: bool, config: Option<&str>) -> Result<()> {
    println!();
    println!(
        " {} {}",
        style("◆").cyan().bold(),
        style("2cha server setup (turn-key)").cyan().bold()
    );
    println!(
        "   {}",
        style("config wizard → systemd service → forwarding → firewall → verify").dim()
    );
    println!();

    ensure_root()?;
    let theme = ColorfulTheme::default();

    // ── Phase 1: config (reuse or run the wizard) ────────────────────────
    let config_path = resolve_config(config, yes, &theme)?;
    let cfg = twocha_core::ServerConfig::from_file(&config_path)
        .map_err(|e| VpnError::Config(format!("{}: {}", config_path.display(), e)))?;
    let port = cfg
        .listen_addr()
        .map_err(|e| VpnError::Config(e.to_string()))?
        .port();
    let proto = match cfg.server.transport {
        TransportKind::Quic | TransportKind::Awg => "udp",
        TransportKind::Tls => "tcp",
    };

    // ── Phase 2: systemd service ─────────────────────────────────────────
    let service_installed = install_systemd_service(&config_path, yes, &theme)?;

    // ── Phase 3: IP forwarding (only relevant in gateway mode) ───────────
    if cfg.gateway.ip_forward || cfg.gateway.ip6_forward {
        enable_forwarding(cfg.gateway.ip_forward, cfg.gateway.ip6_forward, yes, &theme)?;
    } else {
        println!(
            "   {} gateway mode disabled in the config — skipping IP forwarding",
            style("·").dim()
        );
    }

    // ── Phase 4: firewall ────────────────────────────────────────────────
    open_firewall(port, proto, yes, &theme)?;

    // ── Phase 5: verify ──────────────────────────────────────────────────
    if service_installed {
        verify_service();
    }

    println!();
    println!(" {} {}", icon_success(), style("Setup finished").bold());
    println!(
        "   Watch it live: {}   Logs: {}",
        style("2cha status --watch").cyan(),
        style(format!("journalctl -u {} -f", SERVICE_NAME)).cyan()
    );
    println!(
        "   Add more clients any time: {}",
        style("2cha peer add <public-key>").cyan()
    );
    println!();
    Ok(())
}

/// Pick the server config: explicit path > existing default > run the wizard.
fn resolve_config(config: Option<&str>, yes: bool, theme: &ColorfulTheme) -> Result<PathBuf> {
    if let Some(path) = config {
        let path = PathBuf::from(path);
        if !path.exists() {
            return Err(VpnError::Config(format!(
                "config not found: {}",
                path.display()
            )));
        }
        return Ok(path);
    }

    let default = PathBuf::from("/etc/2cha/server.toml");
    if default.exists() {
        let reuse = yes
            || Confirm::with_theme(theme)
                .with_prompt(format!("Use the existing config {}?", default.display()))
                .default(true)
                .interact()
                .map_err(|e| VpnError::Config(format!("prompt failed: {}", e)))?;
        if reuse {
            return Ok(default);
        }
    }

    if yes {
        return Err(VpnError::Config(
            "no server config found; --yes cannot answer the config wizard — \
             run `2cha setup` interactively once, or pass -c <server.toml>"
                .into(),
        ));
    }
    init_wizard::server::run(None)
}

/// Render the systemd unit for the current binary + config.
fn systemd_unit(config_path: &Path) -> String {
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "/usr/local/bin/2cha".to_string());
    format!(
        "[Unit]\n\
         Description=2cha VPN server\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         ExecStart={exe} server -c {config}\n\
         Restart=on-failure\n\
         RestartSec=3\n\
         # Runs as root for TUN + routing. To drop privileges instead, grant CAP_NET_ADMIN.\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        exe = exe,
        config = config_path.display(),
    )
}

/// Install + enable the systemd unit. Returns whether the service was
/// installed and started (drives the verify phase). Never hard-fails:
/// non-systemd hosts and refusals get the unit printed instead.
fn install_systemd_service(config_path: &Path, yes: bool, theme: &ColorfulTheme) -> Result<bool> {
    let unit = systemd_unit(config_path);

    if !Path::new("/run/systemd/system").exists() {
        println!(
            "   {} systemd not detected — start the server manually or with your init system:",
            icon_warning()
        );
        println!(
            "     {}",
            style(format!("2cha server -c {} -d", config_path.display())).cyan()
        );
        print_unit_instructions(&unit);
        return Ok(false);
    }

    let install = yes
        || Confirm::with_theme(theme)
            .with_prompt(format!(
                "Install and enable the systemd service ({})?",
                SERVICE_NAME
            ))
            .default(true)
            .interact()
            .map_err(|e| VpnError::Config(format!("prompt failed: {}", e)))?;
    if !install {
        print_unit_instructions(&unit);
        return Ok(false);
    }

    if let Err(e) = std::fs::write(SERVICE_PATH, &unit) {
        println!(
            "   {} could not write {}: {}",
            icon_warning(),
            SERVICE_PATH,
            e
        );
        print_unit_instructions(&unit);
        return Ok(false);
    }
    if !run_quiet("systemctl", &["daemon-reload"])
        || !run_quiet("systemctl", &["enable", "--now", SERVICE_NAME])
    {
        println!(
            "   {} systemctl failed — enable manually: {}",
            icon_warning(),
            style(format!("systemctl enable --now {}", SERVICE_NAME)).cyan()
        );
        return Ok(false);
    }
    println!(
        "   {} systemd service {} installed and started",
        icon_success(),
        style(SERVICE_NAME).cyan()
    );
    Ok(true)
}

fn print_unit_instructions(unit: &str) {
    println!(
        "   To run as a service, save this as {} and run {}:",
        style(SERVICE_PATH).cyan(),
        style("systemctl daemon-reload && systemctl enable --now 2cha-server").cyan()
    );
    println!();
    for line in unit.lines() {
        println!("     {}", style(line).dim());
    }
    println!();
}

/// Persist net.ipv4/ipv6 forwarding via sysctl.d and apply it now.
fn enable_forwarding(v4: bool, v6: bool, yes: bool, theme: &ColorfulTheme) -> Result<()> {
    let mut content = String::from("# Written by `2cha setup` (gateway mode needs forwarding)\n");
    if v4 {
        content.push_str("net.ipv4.ip_forward = 1\n");
    }
    if v6 {
        content.push_str("net.ipv6.conf.all.forwarding = 1\n");
    }

    let apply = yes
        || Confirm::with_theme(theme)
            .with_prompt(format!(
                "Enable IP forwarding persistently ({})?",
                SYSCTL_PATH
            ))
            .default(true)
            .interact()
            .map_err(|e| VpnError::Config(format!("prompt failed: {}", e)))?;
    if !apply {
        println!(
            "   {} skipped — enable manually: {}",
            icon_warning(),
            style("sysctl -w net.ipv4.ip_forward=1").cyan()
        );
        return Ok(());
    }

    match std::fs::write(SYSCTL_PATH, &content) {
        Ok(()) => {
            let _ = run_quiet("sysctl", &["--system"]);
            println!(
                "   {} IP forwarding enabled (persisted in {})",
                icon_success(),
                style(SYSCTL_PATH).dim()
            );
        }
        Err(e) => {
            println!(
                "   {} could not write {}: {} — enable manually: {}",
                icon_warning(),
                SYSCTL_PATH,
                e,
                style("sysctl -w net.ipv4.ip_forward=1").cyan()
            );
        }
    }
    Ok(())
}

/// Open the listen port on a detected firewall (ufw / firewalld); otherwise
/// print the commands for the admin to run.
fn open_firewall(port: u16, proto: &str, yes: bool, theme: &ColorfulTheme) -> Result<()> {
    let (tool, args): (&str, Vec<String>) = if have("ufw") {
        ("ufw", vec!["allow".into(), format!("{}/{}", port, proto)])
    } else if have("firewall-cmd") {
        (
            "firewall-cmd",
            vec![
                "--permanent".into(),
                format!("--add-port={}/{}", port, proto),
            ],
        )
    } else {
        println!(
            "   {} no ufw/firewalld detected — if a firewall is active, open {}:",
            style("·").dim(),
            style(format!("{}/{}", port, proto)).cyan()
        );
        println!(
            "     e.g. {}",
            style(format!(
                "iptables -A INPUT -p {} --dport {} -j ACCEPT",
                proto, port
            ))
            .dim()
        );
        return Ok(());
    };

    let apply = yes
        || Confirm::with_theme(theme)
            .with_prompt(format!("Open {}/{} via {}?", port, proto, tool))
            .default(true)
            .interact()
            .map_err(|e| VpnError::Config(format!("prompt failed: {}", e)))?;
    if !apply {
        println!(
            "   {} skipped — open manually: {} {}",
            icon_warning(),
            tool,
            args.join(" ")
        );
        return Ok(());
    }

    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut ok = run_quiet(tool, &arg_refs);
    if ok && tool == "firewall-cmd" {
        ok = run_quiet("firewall-cmd", &["--reload"]);
    }
    if ok {
        println!(
            "   {} firewall: {}/{} open ({})",
            icon_success(),
            port,
            proto,
            tool
        );
    } else {
        println!(
            "   {} {} failed — open {}/{} manually",
            icon_warning(),
            tool,
            port,
            proto
        );
    }
    Ok(())
}

/// Poll systemd for the service to come up; point at the logs on failure.
fn verify_service() {
    print!("   verifying service");
    let _ = std::io::stdout().flush();
    for _ in 0..10 {
        if run_quiet("systemctl", &["is-active", "--quiet", SERVICE_NAME]) {
            println!(" {}", icon_success());
            return;
        }
        print!(".");
        let _ = std::io::stdout().flush();
        std::thread::sleep(Duration::from_secs(1));
    }
    println!();
    println!(
        "   {} service did not report active — inspect: {}",
        icon_warning(),
        style(format!("journalctl -u {} -n 20", SERVICE_NAME)).cyan()
    );
}

/// Run a command discarding output; false when missing or non-zero.
fn run_quiet(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd)
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Is `cmd` on PATH?
fn have(cmd: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {} >/dev/null 2>&1", cmd)])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
