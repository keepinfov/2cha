//! Connect / disconnect / toggle commands.

use super::create_spinner;
use crate::cli::output::{format_success, print_connected, print_disconnected};
#[cfg(unix)]
use crate::cli::utils::can_signal_process;
#[cfg(unix)]
use crate::cli::utils::log_file;
use crate::cli::utils::{daemonize, ensure_root, find_pid_file, is_running, pid_file};
use console::style;
use std::time::Duration;
use twocha_lib::vpn::client;
use twocha_protocol::{Result, VpnError};

/// Connect to VPN server
pub fn cmd_up(config_path: &str, daemon: bool, verbose: bool, quiet: bool) -> Result<()> {
    if is_running() {
        if !quiet {
            print_connected("VPN already connected");
            println!(
                "  Use {} or {}",
                style("2cha status").cyan(),
                style("2cha down").cyan()
            );
        }
        return Ok(());
    }

    // Ensure we have root/Administrator privileges
    ensure_root()?;

    // Convert config path to absolute before daemonizing (daemon changes cwd)
    let config_path = std::fs::canonicalize(config_path)
        .map_err(|e| VpnError::Config(format!("Config file '{}' not found: {}", config_path, e)))?
        .to_string_lossy()
        .to_string();

    let spinner = if !quiet {
        Some(create_spinner("Connecting..."))
    } else {
        None
    };

    if daemon {
        if let Some(ref sp) = spinner {
            #[cfg(unix)]
            sp.finish_with_message(format!(
                "Connecting in background. Logs: {}",
                style(log_file()).dim()
            ));
            #[cfg(windows)]
            sp.finish_with_message("Connecting in background...");
        }
        if !quiet {
            #[cfg(windows)]
            print_windows_note();
            println!("  Use {} to check connection", style("2cha status").cyan());
        }
        daemonize()?;
    } else {
        if let Some(ref sp) = spinner {
            sp.finish_and_clear();
        }
        #[cfg(windows)]
        if !quiet {
            print_windows_note();
        }
    }

    if verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
            .format_timestamp_millis()
            .init();
    } else if !quiet && !daemon {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
            .format_target(false)
            .format_timestamp(None)
            .init();
    }

    // PID file is managed by the daemonize crate in daemon mode (Unix);
    // on Windows the daemon re-executes without -d, so it reaches this path itself.
    let pid_path = pid_file();
    if !daemon {
        std::fs::write(&pid_path, std::process::id().to_string()).ok();
    }

    let result = client::run(&config_path, quiet || daemon);

    if !daemon {
        std::fs::remove_file(&pid_path).ok();
    }

    result
}

#[cfg(windows)]
fn print_windows_note() {
    println!(
        "  {} Requires {} and {}",
        style("Note:").dim(),
        style("wintun.dll").yellow(),
        style("Administrator").yellow()
    );
}

/// Disconnect from VPN (Unix)
#[cfg(unix)]
pub fn cmd_down() -> Result<()> {
    if !is_running() {
        print_disconnected("VPN not connected");
        return Ok(());
    }

    // Check if we have permission to stop the VPN, elevate if needed
    if !can_signal_process() {
        ensure_root()?;
    }

    if let Some(pid_path) = find_pid_file() {
        if let Ok(pid_str) = std::fs::read_to_string(&pid_path) {
            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                let spinner = create_spinner("Disconnecting...");

                unsafe {
                    libc::kill(pid, libc::SIGTERM);
                }
                std::thread::sleep(Duration::from_millis(500));

                if !is_running() {
                    spinner.finish_with_message(format_success("Disconnected"));
                } else {
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                    }
                    std::fs::remove_file(&pid_path).ok();
                    spinner.finish_with_message(format_success("Force disconnected"));
                }
                return Ok(());
            }
        }
    }

    print_disconnected("VPN not connected");
    Ok(())
}

/// Disconnect from VPN (Windows)
#[cfg(windows)]
pub fn cmd_down() -> Result<()> {
    if let Some(pid_path) = find_pid_file() {
        if let Ok(pid_str) = std::fs::read_to_string(&pid_path) {
            if let Ok(pid) = pid_str.trim().parse::<u32>() {
                let spinner = create_spinner("Disconnecting...");

                let _ = std::process::Command::new("taskkill")
                    .args(["/PID", &pid.to_string(), "/F"])
                    .output();

                std::thread::sleep(Duration::from_millis(500));
                std::fs::remove_file(&pid_path).ok();

                spinner.finish_with_message(format_success("Disconnected"));
                return Ok(());
            }
        }
    }

    print_disconnected("VPN not connected");
    Ok(())
}

/// Toggle VPN connection
pub fn cmd_toggle(config_path: &str, daemon: bool, verbose: bool, quiet: bool) -> Result<()> {
    if is_running() {
        cmd_down()
    } else {
        cmd_up(config_path, daemon, verbose, quiet)
    }
}
