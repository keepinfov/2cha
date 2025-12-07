//! # CLI Utilities
//!
//! Helper functions for CLI operations.

use crate::core::error::{Result, VpnError};

/// Path constants
#[cfg(unix)]
pub const PID_FILE: &str = "/tmp/2cha.pid";
#[cfg(windows)]
pub const PID_FILE: &str = "C:\\Windows\\Temp\\2cha.pid";

#[cfg(unix)]
pub const DEFAULT_CONFIG: &str = "/etc/2cha/client.toml";
#[cfg(windows)]
pub const DEFAULT_CONFIG: &str = "C:\\ProgramData\\2cha\\client.toml";

#[cfg(unix)]
pub const DEFAULT_SERVER_CONFIG: &str = "/etc/2cha/server.toml";
#[cfg(windows)]
pub const DEFAULT_SERVER_CONFIG: &str = "C:\\ProgramData\\2cha\\server.toml";

/// Check if VPN process is running
#[cfg(unix)]
pub fn is_running() -> bool {
    if let Ok(pid_str) = std::fs::read_to_string(PID_FILE) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            unsafe {
                return libc::kill(pid, 0) == 0;
            }
        }
    }
    false
}

#[cfg(windows)]
pub fn is_running() -> bool {
    if let Ok(pid_str) = std::fs::read_to_string(PID_FILE) {
        if let Ok(pid) = pid_str.trim().parse::<u32>() {
            if let Ok(output) = std::process::Command::new("tasklist")
                .args(["/FI", &format!("PID eq {}", pid), "/NH"])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                return stdout.contains(&pid.to_string());
            }
        }
    }
    false
}

/// Format bytes into human-readable string
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Generate cryptographic key
pub fn generate_key() -> Result<[u8; 32]> {
    let mut key = [0u8; 32];

    #[cfg(unix)]
    {
        if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
            use std::io::Read;
            file.read_exact(&mut key).map_err(VpnError::Io)?;
        } else {
            generate_fallback_key(&mut key);
        }
    }

    #[cfg(windows)]
    {
        use std::io::Read;
        if let Ok(mut file) = std::fs::File::open("C:\\Windows\\System32\\urandom") {
            let _ = file.read_exact(&mut key);
        } else {
            generate_fallback_key(&mut key);
        }
    }

    Ok(key)
}

fn generate_fallback_key(key: &mut [u8; 32]) {
    eprintln!("Warning: Using fallback random source");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let pid = std::process::id() as u128;

    for (i, byte) in key.iter_mut().enumerate() {
        let val = now.wrapping_add(pid).wrapping_mul(i as u128 + 1);
        *byte = ((val >> ((i % 16) * 8)) & 0xff) as u8;
    }
}

/// Parse command-line arguments for config path and flags
pub struct ParsedArgs {
    pub config_path: String,
    pub verbose: bool,
    pub quiet: bool,
}

impl ParsedArgs {
    pub fn parse(args: &[String], default_config: &str) -> Self {
        let mut config_path = default_config.to_string();
        let mut verbose = false;
        let mut quiet = false;

        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "-c" | "--config" => {
                    i += 1;
                    if i < args.len() {
                        config_path = args[i].to_string();
                    }
                }
                "-v" | "--verbose" => verbose = true,
                "-q" | "--quiet" => quiet = true,
                _ => {}
            }
            i += 1;
        }

        Self {
            config_path,
            verbose,
            quiet,
        }
    }
}

/// Setup logging based on verbosity
pub fn setup_logging(verbose: bool, quiet: bool) {
    let log_level = if verbose {
        "debug"
    } else if quiet {
        "error"
    } else {
        "info"
    };

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level))
        .format_timestamp_millis()
        .init();
}
