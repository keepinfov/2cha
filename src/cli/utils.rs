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
    pub daemon: bool,
}

impl ParsedArgs {
    pub fn parse(args: &[String], default_config: &str) -> Self {
        let mut config_path = default_config.to_string();
        let mut verbose = false;
        let mut quiet = false;
        let mut daemon = false;

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
                "-d" | "--daemon" => daemon = true,
                _ => {}
            }
            i += 1;
        }

        Self {
            config_path,
            verbose,
            quiet,
            daemon,
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

/// Log file path for daemon mode
#[cfg(unix)]
pub const LOG_FILE: &str = "/tmp/2cha.log";

/// Daemonize the process (Unix)
/// Uses the `daemonize` crate for robust daemon creation
#[cfg(unix)]
pub fn daemonize() -> Result<()> {
    use daemonize::Daemonize;
    use std::fs::OpenOptions;

    // Create/open log file for daemon output (append mode)
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_FILE)
        .map_err(|e| VpnError::Config(format!("Failed to open log file: {}", e)))?;

    let log_file_err = OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_FILE)
        .map_err(|e| VpnError::Config(format!("Failed to open log file: {}", e)))?;

    let daemonize = Daemonize::new()
        .pid_file(PID_FILE)
        .chown_pid_file(true)
        .working_directory("/")
        .umask(0o022)
        .stdout(log_file)
        .stderr(log_file_err);

    daemonize
        .start()
        .map_err(|e| VpnError::Config(format!("Failed to daemonize: {}", e)))
}

/// Daemonize the process (Windows)
/// Note: config_path should be an absolute path (canonicalized before calling)
#[cfg(windows)]
pub fn daemonize() -> Result<()> {
    // On Windows, we use a different approach
    // We detach from the console and run in the background
    use std::os::windows::process::CommandExt;

    let exe = std::env::current_exe()
        .map_err(|e| VpnError::Config(format!("Failed to get executable path: {}", e)))?;

    let args: Vec<String> = std::env::args().collect();

    // Build args without the daemon flag, converting relative config paths to absolute
    let mut new_args: Vec<String> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        if arg == "-d" || arg == "--daemon" {
            i += 1;
            continue;
        }
        if (arg == "-c" || arg == "--config") && i + 1 < args.len() {
            new_args.push(arg.clone());
            i += 1;
            // Convert config path to absolute
            let config_path = &args[i];
            if let Ok(abs_path) = std::fs::canonicalize(config_path) {
                new_args.push(abs_path.to_string_lossy().to_string());
            } else {
                new_args.push(config_path.clone());
            }
        } else {
            new_args.push(arg.clone());
        }
        i += 1;
    }

    // Start a new detached process
    const DETACHED_PROCESS: u32 = 0x00000008;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    std::process::Command::new(exe)
        .args(&new_args)
        .creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| VpnError::Config(format!("Failed to spawn daemon: {}", e)))?;

    // Exit the parent process
    std::process::exit(0);
}
