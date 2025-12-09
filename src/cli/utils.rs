//! # CLI Utilities
//!
//! Helper functions for CLI operations.

use crate::core::error::{Result, VpnError};
use console::style;
use std::io::Write;

/// Path constants
#[cfg(unix)]
pub const PID_FILE: &str = "/tmp/2cha.pid";
#[cfg(windows)]
pub const PID_FILE: &str = "C:\\Windows\\Temp\\2cha.pid";

/// Log file path for daemon mode
#[cfg(unix)]
pub const LOG_FILE: &str = "/tmp/2cha.log";

/// Check if VPN process is running (Unix)
#[cfg(unix)]
pub fn is_running() -> bool {
    if let Ok(pid_str) = std::fs::read_to_string(PID_FILE) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            unsafe {
                // kill(pid, 0) returns 0 if we can signal the process
                // It returns -1 with EPERM if process exists but we lack permission
                // It returns -1 with ESRCH if process doesn't exist
                if libc::kill(pid, 0) == 0 {
                    return true;
                }
                // Check if error is EPERM (permission denied) - process exists but owned by another user
                #[cfg(target_os = "linux")]
                let errno = *libc::__errno_location();
                #[cfg(target_os = "macos")]
                let errno = *libc::__error();
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                let errno = libc::ESRCH; // Default to "not found" on other platforms

                if errno == libc::EPERM {
                    return true;
                }
            }
        }
    }
    false
}

/// Check if current user can signal the VPN process (has permission to stop it)
#[cfg(unix)]
pub fn can_signal_process() -> bool {
    if let Ok(pid_str) = std::fs::read_to_string(PID_FILE) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            unsafe {
                // Try to send signal 0 (no actual signal, just permission check)
                if libc::kill(pid, 0) == 0 {
                    return true;
                }
            }
        }
    }
    false
}

/// Check if VPN process is running (Windows)
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

/// Check if running as root/superuser (Unix)
#[cfg(unix)]
pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Check if running as Administrator (Windows)
#[cfg(windows)]
pub fn is_root() -> bool {
    // On Windows, we check by attempting to open a privileged resource
    // For simplicity, we'll check if we can write to a system location
    use std::fs::OpenOptions;
    OpenOptions::new()
        .write(true)
        .create(true)
        .open("C:\\Windows\\Temp\\2cha_admin_check.tmp")
        .map(|_| {
            let _ = std::fs::remove_file("C:\\Windows\\Temp\\2cha_admin_check.tmp");
            true
        })
        .unwrap_or(false)
}

/// Prompt for sudo password and re-execute current command with elevated privileges (Unix)
/// Returns Ok(()) if elevation succeeded (and the process exits), or Err if it failed
#[cfg(unix)]
pub fn elevate_with_sudo() -> Result<()> {
    use std::process::{Command, Stdio};

    let exe = std::env::current_exe()
        .map_err(|e| VpnError::Config(format!("Failed to get executable path: {}", e)))?;

    let args: Vec<String> = std::env::args().skip(1).collect();

    // Print prompt for password
    print!(
        "{} This command requires root privileges.\n",
        style("⚡").yellow().bold()
    );
    print!("{}", style("[sudo] password: ").bold());
    std::io::stdout().flush().ok();

    // Read password securely (hidden input)
    let password = rpassword::read_password()
        .map_err(|e| VpnError::Config(format!("Failed to read password: {}", e)))?;

    // Try to validate sudo credentials first with -v (validate)
    let validate = Command::new("sudo")
        .args(["-S", "-v"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn();

    let mut validate_child = match validate {
        Ok(child) => child,
        Err(e) => {
            println!(
                "\n{} sudo not available: {}",
                style("✗").red().bold(),
                e
            );
            return Err(VpnError::Config("sudo not available".into()));
        }
    };

    // Write password to sudo's stdin
    if let Some(ref mut stdin) = validate_child.stdin {
        writeln!(stdin, "{}", password).ok();
    }

    let validate_status = validate_child.wait();
    if validate_status.map(|s| !s.success()).unwrap_or(true) {
        println!("{} Authentication failed", style("✗").red().bold());
        return Err(VpnError::Config("sudo authentication failed".into()));
    }

    // Now run the actual command with cached credentials
    // Use -n (non-interactive) since credentials should be cached
    let mut child = Command::new("sudo")
        .args(["-S", "--"])
        .arg(&exe)
        .args(&args)
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| VpnError::Config(format!("Failed to execute sudo: {}", e)))?;

    // Write password again (in case cache expired)
    if let Some(ref mut stdin) = child.stdin {
        writeln!(stdin, "{}", password).ok();
    }

    // Wait for the elevated process and exit with its status
    let status = child
        .wait()
        .map_err(|e| VpnError::Config(format!("Failed to wait for sudo process: {}", e)))?;

    std::process::exit(status.code().unwrap_or(1));
}

/// Prompt for elevation on Windows (shows message to run as Administrator)
#[cfg(windows)]
pub fn elevate_with_sudo() -> Result<()> {
    println!(
        "{} This command requires Administrator privileges.",
        style("⚡").yellow().bold()
    );
    println!(
        "  Please run this command from an {} prompt.",
        style("Administrator").cyan().bold()
    );
    println!();
    println!("  Right-click Command Prompt or PowerShell and select");
    println!("  \"{}\"", style("Run as administrator").green());
    std::process::exit(1);
}

/// Check if elevation is needed and prompt for sudo password if so
/// This is a convenience function that combines is_root() and elevate_with_sudo()
pub fn ensure_root() -> Result<()> {
    if !is_root() {
        elevate_with_sudo()?;
    }
    Ok(())
}
