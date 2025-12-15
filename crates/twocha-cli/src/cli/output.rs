//! # CLI Output Helpers
//!
//! Centralized output formatting for consistent CLI messages.

use console::{style, StyledObject};

/// Output icons with platform-specific spacing
pub struct Icons;

impl Icons {
    #[cfg(unix)]
    pub const SUCCESS: &'static str = "✅";
    #[cfg(windows)]
    pub const SUCCESS: &'static str = "[OK] ";

    #[cfg(unix)]
    pub const ERROR: &'static str = "❌";
    #[cfg(windows)]
    pub const ERROR: &'static str = "[ERR] ";

    #[cfg(unix)]
    pub const WARNING: &'static str = "⚡";
    #[cfg(windows)]
    pub const WARNING: &'static str = "[!] ";

    #[cfg(unix)]
    pub const CONNECTED: &'static str = "●";
    #[cfg(windows)]
    pub const CONNECTED: &'static str = "[*]";

    #[cfg(unix)]
    pub const DISCONNECTED: &'static str = "○";
    #[cfg(windows)]
    pub const DISCONNECTED: &'static str = "[ ]";
}

/// Format success icon with proper styling
pub fn icon_success() -> StyledObject<&'static str> {
    style(Icons::SUCCESS).green().bold()
}

/// Format error icon with proper styling
pub fn icon_error() -> StyledObject<&'static str> {
    style(Icons::ERROR).red().bold()
}

/// Format warning icon with proper styling
pub fn icon_warning() -> StyledObject<&'static str> {
    style(Icons::WARNING).yellow().bold()
}

/// Format connected icon with proper styling
pub fn icon_connected() -> StyledObject<&'static str> {
    style(Icons::CONNECTED).yellow().bold()
}

/// Format disconnected icon with proper styling
pub fn icon_disconnected() -> StyledObject<&'static str> {
    style(Icons::DISCONNECTED).dim()
}

/// Print a success message
pub fn print_success(msg: &str) {
    println!(" {}{}", icon_success(), msg);
}

/// Print an error message to stderr
pub fn print_error(msg: impl std::fmt::Display) {
    eprintln!(" {}Error: {}", icon_error(), msg);
}

/// Print a warning message
pub fn print_warning(msg: &str) {
    println!(" {}{}", icon_warning(), msg);
}

/// Print status: connected
pub fn print_connected(msg: &str) {
    println!(" {} {}", icon_connected(), msg);
}

/// Print status: disconnected/not connected
pub fn print_disconnected(msg: &str) {
    println!(" {} {}", icon_disconnected(), msg);
}

/// Print permission denied message
pub fn print_permission_denied() {
    println!(" {} Permission denied", icon_error());
}

/// Format success message for spinner
pub fn format_success(msg: &str) -> String {
    format!(" {} {}", icon_success(), msg)
}

/// Format error message for spinner
pub fn format_error(msg: &str) -> String {
    format!(" {} {}", icon_error(), msg)
}
