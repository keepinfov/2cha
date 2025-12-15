//! # Platform Module
//!
//! Platform-specific implementations with conditional compilation.

#[cfg(unix)]
pub mod unix;

#[cfg(windows)]
pub mod windows;

// Re-export platform-specific types with unified names
#[cfg(unix)]
pub use unix::*;

#[cfg(windows)]
pub use windows::*;
