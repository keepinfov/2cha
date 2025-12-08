//! # 2cha - High-Performance VPN Utility

fn main() {
    if let Err(e) = twocha::cli::run() {
        twocha::cli::exit_with_error(e);
    }
}
