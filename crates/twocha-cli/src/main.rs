//! # 2cha - High-Performance VPN Utility

mod cli;

fn main() {
    if let Err(e) = cli::run() {
        cli::exit_with_error(e);
    }
}
