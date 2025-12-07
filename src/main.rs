//! # 2cha - High-Performance VPN Utility
//!
//! Entry point for the command-line interface.

use std::env;
use std::process;

// Import from library
use twocha::cli::{
    cmd_down, cmd_genkey, cmd_init, cmd_server, cmd_status, cmd_toggle, cmd_up,
    print_usage, print_version,
};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }

    let result = match args[1].as_str() {
        "up" | "connect" => cmd_up(&args[2..]),
        "down" | "disconnect" => cmd_down(),
        "status" | "s" => cmd_status(),
        "toggle" | "t" => cmd_toggle(&args[2..]),
        "server" | "serve" => cmd_server(&args[2..]),
        "genkey" | "key" => cmd_genkey(),
        "init" => cmd_init(&args[2..]),
        "-h" | "--help" | "help" => {
            print_usage();
            Ok(())
        }
        "-v" | "--version" | "version" => {
            print_version();
            Ok(())
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            print_usage();
            process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("\x1b[31m✗\x1b[0m Error: {}", e);
        process::exit(1);
    }
}
