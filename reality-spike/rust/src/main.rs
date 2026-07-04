//! REALITY FFI build spike (Rust side). Links the Go c-archive and proves the two
//! load-bearing mechanics: xtls/reality linked in, and a Go-created socketpair fd
//! round-trips a byte stream across the FFI boundary. Exit 0 = greenlight.

use std::io::{Read, Write};
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;

extern "C" {
    fn gor_echo_fd() -> i32;
    fn gor_reality_build_check() -> i32;
}

fn main() {
    // 1. xtls/reality actually linked into the archive.
    let ok = unsafe { gor_reality_build_check() };
    assert_eq!(ok, 1, "xtls/reality symbol did not link/behave");

    // 2. A Go-created socketpair fd carries a live byte stream to Rust.
    let fd = unsafe { gor_echo_fd() };
    assert!(fd >= 0, "gor_echo_fd returned {fd}");
    let mut s = unsafe { UnixStream::from_raw_fd(fd) };

    let msg = b"hello-through-go-reality-socketpair";
    s.write_all(msg).expect("write to socketpair");
    let mut buf = vec![0u8; msg.len()];
    s.read_exact(&mut buf).expect("read echo back");
    assert_eq!(&buf[..], &msg[..], "socketpair echo mismatch");

    println!("REALITY FFI spike OK: xtls/reality linked + socketpair round-trip works");
}
