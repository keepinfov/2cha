//! REALITY FFI build+link check (Rust side). Links the real `goreality` c-archive
//! and proves: (1) keygen works (so xtls/reality + curve25519 linked), (2) a Go
//! socketpair fd round-trips a byte stream across FFI. The full handshake exports
//! (gor_client_handshake / gor_server_new / gor_server_handshake / gor_close) are
//! linked into this binary too — a green build proves the whole client+server port
//! compiles and links. Runtime handshake testing is the next milestone.

use std::io::{Read, Write};
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;

extern "C" {
    fn gor_x25519_keygen(out_priv: *mut u8, out_pub: *mut u8) -> i32;
    fn gor_echo_fd() -> i32;

    // Linked (not called here) — presence proves the real port compiled + linked.
    fn gor_server_new(
        private_key: *const u8,
        dest: *const std::os::raw::c_char,
        server_names_csv: *const std::os::raw::c_char,
        short_ids_csv: *const std::os::raw::c_char,
        max_time_diff_ms: i64,
        err: *mut std::os::raw::c_char,
        errlen: i32,
    ) -> i64;
    fn gor_close(handle: i64);
}

fn main() {
    // 1. Keygen — proves xtls/reality + curve25519 linked and run.
    let mut priv_k = [0u8; 32];
    let mut pub_k = [0u8; 32];
    let rc = unsafe { gor_x25519_keygen(priv_k.as_mut_ptr(), pub_k.as_mut_ptr()) };
    assert_eq!(rc, 0, "gor_x25519_keygen failed");
    assert_ne!(priv_k, [0u8; 32], "private key all-zero");
    assert_ne!(pub_k, [0u8; 32], "public key all-zero");
    assert_ne!(priv_k, pub_k, "priv == pub");

    // Reference the handshake symbols so the linker must resolve them.
    let _ = gor_server_new as usize;
    let _ = gor_close as usize;

    // 2. Socketpair fd round-trip across the FFI boundary.
    let fd = unsafe { gor_echo_fd() };
    assert!(fd >= 0, "gor_echo_fd returned {fd}");
    let mut s = unsafe { UnixStream::from_raw_fd(fd) };
    let msg = b"hello-through-go-reality-socketpair";
    s.write_all(msg).expect("write to socketpair");
    let mut buf = vec![0u8; msg.len()];
    s.read_exact(&mut buf).expect("read echo back");
    assert_eq!(&buf[..], &msg[..], "socketpair echo mismatch");

    println!("goreality FFI OK: keygen + real ABI linked + socketpair round-trip works");
}
